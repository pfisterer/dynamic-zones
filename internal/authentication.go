package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/authn"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/token"
	"go.uber.org/zap"
)

const UserDataKey = "__api_userData"

// The read-only-token rule (recording the flag, reading it, and refusing writes
// for it) lives in cloud-self-service-golib/ginweb, shared with the other
// services. This file only records the flag via ginweb.SetReadOnly once it has
// resolved the token below.

// UserClaims holds the relevant user information extracted from the ID token.
//
// An alias rather than a type of its own: the identity of a caller has to mean
// the same thing in every service — a token issued here and a group resolved
// elsewhere only line up if both agree on the string. The definition lives in
// the shared module; this name stays because the call sites read well with it.
type UserClaims = authn.Claims

// OIDCVerifierConfig holds the minimal configuration for OIDC token verification.
type OIDCVerifierConfig struct {
	IssuerURL string
	ClientID  string
}

// OIDCAuthVerifier manages the OIDC token verification process.
type OIDCAuthVerifier struct {
	Config   OIDCVerifierConfig
	Verifier *oidc.IDTokenVerifier
	Logger   *zap.SugaredLogger
}

// NewOIDCAuthVerifier initializes a new OIDCAuthVerifier.
// It sets up the ID token verifier using the issuer URL and client ID.
func NewOIDCAuthVerifier(cfg OIDCVerifierConfig, log *zap.SugaredLogger) (*OIDCAuthVerifier, error) {
	ctx := context.Background()
	// Discover the OIDC provider's configuration from the issuer URL
	// This fetches the JWKS endpoint and other metadata needed for verification.
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider for issuer '%s': %w", cfg.IssuerURL, err)
	}

	// Configure the ID token verifier.
	// The ClientID here acts as the expected audience (aud claim) for the token.
	oidcConfig := &oidc.Config{
		ClientID: cfg.ClientID,
		// If you have multiple audiences, you can specify them here:
		// ExpectedAudience: []string{"your-api-audience", "another-audience"},
	}
	verifier := provider.Verifier(oidcConfig)

	return &OIDCAuthVerifier{
		Config:   cfg,
		Verifier: verifier,
		Logger:   log,
	}, nil
}

// BearerTokenAuthMiddleware is a Gin middleware to verify OIDC bearer tokens.
// It expects the token in the "Authorization: Bearer <token>" header.
func (m *OIDCAuthVerifier) BearerTokenAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			m.Logger.Debug("Authorization header missing. Denying access.")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header required"})
			return
		}

		// Check if the header uses the Bearer scheme (case-insensitive per RFC 7235)
		rawIDToken, ok := authn.CutBearerPrefix(authHeader)
		if !ok {
			m.Logger.Debug("Authorization header does not use the Bearer scheme. Denying access.")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unsupported authorization type. Use Bearer token."})
			return
		}

		if rawIDToken == "" {
			m.Logger.Debug("Bearer token is empty. Denying access.")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Bearer token missing"})
			return
		}

		ctx := context.Background()
		// Verify the ID token's signature, issuer, audience, and expiry
		idToken, err := m.Verifier.Verify(ctx, rawIDToken)
		if err != nil {
			m.Logger.Warnf("Failed to verify ID token from Authorization header: %v. Denying access.", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid or expired token: %v", err)})
			return
		}

		// Optional: Explicitly check for token expiry, though oidc.Verifier usually handles this.
		if idToken.Expiry.Before(time.Now()) {
			m.Logger.Warnf("ID token expired for user '%s'. Denying access.", idToken.Subject)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Token expired"})
			return
		}

		// Extract claims from the verified ID token
		var claims UserClaims
		if err := idToken.Claims(&claims); err != nil {
			m.Logger.Errorf("Failed to parse ID token claims: %v. Denying access.", err)
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user claims from token."})
			return
		}

		// The probe that used to sit here is gone, together with the question it
		// asked. It watched for a verified ID token whose `email` and
		// `preferred_username` disagreed, because this service keyed zone and
		// token ownership on one and policy rules on the other — and no database
		// here could prove they always matched, since each stores only one.
		//
		// It never answered: over 36 hours of production it saw 8 authenticated
		// requests and not one login, which is what a semester break looks like.
		// Keycloak answered it instead, and completely rather than by sample —
		// 260 accounts in `dhbw-main`, zero with an `email` differing from the
		// username, zero without an address at all (2026-08-26). Everything now
		// reads Claims.Identity() and there is nothing left to compare.
		c.Set(UserDataKey, &claims)

		c.Next() // Continue to the next handler in the chain
	}
}

func CombinedAuthMiddleware(oidcVerifier *OIDCAuthVerifier, store *Storage, log *zap.SugaredLogger, devMode bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Allow preflight OPTIONS requests without authentication
		if c.Request.Method == http.MethodOptions && c.GetHeader("Access-Control-Request-Headers") != "" {
			log.Infof("Allowing pre-flight request without authentication")
			c.Next()
			return
		}

		// Dev-only: trust the X-Dummy-Auth-User header so the self-service UI's
		// dummy-auth mode works for local development. This bypasses token
		// verification entirely, so it is gated on devMode and is NEVER active
		// in production (devMode is false there).
		if devMode {
			if dummyUser := c.GetHeader("X-Dummy-Auth-User"); dummyUser != "" {
				log.Warnf("DEV MODE: trusting X-Dummy-Auth-User '%s' without token verification", dummyUser)
				c.Set(UserDataKey, &UserClaims{Email: dummyUser})
				ginweb.SetReadOnly(c, false)
				c.Next()
				return
			}
		}

		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")

		tokenString, ok := authn.CutBearerPrefix(authHeader)
		if !ok {
			// The header value itself is never logged: a client sending a valid
			// token under an unexpected scheme would write its credential into
			// the log. The scheme alone is what makes this diagnosable.
			log.Warnf("Missing or invalid Authorization header (scheme %q)", authn.Scheme(authHeader))
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization Bearer header"})
			return
		}

		// Check if token is an API key (starts with your prefix)
		if store.Tokens.Owns(tokenString) {

			// Look up the token in storage. An expired one is not found, so the
			// answer here needs no expiry check of its own.
			rec, err := store.Tokens.Lookup(ctx, tokenString)
			if errors.Is(err, token.ErrNotFound) {
				log.Warn("Invalid API token, returning unauthorized")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}
			if err != nil {
				log.Warnf("storage error: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}

			// Recorded here, enforced by the route group: what counts as a
			// write is a property of the OPERATION, and only the REST routes
			// can read that off the HTTP method (see
			// RejectWritesForReadOnlyTokens).
			ginweb.SetReadOnly(c, rec.ReadOnly)

			// One field, because there is one identity. The token was issued
			// under this subject (see tokenSubject) and Identity() reads Email
			// first, so this is the string every later lookup resolves to —
			// zone ownership, policy matching and the %u expansion alike.
			//
			// It used to fill all three claims, and that was not tidiness: for a
			// while it filled only preferred_username, while policy rules matched
			// on Email. Such a token authenticated cleanly and then matched NO
			// rule — its holder saw the zones they already owned and was entitled
			// to nothing, and every create was refused.
			c.Set(UserDataKey, &UserClaims{Email: rec.Subject})

			c.Next()
			return
		}

		// Otherwise, treat it as an OIDC Bearer JWT. Set before handing over:
		// BearerTokenAuthMiddleware calls Next() itself, so anything set after
		// it would land once the handlers have already run.
		ginweb.SetReadOnly(c, false)
		oidcVerifier.BearerTokenAuthMiddleware()(c)

	}
}
