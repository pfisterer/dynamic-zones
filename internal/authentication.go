package app

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/authn"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/oidcauth"
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

// OIDCVerifierConfig holds the minimal configuration for OIDC token
// verification. JWKSURL is what keeps an identity provider that is down from
// taking this service with it — see the oidcauth package for the whole story.
type OIDCVerifierConfig = oidcauth.Config

// OIDCAuthVerifier manages the OIDC token verification process.
type OIDCAuthVerifier struct {
	Verifier *oidcauth.Verifier
	Logger   *zap.SugaredLogger
}

// NewOIDCAuthVerifier initializes a new OIDCAuthVerifier. With a key set
// configured this makes no network call, so the provider being away is a state
// this service can report rather than a reason to die.
func NewOIDCAuthVerifier(cfg OIDCVerifierConfig, log *zap.SugaredLogger) (*OIDCAuthVerifier, error) {
	verifier, err := oidcauth.New(cfg, log)
	if err != nil {
		return nil, err
	}
	return &OIDCAuthVerifier{Verifier: verifier, Logger: log}, nil
}

// KeysUnavailable reports whether the identity provider is currently
// unreachable, for the status the UI shows.
func (m *OIDCAuthVerifier) KeysUnavailable() bool {
	return m != nil && m.Verifier.KeysUnavailable()
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

		claims, err := m.Verifier.Verify(c.Request.Context(), rawIDToken)
		if err != nil {
			// A token nobody can judge right now is not a rejected token. 401
			// would tell the browser to drop its session and sign in again,
			// which is impossible while the provider is away — the user would
			// loop through a login that cannot finish and read it as our fault.
			if errors.Is(err, oidcauth.ErrKeysUnavailable) {
				m.Logger.Warnw("cannot verify tokens: the identity provider is unreachable", "error", err)
				c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
					"error": "sign-in is temporarily unavailable: the identity provider cannot be reached",
				})
				return
			}
			m.Logger.Warnf("Failed to verify ID token from Authorization header: %v. Denying access.", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": fmt.Sprintf("Invalid or expired token: %v", err)})
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
		c.Set(UserDataKey, claims)

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
