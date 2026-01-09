package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

const UserDataKey = "__api_userData"

// UserClaims holds the relevant user information extracted from the ID token.
type UserClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"email,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Name              string `json:"name,omitempty"`
}

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

		// Check if the header starts with "Bearer "
		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.Logger.Debug("Authorization header does not start with 'Bearer '. Denying access.")
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unsupported authorization type. Use Bearer token."})
			return
		}

		// Extract the raw ID token string
		rawIDToken := strings.TrimPrefix(authHeader, "Bearer ")
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

		// Store user claims in Gin context for access in subsequent handlers
		c.Set(UserDataKey, &claims)
		//m.Logger.Debugf("Token verified for user '%s' (sub: %s, email: %s).", claims.PreferredUsername, claims.Subject, claims.Email)

		c.Next() // Continue to the next handler in the chain
	}
}

func CombinedAuthMiddleware(oidcVerifier *OIDCAuthVerifier, store *Storage, log *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()

		// Allow preflight OPTIONS requests without authentication
		if c.Request.Method == http.MethodOptions && c.GetHeader("Access-Control-Request-Headers") != "" {
			log.Infof("Allowing pre-flight request without authentication")
			c.Next()
			return
		}

		// Get the Authorization header
		authHeader := c.GetHeader("Authorization")

		// Remove the bearer prefix from the Authorization header (if present)
		const bearerPrefix = "Bearer "
		tokenString, ok := strings.CutPrefix(authHeader, bearerPrefix)
		if !ok {
			log.Warnf("Missing or invalid Authorization header: %s", authHeader)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization Bearer header"})
			return
		}

		// Check if token is an API key (starts with your prefix)
		if strings.HasPrefix(tokenString, ApiTokenPrefix) {

			// Look up the token in storage
			token, err := store.GetToken(ctx, tokenString)
			if err != nil {
				log.Warnf("storage error: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}

			// Check if a token was found
			if token == nil {
				log.Warn("Invalid API token, got nil token, returning unauthorized")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}

			// Check whether the operation is GET (read-only) and the token is read-only
			if c.Request.Method != http.MethodGet && token.ReadOnly {
				log.Warnf("Attempt to use read-only token for non-GET operation: %s %s", c.Request.Method, c.Request.URL.Path)
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "token is read-only"})
				return
			}

			// Set user info in context
			c.Set(UserDataKey, &UserClaims{
				PreferredUsername: token.Username,
			})

			c.Next()
			return
		}

		// Otherwise, treat it as an OIDC Bearer JWT
		oidcVerifier.BearerTokenAuthMiddleware()(c)

	}
}
