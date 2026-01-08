package auth

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
