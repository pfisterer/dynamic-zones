package auth

import (
	"net/http"
	"strings"

	"github.com/farberg/dynamic-zones/internal/storage"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func CombinedAuthMiddleware(oidcVerifier *OIDCAuthVerifier, store *storage.Storage, log *zap.SugaredLogger) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
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
		if strings.HasPrefix(tokenString, storage.ApiTokenPrefix) {

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
