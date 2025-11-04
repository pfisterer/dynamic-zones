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
		const bearerPrefix = "Bearer "
		ctx := c.Request.Context()
		authHeader := c.GetHeader("Authorization")

		tokenString, ok := strings.CutPrefix(authHeader, bearerPrefix)
		if !ok {
			log.Warnf("Missing or invalid Authorization header: %s", authHeader)
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing or invalid Authorization Bearer header"})
			return
		}

		// Check if token is an API key (starts with your prefix)
		if strings.HasPrefix(tokenString, storage.ApiTokenPrefix) {

			token, err := store.GetToken(ctx, tokenString)
			if err != nil {
				log.Warnf("storage error: %v", err)
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "internal error"})
				return
			}

			if token == nil {
				log.Warn("Invalid API token, got nil token, returning unauthorized")
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
				return
			}

			c.Set(UserDataKey, &UserClaims{
				PreferredUsername: token.User,
			})

			c.Next()
			return
		}

		// Otherwise, treat it as an OIDC Bearer JWT
		oidcVerifier.BearerTokenAuthMiddleware()(c)

	}
}
