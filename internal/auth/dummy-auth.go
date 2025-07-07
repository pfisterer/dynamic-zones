package auth

import (
	"github.com/gin-gonic/gin"
)

const UserDataKey = "DYNAMIC_ZONES_api_userData"

// DummyAuthMiddleware for development
func InjectFakeAuthMiddleware() gin.HandlerFunc {

	return func(c *gin.Context) {

		fakeUserData := UserClaims{
			Subject:           "1234567890",
			Email:             "fakestudent@example.com",
			PreferredUsername: "fakestudent",
		}

		c.Set(UserDataKey, &fakeUserData)
		c.Next()
	}

}
