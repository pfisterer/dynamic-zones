package app

import (
	"net/http"
	"strconv"
	"time"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/storage"
	"github.com/gin-gonic/gin"
)

// CreateTokensApiGroup adds /v1/tokens endpoints to the API
func CreateTokensApiGroup(v1 *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	v1.GET("/tokens/", getTokens(app))
	v1.POST("/tokens/", createToken(app))
	v1.DELETE("/tokens/:id", deleteToken(app))

	return v1
}

// TokensResponse represents a list of tokens returned by GET /tokens
type TokensResponse struct {
	Tokens []storage.Token `json:"tokens"`
}

type CreateTokenRequest struct {
	ReadOnly bool `json:"read_only"`
}

// getTokens retrieves all tokens for the authenticated user
// @Summary List API tokens
// @Description Retrieve all API tokens for the authenticated user
// @Tags tokens
// @Produce json
// @Success 200 {object} TokensResponse
// @Failure 500 {object} map[string]string "Failed to retrieve tokens"
// @Security ApiKeyAuth
// @Router /v1/tokens/ [get]
func getTokens(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 routes.getTokens: Called with user: ", user.PreferredUsername)
		app.Log.Debug("-------------------------------------------------------------------------------")

		tokens, err := app.Storage.GetTokens(ctx, user.PreferredUsername)
		if err != nil {
			app.Log.Errorf("routes.getTokens: Error retrieving tokens for user %s: %v", user.PreferredUsername, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tokens"})
			return
		}

		// Create tokenresponse
		var tokenResponse TokensResponse
		tokenResponse.Tokens = tokens

		app.Log.Debug("🟢 routes.getTokens: Returning tokens: ", tokens)
		c.JSON(http.StatusOK, tokenResponse)
	}
}

// createToken creates a new API token for the authenticated user
// @Summary Create a new API token
// @Description Generate a new API token for the authenticated user with TTL defined in configuration
// @Tags tokens
// @Produce json
// @Success 201 {object} storage.Token
// @Failure 500 {object} map[string]string "Failed to retrieve tokens"
// @Security ApiKeyAuth
// @Router /v1/tokens/ [post]
func createToken(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)
		ttl := time.Duration(app.Config.ApiTokenTTLHours) * time.Hour

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 routes.createToken: Create token called for user: ", user.PreferredUsername)
		app.Log.Debug("-------------------------------------------------------------------------------")

		var input CreateTokenRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		app.Log.Debug("Create token request with readonly =", input.ReadOnly)

		token, err := app.Storage.CreateToken(ctx, user.PreferredUsername, ttl, input.ReadOnly)
		if err != nil {
			app.Log.Errorf("routes.createToken: Error creating token for user %s: %v", user.PreferredUsername, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
			return
		}

		app.Log.Debugf("✳️ routes.createToken: Created token for user: %s", user.PreferredUsername)
		c.JSON(http.StatusCreated, gin.H{"status": "success", "token": token})
	}
}

// deleteToken deletes an API token by TokenString for the authenticated user
// @Summary Delete an API token
// @Description Delete an API token by its TokenString
// @Tags tokens
// @Produce json
// @Param id path string true "TokenString of the token to delete"
// @Success 200 {object} map[string]string
// @Success 404 {object} map[string]string
// @Failure 500 {object} map[string]string "Failed to delete token"
// @Security ApiKeyAuth
// @Router /v1/tokens/{id} [delete]
func deleteToken(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		tokenIdStr := c.Param("id")
		tokenId, err := strconv.Atoi(tokenIdStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token ID"})
			return
		}
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 routes.deleteToken: Delete token called for token: ", tokenId, " and user: ", user.PreferredUsername)
		app.Log.Debug("-------------------------------------------------------------------------------")

		statusCode, returnValue, err := app.Storage.DeleteToken(ctx, user.PreferredUsername, tokenId)
		if err != nil {
			app.Log.Errorf("routes.deleteToken: Error deleting token '%s' for user %s: %v", tokenId, user.PreferredUsername, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete token"})
			return
		}

		app.Log.Debugf("🗑️ routes.deleteToken: Deleted token '%s', returning %s", tokenId, returnValue)
		c.JSON(statusCode, returnValue)
	}
}
