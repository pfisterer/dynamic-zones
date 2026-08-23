package app

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/token"
)

// CreateTokensApiGroup adds /v1/tokens endpoints to the API
func CreateTokensApiGroup(v1 *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	v1.GET("/tokens/", getTokens(app))
	v1.POST("/tokens/", createToken(app))
	v1.DELETE("/tokens/:id", deleteToken(app))

	return v1
}

// Token is the API shape of a token. Deliberately not the stored row: the
// database columns are the shared module's to change, while these field names
// are published — swag reads them into swagger.json and the UI reads that.
type Token struct {
	ID     uint   `json:"id" example:"1" swagger:"desc(The token ID)"`
	User   string `json:"user" example:"alice@example.edu" swagger:"desc(Identity that owns the token)"`
	Prefix string `json:"token_prefix" example:"dynz_token_ab12cd34" swagger:"desc(First characters of the token, for identification)"`
	// TokenString is set only in the response that creates a token. It is not
	// stored and cannot be recovered afterwards.
	TokenString string    `json:"token_string,omitempty" example:"dynz_token_abcdef123456" swagger:"desc(The API token — returned ONLY when it is created)"`
	ExpiresAt   time.Time `json:"expires_at" example:"2025-12-31T23:59:59Z" swagger:"desc(Token expiration date and time)"`
	ReadOnly    bool      `json:"read_only" example:"false"`
	CreatedAt   time.Time `json:"created_at" example:"2025-11-04T12:00:00Z"`
}

func toAPIToken(rec token.Record) Token {
	return Token{
		ID:        rec.ID,
		User:      rec.Subject,
		Prefix:    rec.Prefix,
		ExpiresAt: rec.ExpiresAt,
		ReadOnly:  rec.ReadOnly,
		CreatedAt: rec.CreatedAt,
	}
}

// tokenSubject is the identity a token belongs to here.
//
// preferred_username, NOT authn.Claims.Identity — which would prefer the
// e-mail. This service keys zone ownership on preferred_username
// (Storage.IsZoneOwner, Zone.Username), and the authentication path turns a
// token back into exactly this claim. Issuing tokens under a different string
// would leave them authenticating fine while resolving to somebody else's
// zones, and would hide every existing token from its owner's list.
//
// That this service matches policy rules on the e-mail instead is a genuine
// inconsistency, and an older one than this change.
func tokenSubject(user *UserClaims) string {
	return user.PreferredUsername
}

// TokensResponse represents a list of tokens returned by GET /tokens
type TokensResponse struct {
	Tokens []Token `json:"tokens"`
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
// @ID listTokens
// @Router /v1/tokens/ [get]
func getTokens(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := tokenSubject(c.MustGet(UserDataKey).(*UserClaims))

		records, err := app.Storage.Tokens.List(c.Request.Context(), subject)
		if err != nil {
			app.Log.Errorf("Error retrieving tokens for %s: %v", subject, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve tokens"})
			return
		}

		out := make([]Token, 0, len(records))
		for _, rec := range records {
			out = append(out, toAPIToken(rec))
		}

		// Count only: a token list must never reach the log, and the secret is
		// not in these records to begin with.
		app.Log.Debugf("Returning %d tokens for %s", len(out), subject)
		c.JSON(http.StatusOK, TokensResponse{Tokens: out})
	}
}

// createToken creates a new API token for the authenticated user
// @Summary Create a new API token
// @Description Generate a new API token for the authenticated user with TTL defined in configuration
// @Tags tokens
// @Produce json
// @Success 201 {object} Token
// @Failure 500 {object} map[string]string "Failed to retrieve tokens"
// @Security ApiKeyAuth
// @ID createToken
// @Router /v1/tokens/ [post]
func createToken(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		subject := tokenSubject(c.MustGet(UserDataKey).(*UserClaims))

		var input CreateTokenRequest
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}

		ttl := time.Duration(app.Config.WebServer.ApiTokenTTLHours) * time.Hour
		issued, err := app.Storage.Tokens.Issue(c.Request.Context(), subject, ttl, input.ReadOnly)
		if err != nil {
			app.Log.Errorf("Error creating token for %s: %v", subject, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
			return
		}

		out := toAPIToken(issued.Record)
		out.TokenString = issued.Secret

		app.Log.Debugf("Created token %d for %s", issued.ID, subject)
		c.JSON(http.StatusCreated, gin.H{"status": "success", "token": out})
	}
}

// deleteToken deletes an API token by its numeric ID for the authenticated user
// @Summary Delete an API token
// @Description Delete an API token by its ID
// @Tags tokens
// @Produce json
// @Param id path int true "ID of the token to delete"
// @Success 200 {object} map[string]string
// @Success 404 {object} map[string]string
// @Failure 500 {object} map[string]string "Failed to delete token"
// @Security ApiKeyAuth
// @ID deleteToken
// @Router /v1/tokens/{id} [delete]
func deleteToken(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		id, err := strconv.ParseUint(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid token ID"})
			return
		}

		subject := tokenSubject(c.MustGet(UserDataKey).(*UserClaims))

		err = app.Storage.Tokens.Revoke(c.Request.Context(), subject, uint(id))
		switch {
		case errors.Is(err, token.ErrNotFound):
			// Not found and not yours are the same answer, so the response
			// cannot be used to find out which IDs exist.
			c.JSON(http.StatusNotFound, gin.H{"status": "not found"})
		case err != nil:
			app.Log.Errorf("Error deleting token %d for %s: %v", id, subject, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete token"})
		default:
			app.Log.Debugf("Deleted token %d for %s", id, subject)
			c.JSON(http.StatusOK, gin.H{"status": "deleted"})
		}
	}
}
