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
	// ExpiresAt is null for a token that does not expire.
	//
	// A pointer, so that "no expiry" is null and not the year 1: Go's zero time
	// serialises to 0001-01-01T00:00:00Z, and a client comparing that against
	// now would read a permanent token as long expired.
	ExpiresAt *time.Time `json:"expires_at" example:"2025-12-31T23:59:59Z" swagger:"desc(When the token expires; null means it never does)"`
	ReadOnly  bool       `json:"read_only" example:"false"`
	CreatedAt time.Time  `json:"created_at" example:"2025-11-04T12:00:00Z"`
	// Description is what the owner wrote down about this token. A memory aid,
	// never a permission.
	Description string `json:"description" example:"ddclient on the router at home"`
	// LastUsedAt is when the token last authenticated a request, to the nearest
	// minute, or null if it never has — which is what makes revoking a
	// forgotten token safe to do.
	LastUsedAt *time.Time `json:"last_used_at" example:"2025-11-05T08:30:00Z"`
}

// nilIfZero maps Go's zero time to a JSON null. Both callers say something
// specific with it: no expiry, and never used.
func nilIfZero(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func toAPIToken(rec token.Record) Token {
	return Token{
		ID:          rec.ID,
		User:        rec.Subject,
		Prefix:      rec.Prefix,
		ExpiresAt:   nilIfZero(rec.ExpiresAt),
		ReadOnly:    rec.ReadOnly,
		CreatedAt:   rec.CreatedAt,
		Description: rec.Description,
		LastUsedAt:  nilIfZero(rec.LastUsedAt),
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
	// Description is the owner's note about the token, at most 100 characters.
	Description string `json:"description" example:"ddclient on the router at home"`
	// TTLHours is how long the token should live. Omitted or 0 means the
	// configured default; -1 means it never expires, and is refused unless the
	// deployment allows it.
	//
	// -1 rather than a separate boolean, because that is what NeverExpires is in
	// the shared library: one convention for "no expiry" across the request, the
	// service and the database beats two that have to be kept in step.
	TTLHours int `json:"ttl_hours" example:"720"`
}

// ttlPolicy is the configured lifetime policy. The decision table lives in the
// shared library, because os-mgt-api needs exactly the same one; what belongs
// here are the values, which are the deployment's answer — for this platform,
// both services permit tokens without an expiry, because the callers they exist
// for (a router, a cron job, a CI pipeline) have nobody to notice a quiet
// expiry. What carries that is visibility, not expiry: description and last use
// are listed, and revoking is one request.
func ttlPolicy(cfg WebServerConfig) token.TTLPolicy {
	return token.TTLPolicy{
		Default:    time.Duration(cfg.ApiTokenTTLHours) * time.Hour,
		Max:        time.Duration(cfg.ApiTokenMaxTTLHours) * time.Hour,
		AllowNever: cfg.ApiTokenAllowNeverExpires,
	}
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
// @Description Generate a new API token for the authenticated user. The lifetime comes from ttl_hours, or from the configured default when it is omitted; -1 asks for a token that never expires and is refused unless the deployment allows it.
// @Tags tokens
// @Accept json
// @Produce json
// @Param request body CreateTokenRequest false "Token options"
// @Success 201 {object} Token
// @Failure 400 {object} map[string]string "Invalid lifetime or description"
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

		ttl, err := ttlPolicy(app.Config.WebServer).Resolve(input.TTLHours)
		if err != nil {
			// The caller asked for something this deployment does not grant, and
			// the message says which limit — nothing here is a server fault.
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		issued, err := app.Storage.Tokens.Issue(c.Request.Context(), subject, token.IssueOptions{
			TTL:         ttl,
			ReadOnly:    input.ReadOnly,
			Description: input.Description,
		})
		// A description over the limit is the caller's mistake, not a server
		// fault, and the message says which limit. The description itself is
		// never echoed into the log — it is arbitrary text from a request body.
		if errors.Is(err, token.ErrDescriptionTooLong) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
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
