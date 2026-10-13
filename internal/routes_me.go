package app

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// MeResponse is who the caller is to this service.
type MeResponse struct {
	// Email is the person the request acted as: the caller, or the person named in X-Act-As.
	Email string `json:"email" example:"student@dhbw.de"`
	// SuperAdmin: that person is a super admin here.
	SuperAdmin bool `json:"super_admin"`
	// MayActAs: the signed-in person may act on behalf of others with the X-Act-As header (a super admin).
	MayActAs bool `json:"may_act_as"`
	// ActingAs is the person acted for; empty without X-Act-As.
	ActingAs string `json:"acting_as,omitempty" example:"student@dhbw.de"`
}

// CreateMeRoute registers GET /v1/me.
func CreateMeRoute(v1 *gin.RouterGroup, app *AppData) {
	v1.GET("/me", getMe(app))
}

// getMe answers who the caller is and acts as.
//
//	@Summary		Who am I?
//	@Description	The person the request acted as, whether they are a super admin, whether the signed-in person may act on behalf of others (X-Act-As), and for whom this request acted.
//	@Tags			me
//	@Produce		json
//	@Security		Bearer
//	@Success		200	{object}	MeResponse	"The caller."
//	@ID				getMe
//	@Router			/v1/me [get]
func getMe(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		resp := MeResponse{Email: user.Identity(), SuperAdmin: isSuperAdmin(app, user)}
		signedIn := user.Identity()
		if actor := ActorOf(c); actor != "" {
			resp.ActingAs = user.Identity()
			signedIn = actor
		}
		_, resp.MayActAs = app.Config.DnsPolicyConfig.SuperAdminEmails[strings.ToLower(signedIn)]
		c.JSON(http.StatusOK, resp)
	}
}
