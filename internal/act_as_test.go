package app

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// actAsRouter signs every request in as signedIn (an API token when viaToken) and answers with the user and actor the handlers see.
func actAsRouter(signedIn string, viaToken bool) http.Handler {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set(UserDataKey, &UserClaims{Email: signedIn})
		if viaToken {
			c.Set(viaAPITokenKey, true)
		}
	})
	r.Use(ActAsMiddleware(map[string]struct{}{"admin@x.de": {}}, zap.NewNop().Sugar()))
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, c.MustGet(UserDataKey).(*UserClaims).Identity()+"|"+ActorOf(c))
	})
	return r
}

func TestActAsMiddleware(t *testing.T) {
	for _, tc := range []struct {
		name, signedIn, header string
		viaToken               bool
		status                 int
		body                   string
	}{
		{"no header", "admin@x.de", "", false, 200, "admin@x.de|"},
		{"admin acts for a student", "admin@x.de", "Student@x.de", false, 200, "student@x.de|admin@x.de"},
		{"oneself", "student@x.de", "student@x.de", false, 200, "student@x.de|"},
		{"not an admin", "student@x.de", "admin@x.de", false, 403, ""},
		{"not an address", "admin@x.de", "fakestudent", false, 400, ""},
		{"API token", "admin@x.de", "student@x.de", true, 403, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tc.header != "" {
				req.Header.Set("X-Act-As", tc.header)
			}
			rr := httptest.NewRecorder()
			actAsRouter(tc.signedIn, tc.viaToken).ServeHTTP(rr, req)
			if rr.Code != tc.status || (tc.body != "" && rr.Body.String() != tc.body) {
				t.Errorf("got %d %q, want %d %q", rr.Code, rr.Body.String(), tc.status, tc.body)
			}
		})
	}
}
