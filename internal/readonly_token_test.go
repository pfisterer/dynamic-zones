package app

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/token"
	"go.uber.org/zap"
)

// readOnlyFixture wires the real auth middleware against a real (in-memory)
// token store, so these exercise the path a request from curl takes rather than
// a stand-in for it.
//
// useRESTRule mirrors the two kinds of group the router has: /v1, which carries
// the method rule, and a group that does not and has to decide per operation —
// which is what an MCP endpoint here will be.
func readOnlyFixture(t *testing.T, useRESTRule bool) (http.Handler, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	log := zap.NewNop().Sugar()

	store, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	ctx := context.Background()
	readOnly, err := store.Tokens.Issue(ctx, "alice", token.IssueOptions{TTL: time.Hour, ReadOnly: true})
	if err != nil {
		t.Fatalf("issue read-only token: %v", err)
	}
	writable, err := store.Tokens.Issue(ctx, "alice", token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue write token: %v", err)
	}

	r := gin.New()
	g := r.Group("/v1")
	// No OIDC verifier: every request here carries an API token, and the OIDC
	// branch is not what this is about.
	g.Use(CombinedAuthMiddleware(nil, store, log, false))
	if useRESTRule {
		g.Use(RejectWritesForReadOnlyTokens(log))
	}
	g.GET("/thing", func(c *gin.Context) { c.Status(http.StatusOK) })
	g.POST("/thing", func(c *gin.Context) { c.Status(http.StatusOK) })
	// Stands in for an MCP route: a POST that is a read, answering the
	// read-only question itself instead of letting the method answer it.
	g.POST("/tool", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"read_only": IsReadOnlyToken(c)})
	})
	return r, readOnly.Secret, writable.Secret
}

func callWithToken(t *testing.T, h http.Handler, method, path, secret string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

// The REST rule must behave exactly as it did while it lived inside the auth
// middleware: GET passes, anything else is refused for a read-only token.
func TestReadOnlyToken_RESTRuleUnchanged(t *testing.T) {
	h, readOnlySecret, writeSecret := readOnlyFixture(t, true)

	for _, tc := range []struct {
		name, method, secret string
		want                 int
	}{
		{"read-only GET is allowed", http.MethodGet, readOnlySecret, http.StatusOK},
		{"read-only POST is refused", http.MethodPost, readOnlySecret, http.StatusForbidden},
		{"write token may POST", http.MethodPost, writeSecret, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if rr := callWithToken(t, h, tc.method, "/v1/thing", tc.secret); rr.Code != tc.want {
				t.Errorf("got %d, want %d: %s", rr.Code, tc.want, rr.Body.String())
			}
		})
	}
}

// The reason the rule moved out of the auth middleware: a group without it must
// be able to serve a POST to a read-only token and decide for itself. With the
// old code this was a 403 before any handler ran — which would be every MCP tool
// call, reads included.
func TestReadOnlyToken_GroupWithoutTheRESTRuleDecidesForItself(t *testing.T) {
	h, readOnlySecret, writeSecret := readOnlyFixture(t, false)

	rr := callWithToken(t, h, http.MethodPost, "/v1/tool", readOnlySecret)
	if rr.Code != http.StatusOK {
		t.Fatalf("a read POST must reach its handler, got %d: %s", rr.Code, rr.Body.String())
	}
	if body := rr.Body.String(); body != `{"read_only":true}` {
		t.Errorf("handler saw %s, want the token reported as read-only", body)
	}

	// A write token must be distinguishable there too, or the handler cannot
	// gate its mutating tools.
	rr = callWithToken(t, h, http.MethodPost, "/v1/tool", writeSecret)
	if body := rr.Body.String(); body != `{"read_only":false}` {
		t.Errorf("handler saw %s, want the token reported as writable", body)
	}
}
