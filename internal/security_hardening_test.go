package app

import (
	"context"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/token"
	"go.uber.org/zap"
)

// Zones from before the creator column: the earliest owner becomes the creator, a zone that already has one keeps it, and removing the creator's row hands the role to the next owner instead of leaving the zone without one.
func TestBackfillZoneCreators(t *testing.T) {
	app := newTestApp(t)
	db := app.Storage.db
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	rows := []Zone{
		{Zone: "shared.example.com", Username: "bob@dhbw.de", CreatedAt: base.Add(2 * time.Hour)},
		{Zone: "shared.example.com", Username: "alice@dhbw.de", CreatedAt: base},
		{Zone: "shared.example.com", Username: "carol@dhbw.de", CreatedAt: base.Add(time.Hour)},
		{Zone: "solo.example.com", Username: "dave@dhbw.de", CreatedAt: base},
		// Already has a creator that is not the earliest row: left alone.
		{Zone: "kept.example.com", Username: "erin@dhbw.de", CreatedAt: base},
		{Zone: "kept.example.com", Username: "frank@dhbw.de", CreatedAt: base.Add(time.Hour), Creator: true},
	}
	for i := range rows {
		if err := db.Create(&rows[i]).Error; err != nil {
			t.Fatalf("seeding %+v: %v", rows[i], err)
		}
	}

	if err := backfillZoneCreators(db); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	// Idempotent.
	if err := backfillZoneCreators(db); err != nil {
		t.Fatalf("second backfill: %v", err)
	}

	for zone, want := range map[string]string{
		"shared.example.com": "alice@dhbw.de",
		"solo.example.com":   "dave@dhbw.de",
		"kept.example.com":   "frank@dhbw.de",
	} {
		if got, err := app.Storage.ZoneCreator(zone); err != nil || got != want {
			t.Errorf("creator of %s = %q, %v; want %q", zone, got, err, want)
		}
	}
	var creators int64
	db.Model(&Zone{}).Where("zone = ? AND creator = ?", "shared.example.com", true).Count(&creators)
	if creators != 1 {
		t.Errorf("shared.example.com has %d creators, want 1", creators)
	}

	if err := app.Storage.DeleteZone("alice@dhbw.de", "shared.example.com"); err != nil {
		t.Fatalf("delete creator row: %v", err)
	}
	if got, _ := app.Storage.ZoneCreator("shared.example.com"); got != "carol@dhbw.de" {
		t.Errorf("after the creator left the creator is %q, want the next owner carol", got)
	}
}

// The zone-events ingest token is provisioned from configuration, never expires and may write: it used to be a full account everywhere in /v1 (and on /mcp).
func TestIngestTokenIsConfinedToTheIngestRoutes(t *testing.T) {
	const subject = "alertmanager@platform"
	gin.SetMode(gin.TestMode)
	log := zap.NewNop().Sugar()
	store, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	ctx := context.Background()
	ingest, err := store.Tokens.Issue(ctx, subject, token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue ingest token: %v", err)
	}
	user, err := store.Tokens.Issue(ctx, "alice@dhbw.de", token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue user token: %v", err)
	}

	r := gin.New()
	g := r.Group("/v1")
	g.Use(CombinedAuthMiddleware(nil, store, log, "", subject))
	ok := func(c *gin.Context) { c.Status(http.StatusOK) }
	g.GET("/zones/", ok)
	g.POST("/zones/:zone", ok)
	g.POST("/tokens/", ok)
	g.GET("/zone-events/", ok)
	g.POST("/zone-events/", ok)
	g.POST("/zone-events/alertmanager", ok)

	for _, tc := range []struct {
		method, path, secret string
		want                 int
	}{
		{http.MethodPost, "/v1/zone-events/", ingest.Secret, http.StatusOK},
		{http.MethodPost, "/v1/zone-events/alertmanager", ingest.Secret, http.StatusOK},
		{http.MethodGet, "/v1/zones/", ingest.Secret, http.StatusForbidden},
		{http.MethodPost, "/v1/zones/x.example.com", ingest.Secret, http.StatusForbidden},
		{http.MethodPost, "/v1/tokens/", ingest.Secret, http.StatusForbidden},
		{http.MethodGet, "/v1/zone-events/", ingest.Secret, http.StatusForbidden},
		{http.MethodGet, "/v1/zones/", user.Secret, http.StatusOK},
	} {
		if rr := callWithToken(t, r, tc.method, tc.path, tc.secret); rr.Code != tc.want {
			t.Errorf("%s %s: got %d, want %d", tc.method, tc.path, rr.Code, tc.want)
		}
	}
}

// A CORS preflight on /mcp used to pass the auth middleware unauthenticated and reach the MCP handler, which then panicked on the missing identity.
func TestMCPOptionsNeedsAuthentication(t *testing.T) {
	app := mcpTestApp(t)
	srv, _, writable := mcpTestServer(t, app)

	req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/mcp", nil)
	req.Header.Set("Access-Control-Request-Headers", "authorization")
	req.Header.Set("Origin", "https://evil.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS /mcp without credentials: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("OPTIONS /mcp without credentials: got %d, want 401", resp.StatusCode)
	}

	req, _ = http.NewRequest(http.MethodOptions, srv.URL+"/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+writable)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("OPTIONS /mcp with a token: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("OPTIONS /mcp with a token: got %d, want 405", resp.StatusCode)
	}
}

// Any lifetime used to be accepted, so a token could be issued for a thousand years even where "never expires" was switched off.
func TestTokenLifetimeHasAMaximum(t *testing.T) {
	cfg := WebServerConfig{ApiTokenTTLHours: 24, ApiTokenMaxTTLHours: 365 * 24}
	if _, err := resolveTokenTTL(cfg, 365*24+1); !errors.Is(err, token.ErrTTLTooLong) {
		t.Errorf("a lifetime over the maximum: got %v, want ErrTTLTooLong", err)
	}
	// Large enough to overflow time.Duration inside TTLPolicy.Resolve, which then let it through.
	if _, err := resolveTokenTTL(cfg, 1000*365*24); !errors.Is(err, token.ErrTTLTooLong) {
		t.Errorf("a thousand years: got %v, want ErrTTLTooLong", err)
	}
	if ttl, err := resolveTokenTTL(cfg, 365*24); err != nil || ttl != 365*24*time.Hour {
		t.Errorf("exactly the maximum: got %v, %v", ttl, err)
	}
}

// PDNS_API_KEY used to default to the key printed in this repository's README.
func TestPdnsApiKeyHasNoDefault(t *testing.T) {
	t.Setenv("OIDC_ISSUER_URL", "https://sso.example.org/realms/test")
	t.Setenv("OIDC_CLIENT_ID", "test")
	t.Setenv("UPSTREAM_DNS_ZONE", "example.org")
	t.Setenv("UPSTREAM_DNS_NAME", "ns")
	t.Setenv("PDNS_API_KEY", "")
	os.Unsetenv("PDNS_API_KEY")

	_, err := GetAppConfigFromEnvironment()
	if err == nil || !strings.Contains(err.Error(), "PdnsApiKey") {
		t.Errorf("without PDNS_API_KEY: got %v, want a validation error for PdnsApiKey", err)
	}

	t.Setenv("PDNS_API_KEY", "a-real-key")
	cfg, err := GetAppConfigFromEnvironment()
	if err != nil {
		t.Fatalf("with PDNS_API_KEY: %v", err)
	}
	if cfg.WebServer.ApiTokenMaxTTLHours != 365*24 {
		t.Errorf("default maximum token lifetime is %d hours, want one year", cfg.WebServer.ApiTokenMaxTTLHours)
	}
}
