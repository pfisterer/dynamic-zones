package app

import (
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/farberg/dynamic-zones/internal/test_helpers"
	"go.uber.org/zap"
)

// These tests exercise the sharing subtree against a REAL PowerDNS, because
// ownership is a storage row plus that owner's own TSIG key — a test with only a
// database would pass while leaving co-owners unable to touch the zone.
//
// Unlike the other container tests they do not start the web server, so they can
// run alongside them without fighting over the bind port.

// newPdnsTestApp starts an ephemeral PowerDNS and returns an AppData wired to it
// with a fresh in-memory database.
func newPdnsTestApp(t *testing.T) *AppData {
	t.Helper()

	pdnsDocker, err := test_helpers.StartPndsTestContainer(t.Context())
	if err != nil {
		t.Fatalf("failed to start PowerDNS test container: %v", err)
	}
	t.Cleanup(func() { _ = pdnsDocker.Cleanup() })

	baseURL := pdnsDocker.GetBaseUrl()
	u, err := url.Parse(baseURL)
	if err != nil {
		t.Fatalf("failed to parse PowerDNS URL %q: %v", baseURL, err)
	}
	waitForPdns(t, baseURL, pdnsDocker.GetApiKey())

	log := zap.NewNop().Sugar()
	pdns, err := NewPowerDnsClient(baseURL, u.Hostname(), pdnsDocker.GetApiKey(), 60,
		[]string{"ns.example.com."}, "admin-key", "c3VwZXJzZWNyZXRhZG1pbmtleQ==", "hmac-sha256",
		nil, nil, log)
	if err != nil {
		t.Fatalf("failed to create PowerDNS client: %v", err)
	}

	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to create test storage: %v", err)
	}

	return &AppData{Storage: db, PowerDns: pdns, Log: log, RefreshTime: 3600}
}

// waitForPdns blocks until the container answers API calls. Talking to it right
// after start yields a connection reset, so poll instead of sleeping blindly.
func waitForPdns(t *testing.T, baseURL, apiKey string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, baseURL+"/api/v1/servers", nil)
		if err != nil {
			t.Fatalf("failed to build readiness request: %v", err)
		}
		req.Header.Set("X-API-Key", apiKey)

		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("PowerDNS at %s did not become ready: %v", baseURL, err)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// ownsWithKey reports whether the user owns the zone in storage AND has their own
// TSIG key on it — the two halves that together make a zone usable.
func ownsWithKey(t *testing.T, app *AppData, user, zone string) (owns, hasKey bool) {
	t.Helper()

	owns, err := app.Storage.IsZoneOwner(user, zone)
	if err != nil {
		t.Fatalf("IsZoneOwner(%s, %s) failed: %v", user, zone, err)
	}

	data, err := app.PowerDns.GetZone(t.Context(), zone, user)
	if err != nil {
		t.Fatalf("GetZone(%s, %s) failed: %v", zone, user, err)
	}
	return owns, len(data.ZoneKeys) > 0
}

// seedSharedParentWithSubzone creates a parent zone owned by `owner` with one
// subzone below it, both in PowerDNS and in storage.
func seedSharedParentWithSubzone(t *testing.T, app *AppData, owner, parent, subzone string) {
	t.Helper()

	for _, zone := range []string{parent, subzone} {
		if _, err := app.PowerDns.CreateUserZone(t.Context(), owner, zone, true); err != nil {
			t.Fatalf("failed to create zone %s in PowerDNS: %v", zone, err)
		}
		if _, err := app.Storage.CreateZone(owner, zone, time.Now()); err != nil {
			t.Fatalf("failed to create zone %s in storage: %v", zone, err)
		}
	}

	if _, err := app.Storage.PolicyCreate(&PolicyRule{
		ZonePattern:      parent,
		ZoneSoa:          parent,
		TargetUserFilter: owner,
		AllowSubdomains:  true,
		SharingAllowed:   true,
	}); err != nil {
		t.Fatalf("failed to create policy rule: %v", err)
	}
}

// TestBackfillSubzoneOwners covers the repair path for zones shared before
// sharing covered the subtree: the co-owner is on the parent only.
func TestBackfillSubzoneOwners(t *testing.T) {
	const (
		owner    = "dennis@dhbw.de"
		coOwner  = "clemens@dhbw.de"
		parent   = "services.example.com"
		subzone  = "llm.services.example.com"
		unshared = "other.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()
	seedSharedParentWithSubzone(t, app, owner, parent, subzone)

	// The pre-fix state: joining granted the parent and nothing below it.
	if err := app.grantOwner(ctx, coOwner, parent); err != nil {
		t.Fatalf("failed to seed the co-owner: %v", err)
	}
	if owns, _ := ownsWithKey(t, app, coOwner, subzone); owns {
		t.Fatal("precondition failed: the co-owner already owns the subzone")
	}

	// An unrelated zone must not be dragged in by the repair.
	if _, err := app.PowerDns.CreateUserZone(ctx, owner, unshared, true); err != nil {
		t.Fatalf("failed to create unrelated zone: %v", err)
	}
	if _, err := app.Storage.CreateZone(owner, unshared, time.Now()); err != nil {
		t.Fatalf("failed to create unrelated zone in storage: %v", err)
	}

	if err := app.BackfillSubzoneOwners(ctx); err != nil {
		t.Fatalf("BackfillSubzoneOwners failed: %v", err)
	}

	owns, hasKey := ownsWithKey(t, app, coOwner, subzone)
	if !owns {
		t.Error("expected the co-owner to own the subzone after the backfill")
	}
	if !hasKey {
		t.Error("expected the co-owner to have their own TSIG key on the subzone")
	}
	if owns, _ := ownsWithKey(t, app, coOwner, unshared); owns {
		t.Error("the backfill must not grant zones outside the shared subtree")
	}

	// Running it again changes nothing — it is meant to be safe on every startup.
	if err := app.BackfillSubzoneOwners(ctx); err != nil {
		t.Fatalf("second BackfillSubzoneOwners run failed: %v", err)
	}
	owners, err := app.Storage.ListZoneOwners(subzone)
	if err != nil {
		t.Fatalf("ListZoneOwners failed: %v", err)
	}
	if len(owners) != 2 {
		t.Errorf("expected 2 owners after a repeated run, got %v", owners)
	}
}

// TestShareAndLeaveCoverSubtree covers the forward paths: sharing a zone hands
// over what it delegates, and leaving gives it back.
func TestShareAndLeaveCoverSubtree(t *testing.T) {
	const (
		owner   = "dennis@dhbw.de"
		coOwner = "clemens@dhbw.de"
		parent  = "services.example.com"
		subzone = "llm.services.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()
	seedSharedParentWithSubzone(t, app, owner, parent, subzone)

	caller := &UserClaims{Email: owner, PreferredUsername: owner}
	if status, resp, _ := app.ZoneAddOwner(ctx, caller, parent, coOwner); status != 200 {
		t.Fatalf("ZoneAddOwner returned %d: %v", status, resp)
	}

	owns, hasKey := ownsWithKey(t, app, coOwner, subzone)
	if !owns || !hasKey {
		t.Errorf("sharing the parent must hand over the subzone too (owns=%v, key=%v)", owns, hasKey)
	}

	// Leaving is symmetric: the subzone goes back with the parent.
	if status, resp, _ := app.ZoneRemoveOwner(ctx, caller, parent, coOwner); status != 200 {
		t.Fatalf("ZoneRemoveOwner returned %d: %v", status, resp)
	}
	if owns, _ := ownsWithKey(t, app, coOwner, subzone); owns {
		t.Error("leaving the parent must revoke the subzone as well")
	}

	// The original owner is untouched by the co-owner leaving.
	owns, hasKey = ownsWithKey(t, app, owner, subzone)
	if !owns || !hasKey {
		t.Errorf("the remaining owner lost access to the subzone (owns=%v, key=%v)", owns, hasKey)
	}
}

// TestSubzoneCreationInheritsParentOwners covers the create side: a subzone added
// later is visible to everyone sharing the parent.
func TestSubzoneCreationInheritsParentOwners(t *testing.T) {
	const (
		owner   = "dennis@dhbw.de"
		coOwner = "clemens@dhbw.de"
		parent  = "services.example.com"
		subzone = "llm.services.example.com"
		fresh   = "new.services.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()
	seedSharedParentWithSubzone(t, app, owner, parent, subzone)

	caller := &UserClaims{Email: owner, PreferredUsername: owner}
	if status, resp, _ := app.ZoneAddOwner(ctx, caller, parent, coOwner); status != 200 {
		t.Fatalf("ZoneAddOwner returned %d: %v", status, resp)
	}

	// The co-owner delegates a new subzone under the shared parent.
	def, err := app.subzoneDefViaOwnedParent(fresh, coOwner)
	if err != nil {
		t.Fatalf("subzoneDefViaOwnedParent failed: %v", err)
	}
	if def == nil {
		t.Fatal("a co-owner of a zone that allows subdomains must be allowed to delegate below it")
	}
	if status, resp, _ := app.ZoneCreate(ctx, coOwner, *def); status != 201 {
		t.Fatalf("ZoneCreate returned %d: %v", status, resp)
	}

	// ... and the original owner sees it, rather than it being invisible to them.
	owns, hasKey := ownsWithKey(t, app, owner, fresh)
	if !owns || !hasKey {
		t.Errorf("the parent's other owner did not inherit the new subzone (owns=%v, key=%v)", owns, hasKey)
	}
}
