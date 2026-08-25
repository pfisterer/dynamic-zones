package app

import (
	"net/http"
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
	app, _ := newPdnsTestAppWithContainer(t)
	return app
}

// newPdnsTestAppWithContainer is the same fixture, plus the container itself —
// which a test needs when it talks DNS rather than only using the client (the
// published DNS port is not derivable from the API URL).
func newPdnsTestAppWithContainer(t *testing.T) (*AppData, *test_helpers.PdnsContainerTestInstance) {
	t.Helper()

	pdnsDocker, err := test_helpers.StartPndsTestContainer(t.Context())
	if err != nil {
		t.Fatalf("failed to start PowerDNS test container: %v", err)
	}
	t.Cleanup(func() { _ = pdnsDocker.Cleanup() })

	baseURL := pdnsDocker.GetBaseUrl()
	waitForPdns(t, pdnsDocker, baseURL, pdnsDocker.GetApiKey())

	log := zap.NewNop().Sugar()
	// "localhost" is PowerDNS' SERVER ID (the API path is /api/v1/servers/<id>),
	// not the host to connect to. Taking it from the URL only worked while the
	// container was addressed as localhost; against 127.0.0.1 every call came
	// back "Not Found".
	pdns, err := NewPowerDnsClient(baseURL, "localhost", pdnsDocker.GetApiKey(), 60,
		[]string{"ns.example.com."}, "admin-key", "c3VwZXJzZWNyZXRhZG1pbmtleQ==", "hmac-sha256",
		nil, nil, log)
	if err != nil {
		t.Fatalf("failed to create PowerDNS client: %v", err)
	}

	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to create test storage: %v", err)
	}

	return &AppData{Storage: db, PowerDns: pdns, Log: log, RefreshTime: 3600}, pdnsDocker
}

// waitForPdns blocks until the container answers API calls. Talking to it right
// after start yields a connection reset, so poll instead of sleeping blindly.
func waitForPdns(t *testing.T, pdnsDocker *test_helpers.PdnsContainerTestInstance, baseURL, apiKey string) {
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
			t.Fatalf("PowerDNS at %s did not become ready: %v\n%s", baseURL, err, pdnsDocker.Diagnose(t.Context()))
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
