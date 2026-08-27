package app

import (
	"testing"

	"go.uber.org/zap"
)

// newTestApp returns an AppData backed by a fresh in-memory sqlite storage. Only
// the storage/policy side is wired — helpers that touch PowerDNS are covered by
// the container-based tests.
func newTestApp(t *testing.T) *AppData {
	t.Helper()
	// A private cache per test, so parallel tests do not share a database.
	db, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("failed to create test storage: %v", err)
	}
	return &AppData{Storage: db, Log: zap.NewNop().Sugar()}
}

func addZone(t *testing.T, app *AppData, user, zone string) {
	t.Helper()
	if _, err := app.Storage.CreateZone(user, zone); err != nil {
		t.Fatalf("failed to create zone %s for %s: %v", zone, user, err)
	}
}

func TestSubzonesOf(t *testing.T) {
	app := newTestApp(t)
	addZone(t, app, "dennis@dhbw.de", "services.dhbw.cloud")
	addZone(t, app, "clemens@dhbw.de", "services.dhbw.cloud") // co-owner: second row, same zone
	addZone(t, app, "dennis@dhbw.de", "llm.services.dhbw.cloud")
	addZone(t, app, "dennis@dhbw.de", "deep.llm.services.dhbw.cloud")
	addZone(t, app, "dennis@dhbw.de", "other.dhbw.cloud")
	addZone(t, app, "dennis@dhbw.de", "notservices.dhbw.cloud") // suffix match, but not a subdomain

	subzones, err := app.subzonesOf("services.dhbw.cloud")
	if err != nil {
		t.Fatalf("subzonesOf failed: %v", err)
	}

	want := map[string]bool{"llm.services.dhbw.cloud": true, "deep.llm.services.dhbw.cloud": true}
	if len(subzones) != len(want) {
		t.Fatalf("expected %d subzones, got %v", len(want), subzones)
	}
	for _, s := range subzones {
		if !want[s] {
			t.Errorf("unexpected subzone %q", s)
		}
	}
}

func TestClosestStoredParent(t *testing.T) {
	app := newTestApp(t)
	addZone(t, app, "dennis@dhbw.de", "services.dhbw.cloud")
	addZone(t, app, "dennis@dhbw.de", "llm.services.dhbw.cloud")

	cases := []struct {
		zone, want string
	}{
		// The most specific stored ancestor wins, not the first or the shortest.
		{"deep.llm.services.dhbw.cloud", "llm.services.dhbw.cloud"},
		{"new.services.dhbw.cloud", "services.dhbw.cloud"},
		// A policy base zone whose SOA is not itself stored has no parent.
		{"alice.users.dhbw.site", ""},
		// A zone is not its own parent.
		{"services.dhbw.cloud", ""},
	}
	for _, tc := range cases {
		got, err := app.closestStoredParent(tc.zone)
		if err != nil {
			t.Fatalf("closestStoredParent(%s) failed: %v", tc.zone, err)
		}
		if got != tc.want {
			t.Errorf("closestStoredParent(%s) = %q, want %q", tc.zone, got, tc.want)
		}
	}
}

func TestSubzoneDefViaOwnedParent(t *testing.T) {
	app := newTestApp(t)

	// The rule entitles dennis only; clemens holds the zone through sharing.
	if _, err := app.Storage.PolicyCreate(&PolicyRule{
		ZonePattern:      "services.dhbw.cloud",
		ZoneSoa:          "dhbw.cloud",
		TargetUserFilter: "dennis@dhbw.de",
		AllowSubdomains:  true,
		SharingAllowed:   true,
	}); err != nil {
		t.Fatalf("failed to create policy rule: %v", err)
	}
	addZone(t, app, "dennis@dhbw.de", "services.dhbw.cloud")
	addZone(t, app, "clemens@dhbw.de", "services.dhbw.cloud")

	def, err := app.subzoneDefViaOwnedParent("new.services.dhbw.cloud", "clemens@dhbw.de")
	if err != nil {
		t.Fatalf("subzoneDefViaOwnedParent failed: %v", err)
	}
	if def == nil {
		t.Fatal("expected the shared co-owner to be allowed to create a subzone")
	}
	if def.ZoneSOA != "services.dhbw.cloud" || !def.AllowSubdomains || !def.SharingAllowed {
		t.Errorf("unexpected zone definition: %+v", def)
	}

	// Someone who owns nothing above the zone gets nothing.
	def, err = app.subzoneDefViaOwnedParent("new.services.dhbw.cloud", "mallory@dhbw.de")
	if err != nil {
		t.Fatalf("subzoneDefViaOwnedParent failed: %v", err)
	}
	if def != nil {
		t.Errorf("expected no definition for a non-owner, got %+v", def)
	}
}
