package app

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/pfisterer/cloud-self-service-golib/msg"
)

// The shape this is for: the old %u rule is deprecated next to a new %l rule for the same domain.
func deprecatedSetup(t *testing.T) *AppData {
	t.Helper()
	app := newTestApp(t)
	for _, rule := range []PolicyRule{
		{ZonePattern: "%u.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true, SharingAllowed: true, Deprecated: true},
		{ZonePattern: "%l.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true},
	} {
		mustCreatePolicy(t, app, rule)
	}
	addZone(t, app, "alice@dhbw.de", "alice-at-dhbw-de.users.dhbw.site")
	return app
}

func listed(t *testing.T, app *AppData, user string) map[string]ZoneStatus {
	t.Helper()
	zones, err := app.ZoneList(claimsOf(user))
	if err != nil {
		t.Fatalf("ZoneList(%s) failed: %v", user, err)
	}
	got := map[string]ZoneStatus{}
	for _, z := range zones {
		got[z.Name] = z
	}
	return got
}

// A deprecated rule keeps the zone its owner has and offers nothing new: alice sees her %u zone and the new %l one, bob only the %l one.
func TestDeprecatedRuleListsOnlyExistingZones(t *testing.T) {
	app := deprecatedSetup(t)

	alice := listed(t, app, "alice@dhbw.de")
	if z, ok := alice["alice-at-dhbw-de.users.dhbw.site"]; !ok || !z.Exists || !z.Deprecated || z.ZoneSoa != "users.dhbw.site" {
		t.Errorf("alice's %%u zone: %+v (listed %v), want existing, deprecated", z, ok)
	}
	if z, ok := alice["alice.users.dhbw.site"]; !ok || z.Exists || z.Deprecated {
		t.Errorf("alice's %%l zone: %+v (listed %v), want offered", z, ok)
	}

	bob := listed(t, app, "bob@dhbw.de")
	if _, ok := bob["bob-at-dhbw-de.users.dhbw.site"]; ok {
		t.Error("a deprecated rule must not offer bob a new zone")
	}
	if _, ok := bob["bob.users.dhbw.site"]; !ok || len(bob) != 1 {
		t.Errorf("bob: got %v, want only bob.users.dhbw.site", bob)
	}

	// Somebody else's zone from a deprecated rule is not offered to join either (sharing is on in that rule).
	addZone(t, app, "carol@dhbw.de", "shared.users.dhbw.site")
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "shared.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", SharingAllowed: true, Deprecated: true})
	if z, ok := listed(t, app, "bob@dhbw.de")["shared.users.dhbw.site"]; ok {
		t.Errorf("bob was offered %+v", z)
	}
	if z, ok := listed(t, app, "carol@dhbw.de")["shared.users.dhbw.site"]; !ok || !z.Exists {
		t.Errorf("carol's own zone: %+v (listed %v)", z, ok)
	}
	if status, _, _ := app.ZoneJoin(context.Background(), claimsOf("bob@dhbw.de"), "shared.users.dhbw.site"); status != http.StatusForbidden {
		t.Errorf("joining through a deprecated rule: status %d, want 403", status)
	}
}

// Creating a zone only a deprecated rule grants is refused, naming the zone to create instead; checked before anything touches PowerDNS.
func TestDeprecatedRuleRefusesNewZone(t *testing.T) {
	app := deprecatedSetup(t)
	bob := claimsOf("bob@dhbw.de")

	allowed, def, err := app.PolicyIsZoneAllowedForUser("bob-at-dhbw-de.users.dhbw.site", bob)
	if err != nil || !allowed || !def.Deprecated {
		t.Fatalf("the deprecated rule still covers the name: allowed %v, def %+v, err %v", allowed, def, err)
	}
	status, _, _ := app.ZoneCreate(context.Background(), bob, *def)
	if status != http.StatusForbidden {
		t.Fatalf("status %d, want 403", status)
	}
	text := app.deprecatedZoneText(bob, "bob-at-dhbw-de.users.dhbw.site")
	if de, en := text.In(msg.DE), text.In(msg.EN); !strings.Contains(de, "veraltet") || !strings.Contains(de, "bob.users.dhbw.site") || !strings.Contains(en, "deprecated") || !strings.Contains(en, "bob.users.dhbw.site") {
		t.Errorf("message: %q / %q", de, en)
	}
	if exists, _ := app.Storage.ZoneExists("bob-at-dhbw-de.users.dhbw.site"); exists {
		t.Error("the zone was stored")
	}
}

// Existing zones of a deprecated rule stay covered: not orphaned, still granted to their owner (the check every permission asks), subzones below them allowed.
func TestDeprecatedRuleKeepsExistingZonesCovered(t *testing.T) {
	app := deprecatedSetup(t)
	alice := claimsOf("alice@dhbw.de")

	orphaned, err := app.OrphanedZones()
	if err != nil {
		t.Fatalf("OrphanedZones failed: %v", err)
	}
	if len(orphaned) != 0 {
		t.Errorf("orphaned: %v, want none", orphaned)
	}

	allowed, def, err := app.PolicyIsZoneAllowedForUser("alice-at-dhbw-de.users.dhbw.site", alice)
	if err != nil || !allowed || def.ZoneSOA != "users.dhbw.site" || !def.AllowSubdomains {
		t.Errorf("alice's zone: allowed %v, def %+v, err %v", allowed, def, err)
	}
	if def, err := app.zoneGoverningDef("alice-at-dhbw-de.users.dhbw.site"); err != nil || def == nil || !def.SharingAllowed {
		t.Errorf("governing rule of alice's zone: %+v, %v", def, err)
	}

	allowed, def, err = app.PolicyIsZoneAllowedForUser("iot.alice-at-dhbw-de.users.dhbw.site", alice)
	if err != nil || !allowed || !def.Subzone || def.Deprecated || def.ZoneSOA != "alice-at-dhbw-de.users.dhbw.site" {
		t.Errorf("subzone: allowed %v, def %+v, err %v", allowed, def, err)
	}
}

// A current rule granting the same name wins over a deprecated one, so the zone stays creatable.
func TestCurrentRuleWinsOverDeprecatedForTheSameName(t *testing.T) {
	user := claimsOf("x@dhbw.de")
	for _, order := range [][]PolicyRule{
		{{ZonePattern: "%l.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", Deprecated: true}, {ZonePattern: "x.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "x@dhbw.de"}},
		{{ZonePattern: "x.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "x@dhbw.de"}, {ZonePattern: "%l.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", Deprecated: true}},
	} {
		zones := rulesToUserZones(order, user)
		if len(zones) != 1 || zones[0].Deprecated {
			t.Errorf("got %+v, want one current zone", zones)
		}
	}
}

// deprecated is created, updated in both directions and read back; false persists too (it is in PolicyUpdate's Select).
func TestDeprecatedRuleToggle(t *testing.T) {
	app := newTestApp(t)
	req := PolicyRuleRequest{ZonePattern: "%u.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de"}
	rule, err := app.PolicyCreateRule(req)
	if err != nil || rule.Deprecated {
		t.Fatalf("created %+v, %v; want not deprecated", rule, err)
	}
	for _, want := range []bool{true, false, true} {
		req.Deprecated = want
		if _, err := app.PolicyUpdateRule(rule.ID, req); err != nil {
			t.Fatalf("update to %v: %v", want, err)
		}
		got, err := app.Storage.PolicyGetByID(rule.ID)
		if err != nil || got.Deprecated != want {
			t.Errorf("after update to %v: %+v, %v", want, got, err)
		}
	}
}
