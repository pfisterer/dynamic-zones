package app

import (
	"context"
	"net/http"
	"testing"
)

// %l expands to the local part of the address; %u stays the whole address.
func TestExpandZonePattern(t *testing.T) {
	for _, tc := range []struct {
		pattern, email, want string
		ok                   bool
	}{
		{"%l.users.dhbw.site", "dennis.pfisterer@dhbw.de", "dennis-pfisterer.users.dhbw.site", true},
		{"%l-stma.users.dhbw.site", "s252690@student.dhbw-mannheim.de", "s252690-stma.users.dhbw.site", true},
		{"%l-stg.users.dhbw.site", "Max.Mustermann@DHBW-Stuttgart.de", "max-mustermann-stg.users.dhbw.site", true},
		{"%l.users.dhbw.site", "max+dns@dhbw.de", "max-dns.users.dhbw.site", true},
		{"%l.users.dhbw.site", "max_muster@dhbw.de", "max-muster.users.dhbw.site", true},
		{"%l.Users.DHBW.site.", "x@dhbw.de", "x.users.dhbw.site", true},
		{"%u.users.dhbw.site", "dennis.pfisterer@dhbw.de", "dennis-pfisterer-at-dhbw-de.users.dhbw.site", true},
		{"%l.%u.example.com", "a.b@c.de", "a-b.a-b-at-c-de.example.com", true},
		{"fixed.example.com", "a@b.de", "fixed.example.com", true},
		{"%l.users.dhbw.site", "+@dhbw.de", "", false}, // nothing left of the local part
	} {
		got, ok := expandZonePattern(tc.pattern, tc.email)
		if got != tc.want || ok != tc.ok {
			t.Errorf("expandZonePattern(%q, %q) = %q, %v; want %q, %v", tc.pattern, tc.email, got, ok, tc.want, tc.ok)
		}
	}
}

func TestZonePatternMatchesLocalPart(t *testing.T) {
	for _, tc := range []struct {
		pattern, zone string
		want          bool
	}{
		{"%l-stma.users.dhbw.site", "s252690-stma.users.dhbw.site", true},
		{"%l-stma.users.dhbw.site", "s252690.users.dhbw.site", false},
		{"%l-stma.users.dhbw.site", "a.s252690-stma.users.dhbw.site", false},
		{"%l.users.dhbw.site", "dennis-pfisterer.users.dhbw.site", true},
		{"%u.users.dhbw.site", "dennis-at-dhbw-de.users.dhbw.site", true},
		{"%u.users.dhbw.site", "users.dhbw.site", false},
	} {
		if got := zonePatternMatches(tc.pattern, tc.zone); got != tc.want {
			t.Errorf("zonePatternMatches(%q, %q) = %v, want %v", tc.pattern, tc.zone, got, tc.want)
		}
	}
}

// %l is accepted with any user filter (no single-domain rule any more): two people granted the same %l name compete for it, and zone ownership settles that.
func TestLocalPartAcceptsAnyFilter(t *testing.T) {
	for _, filter := range []string{"*@student.dhbw-mannheim.de", "*", "*@dhbw.de,*@cas.dhbw.de", "a@dhbw.de,b@cas.dhbw.de", "group:wwi23seb", "group:wwi23seb#studierende,*@dhbw.de", "user:max@dhbw.de"} {
		if err := policyValidateRequest(PolicyRuleRequest{ZonePattern: "%l.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: filter}); err != nil {
			t.Errorf("%%l with filter %q: %v", filter, err)
		}
	}
}

func TestLocalPartPatternValidation(t *testing.T) {
	for _, p := range []string{"%l.users.dhbw.site", "%l-stma.users.dhbw.site", "x-%l.users.dhbw.site"} {
		if err := validateZonePattern(p); err != nil {
			t.Errorf("validateZonePattern(%q) = %v", p, err)
		}
		if err := validatePatternWithinSoa(p, "users.dhbw.site"); err != nil {
			t.Errorf("validatePatternWithinSoa(%q) = %v", p, err)
		}
	}
	if err := validatePatternWithinSoa("%l.evil-users.dhbw.site", "users.dhbw.site"); err == nil {
		t.Error("a %l pattern outside its SOA must be refused")
	}
	if err := validateZonePattern("%l..users.dhbw.site"); err == nil {
		t.Error("an empty label must be refused")
	}
}

// Two addresses whose local parts make the same label (max.muster and max_muster) are granted the same %l zone: the first to create it owns it, the other sees it as taken and cannot create it. A %u zone next to it is unaffected.
func TestLocalPartZoneOfSomeoneElseIsRefused(t *testing.T) {
	app := newTestApp(t)
	for _, rule := range []PolicyRule{
		{ZonePattern: "%u.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true},
		{ZonePattern: "%l.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true},
	} {
		if _, err := app.Storage.PolicyCreate(&rule); err != nil {
			t.Fatalf("failed to create policy rule: %v", err)
		}
	}
	addZone(t, app, "max.muster@dhbw.de", "max-muster.users.dhbw.site")

	other := &UserClaims{Email: "max_muster@dhbw.de"}
	allowed, def, err := app.PolicyIsZoneAllowedForUser("max-muster.users.dhbw.site", other)
	if err != nil || !allowed {
		t.Fatalf("the rule grants the name to both: allowed %v, err %v", allowed, err)
	}
	status, body, _ := app.ZoneCreate(context.Background(), other, *def)
	if status != http.StatusConflict {
		t.Fatalf("creating a zone owned by someone else: status %d (%v), want 409", status, body)
	}
	if owns, _ := app.Storage.IsZoneOwner(other.Email, "max-muster.users.dhbw.site"); owns {
		t.Error("the second person must not have become an owner")
	}

	zones, err := app.ZoneList(other)
	if err != nil {
		t.Fatalf("ZoneList failed: %v", err)
	}
	seen := map[string]ZoneStatus{}
	for _, z := range zones {
		seen[z.Name] = z
	}
	if z, ok := seen["max-muster.users.dhbw.site"]; !ok || !z.AlreadyTakenBySomeoneElse || z.Exists || len(z.Owners) != 0 {
		t.Errorf("%%l zone of someone else: %+v (listed %v), want taken, not owned, owners hidden", z, ok)
	}
	if z, ok := seen["max-muster-at-dhbw-de.users.dhbw.site"]; !ok || z.AlreadyTakenBySomeoneElse {
		t.Errorf("%%u zone: %+v (listed %v), want free", z, ok)
	}
}
