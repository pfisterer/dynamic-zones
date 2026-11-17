package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pfisterer/cloud-self-service-golib/msg"
	"go.uber.org/zap"
)

// fakeRoleProvider answers GET /v1/users/{email}/tokens from a map, counts requests, and can be switched off (500) or made to require a bearer.
type fakeRoleProvider struct {
	srv      *httptest.Server
	mu       sync.Mutex
	tokens   map[string][]string
	down     atomic.Bool
	requests atomic.Int64
}

func newFakeRoleProvider(t *testing.T, tokens map[string][]string) *fakeRoleProvider {
	t.Helper()
	f := &fakeRoleProvider{tokens: tokens}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.requests.Add(1)
		if f.down.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		if r.Header.Get("Authorization") != "Bearer read-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		email, ok := strings.CutPrefix(r.URL.Path, "/v1/users/")
		email, ok2 := strings.CutSuffix(email, "/tokens")
		if !ok || !ok2 {
			http.NotFound(w, r)
			return
		}
		f.mu.Lock()
		list := append([]string{"user:" + email}, f.tokens[email]...)
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// newRoleTestApp is a storage-only app with a role provider pointing at f, on a clock the test moves.
func newRoleTestApp(t *testing.T, f *fakeRoleProvider) (*AppData, *time.Time) {
	t.Helper()
	app := newTestApp(t)
	app.Config.DnsPolicyConfig.SuperAdminEmails = map[string]struct{}{"admin@dhbw.de": {}}
	rp := NewRoleProvider(f.srv.URL, "read-token", zap.NewNop().Sugar())
	clock := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	rp.now = func() time.Time { return clock }
	app.Roles = rp
	return app, &clock
}

func principalWith(email string, known bool, tokens ...string) principal {
	set := map[string]struct{}{"user:" + email: {}}
	for _, t := range tokens {
		set[t] = struct{}{}
	}
	return principal{email: email, tokens: set, known: known}
}

func TestMatchFilter(t *testing.T) {
	p := principalWith("max@dhbw.de", true, "group:wwi23seb", "group:wwi23seb#studierende")
	for _, tc := range []struct {
		filter string
		want   bool
	}{
		{"*@dhbw.de", true},
		{"max@dhbw.de", true},
		{"MAX@DHBW.DE", true},
		{"user:max@dhbw.de", true},
		{"user:MAX@dhbw.de", true},
		{"user:other@dhbw.de", false},
		{"group:wwi23seb", true},
		{"group:WWI23SEB", true},
		{"group:wwi23seb#studierende", true},
		{"group:wwi23seb#dozent", false},
		{"group:other", false},
		{"other@dhbw.de, group:other ,group:wwi23seb#studierende", true},
		{"*@cas.dhbw.de,group:other", false},
		{"", false},
	} {
		if got := matchFilter(p, tc.filter); got.match != tc.want || got.unknown {
			t.Errorf("matchFilter(%q) = %+v, want match %v", tc.filter, got, tc.want)
		}
	}

	// Tokens unknown: e-mail and user: entries still decide; a group entry is unknown, never a match.
	u := principalWith("max@dhbw.de", false)
	if m := matchFilter(u, "group:wwi23seb"); m.match || !m.unknown || m.allowed(false) || !m.allowed(true) {
		t.Errorf("unknown group entry: %+v", m)
	}
	if m := matchFilter(u, "group:wwi23seb,*@dhbw.de"); !m.match {
		t.Errorf("e-mail entry must match without the role provider: %+v", m)
	}
	if m := matchFilter(u, "user:max@dhbw.de"); !m.match {
		t.Errorf("user: entry must match without the role provider: %+v", m)
	}
	if m := matchFilter(u, "*@cas.dhbw.de"); m.match || m.unknown {
		t.Errorf("an e-mail-only filter is never unknown: %+v", m)
	}
}

// Without a role provider (nil) everybody holds only their own user token, known: e-mail filters behave exactly as before, group entries match nobody.
func TestNoRoleProvider(t *testing.T) {
	var rp *RoleProvider
	p := rp.Resolve(" Max@DHBW.de ")
	if !p.known || p.email != "max@dhbw.de" || len(p.tokens) != 1 {
		t.Fatalf("Resolve without role provider = %+v", p)
	}
	if matchFilter(p, "group:wwi23seb").allowed(true) {
		t.Error("a group entry must not match without a role provider, not even optimistically")
	}
	if NewRoleProvider("  ", "x", nil) != nil {
		t.Error("an empty URL must mean no role provider")
	}
}

func TestValidateUserFilterTokens(t *testing.T) {
	for _, ok := range []string{
		"*@dhbw.de", "a@dhbw.de", "*", "user:a@dhbw.de", "group:wwi23seb", "group:WWI23SEB", "group:wwi23seb#studierende", "group:standort-ma.x_y",
		"*@dhbw.de, group:wwi23seb#dozent ,user:b@cas.dhbw.de,",
	} {
		if err := validateUserFilter(ok); err != nil {
			t.Errorf("validateUserFilter(%q) = %v, want accepted", ok, err)
		}
	}
	for _, bad := range []string{
		"", ",", "group:", "group:-x", "group:a b", "group:x#", "group:x#1rel", "group:x#a#b", "user:", "user:not-an-address", "user:*@dhbw.de",
		"pattern:*@dhbw.de", "role:x", "**@dhbw.de", "no-address", strings.Repeat("a", 260) + "@x.de",
	} {
		if err := validateUserFilter(bad); err == nil {
			t.Errorf("validateUserFilter(%q) accepted, want refused", bad)
		}
	}
	// The message names the token forms in both languages.
	err := validateUserFilter("role:x")
	if de, en := msg.TextOf(err).In(msg.DE), msg.TextOf(err).In(msg.EN); !strings.Contains(de, "group:<gruppe>#<rolle>") || !strings.Contains(en, "group:<group>#<role>") {
		t.Errorf("message: %q / %q", de, en)
	}
}

// One request per person within the fresh period; after it the role provider is asked again, and a changed membership counts.
func TestRoleProviderCaches(t *testing.T) {
	f := newFakeRoleProvider(t, map[string][]string{"max@dhbw.de": {"group:wwi23seb"}})
	app, clock := newRoleTestApp(t, f)

	for range 5 {
		if p := app.principalOf("Max@dhbw.de"); !p.known || !matchFilter(p, "group:wwi23seb").match {
			t.Fatalf("tokens: %+v", p)
		}
	}
	if n := f.requests.Load(); n != 1 {
		t.Fatalf("requests within the fresh period: %d, want 1", n)
	}

	f.mu.Lock()
	f.tokens["max@dhbw.de"] = []string{"group:other"}
	f.mu.Unlock()
	*clock = clock.Add(61 * time.Second)
	p := app.principalOf("max@dhbw.de")
	if f.requests.Load() != 2 || matchFilter(p, "group:wwi23seb").match || !matchFilter(p, "group:other").match {
		t.Fatalf("after the fresh period: requests %d, tokens %+v", f.requests.Load(), p.tokens)
	}
}

// Unreachable: the last answer of the past day stands in; older or none means unknown. After a failure the role provider is left alone for the backoff.
func TestRoleProviderFallback(t *testing.T) {
	f := newFakeRoleProvider(t, map[string][]string{"max@dhbw.de": {"group:wwi23seb"}})
	app, clock := newRoleTestApp(t, f)
	app.principalOf("max@dhbw.de")

	f.down.Store(true)
	*clock = clock.Add(2 * time.Hour)
	p := app.principalOf("max@dhbw.de")
	if !p.known || !matchFilter(p, "group:wwi23seb").match {
		t.Fatalf("stale fallback: %+v", p)
	}
	before := f.requests.Load()
	app.principalOf("max@dhbw.de")
	if f.requests.Load() != before {
		t.Error("within the backoff the role provider must not be asked again")
	}

	if p := app.principalOf("new@dhbw.de"); p.known {
		t.Errorf("a person never seen must be unknown during an outage: %+v", p)
	}

	*clock = clock.Add(23 * time.Hour)
	if p := app.principalOf("max@dhbw.de"); p.known {
		t.Errorf("an answer older than a day must not stand in: %+v", p)
	}

	f.down.Store(false)
	*clock = clock.Add(time.Minute)
	if p := app.principalOf("max@dhbw.de"); !p.known || !matchFilter(p, "group:wwi23seb").match {
		t.Errorf("back online: %+v", p)
	}
}

func TestRoleProviderWrongToken(t *testing.T) {
	f := newFakeRoleProvider(t, nil)
	rp := NewRoleProvider(f.srv.URL, "wrong", nil)
	if p := rp.Resolve("max@dhbw.de"); p.known {
		t.Errorf("a refused request must not count as an answer: %+v", p)
	}
}

func groupRuleSetup(t *testing.T, f *fakeRoleProvider) (*AppData, *time.Time) {
	t.Helper()
	app, clock := newRoleTestApp(t, f)
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%l.kurs.dhbw.site", ZoneSoa: "kurs.dhbw.site", TargetUserFilter: "group:wwi23seb#studierende", AllowSubdomains: true, SharingAllowed: true})
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%u.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de"})
	return app, clock
}

// A rule with a group token grants its zone (here with %l) to the group's members, and only to them.
func TestGroupRuleGrantsZones(t *testing.T) {
	f := newFakeRoleProvider(t, map[string][]string{
		"s1@student.dhbw.de": {"group:wwi23seb", "group:wwi23seb#studierende"},
		"doz@dhbw.de":        {"group:wwi23seb", "group:wwi23seb#dozent"},
	})
	app, _ := groupRuleSetup(t, f)

	allowed, def, err := app.PolicyIsZoneAllowedForUser("s1.kurs.dhbw.site", claimsOf("s1@student.dhbw.de"))
	if err != nil || !allowed || def.ZoneSOA != "kurs.dhbw.site" {
		t.Fatalf("member: allowed %v, def %+v, err %v", allowed, def, err)
	}
	if allowed, _, _ := app.PolicyIsZoneAllowedForUser("doz.kurs.dhbw.site", claimsOf("doz@dhbw.de")); allowed {
		t.Error("a lecturer of the course is not in the relation studierende")
	}
	zones := listed(t, app, "doz@dhbw.de")
	if _, ok := zones["doz.kurs.dhbw.site"]; ok {
		t.Error("the lecturer must not be offered the course zone")
	}
	if _, ok := zones["doz-at-dhbw-de.users.dhbw.site"]; !ok {
		t.Error("the e-mail rule must still offer the personal zone")
	}
	if _, ok := listed(t, app, "s1@student.dhbw.de")["s1.kurs.dhbw.site"]; !ok {
		t.Error("the student must be offered the course zone")
	}
}

// Role provider unreachable and nothing known: existing zones stay covered (not orphaned, flags kept), a new zone only a group rule grants is refused with 503 and a bilingual message, e-mail rules keep working.
func TestRoleProviderOutage(t *testing.T) {
	f := newFakeRoleProvider(t, map[string][]string{"s1@student.dhbw.de": {"group:wwi23seb#studierende"}})
	app, _ := groupRuleSetup(t, f)
	addZone(t, app, "s1@student.dhbw.de", "s1.kurs.dhbw.site")
	f.down.Store(true)

	orphaned, err := app.OrphanedZones()
	if err != nil {
		t.Fatal(err)
	}
	if len(orphaned) != 0 {
		t.Errorf("unknown tokens must not orphan a zone: %+v", orphaned)
	}
	if def, err := app.zoneGoverningDef("s1.kurs.dhbw.site"); err != nil || def == nil || !def.SharingAllowed || !def.AllowSubdomains {
		t.Errorf("governing rule of an existing zone during the outage: %+v, %v", def, err)
	}
	// The owner still sees their zone, with its flags.
	if z, ok := listed(t, app, "s1@student.dhbw.de")["s1.kurs.dhbw.site"]; !ok || !z.Exists || !z.AllowSubdomains {
		t.Errorf("owner's zone during the outage: %+v (listed %v)", z, ok)
	}

	_, err = app.ZoneCreateAuthorized(context.Background(), claimsOf("s2@student.dhbw.de"), "s2.kurs.dhbw.site")
	var se *StatusError
	if !errors.As(err, &se) || se.Status != http.StatusServiceUnavailable || !strings.Contains(se.Msg.In(msg.DE), "Gruppendienst nicht erreichbar") || !strings.Contains(se.Msg.In(msg.EN), "group service is unreachable") {
		t.Fatalf("group-only zone during the outage: %v", err)
	}
	// A stranger is not let in: no rule would grant them the zone even with every group counted.
	_, err = app.ZoneCreateAuthorized(context.Background(), claimsOf("s2@student.dhbw.de"), "s1.users.dhbw.site")
	if !errors.As(err, &se) || se.Status != http.StatusForbidden {
		t.Fatalf("a zone no rule grants: %v", err)
	}
	status, _, _ := app.ZoneJoin(context.Background(), claimsOf("s2@student.dhbw.de"), "s1.kurs.dhbw.site")
	if status != http.StatusForbidden {
		t.Errorf("joining someone else's %%l zone: %d, want 403 (not s2's name)", status)
	}

	// E-mail rules keep working.
	if allowed, _, _ := app.PolicyIsZoneAllowedForUser("x-at-dhbw-de.users.dhbw.site", claimsOf("x@dhbw.de")); !allowed {
		t.Error("an e-mail rule must keep working during the outage")
	}
}

// With the role provider answering, a member who left the group orphans their zone.
func TestOrphanedWhenGroupLeft(t *testing.T) {
	f := newFakeRoleProvider(t, map[string][]string{})
	app, _ := groupRuleSetup(t, f)
	addZone(t, app, "s1@student.dhbw.de", "s1.kurs.dhbw.site")
	orphaned, err := app.OrphanedZones()
	if err != nil || len(orphaned) != 1 || orphaned[0].Zone != "s1.kurs.dhbw.site" {
		t.Errorf("orphaned: %+v, %v", orphaned, err)
	}
}

func TestDelegationsWithGroupTokens(t *testing.T) {
	f := newFakeRoleProvider(t, map[string][]string{"lead@dhbw.de": {"group:stg-wi", "group:stg-wi#studiengangsleiter"}})
	app, _ := newRoleTestApp(t, f)
	for _, d := range []DelegationPolicy{
		{TargetUserFilter: "group:stg-wi#studiengangsleiter", ZoneSuffix: "wi.dhbw.site", Description: "WI"},
		{TargetUserFilter: "group:other", ZoneSuffix: "other.dhbw.site"},
	} {
		if _, err := app.Storage.DelegationCreate(&d); err != nil {
			t.Fatal(err)
		}
	}
	got, err := app.DelegationsVisibleTo(claimsOf("lead@dhbw.de"))
	if err != nil || len(got) != 1 || got[0].ZoneSuffix != "wi.dhbw.site" {
		t.Fatalf("visible: %+v, %v", got, err)
	}
	if ok, _ := app.userCanManageZoneSoa(claimsOf("lead@dhbw.de"), "kurs.wi.dhbw.site"); !ok {
		t.Error("the delegate must manage rules below wi.dhbw.site")
	}
	if ok, _ := app.userCanManageZoneSoa(claimsOf("lead@dhbw.de"), "other.dhbw.site"); ok {
		t.Error("not a member of group:other")
	}
	if ok, _ := app.userCanManageZoneSoa(claimsOf("someone@dhbw.de"), "wi.dhbw.site"); ok {
		t.Error("a non-member must not manage")
	}
	// Outage with nothing known: a delegation through a group grants nothing new.
	f.down.Store(true)
	if ok, _ := app.userCanManageZoneSoa(claimsOf("lead2@dhbw.de"), "wi.dhbw.site"); ok {
		t.Error("unknown tokens must not grant a delegation")
	}
}

func TestRoleProviderURLNeedsToken(t *testing.T) {
	t.Setenv("ROLE_PROVIDER_URL", "http://role-provider-service:8085")
	t.Setenv("ROLE_PROVIDER_TOKEN", "")
	if _, err := GetAppConfigFromEnvironment(); err == nil || !strings.Contains(err.Error(), "ROLE_PROVIDER_TOKEN") {
		t.Errorf("want a refusal naming ROLE_PROVIDER_TOKEN, got %v", err)
	}
}
