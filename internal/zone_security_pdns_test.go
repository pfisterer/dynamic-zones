package app

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/joeig/go-powerdns/v3"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
)

// Regression tests for the zone takeover and delegation findings, against a real PowerDNS: both attacks lived in what PowerDNS does with a name (case-insensitive, trailing dot optional, NS records in whatever zone they are written to), which a test with only a database cannot see.

func claimsOf(email string) *UserClaims { return &UserClaims{Email: email} }

func mustCreatePolicy(t *testing.T, app *AppData, rule PolicyRule) {
	t.Helper()
	if _, err := app.Storage.PolicyCreate(&rule); err != nil {
		t.Fatalf("failed to create policy rule: %v", err)
	}
}

func userKey(t *testing.T, app *AppData, zone, user string) string {
	t.Helper()
	data, err := app.PowerDns.GetZone(t.Context(), zone, user)
	if err != nil {
		t.Fatalf("GetZone(%s, %s) failed: %v", zone, user, err)
	}
	if len(data.ZoneKeys) == 0 {
		return ""
	}
	return data.ZoneKeys[0].Key
}

func pdnsZoneExists(t *testing.T, app *AppData, zone string) bool {
	t.Helper()
	exists, err := app.PowerDns.ZoneExists(t.Context(), zone)
	if err != nil {
		t.Fatalf("ZoneExists(%s) failed: %v", zone, err)
	}
	return exists
}

// Bob owns p.example.com (subdomains allowed), Alice owns x.p.example.com below it. Asking for Alice's zone under another spelling used to pass the case-sensitive "already exists" check, and the forced create then deleted her zone in PowerDNS and recreated it with Bob's key.
func TestZoneTakeoverViaNameVariantIsRefused(t *testing.T) {
	const (
		alice  = "alice@dhbw.de"
		bob    = "bob@dhbw.de"
		parent = "p.example.com"
		victim = "x.p.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()

	mustCreatePolicy(t, app, PolicyRule{ZonePattern: parent, ZoneSoa: "example.com", TargetUserFilter: bob, AllowSubdomains: true})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(bob), parent); err != nil {
		t.Fatalf("bob could not create his own zone: %v", err)
	}

	// Alice's zone, as it can exist from before (e.g. granted by a rule of its own).
	if _, err := app.PowerDns.CreateUserZone(ctx, alice, victim, false); err != nil {
		t.Fatalf("seeding alice's zone in PowerDNS: %v", err)
	}
	if _, err := app.Storage.CreateZone(alice, victim, true); err != nil {
		t.Fatalf("seeding alice's zone in storage: %v", err)
	}
	aliceKey := userKey(t, app, victim, alice)

	for _, variant := range []string{"X.p.example.com", "x.p.example.com.", " x.P.Example.com. "} {
		_, err := app.ZoneCreateAuthorized(ctx, claimsOf(bob), variant)
		if err == nil {
			t.Fatalf("creating %q must be refused: it is alice's zone", variant)
		}
		if got := StatusOf(err); got != http.StatusConflict {
			t.Errorf("creating %q: got %d, want 409", variant, got)
		}
	}

	if got := userKey(t, app, victim, alice); got != aliceKey {
		t.Error("alice's key was replaced")
	}
	if got := userKey(t, app, victim, bob); got != "" {
		t.Error("bob holds a key for alice's zone")
	}
	for _, stored := range []string{"X.p.example.com", "x.p.example.com."} {
		if owns, _ := app.Storage.IsZoneOwner(bob, stored); owns {
			t.Errorf("a non-canonical name %q was stored", stored)
		}
	}

	// A row stored before names were canonical still blocks every spelling of its zone.
	if _, err := app.PowerDns.CreateUserZone(ctx, alice, "z.p.example.com", false); err != nil {
		t.Fatalf("seeding alice's legacy zone in PowerDNS: %v", err)
	}
	if _, err := app.Storage.CreateZone(alice, "Z.p.example.com", true); err != nil {
		t.Fatalf("seeding alice's legacy row: %v", err)
	}
	legacyKey := userKey(t, app, "z.p.example.com", alice)
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(bob), "z.p.example.com"); StatusOf(err) != http.StatusConflict {
		t.Errorf("creating over a legacy-spelled zone: got %v, want 409", err)
	}
	if userKey(t, app, "z.p.example.com", alice) != legacyKey || userKey(t, app, "z.p.example.com", bob) != "" {
		t.Error("the legacy zone's keys were changed")
	}
}

// Names that are no plain host name are refused at the entry point, before anything is looked up or stored.
func TestCanonicalZoneName(t *testing.T) {
	ok := map[string]string{
		"X.Example.COM.":   "x.example.com",
		" a-b.example.com": "a-b.example.com",
		"x.p.example.com":  "x.p.example.com",
	}
	for in, want := range ok {
		got, err := canonicalZoneName(in)
		if err != nil || got != want {
			t.Errorf("canonicalZoneName(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "com", "a_b.example.com", "*.example.com", "a..example.com", "example.com..", "-a.example.com", "a-.example.com", strings.Repeat("a", 64) + ".example.com", strings.Repeat("abcdefghi.", 26) + "com"} {
		if got, err := canonicalZoneName(bad); err == nil {
			t.Errorf("canonicalZoneName(%q) = %q, want an error", bad, got)
		}
	}

	// And through a route: refused with 400 before the handler looks at anything.
	gin.SetMode(gin.TestMode)
	app := newTestApp(t)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set(UserDataKey, claimsOf("alice@dhbw.de")) })
	CreateApiV1Zones(r.Group("/v1"), app)
	for _, path := range []string{"/v1/zones/a_b.example.com", "/v1/zones/%2A.example.com", "/v1/zones/a..example.com/owners"} {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
		if rr.Code != http.StatusBadRequest {
			t.Errorf("GET %s: got %d, want 400", path, rr.Code)
		}
	}
}

// Alice owns lab.example.com; Bob is entitled to the same name (already taken, sharing off) with subdomains allowed. Creating www.lab.example.com used to write an NS delegation for it into ALICE's zone and hand Bob the delegated zone.
func TestSubzoneCannotBeDelegatedInsideSomeoneElsesZone(t *testing.T) {
	const (
		alice = "alice@dhbw.de"
		bob   = "bob@dhbw.de"
		lab   = "lab.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()

	mustCreatePolicy(t, app, PolicyRule{ZonePattern: lab, ZoneSoa: "example.com", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), lab); err != nil {
		t.Fatalf("alice could not create her zone: %v", err)
	}

	_, err := app.ZoneCreateAuthorized(ctx, claimsOf(bob), "www."+lab)
	if err == nil {
		t.Fatal("bob must not create a subzone inside alice's zone")
	}
	if got := StatusOf(err); got != http.StatusForbidden {
		t.Errorf("got %d, want 403", got)
	}
	nsType := powerdns.RRTypeNS
	rrsets, err := app.PowerDns.powerdns.Records.Get(ctx, lab+".", "www."+lab+".", &nsType)
	if err != nil {
		t.Fatalf("reading alice's zone: %v", err)
	}
	if len(rrsets) != 0 {
		t.Errorf("an NS delegation was written into alice's zone: %+v", rrsets)
	}
	if pdnsZoneExists(t, app, "www."+lab) {
		t.Error("the subzone was created in PowerDNS")
	}

	// Alice herself may delegate below her zone ...
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), "www."+lab); err != nil {
		t.Fatalf("alice could not create a subzone of her own zone: %v", err)
	}
	// ... two levels of new intermediate zones at once, but not three.
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), "a.b.c."+lab); err != nil {
		t.Errorf("two intermediate levels must be allowed: %v", err)
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), "a.b.c.d."+lab); StatusOf(err) != http.StatusBadRequest {
		t.Errorf("three intermediate levels: got %v, want 400", err)
	}
	if pdnsZoneExists(t, app, "d."+lab) {
		t.Error("a refused request left an intermediate zone behind")
	}

	// A subzone needs its parent to exist and be the caller's: Bob's own base zone that nobody created yet is not created as an ownerless side effect.
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "team.example.com", ZoneSoa: "example.com", TargetUserFilter: bob, AllowSubdomains: true})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(bob), "x.team.example.com"); StatusOf(err) != http.StatusForbidden {
		t.Errorf("subzone below an uncreated parent: got %v, want 403", err)
	}
	if pdnsZoneExists(t, app, "team.example.com") {
		t.Error("the parent was created as an ownerless intermediate zone")
	}
}

// A co-owner who joined a shared zone used to be able to delete it, remove its creator and rotate everyone's keys.
func TestCoOwnerCannotDeleteEvictOrRekeyTheCreator(t *testing.T) {
	const (
		alice = "alice@dhbw.de"
		bob   = "bob@dhbw.de"
		zone  = "team.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()

	mustCreatePolicy(t, app, PolicyRule{ZonePattern: zone, ZoneSoa: "example.com", TargetUserFilter: "*@dhbw.de", SharingAllowed: true})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), zone); err != nil {
		t.Fatalf("alice could not create the zone: %v", err)
	}
	if status, resp, _ := app.ZoneJoin(ctx, claimsOf(bob), zone); status != http.StatusOK {
		t.Fatalf("bob could not join: %d %v", status, resp)
	}
	if creator, _ := app.Storage.ZoneCreator(zone); creator != alice {
		t.Fatalf("creator is %q, want alice", creator)
	}

	if err := app.ZoneDeleteAuthorized(ctx, claimsOf(bob), zone); StatusOf(err) != http.StatusForbidden {
		t.Errorf("co-owner deleting the zone: got %v, want 403", err)
	}
	if !pdnsZoneExists(t, app, zone) {
		t.Fatal("the co-owner deleted the zone")
	}

	if status, _, _ := app.ZoneRemoveOwner(ctx, claimsOf(bob), zone, alice); status != http.StatusForbidden {
		t.Errorf("co-owner removing the creator: got %d, want 403", status)
	}
	if owns, hasKey := ownsWithKey(t, app, alice, zone); !owns || !hasKey {
		t.Fatal("the co-owner removed the creator")
	}

	aliceKey, bobKey := userKey(t, app, zone, alice), userKey(t, app, zone, bob)
	if status, resp, _ := app.ZoneRotateKeys(ctx, claimsOf(bob), zone); status != http.StatusOK {
		t.Fatalf("co-owner rotating their own key: %d %v", status, resp)
	}
	if userKey(t, app, zone, alice) != aliceKey {
		t.Error("the co-owner rotated the creator's key")
	}
	if userKey(t, app, zone, bob) == bobKey {
		t.Error("the co-owner's own key was not rotated")
	}

	// The creator cannot leave; a co-owner can.
	if status, _, _ := app.ZoneRemoveOwner(ctx, claimsOf(alice), zone, alice); status != http.StatusConflict {
		t.Errorf("creator leaving: got %d, want 409", status)
	}
	if status, resp, _ := app.ZoneRemoveOwner(ctx, claimsOf(bob), zone, bob); status != http.StatusOK {
		t.Errorf("co-owner leaving: %d %v", status, resp)
	}

	// The creator manages the zone as a whole.
	if status, resp, _ := app.ZoneJoin(ctx, claimsOf(bob), zone); status != http.StatusOK {
		t.Fatalf("bob could not re-join: %d %v", status, resp)
	}
	if status, resp, _ := app.ZoneRotateKeys(ctx, claimsOf(alice), zone); status != http.StatusOK || resp.(gin.H)["rotated"] != 2 {
		t.Errorf("creator rotating all keys: %d %v", status, resp)
	}
	if status, resp, _ := app.ZoneRemoveOwner(ctx, claimsOf(alice), zone, bob); status != http.StatusOK {
		t.Errorf("creator removing a co-owner: %d %v", status, resp)
	}
	if err := app.ZoneDeleteAuthorized(ctx, claimsOf(alice), zone); err != nil {
		t.Errorf("creator deleting the zone: %v", err)
	}
}

// A read-only API token used to receive the zone's TSIG key — which may write the zone — in the JSON and in the external-dns values. And image-version went into that YAML unchecked.
func TestReadOnlyTokenGetsNoZoneKey(t *testing.T) {
	const alice = "alice@dhbw.de"
	app := newPdnsTestApp(t)
	app.Config.WebServer.ExternalDnsVersion = "v0.19.0"
	ctx := t.Context()

	zone := "alice.example.com"
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: zone, ZoneSoa: "example.com", TargetUserFilter: alice})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), zone); err != nil {
		t.Fatalf("create zone: %v", err)
	}

	gin.SetMode(gin.TestMode)
	router := func(readOnly bool) *gin.Engine {
		r := gin.New()
		r.Use(func(c *gin.Context) {
			c.Set(UserDataKey, claimsOf(alice))
			ginweb.SetReadOnly(c, readOnly)
		})
		CreateApiV1Zones(r.Group("/v1"), app)
		return r
	}
	get := func(r *gin.Engine, query string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/v1/zones/"+zone+query, nil))
		return rr
	}
	key := userKey(t, app, zone, alice)

	readOnly := router(true)
	if rr := get(readOnly, "?format=external-dns"); rr.Code != http.StatusForbidden || strings.Contains(rr.Body.String(), key) {
		t.Errorf("read-only external-dns: got %d, want 403 without the key", rr.Code)
	}
	rr := get(readOnly, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("read-only GET: got %d: %s", rr.Code, rr.Body.String())
	}
	if strings.Contains(rr.Body.String(), key) || strings.Contains(rr.Body.String(), "externalDnsValuesYaml") {
		t.Errorf("a read-only token received the zone key: %s", rr.Body.String())
	}

	writable := router(false)
	if rr := get(writable, ""); !strings.Contains(rr.Body.String(), key) {
		t.Errorf("a writable caller must still get its key: %d %s", rr.Code, rr.Body.String())
	}
	injected := "?format=external-dns&image-version=" + url.QueryEscape("v1\nevil: true")
	if rr := get(writable, injected); rr.Code != http.StatusBadRequest || strings.Contains(rr.Body.String(), "evil") {
		t.Errorf("image-version injection: got %d %s, want 400", rr.Code, rr.Body.String())
	}
}

// Rows stored before canonicalisation are found (and reported at startup), canonical ones are not.
func TestNonCanonicalZoneNamesAreReported(t *testing.T) {
	app := newTestApp(t)
	addZone(t, app, "alice@dhbw.de", "x.p.example.com")
	addZone(t, app, "bob@dhbw.de", "X.p.example.com")
	addZone(t, app, "carol@dhbw.de", "y.example.com.")

	odd, err := app.nonCanonicalZoneNames()
	if err != nil {
		t.Fatalf("nonCanonicalZoneNames: %v", err)
	}
	got := map[string]bool{}
	for _, z := range odd {
		got[z.Zone] = true
	}
	if len(odd) != 2 || !got["X.p.example.com"] || !got["y.example.com."] {
		t.Errorf("got %+v, want exactly the two non-canonical rows", odd)
	}
}

func nsRecords(t *testing.T, app *AppData, zone, name string) []powerdns.RRset {
	t.Helper()
	nsType := powerdns.RRTypeNS
	rrsets, err := app.PowerDns.powerdns.Records.Get(t.Context(), zone+".", name+".", &nsType)
	if err != nil {
		t.Fatalf("reading NS %s in %s: %v", name, zone, err)
	}
	return rrsets
}

// A zone granted by a rule of its own was authorised by whoever wrote the rule, so its delegation goes into the parent even when the parent is somebody else's zone (the prod shapes petko.proj.dhbw.site below clemens' proj.dhbw.site, and test.pfisterer.users.dhbw.site below pfisterer.users.dhbw.site). What stays forbidden is the allow_subdomains path into a zone the caller does not own, and claiming a name a rule reserves for someone else.
func TestExplicitRuleMayDelegateBelowSomeoneElsesZone(t *testing.T) {
	const (
		clemens = "clemens@dhbw.de"
		petko   = "petko.rutesic@dhbw.de"
		mallory = "mallory@dhbw.de"
		proj    = "proj.dhbw.site"
		petkoZ  = "petko.proj.dhbw.site"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()

	// Sharing off for proj: with it on, the parent's owners inherit every zone created below it (the sharing subtree rule), so clemens would co-own petko's zone and rightly be allowed below it.
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: proj, ZoneSoa: "dhbw.site", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true})
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: petkoZ, ZoneSoa: proj, TargetUserFilter: petko, AllowSubdomains: true, SharingAllowed: true})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(clemens), proj); err != nil {
		t.Fatalf("clemens could not create %s: %v", proj, err)
	}

	// The owner of the parent cannot take a name a rule grants to someone else through allow_subdomains.
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(clemens), petkoZ); StatusOf(err) != http.StatusForbidden {
		t.Errorf("clemens claiming petko's zone: got %v, want 403", err)
	}

	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(petko), petkoZ); err != nil {
		t.Fatalf("petko could not create the zone his rule grants: %v", err)
	}
	if len(nsRecords(t, app, proj, petkoZ)) == 0 {
		t.Error("no delegation for petko's zone in proj.dhbw.site")
	}
	if creator, _ := app.Storage.ZoneCreator(petkoZ); creator != petko {
		t.Errorf("creator of %s is %q, want petko", petkoZ, creator)
	}

	// Somebody matched only through allow_subdomains (of the proj rule) cannot delegate inside petko's zone — not even the owner of the zone above it.
	for _, who := range []string{mallory, clemens} {
		if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(who), "www."+petkoZ); StatusOf(err) != http.StatusForbidden {
			t.Errorf("%s creating www.%s: got %v, want 403", who, petkoZ, err)
		}
	}
	if len(nsRecords(t, app, petkoZ, "www."+petkoZ)) != 0 {
		t.Error("a delegation was written into petko's zone")
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(petko), "www."+petkoZ); err != nil {
		t.Errorf("petko could not create a subzone of his own zone: %v", err)
	}

	// The %u shape: an explicit rule for a student below the %u zone of a lecturer.
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%u.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "pfisterer", AllowSubdomains: true})
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "test.pfisterer.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "student@dhbw.de"})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf("pfisterer"), "pfisterer.users.dhbw.site"); err != nil {
		t.Fatalf("pfisterer could not create his zone: %v", err)
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf("student@dhbw.de"), "test.pfisterer.users.dhbw.site"); err != nil {
		t.Fatalf("the student could not create the zone her rule grants: %v", err)
	}
	if len(nsRecords(t, app, "pfisterer.users.dhbw.site", "test.pfisterer.users.dhbw.site")) == 0 {
		t.Error("no delegation for the student's zone in pfisterer's zone")
	}
	// A policy SOA is not a place for allow_subdomains delegations either: pfisterer owns his zone, but users.dhbw.site belongs to the rule.
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf("pfisterer"), "x.test.pfisterer.users.dhbw.site"); StatusOf(err) != http.StatusForbidden {
		t.Errorf("pfisterer creating inside the student's zone: got %v, want 403", err)
	}
}

// A zone that was created as an ownerless intermediate on the way to a deeper ruled zone is adopted by the person its own rule grants it to, keeping the delegation it already holds — instead of being refused for good, or deleted and recreated (which cut that delegation).
func TestRuledIntermediateZoneIsAdoptedNotReplaced(t *testing.T) {
	const (
		clemens = "clemens@dhbw.de"
		petko   = "petko.rutesic@dhbw.de"
		team    = "team2.dhbw.site"
		deep    = "deep.team2.dhbw.site"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()

	mustCreatePolicy(t, app, PolicyRule{ZonePattern: deep, ZoneSoa: "dhbw.site", TargetUserFilter: petko})
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: team, ZoneSoa: "dhbw.site", TargetUserFilter: clemens})

	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(petko), deep); err != nil {
		t.Fatalf("petko could not create %s: %v", deep, err)
	}
	if !pdnsZoneExists(t, app, team) {
		t.Fatalf("%s was not created as an intermediate zone", team)
	}

	// Someone else entitled to nothing there cannot have it.
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf("mallory@dhbw.de"), team); StatusOf(err) != http.StatusForbidden {
		t.Errorf("mallory creating %s: got %v, want 403", team, err)
	}

	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(clemens), team); err != nil {
		t.Fatalf("clemens could not claim the zone his rule grants: %v", err)
	}
	if userKey(t, app, team, clemens) == "" {
		t.Error("clemens got no key on the adopted zone")
	}
	if len(nsRecords(t, app, team, deep)) == 0 {
		t.Error("adopting the zone cut petko's delegation")
	}
	if userKey(t, app, deep, petko) == "" {
		t.Error("petko lost his key")
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(clemens), team); StatusOf(err) != http.StatusConflict {
		t.Errorf("creating the adopted zone again: got %v, want 409", err)
	}
}
