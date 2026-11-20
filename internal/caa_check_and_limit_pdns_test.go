package app

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/joeig/go-powerdns/v3"
	"github.com/pfisterer/cloud-self-service-golib/msg"
)

// The limit of zones per person counts the zones a person created; super admins are exempt.
func TestZoneLimitPerPerson(t *testing.T) {
	const (
		alice = "alice@example.com"
		admin = "root@example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()
	app.Config.DnsPolicyConfig.MaxZonesPerUser = 2
	app.Config.DnsPolicyConfig.SuperAdminEmails = map[string]struct{}{admin: {}}
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%l.example.com", ZoneSoa: "example.com", TargetUserFilter: "*@example.com", AllowSubdomains: true})

	for _, zone := range []string{"alice.example.com", "a.alice.example.com"} {
		if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), zone); err != nil {
			t.Fatalf("creating %s within the limit: %v", zone, err)
		}
	}
	_, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), "b.alice.example.com")
	if err == nil || StatusOf(err) != http.StatusForbidden {
		t.Fatalf("the third zone must be refused with 403, got %v", err)
	}
	if de := MessageOf(err).String(); !strings.Contains(de, "höchstens 2 Zonen") {
		t.Errorf("message %q does not name the limit", de)
	}
	if pdnsZoneExists(t, app, "b.alice.example.com") {
		t.Error("a refused zone must not reach PowerDNS")
	}

	// Super admins are exempt.
	for _, zone := range []string{"root.example.com", "a.root.example.com", "b.root.example.com"} {
		if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(admin), zone); err != nil {
			t.Fatalf("super admin creating %s: %v", zone, err)
		}
	}

	// Deleting a zone makes room again.
	if status, _, err := app.ZoneDelete(ctx, alice, "a.alice.example.com"); err != nil || status >= 300 {
		t.Fatalf("ZoneDelete: %d, %v", status, err)
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), "b.alice.example.com"); err != nil {
		t.Fatalf("creating after deleting one: %v", err)
	}
}

// The CAA check reports CAA record sets in user zones as zone events, ignores sets that only repeat the enforced CAA, resolves the event once the records are gone, and with DeleteRecords removes them itself.
func TestCaaCheck(t *testing.T) {
	const (
		alice = "alice@example.com"
		zone  = "alice.example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()
	app.Config.CaaCheck.IntervalMinutes = 60
	app.Config.ZoneEvents.TTLHours = 24
	app.PowerDns.defaultSoaZoneRecords = []DefaultRecord{{Name: "", Type: "CAA", Content: `0 issue "letsencrypt.org"`}}
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%l.example.com", ZoneSoa: "example.com", TargetUserFilter: "*@example.com"})
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(alice), zone); err != nil {
		t.Fatalf("creating the zone: %v", err)
	}

	events := func() []ZoneEvent {
		t.Helper()
		evs, err := app.Storage.ListZoneEventsForZones([]string{zone}, time.Now())
		if err != nil {
			t.Fatalf("listing events: %v", err)
		}
		return evs
	}
	run := func() CaaCheckSummary {
		t.Helper()
		sum, err := app.CheckUserZoneCAA(ctx, app.PowerDns)
		if err != nil {
			t.Fatalf("CheckUserZoneCAA: %v", err)
		}
		return sum
	}
	addCAA := func(name, content string) {
		t.Helper()
		if err := app.PowerDns.powerdns.Records.Add(ctx, zone+".", name, powerdns.RRTypeCAA, 300, []string{content}); err != nil {
			t.Fatalf("adding CAA at %s: %v", name, err)
		}
	}

	// Clean zone: nothing to report.
	if sum := run(); sum.Checked != 1 || sum.Findings != 0 || len(events()) != 0 {
		t.Fatalf("clean zone: %+v, events %v", sum, events())
	}

	// A set that only repeats the enforced CAA is harmless.
	addCAA(zone+".", `0 issue "letsencrypt.org"`)
	if sum := run(); sum.Findings != 0 || len(events()) != 0 {
		t.Fatalf("enforced CAA repeated: %+v, events %v", sum, events())
	}

	// An overriding set is reported once per zone, refreshed on the next run.
	addCAA("www."+zone+".", `0 issue "evil-ca.example"`)
	run()
	sum := run()
	evs := events()
	if sum.Findings != 1 || len(evs) != 1 {
		t.Fatalf("overriding CAA: %+v, events %v", sum, evs)
	}
	ev := evs[0]
	if ev.Source != caaCheckSource || ev.Class != caaClassFound || ev.Count != 2 || !strings.Contains(ev.Detail, `www CAA 0 issue "evil-ca.example"`) || strings.Contains(ev.Detail, "letsencrypt") {
		t.Errorf("unexpected event %+v", ev)
	}
	// Rendered in the reader's language.
	for l, want := range map[msg.Lang]string{msg.DE: "CAA-Einträge", msg.EN: "CAA records"} {
		infos := toZoneEventInfos(evs, nil, l)
		if !strings.Contains(infos[0].Message, want) || !strings.Contains(infos[0].Detail, "evil-ca.example") {
			t.Errorf("%v: %+v", l, infos[0])
		}
	}
	// The owner sees it like every zone event.
	if owners, _ := app.Storage.ListOwnersForZones([]string{zone}); len(owners[zone]) != 1 || owners[zone][0] != alice {
		t.Errorf("owners of the event's zone: %v", owners)
	}

	// The records go away: the event is resolved.
	if err := app.PowerDns.DeleteCAARecordSet(ctx, zone, "www."+zone); err != nil {
		t.Fatalf("deleting: %v", err)
	}
	if run(); len(events()) != 0 {
		t.Fatalf("event not resolved: %v", events())
	}

	// With DeleteRecords the check removes the set itself and says so; the enforced repetition stays.
	addCAA("www."+zone+".", `0 issue "evil-ca.example"`)
	app.Config.CaaCheck.DeleteRecords = true
	if sum := run(); sum.Removed != 1 {
		t.Fatalf("removing: %+v", sum)
	}
	sets, err := app.PowerDns.CAARecordSets(ctx, zone)
	if err != nil || len(sets) != 1 || sets[0].Name != zone+"." {
		t.Fatalf("after removal: %v, %v", sets, err)
	}
	evs = events()
	if len(evs) != 1 || evs[0].Class != caaClassRemoved || !strings.Contains(evs[0].Detail, "evil-ca.example") {
		t.Fatalf("removal event: %v", evs)
	}
	// The next run finds nothing and leaves the removal notice in place until it expires.
	if run(); len(events()) != 1 {
		t.Errorf("the removal notice must stay: %v", events())
	}
}

// End to end: the second person whose address maps to a taken personal name creates the offered variant; the plain name is refused to them.
func TestPersonalZoneNameCollisionCreatesVariant(t *testing.T) {
	const (
		first  = "max.mueller@example.com"
		second = "max_mueller@example.com"
	)
	app := newPdnsTestApp(t)
	ctx := t.Context()
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%l.example.com", ZoneSoa: "example.com", TargetUserFilter: "*@example.com"})

	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(first), "max-mueller.example.com"); err != nil {
		t.Fatalf("first person: %v", err)
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(second), "max-mueller.example.com"); err == nil {
		t.Fatal("the first person's zone must be refused to the second")
	}
	zones, err := app.ZoneList(claimsOf(second))
	if err != nil || len(zones) != 1 {
		t.Fatalf("ZoneList: %v, %v", zones, err)
	}
	variant := zones[0].Name
	if variant != "max-mueller"+personalNameSuffix(second)+".example.com" {
		t.Fatalf("offered %s", variant)
	}
	if _, err := app.ZoneCreateAuthorized(ctx, claimsOf(second), variant); err != nil {
		t.Fatalf("creating the variant: %v", err)
	}
	if creator, _ := app.Storage.ZoneCreator("max-mueller.example.com"); creator != first {
		t.Errorf("the plain zone must stay the first person's, creator %q", creator)
	}
}
