package app

import (
	"slices"
	"testing"
)

// A shared zone belongs to its creator: co-owners without a rule of their own (the wi-ma.dhbw.site case on prod) do not make it orphaned; once no rule covers the creator, the zone is listed once, under the creator.
func TestOrphanedZonesJudgeSharedZonesByTheirCreator(t *testing.T) {
	app := newTestApp(t)
	rule, err := app.Storage.PolicyCreate(&PolicyRule{ZonePattern: "wi-ma.dhbw.site", ZoneSoa: "wi-ma.dhbw.site", TargetUserFilter: "clemens@dhbw.de, dennis@dhbw.de", AllowSubdomains: true, SharingAllowed: true})
	if err != nil {
		t.Fatalf("PolicyCreate failed: %v", err)
	}
	addZone(t, app, "clemens@dhbw.de", "wi-ma.dhbw.site")
	addZone(t, app, "johann@dhbw.de", "wi-ma.dhbw.site")
	addZone(t, app, "dennis@dhbw.de", "crm.wi-ma.dhbw.site")
	addZone(t, app, "volker@dhbw.de", "crm.wi-ma.dhbw.site")
	// An orphan for contrast: nobody's rule covers it.
	addZone(t, app, "eve@dhbw.de", "old.example.org")

	orphaned, err := app.OrphanedZones()
	if err != nil {
		t.Fatalf("OrphanedZones failed: %v", err)
	}
	if want := []OrphanedZone{{Zone: "old.example.org", User: "eve@dhbw.de"}}; !slices.Equal(orphaned, want) {
		t.Errorf("orphaned %v, want %v", orphaned, want)
	}
	for zone, want := range map[string]bool{"wi-ma.dhbw.site": false, "crm.wi-ma.dhbw.site": false, "old.example.org": true} {
		if got, _, err := app.ZoneIsOrphaned(zone); err != nil || got != want {
			t.Errorf("ZoneIsOrphaned(%s) = %v, %v; want %v", zone, got, err, want)
		}
	}

	// The rule no longer covers the creators: both zones are orphaned, each listed once under its creator.
	rule.TargetUserFilter = "someone-else@dhbw.de"
	if _, err := app.Storage.PolicyUpdate(rule); err != nil {
		t.Fatalf("PolicyUpdate failed: %v", err)
	}
	orphaned, err = app.OrphanedZones()
	if err != nil {
		t.Fatalf("OrphanedZones failed: %v", err)
	}
	slices.SortFunc(orphaned, func(a, b OrphanedZone) int {
		if a.Zone < b.Zone {
			return -1
		}
		return 1
	})
	want := []OrphanedZone{{Zone: "crm.wi-ma.dhbw.site", User: "dennis@dhbw.de"}, {Zone: "old.example.org", User: "eve@dhbw.de"}, {Zone: "wi-ma.dhbw.site", User: "clemens@dhbw.de"}}
	if !slices.Equal(orphaned, want) {
		t.Errorf("orphaned %v, want %v", orphaned, want)
	}
}
