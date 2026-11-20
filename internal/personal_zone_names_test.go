package app

import (
	"strings"
	"testing"

	"github.com/pfisterer/dynamic-zones/internal/helper"
)

func TestPersonalNameVariant(t *testing.T) {
	a, b := "max.mueller@dhbw.de", "max_mueller@dhbw.de"
	va, _ := expandZonePatternVariant("%l.users.dhbw.site", a)
	vb, _ := expandZonePatternVariant("%l.users.dhbw.site", b)
	if va == vb {
		t.Fatalf("two addresses got the same variant %s", va)
	}
	if again, _ := expandZonePatternVariant("%l.users.dhbw.site", " Max.Mueller@DHBW.de "); again != va {
		t.Errorf("the variant must depend only on the address: %s vs %s", again, va)
	}
	if !strings.HasPrefix(vb, "max-mueller-") || !strings.HasSuffix(vb, ".users.dhbw.site") || len(strings.Split(vb, ".")[0]) != len("max-mueller")+1+personalNameHashLength {
		t.Errorf("unexpected variant %s", vb)
	}
	if !zonePatternMatches("%l.users.dhbw.site", vb) {
		t.Errorf("the variant %s must still match its pattern", vb)
	}
	if _, ok := expandZonePatternVariant("fixed.users.dhbw.site", a); ok {
		t.Error("a pattern without placeholder has no variant")
	}

	// A long local part is shortened so that the label stays valid.
	long := strings.Repeat("a", 70) + "@dhbw.de"
	v, ok := expandZonePatternVariant("%l.users.dhbw.site", long)
	if !ok {
		t.Fatal("no variant for a long address")
	}
	if err := helper.DnsValidateName(v); err != nil {
		t.Errorf("variant %s of a long address is invalid: %v", v, err)
	}
}

// The second person whose address maps to a taken name is offered the variant; once they created it, it stays theirs (and covered, not orphaned) even after the zone that forced it is gone.
func TestPersonalZoneNameCollision(t *testing.T) {
	app := newTestApp(t)
	if _, err := app.Storage.PolicyCreate(&PolicyRule{ZonePattern: "%l.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de"}); err != nil {
		t.Fatalf("PolicyCreate failed: %v", err)
	}
	first, second := "max.mueller@dhbw.de", "max_mueller@dhbw.de"
	plain := "max-mueller.users.dhbw.site"
	variant := "max-mueller" + personalNameSuffix(second) + ".users.dhbw.site"

	offered := func(user string) string {
		t.Helper()
		zones, err := app.PolicyGetUserZones(&UserClaims{Email: user})
		if err != nil || len(zones) != 1 {
			t.Fatalf("PolicyGetUserZones(%s) = %v, %v", user, zones, err)
		}
		return zones[0].Zone
	}

	// Nothing created yet: both are offered the plain name.
	if got := offered(second); got != plain {
		t.Errorf("before any zone: offered %s, want %s", got, plain)
	}
	addZone(t, app, first, plain)
	if got := offered(first); got != plain {
		t.Errorf("creator: offered %s, want %s", got, plain)
	}
	if got := offered(second); got != variant {
		t.Errorf("second person: offered %s, want %s", got, variant)
	}
	addZone(t, app, second, variant)

	// The plain zone goes away: the second person keeps their variant, and it is not orphaned.
	if err := app.Storage.DeleteZone(first, plain); err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}
	if got := offered(second); got != variant {
		t.Errorf("after the plain zone is gone: offered %s, want %s", got, variant)
	}
	if orphaned, _, err := app.ZoneIsOrphaned(variant); err != nil || orphaned {
		t.Errorf("the variant zone must stay covered: orphaned %v, err %v", orphaned, err)
	}
	// And a third person with yet another spelling gets the plain name again, which is free now.
	if got := offered("max-mueller@dhbw.de"); got != plain {
		t.Errorf("third person: offered %s, want %s", got, plain)
	}
}
