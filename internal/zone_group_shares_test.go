package app

import (
	"context"
	"net/http"
	"testing"
)

// groupShareSetup: a personal-zone rule with sharing on, Alice's zone with a subzone, and a role provider in which Bob is in the lab group and Carol is not.
func groupShareSetup(t *testing.T) (*AppData, *fakeRoleProvider) {
	t.Helper()
	f := newFakeRoleProvider(t, map[string][]string{
		"bob@dhbw.de": {"group:lab", "group:lab#member"},
	})
	app, _ := newRoleTestApp(t, f)
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "%u.users.dhbw.site", ZoneSoa: "users.dhbw.site", TargetUserFilter: "*@dhbw.de", AllowSubdomains: true, SharingAllowed: true})
	addZone(t, app, "alice@dhbw.de", "alice-at-dhbw-de.users.dhbw.site")
	addZone(t, app, "alice@dhbw.de", "www.alice-at-dhbw-de.users.dhbw.site")
	return app, f
}

const aliceZone = "alice-at-dhbw-de.users.dhbw.site"

func mustShare(t *testing.T, app *AppData, by, zone, group string) {
	t.Helper()
	if status, body, err := app.ZoneAddGroupShare(context.Background(), claimsOf(by), zone, group); status != http.StatusOK {
		t.Fatalf("sharing %s with %s: %d %v %v", zone, group, status, body, err)
	}
}

func viaOf(t *testing.T, app *AppData, user, zone string) (bool, string) {
	t.Helper()
	owns, err := app.Storage.IsZoneOwner(user, zone)
	if err != nil || !owns {
		return false, ""
	}
	row, err := app.Storage.GetZone(user, zone)
	if err != nil {
		t.Fatal(err)
	}
	return true, row.Via
}

// A member gets the zone and the zones below it, through the group; a non-member gets nothing.
func TestGroupShareGrantsMembers(t *testing.T) {
	app, _ := groupShareSetup(t)
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab#member")
	ctx := context.Background()
	for _, u := range []string{"bob@dhbw.de", "carol@dhbw.de"} {
		if err := app.syncGroupAccess(ctx, u); err != nil {
			t.Fatal(err)
		}
	}
	for _, z := range []string{aliceZone, "www." + aliceZone} {
		if owns, via := viaOf(t, app, "bob@dhbw.de", z); !owns || via != "group:lab#member" {
			t.Errorf("bob on %s: owns %v via %q", z, owns, via)
		}
		if owns, _ := viaOf(t, app, "carol@dhbw.de", z); owns {
			t.Errorf("carol must not own %s", z)
		}
	}
	// The list shows the zone to Bob, with the group and his path to it; Alice sees the group too.
	if z, ok := listed(t, app, "bob@dhbw.de")[aliceZone]; !ok || !z.Exists || z.Via != "group:lab#member" || len(z.Groups) != 1 {
		t.Errorf("bob's list: %+v (listed %v)", z, ok)
	}
	if z := listed(t, app, "alice@dhbw.de")[aliceZone]; z.Via != "" || len(z.Groups) != 1 || z.Groups[0] != "group:lab#member" {
		t.Errorf("alice's list: %+v", z)
	}
	// Syncing again changes nothing.
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	if n, _ := app.Storage.CountZoneOwners(aliceZone); n != 2 {
		t.Errorf("owners after a second sync: %d, want 2", n)
	}
}

// Leaving the group takes the zone; with the groups unknown nothing is taken.
func TestGroupShareLeavingTheGroup(t *testing.T) {
	app, f := groupShareSetup(t)
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab")
	ctx := context.Background()
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.tokens["bob@dhbw.de"] = nil
	f.mu.Unlock()
	app.Roles.entries = map[string]tokenEntry{} // forget the cached answer
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	if owns, _ := viaOf(t, app, "bob@dhbw.de", aliceZone); owns {
		t.Error("bob left the group and must lose the zone")
	}
	if owns, _ := viaOf(t, app, "bob@dhbw.de", "www."+aliceZone); owns {
		t.Error("bob must lose the subzone too")
	}
}

func TestGroupShareUnknownGroupsKeepAccess(t *testing.T) {
	app, f := groupShareSetup(t)
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab")
	ctx := context.Background()
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	app.Roles.entries = map[string]tokenEntry{}
	f.down.Store(true)
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	if owns, _ := viaOf(t, app, "bob@dhbw.de", aliceZone); !owns {
		t.Error("with the role provider down bob keeps the zone")
	}
}

// Removing the share takes the zone from the members, not from owners in their own right.
func TestGroupShareRemoved(t *testing.T) {
	app, _ := groupShareSetup(t)
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab")
	ctx := context.Background()
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	// Bob as a member may remove the share (any owner may).
	if status, body, _ := app.ZoneRemoveGroupShare(ctx, claimsOf("bob@dhbw.de"), aliceZone, "group:lab"); status != http.StatusOK {
		t.Fatalf("removing the share: %d %v", status, body)
	}
	if owns, _ := viaOf(t, app, "bob@dhbw.de", aliceZone); owns {
		t.Error("the share is gone, so is bob's access")
	}
	if owns, via := viaOf(t, app, "alice@dhbw.de", aliceZone); !owns || via != "" {
		t.Error("alice owns the zone in her own right")
	}
	if status, _, _ := app.ZoneRemoveGroupShare(ctx, claimsOf("alice@dhbw.de"), aliceZone, "group:lab"); status != http.StatusNotFound {
		t.Errorf("removing it twice: %d, want 404", status)
	}
}

// Who may share and with what.
func TestGroupShareChecks(t *testing.T) {
	app, _ := groupShareSetup(t)
	ctx := context.Background()
	for _, bad := range []string{"lab", "user:bob@dhbw.de", "group:", "group:la b", "group:lab#"} {
		if status, _, _ := app.ZoneAddGroupShare(ctx, claimsOf("alice@dhbw.de"), aliceZone, bad); status != http.StatusBadRequest {
			t.Errorf("subject %q: %d, want 400", bad, status)
		}
	}
	if status, _, _ := app.ZoneAddGroupShare(ctx, claimsOf("carol@dhbw.de"), aliceZone, "group:lab"); status != http.StatusForbidden {
		t.Errorf("a non-owner shares: %d, want 403", status)
	}
	// A member shares further, with another group.
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab")
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	mustShare(t, app, "bob@dhbw.de", aliceZone, "group:other")
	app.Roles = nil
	if status, _, _ := app.ZoneAddGroupShare(ctx, claimsOf("alice@dhbw.de"), aliceZone, "group:x"); status != http.StatusConflict {
		t.Errorf("without a role provider: %d, want 409", status)
	}
}

// A member may delete the zone; they cannot be removed as an owner (the share is what goes); the zone counts toward their limit.
func TestGroupShareAuthority(t *testing.T) {
	app, _ := groupShareSetup(t)
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab")
	ctx := context.Background()
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	a, err := app.zoneAuthorityOf(claimsOf("bob@dhbw.de"), aliceZone)
	if err != nil || !a.owner || !a.viaGroup || !a.deletes() || a.manages() {
		t.Errorf("bob's authority: %+v (deletes %v), %v", a, a.deletes(), err)
	}
	if status, _, _ := app.ZoneRemoveOwner(ctx, claimsOf("alice@dhbw.de"), aliceZone, "bob@dhbw.de"); status != http.StatusConflict {
		t.Errorf("removing a group owner: %d, want 409", status)
	}
	if n, err := app.Storage.CountGroupZones("bob@dhbw.de"); err != nil || n != 2 {
		t.Errorf("bob's group zones: %d, %v; want 2 (zone and subzone)", n, err)
	}
	// Added by address, bob owns it in his own right from then on.
	if status, _, _ := app.ZoneAddOwner(ctx, claimsOf("alice@dhbw.de"), aliceZone, "bob@dhbw.de"); status != http.StatusOK {
		t.Fatalf("adding bob by address: %d", status)
	}
	if _, via := viaOf(t, app, "bob@dhbw.de", aliceZone); via != "" {
		t.Errorf("bob added by address still via %q", via)
	}
}

// Only owners through a group are left and the group is gone: the last row stays and the zone is orphaned.
func TestGroupShareOrphan(t *testing.T) {
	app, f := groupShareSetup(t)
	// A zone every address may hold, so the rule covers whoever is its creator; only the group decides here.
	mustCreatePolicy(t, app, PolicyRule{ZonePattern: "lab.dhbw.site", ZoneSoa: "dhbw.site", TargetUserFilter: "*@dhbw.de", SharingAllowed: true})
	const lab = "lab.dhbw.site"
	addZone(t, app, "alice@dhbw.de", lab)
	mustShare(t, app, "alice@dhbw.de", lab, "group:lab")
	ctx := context.Background()
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	// Alice goes (a super admin removed her); bob, through the group, is the only owner.
	if err := app.Storage.DeleteZone("alice@dhbw.de", lab); err != nil {
		t.Fatal(err)
	}
	if orphaned, _, _ := app.ZoneIsOrphaned(lab); orphaned {
		t.Error("bob is still in the group: not orphaned")
	}
	f.mu.Lock()
	f.tokens["bob@dhbw.de"] = nil
	f.mu.Unlock()
	app.Roles.entries = map[string]tokenEntry{}
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	if owns, _ := viaOf(t, app, "bob@dhbw.de", lab); !owns {
		t.Error("the last row must stay")
	}
	if orphaned, _, err := app.ZoneIsOrphaned(lab); err != nil || !orphaned {
		t.Errorf("the zone of a gone group must be orphaned: %v, %v", orphaned, err)
	}
}

// A subzone created later is held by the group's members through the group.
func TestGroupShareInheritedBySubzone(t *testing.T) {
	app, _ := groupShareSetup(t)
	mustShare(t, app, "alice@dhbw.de", aliceZone, "group:lab")
	ctx := context.Background()
	if err := app.syncGroupAccess(ctx, "bob@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	addZone(t, app, "alice@dhbw.de", "api."+aliceZone)
	if err := app.inheritOwnersFromParent(ctx, "api."+aliceZone, "alice@dhbw.de"); err != nil {
		t.Fatal(err)
	}
	if owns, via := viaOf(t, app, "bob@dhbw.de", "api."+aliceZone); !owns || via != "group:lab" {
		t.Errorf("bob on the new subzone: owns %v via %q", owns, via)
	}
}
