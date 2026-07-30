package app

import (
	"context"
	"fmt"
	"time"
)

// Sharing is a property of a zone SUBTREE, not of a single zone: whoever owns a
// shared zone also owns every zone delegated below it. Without that rule a
// co-owner sees the parent but neither the subzones already delegated under it
// nor their TSIG keys — the zone looks empty to them and its delegations are
// unmanageable.
//
// The helpers below maintain that invariant on every path that changes an owner
// set (join, share, leave, subzone creation) and once at startup, to backfill
// zones that were shared before the rule existed.

// subzonesOf returns every stored zone that is a strict subdomain of `zone`,
// deduplicated (the zone table holds one row per owner).
func (app *AppData) subzonesOf(zone string) ([]string, error) {
	all, err := app.Storage.ListAllZones()
	if err != nil {
		return nil, fmt.Errorf("app.subzonesOf: %w", err)
	}

	seen := make(map[string]bool, len(all))
	subzones := make([]string, 0)
	for _, z := range all {
		if !seen[z.Zone] && isSubdomainOf(z.Zone, zone) {
			seen[z.Zone] = true
			subzones = append(subzones, z.Zone)
		}
	}
	return subzones, nil
}

// closestStoredParent returns the most specific stored zone that `zone` sits
// under, or "" when it sits under none. Base zones delegated straight from a
// policy rule (e.g. alice.users.dhbw.site under the unstored users.dhbw.site)
// have no stored parent — exactly the case where nothing should be inherited.
func (app *AppData) closestStoredParent(zone string) (string, error) {
	all, err := app.Storage.ListAllZones()
	if err != nil {
		return "", fmt.Errorf("app.closestStoredParent: %w", err)
	}

	parent := ""
	for _, z := range all {
		if isSubdomainOf(zone, z.Zone) && len(z.Zone) > len(parent) {
			parent = z.Zone
		}
	}
	return parent, nil
}

// grantOwner makes `user` an owner of `zone`: storage row plus their own TSIG
// key. A no-op when they already own it, so callers may run it repeatedly.
func (app *AppData) grantOwner(ctx context.Context, user, zone string) error {
	already, err := app.Storage.IsZoneOwner(user, zone)
	if err != nil {
		return fmt.Errorf("app.grantOwner: %w", err)
	}
	if already {
		return nil
	}

	refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
	if _, err := app.Storage.CreateZone(user, zone, refreshTime); err != nil {
		return fmt.Errorf("app.grantOwner: %w", err)
	}
	if err := app.PowerDns.AddOwnerKey(ctx, zone, user); err != nil {
		return fmt.Errorf("app.grantOwner: %w", err)
	}
	return nil
}

// grantOwnerSubtree makes `user` an owner of every zone already delegated below
// `zone` (the zone itself is granted by the caller). Returns the subzones that
// were newly granted.
func (app *AppData) grantOwnerSubtree(ctx context.Context, user, zone string) ([]string, error) {
	subzones, err := app.subzonesOf(zone)
	if err != nil {
		return nil, err
	}

	granted := make([]string, 0, len(subzones))
	for _, sub := range subzones {
		already, err := app.Storage.IsZoneOwner(user, sub)
		if err != nil {
			return granted, fmt.Errorf("app.grantOwnerSubtree: %w", err)
		}
		if already {
			continue
		}
		if err := app.grantOwner(ctx, user, sub); err != nil {
			return granted, fmt.Errorf("app.grantOwnerSubtree: %w", err)
		}
		granted = append(granted, sub)
	}
	return granted, nil
}

// revokeOwnerSubtree removes `user` from every zone delegated below `zone`,
// mirroring grantOwnerSubtree: leaving a zone gives up what it delegates too.
// A subzone where they are the LAST owner is kept instead of revoked — dropping
// that row would leave a zone in PowerDNS that nobody can manage or delete.
func (app *AppData) revokeOwnerSubtree(ctx context.Context, user, zone string) (revoked, kept []string, err error) {
	subzones, err := app.subzonesOf(zone)
	if err != nil {
		return nil, nil, err
	}

	revoked, kept = make([]string, 0, len(subzones)), make([]string, 0)
	for _, sub := range subzones {
		isOwner, err := app.Storage.IsZoneOwner(user, sub)
		if err != nil {
			return revoked, kept, fmt.Errorf("app.revokeOwnerSubtree: %w", err)
		}
		if !isOwner {
			continue
		}

		count, err := app.Storage.CountZoneOwners(sub)
		if err != nil {
			return revoked, kept, fmt.Errorf("app.revokeOwnerSubtree: %w", err)
		}
		if count <= 1 {
			kept = append(kept, sub)
			continue
		}

		if err := app.Storage.DeleteZone(user, sub); err != nil {
			return revoked, kept, fmt.Errorf("app.revokeOwnerSubtree: %w", err)
		}
		if err := app.PowerDns.RemoveOwnerKey(ctx, sub, user); err != nil {
			return revoked, kept, fmt.Errorf("app.revokeOwnerSubtree: %w", err)
		}
		revoked = append(revoked, sub)
	}
	return revoked, kept, nil
}

// inheritOwnersFromParent gives every owner of the closest stored parent zone
// ownership of the freshly created `zone` — the create-side of the subtree rule,
// so a subzone created later is visible to the same people as its parent.
//
// Only applies when the parent's governing rule enables sharing: with sharing
// off a zone has a single owner, and a subzone created by another
// policy-entitled user must not pull that owner in.
func (app *AppData) inheritOwnersFromParent(ctx context.Context, zone, creator string) error {
	parent, err := app.closestStoredParent(zone)
	if err != nil {
		return err
	}
	if parent == "" {
		return nil
	}

	shareable, err := app.zoneSharingAllowed(parent)
	if err != nil {
		return fmt.Errorf("app.inheritOwnersFromParent: %w", err)
	}
	if !shareable {
		return nil
	}

	owners, err := app.Storage.ListZoneOwners(parent)
	if err != nil {
		return fmt.Errorf("app.inheritOwnersFromParent: %w", err)
	}
	for _, owner := range owners {
		if owner == creator {
			continue
		}
		if err := app.grantOwner(ctx, owner, zone); err != nil {
			return fmt.Errorf("app.inheritOwnersFromParent: %w", err)
		}
		app.Log.Infof("app.inheritOwnersFromParent: %s inherits '%s' from parent '%s'", owner, zone, parent)
	}
	return nil
}

// BackfillSubzoneOwners restores the subtree invariant for zones that were
// shared before it existed: every owner of a shareable zone becomes an owner of
// the zones already delegated below it. Runs once at startup and is idempotent —
// on consistent data it changes nothing and only walks the zone table.
func (app *AppData) BackfillSubzoneOwners(ctx context.Context) error {
	all, err := app.Storage.ListAllZones()
	if err != nil {
		return fmt.Errorf("app.BackfillSubzoneOwners: %w", err)
	}

	// Build the owner sets once: the table is walked here, not per zone, so the
	// pass stays a single query no matter how many zones exist.
	owners := make(map[string]map[string]bool, len(all))
	names := make([]string, 0, len(all))
	for _, z := range all {
		if owners[z.Zone] == nil {
			owners[z.Zone] = make(map[string]bool)
			names = append(names, z.Zone)
		}
		owners[z.Zone][z.Username] = true
	}

	granted := 0
	for _, zone := range names {
		// Only zones that actually have subzones can be inconsistent, and resolving
		// the governing rule is the expensive part — so filter before asking.
		subzones := make([]string, 0)
		for _, candidate := range names {
			if isSubdomainOf(candidate, zone) {
				subzones = append(subzones, candidate)
			}
		}
		if len(subzones) == 0 {
			continue
		}

		shareable, err := app.zoneSharingAllowed(zone)
		if err != nil {
			return fmt.Errorf("app.BackfillSubzoneOwners: %w", err)
		}
		if !shareable {
			continue
		}

		for owner := range owners[zone] {
			for _, sub := range subzones {
				if owners[sub][owner] {
					continue
				}
				if err := app.grantOwner(ctx, owner, sub); err != nil {
					return fmt.Errorf("app.BackfillSubzoneOwners: %w", err)
				}
				owners[sub][owner] = true
				granted++
				app.Log.Infof("app.BackfillSubzoneOwners: granted %s ownership of '%s' (shared parent '%s')", owner, sub, zone)
			}
		}
	}

	if granted > 0 {
		app.Log.Infof("app.BackfillSubzoneOwners: backfilled %d subzone ownership(s)", granted)
	} else {
		app.Log.Debug("app.BackfillSubzoneOwners: subzone ownership already consistent")
	}
	return nil
}

// subzoneDefViaOwnedParent returns the zone definition for creating `zone` when
// `user` owns a zone above it whose governing rule allows subdomains. This is
// the sharing path into subzone creation: a co-owner shared into a zone manages
// it, so they may delegate below it even without their own policy entitlement.
// Nil when no owned parent qualifies.
func (app *AppData) subzoneDefViaOwnedParent(zone, user string) (*ZoneResponse, error) {
	owned, err := app.Storage.ListUserZones(user)
	if err != nil {
		return nil, fmt.Errorf("app.subzoneDefViaOwnedParent: %w", err)
	}

	parent := ""
	for _, z := range owned {
		if isSubdomainOf(zone, z.Zone) && len(z.Zone) > len(parent) {
			parent = z.Zone
		}
	}
	if parent == "" {
		return nil, nil
	}

	def, err := app.zoneGoverningDef(parent)
	if err != nil {
		return nil, fmt.Errorf("app.subzoneDefViaOwnedParent: %w", err)
	}
	if def == nil || !def.AllowSubdomains {
		return nil, nil
	}
	return &ZoneResponse{Zone: zone, ZoneSOA: parent, AllowSubdomains: true, SharingAllowed: def.SharingAllowed}, nil
}
