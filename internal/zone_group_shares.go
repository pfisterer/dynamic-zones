package app

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/msg"
)

// Sharing a zone with a group (ZoneGroupShare) works through the same owner rows as sharing with a person, so every check that asks "does this person own the zone" — records, keys, the zone list, MCP, the RFC 2136 client — holds for group members without knowing about groups. The rows of a member carry the group in Zone.Via and are kept in step with the person's groups by syncGroupAccess:
//   - on the person's requests (groupAccessMiddleware, at most every groupSyncMinInterval), so access appears as soon as they open the portal or call the API, and
//   - for everybody holding such rows every groupSyncInterval (RunPeriodicGroupShareSync), so a person who left the group loses the zone and their key even if they never come back.
//
// A member manages the zone like its creator does in one respect the user asked for (24.11.2026): they may delete it (zoneAuthority.deletes). They share it further like every owner, with people or groups.
//
// When the group is gone or the person is no longer in it, the row and its key go — unless it is the zone's last row: a zone in PowerDNS nobody can manage would be worse than a stale row. Such a zone shows up as orphaned (zoneOrphanCheck) for the admins to decide.

const (
	// groupSyncMinInterval throttles the per-request sync of one person; the role provider's answer is cached for a minute anyway.
	groupSyncMinInterval = 30 * time.Second
	// groupSyncInterval is how often everybody with access through a group is checked against their groups.
	groupSyncInterval = 15 * time.Minute
)

// groupSyncState remembers when each person was last synced, for the throttle.
var groupSyncState = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

// validGroupSubject reports whether s is a group token a zone can be shared with: group:<id> or group:<id>#<relation>, in the shapes the rule filters accept.
func validGroupSubject(s string) bool {
	return strings.HasPrefix(s, tokenGroupPrefix) && validFilterEntry(s)
}

// addOwnerKey and removeOwnerKey are the PowerDNS side of an owner row. The storage-only unit tests run without PowerDNS (app.PowerDns nil); the container tests and every real deployment have it.
func (app *AppData) addOwnerKey(ctx context.Context, zone, user string) error {
	if app.PowerDns == nil {
		return nil
	}
	return app.PowerDns.AddOwnerKey(ctx, zone, user)
}

func (app *AppData) removeOwnerKey(ctx context.Context, zone, user string) error {
	if app.PowerDns == nil {
		return nil
	}
	return app.PowerDns.RemoveOwnerKey(ctx, zone, user)
}

// syncGroupAccess brings the group rows of `user` in line with the group shares and the person's groups: a row (and key) for every zone shared with a group they hold, and for every zone delegated below it; no group row where that no longer holds. Rows of their own (Via empty) are never touched. With the person's groups unknown (role provider unreachable, nothing cached) nothing is taken away.
func (app *AppData) syncGroupAccess(ctx context.Context, user string) error {
	user = strings.ToLower(strings.TrimSpace(user))
	if !strings.Contains(user, "@") {
		return nil
	}
	shares, err := app.Storage.ListAllGroupShares()
	if err != nil {
		return fmt.Errorf("app.syncGroupAccess: %w", err)
	}
	rows, err := app.Storage.ListUserZones(user)
	if err != nil {
		return fmt.Errorf("app.syncGroupAccess: %w", err)
	}
	hasGroupRows := false
	for _, r := range rows {
		if r.Via != "" {
			hasGroupRows = true
			break
		}
	}
	if len(shares) == 0 && !hasGroupRows {
		return nil
	}

	p := app.principalOf(user)
	// The zones the person should hold through a group, each with the first share that gives it.
	desired := map[string]string{}
	order := []string{}
	want := func(zone, subject string) {
		if _, ok := desired[zone]; !ok {
			desired[zone] = subject
			order = append(order, zone)
		}
	}
	for _, s := range shares {
		if _, ok := p.tokens[s.Subject]; !ok {
			continue
		}
		want(s.Zone, s.Subject)
		subs, err := app.subzonesOf(s.Zone)
		if err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		}
		for _, sub := range subs {
			want(sub, s.Subject)
		}
	}

	held := make(map[string]Zone, len(rows))
	for _, r := range rows {
		held[r.Zone] = r
	}
	for _, zone := range order {
		if _, ok := held[zone]; ok {
			continue
		}
		if exists, err := app.Storage.ZoneExists(zone); err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		} else if !exists {
			continue
		}
		if _, err := app.Storage.CreateZoneVia(user, zone, desired[zone]); err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		}
		if err := app.addOwnerKey(ctx, zone, user); err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		}
		app.Log.Infof("app.syncGroupAccess: %s owns %s through %s", user, zone, desired[zone])
	}

	if !p.known {
		return nil
	}
	for _, r := range rows {
		if r.Via == "" {
			continue
		}
		if _, ok := desired[r.Zone]; ok {
			continue
		}
		count, err := app.Storage.CountZoneOwners(r.Zone)
		if err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		}
		if count <= 1 {
			app.Log.Warnf("app.syncGroupAccess: %s is no longer in %s but the last owner of '%s'; the row stays, the zone is orphaned", user, r.Via, r.Zone)
			continue
		}
		if err := app.Storage.DeleteZone(user, r.Zone); err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		}
		if err := app.removeOwnerKey(ctx, r.Zone, user); err != nil {
			return fmt.Errorf("app.syncGroupAccess: %w", err)
		}
		app.Log.Infof("app.syncGroupAccess: %s no longer owns %s (was through %s)", user, r.Zone, r.Via)
	}
	return nil
}

// syncGroupAccessThrottled is syncGroupAccess at most every groupSyncMinInterval per person. Failures are logged; the request goes on with what the person holds.
func (app *AppData) syncGroupAccessThrottled(ctx context.Context, user string) {
	user = strings.ToLower(strings.TrimSpace(user))
	now := time.Now()
	groupSyncState.Lock()
	if last, ok := groupSyncState.last[user]; ok && now.Sub(last) < groupSyncMinInterval {
		groupSyncState.Unlock()
		return
	}
	groupSyncState.last[user] = now
	if len(groupSyncState.last) > 4096 {
		for k, t := range groupSyncState.last {
			if now.Sub(t) > groupSyncInterval {
				delete(groupSyncState.last, k)
			}
		}
	}
	groupSyncState.Unlock()
	if err := app.syncGroupAccess(ctx, user); err != nil {
		app.Log.Warnf("group access of %s not synced: %v", user, err)
	}
}

// groupAccessMiddleware syncs the caller's group rows before the request is handled (throttled).
func groupAccessMiddleware(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		if v, ok := c.Get(UserDataKey); ok {
			if user, ok := v.(*UserClaims); ok && user != nil {
				app.syncGroupAccessThrottled(c.Request.Context(), user.Identity())
			}
		}
		c.Next()
	}
}

// RunPeriodicGroupShareSync syncs everybody who holds a zone through a group every groupSyncInterval, the first time two minutes after startup.
func RunPeriodicGroupShareSync(app *AppData) {
	time.Sleep(2 * time.Minute)
	for {
		users, err := app.Storage.UsersWithGroupAccess()
		if err != nil {
			app.Log.Errorf("group-share-sync: %v", err)
		}
		for _, u := range users {
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			if err := app.syncGroupAccess(ctx, u); err != nil {
				app.Log.Warnf("group-share-sync: %s: %v", u, err)
			}
			cancel()
		}
		time.Sleep(groupSyncInterval)
	}
}

// ZoneAddGroupShare shares `zone` with the group token `subject`. Like adding a person: the caller must own the zone (or be a super admin) and its rule must allow sharing.
func (app *AppData) ZoneAddGroupShare(ctx context.Context, caller *UserClaims, zone, subject string) (int, any, error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	if !validGroupSubject(subject) {
		return errorResult(http.StatusBadRequest, msg.T("Ungültige Gruppe; erwartet wird group:<gruppe> oder group:<gruppe>#<rolle>.", "Invalid group; expected group:<group> or group:<group>#<role>."), fmt.Errorf("app.ZoneAddGroupShare: %q", subject))
	}
	if app.Roles == nil {
		return errorResult(http.StatusConflict, msg.T("Gruppen gibt es hier nicht (kein Gruppendienst eingerichtet).", "Groups are not available here (no group service configured)."), nil)
	}
	if status, body, err, ok := app.ownerForSharing(caller, zone); !ok {
		return status, body, err
	}
	if err := app.Storage.AddGroupShare(zone, subject, caller.Identity()); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Freigabe für die Gruppe ließ sich nicht speichern.", "The share with the group could not be saved."), err)
	}
	app.Log.Infof("app.ZoneAddGroupShare: %s shared %s with %s", caller.Identity(), zone, subject)
	if err := app.syncGroupAccess(ctx, caller.Identity()); err != nil {
		app.Log.Warnf("app.ZoneAddGroupShare: %v", err)
	}
	return app.ownersResult(zone)
}

// ZoneRemoveGroupShare ends the share of `zone` with `subject`: its members lose the zone (and the zones below it) unless they own it in their own right or through another share. Any owner may do it, as any owner may share.
func (app *AppData) ZoneRemoveGroupShare(ctx context.Context, caller *UserClaims, zone, subject string) (int, any, error) {
	subject = strings.ToLower(strings.TrimSpace(subject))
	authority, err := app.zoneAuthorityOf(caller, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	}
	if !authority.owner && !authority.superAdmin {
		return errorResult(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), nil)
	}
	removed, err := app.Storage.RemoveGroupShare(zone, subject)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Freigabe für die Gruppe ließ sich nicht entfernen.", "The share with the group could not be removed."), err)
	}
	if !removed {
		return errorResult(http.StatusNotFound, msg.T("Die Zone ist nicht mit dieser Gruppe geteilt.", "The zone is not shared with this group."), nil)
	}
	// Everybody holding the zone or a zone below it through this group, now.
	affected := map[string]bool{}
	zones := []string{zone}
	if subs, err := app.subzonesOf(zone); err == nil {
		zones = append(zones, subs...)
	}
	for _, z := range zones {
		rows, err := app.Storage.ListZoneOwnerRows(z)
		if err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer ließen sich nicht laden.", "The owners could not be loaded."), err)
		}
		for _, r := range rows {
			if r.Via == subject {
				affected[r.Username] = true
			}
		}
	}
	for u := range affected {
		if err := app.syncGroupAccess(ctx, u); err != nil {
			app.Log.Warnf("app.ZoneRemoveGroupShare: %v", err)
		}
	}
	app.Log.Infof("app.ZoneRemoveGroupShare: %s removed the share of %s with %s (%d member(s) synced)", caller.Identity(), zone, subject, len(affected))
	return app.ownersResult(zone)
}

// ownerForSharing checks what sharing needs: the caller owns the zone (or is a super admin), the zone exists and its rule allows sharing.
func (app *AppData) ownerForSharing(caller *UserClaims, zone string) (int, any, error, bool) {
	authority, err := app.zoneAuthorityOf(caller, zone)
	if err != nil {
		s, b, e := errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
		return s, b, e, false
	}
	if !authority.owner && !authority.superAdmin {
		s, b, e := errorResult(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), nil)
		return s, b, e, false
	}
	if exists, err := app.Storage.ZoneExists(zone); err != nil {
		s, b, e := errorResult(http.StatusInternalServerError, msg.T("Ob es die Zone gibt, ließ sich nicht prüfen.", "Whether the zone exists could not be checked."), err)
		return s, b, e, false
	} else if !exists {
		s, b, e := errorResult(http.StatusNotFound, msg.T("Die Zone gibt es nicht.", "The zone does not exist."), nil)
		return s, b, e, false
	}
	shareable, err := app.zoneSharingAllowed(zone)
	if err != nil {
		s, b, e := errorResult(http.StatusInternalServerError, msg.T("Ob die Zone geteilt werden darf, ließ sich nicht prüfen.", "Whether the zone may be shared could not be checked."), err)
		return s, b, e, false
	}
	if !shareable {
		s, b, e := errorResult(http.StatusForbidden, msg.T("Teilen ist für diese Zone nicht eingeschaltet.", "Sharing is not switched on for this zone."), nil)
		return s, b, e, false
	}
	return 0, nil, nil, true
}

// zoneSharing is what the owner answers carry about groups: the groups the zone is shared with, and which owners hold it through which group.
func (app *AppData) zoneSharing(zone string) (groups []string, via map[string]string, err error) {
	shares, err := app.Storage.ListGroupShares(zone)
	if err != nil {
		return nil, nil, err
	}
	groups = make([]string, 0, len(shares))
	for _, s := range shares {
		groups = append(groups, s.Subject)
	}
	rows, err := app.Storage.ListZoneOwnerRows(zone)
	if err != nil {
		return nil, nil, err
	}
	via = map[string]string{}
	for _, r := range rows {
		if r.Via != "" {
			via[r.Username] = r.Via
		}
	}
	return groups, via, nil
}
