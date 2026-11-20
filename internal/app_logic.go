package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"regexp"
	"strings"
	"text/template"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/apierr"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/msg"
	"github.com/pfisterer/dynamic-zones/internal/helper"
	"gorm.io/gorm"
)

const AppLogicKey = "AppLogicKey"

func InjectAppLogic(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(AppLogicKey, app)
	}
}

// PolicyRuleRequest is used for create/update operations.
type PolicyRuleRequest struct {
	// ZonePattern is the zone the rule grants. %u stands for the user's e-mail address made DNS-compliant (dennis@dhbw.de → dennis-at-dhbw-de.users.dhbw.site for %u.users.dhbw.site), %l for its local part only (s252690@student.dhbw-mannheim.de → s252690-stma.users.dhbw.site for %l-stma.users.dhbw.site). Two people whose %l is the same compete for one name: whoever creates it first owns it.
	ZonePattern string `json:"zone_pattern" binding:"required"`
	ZoneSoa     string `json:"zone_soa" binding:"required"`
	// TargetUserFilter is a comma-separated list of e-mail addresses, patterns with one '*' such as *@dhbw.de, and role-provider tokens user:<email>, group:<id> and group:<id>#<relation>; the rule applies to whoever matches any entry.
	TargetUserFilter string `json:"target_user_filter" binding:"required"`
	AllowSubdomains  bool   `json:"allow_subdomains"`
	SharingAllowed   bool   `json:"sharing_allowed"`
	// Deprecated: existing zones of the rule keep working, but it offers no new zones (see PolicyRule.Deprecated).
	Deprecated  bool   `json:"deprecated"`
	Description string `json:"description"`
}

// PolicyRulesResponse wraps policy rules for list endpoint.
type PolicyRulesResponse struct {
	EditAllowed bool `json:"edit_allowed"`
	// IsSuperAdmin distinguishes full admins (who may also manage delegations)
	// from delegated users (who can edit in-scope rules but not delegations).
	IsSuperAdmin bool         `json:"is_super_admin"`
	Rules        []PolicyRule `json:"rules"`
}

func (app *AppData) PolicyGetAllUserRules(user *UserClaims) (*PolicyRulesResponse, error) {
	// Get all rules from storage
	rules, err := app.Storage.PolicyGetAll()
	if err != nil {
		app.Log.Errorf("Error retrieving policy rules: %v", err)
		return nil, err
	}

	// Super-admins see and can edit every rule.
	if isSuperAdmin(app, user) {
		return &PolicyRulesResponse{Rules: rules, EditAllowed: true, IsSuperAdmin: true}, nil
	}

	// Delegated users: show (and allow editing of) the rules whose ZoneSoa falls
	// within one of the delegations granted to them.
	delegations, err := app.Storage.DelegationGetAll()
	if err != nil {
		app.Log.Errorf("Error retrieving delegations: %v", err)
		return nil, err
	}
	p := app.principalOf(user.Identity())
	var userDelegations []DelegationPolicy
	for _, d := range delegations {
		if matchFilter(p, d.TargetUserFilter).match {
			userDelegations = append(userDelegations, d)
		}
	}
	if len(userDelegations) > 0 {
		inScope := make([]PolicyRule, 0)
		for _, r := range rules {
			for _, d := range userDelegations {
				if zoneInScope(r.ZoneSoa, d.ZoneSuffix) {
					inScope = append(inScope, r)
					break
				}
			}
		}
		return &PolicyRulesResponse{Rules: inScope, EditAllowed: true}, nil
	}

	// Plain users: read-only view of the rules that grant them zones.
	return &PolicyRulesResponse{Rules: filterUserRules(rules, p, false), EditAllowed: false}, nil
}

// PolicyGetUserZones is what the rules grant the user (offers): a group entry counts only when the user's tokens are known to contain it.
func (app *AppData) PolicyGetUserZones(user *UserClaims) ([]ZoneResponse, error) {
	return app.policyZonesOf(app.principalOf(user.Identity()), false)
}

// policyZonesOf is the zones the rules grant a person. optimistic counts a group entry that cannot be checked (role provider unreachable, the person's tokens unknown) as matching — only for questions about zones that exist already (are they still covered?), never for granting a new one.
func (app *AppData) policyZonesOf(p principal, optimistic bool) ([]ZoneResponse, error) {
	rules, err := app.Storage.PolicyGetAll()
	if err != nil {
		app.Log.Errorf("Error retrieving policy rules: %v", err)
		return nil, err
	}
	// The names are derived collision-free (personalZoneName); the first error the storage reports ends the lookup.
	var lookupErr error
	zones := rulesToUserZonesWith(filterUserRules(rules, p, optimistic), p.email, func(pattern, identity string) (string, bool) {
		if lookupErr != nil {
			return "", false
		}
		zone, ok, err := app.personalZoneName(pattern, identity)
		if err != nil {
			lookupErr = err
		}
		return zone, ok
	})
	if lookupErr != nil {
		app.Log.Errorf("Error deriving personal zone names: %v", lookupErr)
		return nil, lookupErr
	}
	return zones, nil
}

// PolicyIsZoneAllowedForUser decides whether the rules grant the zone to the user, for creating or joining it: strict, so a group entry counts only when the user's tokens are known.
func (app *AppData) PolicyIsZoneAllowedForUser(zone string, user *UserClaims) (bool, *ZoneResponse, error) {
	return app.policyZoneAllowed(zone, app.principalOf(user.Identity()), false)
}

// policyZoneCovered asks the same for a zone that exists, on behalf of its owner (orphan detection, the governing rule of a shared zone): an unknown group entry counts as covering it, so an unreachable role provider never orphans a zone or changes its flags. Logged when that made the difference.
func (app *AppData) policyZoneCovered(zone, owner string) (bool, *ZoneResponse, error) {
	p := app.principalOf(owner)
	allowed, def, err := app.policyZoneAllowed(zone, p, true)
	if err == nil && allowed && !p.known {
		if strict, _, _ := app.policyZoneAllowed(zone, p, false); !strict {
			app.Log.Warnw("zone counted as covered because its owner's group tokens are unknown (role provider unreachable)", "zone", zone, "owner", owner)
		}
	}
	return allowed, def, err
}

func (app *AppData) policyZoneAllowed(zone string, p principal, optimistic bool) (bool, *ZoneResponse, error) {
	user := &UserClaims{Email: p.email}
	zones, err := app.policyZonesOf(p, optimistic)
	if err != nil {
		app.Log.Errorf("Error getting user zones: %v", err)
		return false, nil, err
	}

	// Exact match: the requested zone is one of the user's base zones.
	for i := range zones {
		if zones[i].Zone == zone {
			app.Log.Debugf("User %s is allowed to use zone %s", user.Identity(), zone)
			return true, &zones[i], nil
		}
	}

	// Subzone match: the requested zone is a subdomain of a base zone whose rule
	// allows subdomains. Pick the most specific (longest) matching parent so the
	// subzone is delegated under the closest owned zone.
	var bestParent *ZoneResponse
	for i := range zones {
		if zones[i].AllowSubdomains && isSubdomainOf(zone, zones[i].Zone) {
			if bestParent == nil || len(zones[i].Zone) > len(bestParent.Zone) {
				bestParent = &zones[i]
			}
		}
	}
	if bestParent != nil {
		app.Log.Debugf("User %s is allowed to use subzone %s under %s", user.Identity(), zone, bestParent.Zone)
		// Delegate the subzone under its parent (ZoneSOA = parent zone); the
		// subzone inherits the parent's sharing setting.
		return true, &ZoneResponse{Zone: zone, ZoneSOA: bestParent.Zone, AllowSubdomains: true, SharingAllowed: bestParent.SharingAllowed, Subzone: true}, nil
	}

	app.Log.Debugf("User %s is not allowed to use zone %s", user.Identity(), zone)
	return false, nil, nil
}

// msgGroupsUnavailable is the answer when a zone could only be granted through a group entry and the person's groups cannot be looked up right now.
var msgGroupsUnavailable = msg.T("Die Gruppenzugehörigkeit lässt sich gerade nicht prüfen, weil der Gruppendienst nicht erreichbar ist. Zonen, die eine Regel über Gruppen vergibt, lassen sich deshalb im Moment nicht anlegen oder beitreten; bitte später erneut versuchen. Bestehende Zonen funktionieren weiter.", "Group membership cannot be checked right now because the group service is unreachable. Zones that a rule grants through groups can therefore not be created or joined at the moment; please try again later. Existing zones keep working.")

// refusedForUnknownGroups reports whether the rules refuse the zone to the user only because their group tokens are unknown: with the unknown group entries counted as matching, a rule would grant it.
func (app *AppData) refusedForUnknownGroups(zone string, user *UserClaims) bool {
	p := app.principalOf(user.Identity())
	if p.known {
		return false
	}
	allowed, _, err := app.policyZoneAllowed(zone, p, true)
	return err == nil && allowed
}

// isSubdomainOf reports whether child is a strict subdomain of parent
// (e.g. "sub.example.com" is a subdomain of "example.com"). Case and trailing
// dots are normalized.
func isSubdomainOf(child, parent string) bool {
	c := strings.ToLower(strings.TrimSuffix(child, "."))
	p := strings.ToLower(strings.TrimSuffix(parent, "."))
	return c != p && strings.HasSuffix(c, "."+p)
}

func (app *AppData) PolicyCreateRule(req PolicyRuleRequest) (*PolicyRule, error) {
	err := policyValidateRequest(req)
	if err != nil {
		app.Log.Errorf("Invalid policy rule request: %v", err)
		return nil, statusErr(http.StatusBadRequest, msg.TextOf(err), nil)
	}

	// Create and store the new rule
	newRule := PolicyRule{
		ZonePattern:      req.ZonePattern,
		ZoneSoa:          req.ZoneSoa,
		TargetUserFilter: req.TargetUserFilter,
		AllowSubdomains:  req.AllowSubdomains,
		SharingAllowed:   req.SharingAllowed,
		Deprecated:       req.Deprecated,
		Description:      req.Description,
	}

	app.Log.Infof("Storing new policy rule: %+v", newRule)
	createdRule, err := app.Storage.PolicyCreate(&newRule)
	if err != nil {
		app.Log.Errorf("Error storing policy rule: %v", err)
		return nil, err
	}

	return createdRule, nil
}

func (app *AppData) PolicyUpdateRule(id int64, req PolicyRuleRequest) (*PolicyRule, error) {
	err := policyValidateRequest(req)
	if err != nil {
		app.Log.Errorf("Invalid policy rule request: %v", err)
		return nil, statusErr(http.StatusBadRequest, msg.TextOf(err), nil)
	}

	// Check if rule exists before update attempt
	existingRule, err := app.Storage.PolicyGetByID(id)
	if err != nil {
		app.Log.Errorf("Error retrieving existing policy rule #%d: %v", id, err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errRuleNotFound
		} else {
			return nil, fmt.Errorf("failed to retrieve rule: %w", err)
		}
	}

	// Update the fields on the existing rule object
	existingRule.ZonePattern = req.ZonePattern
	existingRule.ZoneSoa = req.ZoneSoa
	existingRule.TargetUserFilter = req.TargetUserFilter
	existingRule.AllowSubdomains = req.AllowSubdomains
	existingRule.SharingAllowed = req.SharingAllowed
	existingRule.Deprecated = req.Deprecated
	existingRule.Description = req.Description

	app.Log.Infof("Updating policy rule #%d to: %+v", id, existingRule)
	updatedRule, err := app.Storage.PolicyUpdate(existingRule)
	if err != nil {
		app.Log.Errorf("Error updating policy rule #%d: %v", id, err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, errRuleNotFound
		}
		return nil, fmt.Errorf("failed to update rule: %w", err)
	}

	return updatedRule, nil
}

func (app *AppData) PolicyDeleteRule(id int64) error {
	app.Log.Debugf("Deleting policy rule #%d", id)

	if err := app.Storage.PolicyDelete(id); err != nil {
		app.Log.Errorf("Error deleting policy rule #%d: %v", id, err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return errRuleNotFound
		}
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	return nil
}

// ZoneGet returns a zone (with the caller's own TSIG key + the current owner
// list). Access = the caller is an owner OR is policy-entitled to this exact
// zone and the governing rule has sharing enabled — in which case the caller
// auto-joins as a co-owner (own row + own TSIG key created lazily here).
//
// readOnly is the caller's credential: a read-only API token gets the zone without its TSIG key and without the external-dns values (which embed the key). The key may write the zone, so handing it to a token that may only read would make "read-only" a formality.
func (app *AppData) ZoneGet(ctx context.Context, user *UserClaims, zone, externalDnsVersion string, readOnly bool) (int, any, error) {
	username := user.Identity()

	// The zone must have been created by someone.
	exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Ob es die Zone gibt, ließ sich nicht prüfen.", "Whether the zone exists could not be checked."), fmt.Errorf("app.getZone: %w", err))
	}
	if !exists {
		return errorResult(http.StatusNotFound, msg.T("Die Zone gibt es nicht.", "The zone does not exist."), fmt.Errorf("app.getZone: zone %s not found", zone))
	}

	// Access requires being an owner. Policy-entitled users of a shareable zone
	// must first JOIN it explicitly (POST /zones/:zone/join) — no implicit
	// self-join on read.
	isOwner, err := app.Storage.IsZoneOwner(username, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), fmt.Errorf("app.getZone: %w", err))
	}
	if !isOwner {
		return errorResult(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), fmt.Errorf("app.getZone: %s not owned by %s", zone, username))
	}

	// Get from PowerDNS — scoped to the caller's own key only.
	pdnsZone, err := app.PowerDns.GetZone(ctx, zone, username)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Zone ließ sich nicht vom DNS-Server lesen.", "The zone could not be read from the DNS server."), fmt.Errorf("app.getZone: %w", err))
	}

	// Generate external-dns config (it carries the key, so not for a read-only token)
	valuesYaml := ""
	if readOnly {
		pdnsZone.ZoneKeys = []ZoneKey{}
	} else {
		valuesYaml, err = toExternalDNSConfig(app, pdnsZone, externalDnsVersion)
		if err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Die external-dns-Konfiguration ließ sich nicht erzeugen.", "The external-dns configuration could not be generated."), fmt.Errorf("app.getZone: %w", err))
		}
	}

	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer ließen sich nicht laden.", "The owners could not be loaded."), fmt.Errorf("app.getZone: %w", err))
	}
	creator, err := app.Storage.ZoneCreator(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Wer die Zone angelegt hat, ließ sich nicht ermitteln.", "Who created the zone could not be determined."), fmt.Errorf("app.getZone: %w", err))
	}

	sharingAllowed, err := app.zoneSharingAllowed(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Ob die Zone geteilt werden darf, ließ sich nicht prüfen.", "Whether the zone may be shared could not be checked."), fmt.Errorf("app.getZone: %w", err))
	}

	// Return zone data
	app.Log.Infof("app.getZone: returning zone %s", zone)

	body := gin.H{
		"zoneData":        pdnsZone,
		"owners":          owners,
		"creator":         creator,
		"sharing_allowed": sharingAllowed,
	}
	if !readOnly {
		body["externalDnsValuesYaml"] = valuesYaml
	}
	return http.StatusOK, body, nil
}

func (app *AppData) ZoneDelete(ctx context.Context, username, zone string) (int, any, error) {
	// Refuse to delete a zone that still has delegated subzones under it — the
	// user must delete the subzones first. Every stored subzone counts, not only
	// the caller's: deleting the parent cuts the delegation of all of them.
	subzones, err := app.subzonesOf(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Subzonen ließen sich nicht laden.", "The subzones could not be loaded."), fmt.Errorf("app.ZoneDelete: %w", err))
	}
	if len(subzones) > 0 {
		return errorResult(http.StatusConflict, msg.T("Die Zone hat noch Subzonen. Erst diese löschen.", "The zone still has subzones. Delete them first."),
			fmt.Errorf("app.ZoneDelete: %s still has subzone %s", zone, subzones[0]))
	}

	if err := app.PowerDns.DeleteZone(ctx, zone, true); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Zone ließ sich nicht vom DNS-Server löschen.", "The zone could not be deleted from the DNS server."),
			fmt.Errorf("app.ZoneDelete: %w", err))
	}

	// Deleting the zone removes it for ALL owners (their per-owner keys are gone
	// with the pdns zone above), so drop every owner row, not just the caller's.
	if err := app.Storage.DeleteAllZoneOwners(zone); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Zone ließ sich nicht aus der Datenbank löschen.", "The zone could not be deleted from the database."),
			fmt.Errorf("app.ZoneDelete: %w", err))
	}

	app.Log.Infof("app.ZoneDelete: %s deleted for user %s", zone, username)
	return http.StatusNoContent, nil, nil
}

// ZoneJoin makes the caller a co-owner of an existing shareable zone (own row +
// own TSIG key). Requires the zone to exist, the caller to be policy-entitled to
// it, and sharing to be enabled. Idempotent for existing owners.
func (app *AppData) ZoneJoin(ctx context.Context, user *UserClaims, zone string) (int, any, error) {
	username := user.Identity()

	exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Ob es die Zone gibt, ließ sich nicht prüfen.", "Whether the zone exists could not be checked."), err)
	}
	if !exists {
		return errorResult(http.StatusNotFound, msg.T("Die Zone gibt es nicht.", "The zone does not exist."), nil)
	}

	if isOwner, err := app.Storage.IsZoneOwner(username, zone); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	} else if isOwner {
		return app.ownersResult(zone) // already a member
	}

	allowed, zoneDef, err := app.PolicyIsZoneAllowedForUser(zone, user)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Regeln ließen sich nicht auswerten.", "The rules could not be evaluated."), err)
	}
	if !allowed && app.refusedForUnknownGroups(zone, user) {
		return errorResult(http.StatusServiceUnavailable, msgGroupsUnavailable, fmt.Errorf("app.ZoneJoin: group tokens of %q unknown", username))
	}
	if !allowed || zoneDef == nil || !zoneDef.SharingAllowed {
		return errorResult(http.StatusForbidden, msg.T("Keine Berechtigung, dieser Zone beizutreten.", "No permission to join this zone."), nil)
	}
	// Joining through the policy is a new zone for this user; a deprecated rule hands out none. Owners can still add co-owners (ZoneAddOwner).
	if zoneDef.Deprecated {
		return errorResult(http.StatusForbidden, msg.T("Die Regel dieser Zone ist veraltet; beitreten lässt sich nicht mehr. Die bisherigen Eigentümer können weitere Eigentümer hinzufügen.", "The rule of this zone is deprecated; it can no longer be joined. Its current owners can add further owners."), nil)
	}

	if _, err := app.Storage.CreateZone(username, zone, false); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Beitritt zur Zone ist fehlgeschlagen.", "Joining the zone failed."), err)
	}
	if err := app.PowerDns.AddOwnerKey(ctx, zone, username); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Schlüssel für die Zone ließ sich nicht anlegen.", "The key for the zone could not be created."), err)
	}

	// Sharing covers the subtree: take over the zones already delegated below.
	subzones, err := app.grantOwnerSubtree(ctx, username, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Zugriff auf die Subzonen ließ sich nicht einrichten.", "Access to the subzones could not be set up."), err)
	}
	app.Log.Infof("app.ZoneJoin: %s joined shared zone %s (%d subzone(s))", username, zone, len(subzones))

	return app.ownersResult(zone)
}

// ownersResult is the answer of every call that changes or lists a zone's owners: who owns it, and which of them created it (the one who may delete it and remove the others).
func (app *AppData) ownersResult(zone string) (int, any, error) {
	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer ließen sich nicht laden.", "The owners could not be loaded."), err)
	}
	creator, err := app.Storage.ZoneCreator(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Wer die Zone angelegt hat, ließ sich nicht ermitteln.", "Who created the zone could not be determined."), err)
	}
	return http.StatusOK, gin.H{"owners": owners, "creator": creator}, nil
}

// zoneAuthority is what the caller may do with a zone: whether they own it, whether they created it, and whether they are a super admin (who may do what a creator may, on any zone).
type zoneAuthority struct {
	owner, creator, superAdmin bool
}

// manages reports whether the caller may act on the zone as a whole — delete it, remove other owners, rotate everybody's keys.
func (a zoneAuthority) manages() bool { return a.creator || a.superAdmin }

func (app *AppData) zoneAuthorityOf(user *UserClaims, zone string) (zoneAuthority, error) {
	owner, err := app.Storage.IsZoneOwner(user.Identity(), zone)
	if err != nil {
		return zoneAuthority{}, err
	}
	creator, err := app.Storage.IsZoneCreator(user.Identity(), zone)
	if err != nil {
		return zoneAuthority{}, err
	}
	return zoneAuthority{owner: owner, creator: creator, superAdmin: isSuperAdmin(app, user)}, nil
}

// zoneGoverningDef returns the policy ZoneResponse (sharing / subdomain flags)
// that governs `zone`, resolved via any current owner that is policy-entitled
// (the creator is). Nil if no owner is policy-entitled anymore (e.g. the rule was
// removed) — used to fill flags for zones a user holds via sharing, not policy.
func (app *AppData) zoneGoverningDef(zone string) (*ZoneResponse, error) {
	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return nil, err
	}
	for _, o := range owners {
		allowed, def, err := app.policyZoneCovered(zone, o)
		if err != nil {
			return nil, err
		}
		if allowed && def != nil {
			return def, nil
		}
	}
	return nil, nil
}

// zoneSharingAllowed reports whether a zone may be shared — true iff its governing
// rule has sharing enabled.
func (app *AppData) zoneSharingAllowed(zone string) (bool, error) {
	def, err := app.zoneGoverningDef(zone)
	if err != nil {
		return false, err
	}
	return def != nil && def.SharingAllowed, nil
}

// ZoneAddOwner adds `newOwner` as a co-owner of `zone` (own row + own TSIG key).
// The caller must already be an owner and the zone must be shareable.
func (app *AppData) ZoneAddOwner(ctx context.Context, caller *UserClaims, zone, newOwner string) (int, any, error) {
	newOwner = strings.ToLower(strings.TrimSpace(newOwner))
	if _, err := mail.ParseAddress(newOwner); err != nil {
		return errorResult(http.StatusBadRequest, msg.T("Ungültige E-Mail-Adresse des Eigentümers.", "Invalid e-mail address of the owner."), fmt.Errorf("app.ZoneAddOwner: %w", err))
	}

	isOwner, err := app.Storage.IsZoneOwner(caller.Identity(), zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	}
	if !isOwner {
		return errorResult(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), nil)
	}

	shareable, err := app.zoneSharingAllowed(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Ob die Zone geteilt werden darf, ließ sich nicht prüfen.", "Whether the zone may be shared could not be checked."), err)
	}
	if !shareable {
		return errorResult(http.StatusForbidden, msg.T("Teilen ist für diese Zone nicht eingeschaltet.", "Sharing is not switched on for this zone."), nil)
	}

	if already, err := app.Storage.IsZoneOwner(newOwner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	} else if !already {
		if _, err := app.Storage.CreateZone(newOwner, zone, false); err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Der Eigentümer ließ sich nicht hinzufügen.", "The owner could not be added."), err)
		}
		if err := app.PowerDns.AddOwnerKey(ctx, zone, newOwner); err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Der Schlüssel des Eigentümers ließ sich nicht anlegen.", "The owner's key could not be created."), err)
		}
		app.Log.Infof("app.ZoneAddOwner: %s added %s as owner of %s", caller.Identity(), newOwner, zone)
	}

	// Unconditional (not only for a fresh owner): sharing covers the subtree, so
	// this also repairs an owner who predates a subzone.
	subzones, err := app.grantOwnerSubtree(ctx, newOwner, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Zugriff auf die Subzonen ließ sich nicht einrichten.", "Access to the subzones could not be set up."), err)
	}
	for _, sub := range subzones {
		app.Log.Infof("app.ZoneAddOwner: %s also owns subzone %s", newOwner, sub)
	}

	return app.ownersResult(zone)
}

// ZoneRemoveOwner removes an owner (row + their TSIG key, revoking access at
// once). Removing SOMEONE ELSE is for the zone's creator (or a super admin); any
// other owner may only remove themself, i.e. leave. The creator cannot leave —
// their zone is deleted, not abandoned — and the last owner cannot be removed.
func (app *AppData) ZoneRemoveOwner(ctx context.Context, caller *UserClaims, zone, owner string) (int, any, error) {
	owner = strings.ToLower(strings.TrimSpace(owner))
	self := strings.EqualFold(owner, caller.Identity())

	authority, err := app.zoneAuthorityOf(caller, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	}
	if !authority.owner && !authority.superAdmin {
		return errorResult(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), nil)
	}
	if !self && !authority.manages() {
		return errorResult(http.StatusForbidden, msg.T("Andere Eigentümer entfernen kann nur, wer die Zone angelegt hat; das eigene Konto lässt sich aber entfernen.", "Only whoever created the zone can remove other owners; your own account can be removed, though."), nil)
	}

	if targetIsOwner, err := app.Storage.IsZoneOwner(owner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	} else if !targetIsOwner {
		return errorResult(http.StatusNotFound, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), nil)
	}

	// The creator leaving would hand the zone to whoever joined first, without either of them deciding that. A super admin may still remove them (the next owner then becomes the creator, see Storage.DeleteZone).
	if targetIsCreator, err := app.Storage.IsZoneCreator(owner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Wer die Zone angelegt hat, ließ sich nicht prüfen.", "Who created the zone could not be checked."), err)
	} else if targetIsCreator && !authority.superAdmin {
		return errorResult(http.StatusConflict, msg.T("Wer die Zone angelegt hat, kann sie nicht verlassen, sondern nur löschen.", "Whoever created the zone cannot leave it, only delete it."), nil)
	}

	count, err := app.Storage.CountZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer ließen sich nicht zählen.", "The owners could not be counted."), err)
	}
	if count <= 1 {
		return errorResult(http.StatusConflict, msg.T("Der letzte Eigentümer lässt sich nicht entfernen; stattdessen die Zone löschen.", "The last owner cannot be removed; delete the zone instead."), nil)
	}

	if err := app.Storage.DeleteZone(owner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Eigentümer ließ sich nicht entfernen.", "The owner could not be removed."), err)
	}
	if err := app.PowerDns.RemoveOwnerKey(ctx, zone, owner); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Schlüssel des Eigentümers ließ sich nicht löschen.", "The owner's key could not be deleted."), err)
	}

	// Symmetric to joining: giving up a zone gives up what it delegates. Subzones
	// where they are the last owner are kept — see revokeOwnerSubtree.
	revoked, kept, err := app.revokeOwnerSubtree(ctx, owner, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Der Zugriff auf die Subzonen ließ sich nicht entziehen.", "Access to the subzones could not be revoked."), err)
	}
	app.Log.Infof("app.ZoneRemoveOwner: %s removed %s from %s (%d subzone(s) revoked)", caller.Identity(), owner, zone, len(revoked))
	for _, sub := range kept {
		app.Log.Warnf("app.ZoneRemoveOwner: %s stays the only owner of subzone '%s' — removing them would orphan it", owner, sub)
	}

	return app.ownersResult(zone)
}

// ZoneRotateKeys regenerates TSIG keys of `zone` (e.g. after a suspected key
// compromise). The creator (or a super admin) rotates every owner's key, and
// every owner must re-fetch theirs afterwards; any other owner rotates only
// their own — a co-owner must not be able to cut everybody else's external-dns
// off.
func (app *AppData) ZoneRotateKeys(ctx context.Context, caller *UserClaims, zone string) (int, any, error) {
	authority, err := app.zoneAuthorityOf(caller, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	}
	if !authority.owner && !authority.superAdmin {
		return errorResult(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), nil)
	}

	owners := []string{caller.Identity()}
	if authority.manages() {
		if owners, err = app.Storage.ListZoneOwners(zone); err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer ließen sich nicht laden.", "The owners could not be loaded."), err)
		}
		if len(owners) == 0 {
			return errorResult(http.StatusNotFound, msg.T("Die Zone gibt es nicht.", "The zone does not exist."), nil)
		}
	}
	if err := app.PowerDns.RotateZoneKeys(ctx, zone, owners); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Schlüssel ließen sich nicht erneuern.", "The keys could not be renewed."), err)
	}
	app.Log.Infof("app.ZoneRotateKeys: %s rotated %d key(s) for %s", caller.Identity(), len(owners), zone)
	return http.StatusOK, gin.H{"rotated": len(owners)}, nil
}

// OrphanedZone is a stored zone that is no longer covered by any policy rule for its creator (e.g. because the policy was later deleted or changed). User is the creator.
type OrphanedZone struct {
	Zone string `json:"zone"`
	User string `json:"user"`
}

// zoneOrphanCheck decides whether `zone` is orphaned and names the owner it was judged by. A zone belongs to its creator: co-owners got it by sharing or joining under the creator's rule, so whether a rule covers them themselves does not matter — a shared zone is orphaned only when no rule covers its creator anymore. A zone without a creator row (should not happen, see backfillZoneCreators) is judged by its first owner row. An owner whose group tokens are unknown (role provider unreachable, nothing cached) counts as covered.
func (app *AppData) zoneOrphanCheck(zone string, owners []string) (bool, string, error) {
	creator, err := app.Storage.ZoneCreator(zone)
	if err != nil {
		return false, "", err
	}
	if creator == "" {
		if len(owners) == 0 {
			return false, "", nil
		}
		creator = owners[0]
	}
	covered, _, err := app.policyZoneCovered(zone, creator)
	if err != nil {
		return false, "", err
	}
	return !covered, creator, nil
}

// OrphanedZones returns every stored zone that no current policy would grant to its creator anymore, once per zone.
func (app *AppData) OrphanedZones() ([]OrphanedZone, error) {
	rows, err := app.Storage.ListAllZones()
	if err != nil {
		return nil, err
	}
	owners := map[string][]string{}
	order := []string{}
	for _, z := range rows {
		if _, seen := owners[z.Zone]; !seen {
			order = append(order, z.Zone)
		}
		owners[z.Zone] = append(owners[z.Zone], z.Username)
	}
	orphaned := make([]OrphanedZone, 0)
	for _, zone := range order {
		isOrphan, creator, err := app.zoneOrphanCheck(zone, owners[zone])
		if err != nil {
			return nil, err
		}
		if isOrphan {
			orphaned = append(orphaned, OrphanedZone{Zone: zone, User: creator})
		}
	}
	return orphaned, nil
}

// ZoneIsOrphaned reports whether `zone` is orphaned in the sense of OrphanedZones, and its creator.
func (app *AppData) ZoneIsOrphaned(zone string) (bool, string, error) {
	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return false, "", err
	}
	return app.zoneOrphanCheck(zone, owners)
}

// maxIntermediateZones caps how many zones that do not exist yet one subzone request may create between the zone it delegates from and the zone it asks for. Each of them is an ownerless zone in PowerDNS that nobody can see, manage or delete through this API, so "a.b.c.d.e.mine.example.com" must not mint four of them as a side effect. Zones granted by a rule of their own are not capped: their depth is what the rule's author wrote.
const maxIntermediateZones = 2

// ZoneCreate creates `zone` for `user`, together with the delegation chain above it.
//
// The chain is written into zones that already exist — the delegation of a new zone is an NS record in its parent — so it matters who decided that this name may be delegated:
//   - A zone granted by a policy rule of its own (zone.Subzone false) was authorised by whoever wrote that rule: a super admin, or a delegate for its SOA. Writing its delegation into the parent is what the rule means, also when the parent is somebody else's stored zone (e.g. petko.proj.dhbw.site below clemens' proj.dhbw.site).
//   - A subzone reached only through allow_subdomains (zone.Subzone true) was authorised by nobody but the caller. It must be created below a stored zone the caller owns (the closest stored ancestor, or the caller is a super admin), it must not run into a name a rule reserves for someone else or a policy SOA, and it may add at most maxIntermediateZones new levels. That path is the one that let Bob write www.lab.example.com into Alice's lab.example.com.
//
// Either way the chain starts at the closest stored zone above the requested one (when there is one below the SOA): the zones above it already delegate to it and are left alone.
//
// The requested zone must not be stored under any spelling. If PowerDNS already serves it without a stored owner, it is an intermediate zone created for a deeper one (e.g. proj.dhbw.site created on the way to petko.proj.dhbw.site before clemens claimed it): the caller, entitled as above, adopts it — gets their key on it and keeps the delegations it holds — instead of it being deleted and recreated, which would cut those delegations.
func (app *AppData) ZoneCreate(ctx context.Context, user *UserClaims, zone ZoneResponse) (int, any, error) {
	username := user.Identity()

	name, err := canonicalZoneName(zone.Zone)
	if err != nil {
		return errorResult(http.StatusBadRequest, msg.TextOf(err), fmt.Errorf("app.ZoneCreate: %w", err))
	}
	soa := normalizeZone(zone.ZoneSOA)

	// Somebody's zone under any spelling (rows stored before names were canonical included) is taken.
	if exists, err := app.Storage.ZoneExistsAnySpelling(name); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Ob es die Zone gibt, ließ sich nicht prüfen.", "Whether the zone exists could not be checked."), fmt.Errorf("app.ZoneCreate: %w", err))
	} else if exists {
		return errorResult(http.StatusConflict, msg.T("Die Zone gibt es bereits.", "The zone already exists."), fmt.Errorf("app.ZoneCreate: %s is stored", name))
	}

	// The limit of zones per person (DnsPolicyConfig.MaxZonesPerUser); super admins are exempt.
	if limit := app.Config.DnsPolicyConfig.MaxZonesPerUser; limit > 0 && !isSuperAdmin(app, user) {
		count, err := app.Storage.CountCreatedZones(username)
		if err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Die Zahl der eigenen Zonen ließ sich nicht prüfen.", "The number of your zones could not be checked."), fmt.Errorf("app.ZoneCreate: %w", err))
		}
		if count >= int64(limit) {
			return errorResult(http.StatusForbidden, msg.F("Pro Person lassen sich höchstens %d Zonen anlegen; dieses Konto hat bereits %d. Für eine neue Zone zuerst eine nicht mehr benötigte löschen.", "At most %d zones can be created per person; this account already has %d. To create a new zone, first delete one that is no longer needed.", limit, count),
				fmt.Errorf("app.ZoneCreate: %q has created %d zones, the limit is %d", username, count, limit))
		}
	}

	// A deprecated rule keeps the zones it granted but offers no new ones (PolicyRule.Deprecated). Subzones (zone.Subzone) are not affected: they hang below a zone that exists.
	if zone.Deprecated && !zone.Subzone {
		return errorResult(http.StatusForbidden, app.deprecatedZoneText(user, name),
			fmt.Errorf("app.ZoneCreate: %q is only granted to %q by a deprecated rule", name, username))
	}

	// Check which zones this nameserver is authoritative for. A nil result means
	// the zone is NOT under its own SOA — the chain of intermediate zones cannot
	// be built, and creating the zone anyway would mint a name outside the SOA
	// the caller was authorized for. Refuse instead of silently skipping the loop.
	authoritative := getAuthoritativeZones(name, soa)
	if len(authoritative) == 0 {
		return errorResult(http.StatusBadRequest, msg.T("Die Zone liegt nicht unter ihrem SOA.", "The zone is not below its SOA."),
			fmt.Errorf("app.ZoneCreate: zone %q is not at or below soa %q", name, soa))
	}

	parent, err := app.closestStoredParent(name)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die übergeordnete Zone ließ sich nicht ermitteln.", "The parent zone could not be determined."), fmt.Errorf("app.ZoneCreate: %w", err))
	}
	parentInChain := parent != "" && (parent == soa || isSubdomainOf(parent, soa))
	if parentInChain {
		authoritative = authoritative[slicesIndex(authoritative, parent):]
	}

	if zone.Subzone {
		if !parentInChain {
			return errorResult(http.StatusForbidden, msg.T("Subzonen lassen sich nur unter einer eigenen Zone anlegen.", "Subzones can only be created under a zone of your own."),
				fmt.Errorf("app.ZoneCreate: no stored parent of %q at or below %q", name, soa))
		}
		owns, err := app.Storage.IsZoneOwner(username, parent)
		if err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone darüber ließen sich nicht prüfen.", "The owners of the zone above could not be checked."), fmt.Errorf("app.ZoneCreate: %w", err))
		}
		if !owns && !isSuperAdmin(app, user) {
			return errorResult(http.StatusForbidden, msg.T("Die Zone darüber gehört jemand anderem.", "The zone above belongs to someone else."),
				fmt.Errorf("app.ZoneCreate: %q would be delegated from %q, which %q does not own", name, parent, username))
		}
		rules, err := app.Storage.PolicyGetAll()
		if err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Die Regeln ließen sich nicht lesen.", "The rules could not be read."), fmt.Errorf("app.ZoneCreate: %w", err))
		}
		for _, z := range authoritative[1:] {
			if rule, reserved := reservedByPolicy(rules, z, app.principalOf(username)); reserved {
				return errorResult(http.StatusForbidden, msg.F("%s ist durch eine Regel reserviert.", "%s is reserved by a rule.", z),
					fmt.Errorf("app.ZoneCreate: subzone %q of %q runs into %q, reserved by rule %d", name, username, z, rule.ID))
			}
		}
	}

	// The requested zone may already be served by PowerDNS as an ownerless intermediate zone; see above.
	adopt, err := app.PowerDns.ZoneExists(ctx, name)
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Ob es die Zone gibt, ließ sich nicht prüfen.", "Whether the zone exists could not be checked."), fmt.Errorf("app.ZoneCreate: %w", err))
	}

	if zone.Subzone {
		// Count the intermediate zones this request would have to create (the first entry is the zone delegated from, the last the requested one).
		missing := 0
		for _, z := range authoritative[1 : len(authoritative)-1] {
			exists, err := app.PowerDns.ZoneExists(ctx, z)
			if err != nil {
				return errorResult(http.StatusInternalServerError, msg.T("Eine Zone dazwischen ließ sich nicht prüfen.", "A zone in between could not be checked."), fmt.Errorf("app.ZoneCreate: %w", err))
			}
			if !exists {
				missing++
			}
		}
		if missing > maxIntermediateZones {
			return errorResult(http.StatusBadRequest, msg.F("Die Zone liegt zu tief: Unter einer bestehenden Zone lassen sich höchstens %d Ebenen auf einmal anlegen.", "The zone lies too deep: at most %d levels can be created at once under an existing zone.", maxIntermediateZones+1),
				fmt.Errorf("app.ZoneCreate: %q needs %d intermediate zones", name, missing))
		}
	}

	// Create all  intermediates zones
	for i, z := range authoritative {
		// Skip the requested zone itself
		if z == name {
			continue
		}

		// Determine next child zone
		nextChildZone := next(authoritative, i)

		app.Log.Infof("app.ZoneCreate: Creating intermediate zone '%s' I'm authoritative for (with child zone delegation to %s)", z, nextChildZone)
		if err := app.PowerDns.EnsureIntermediateZoneExists(ctx, z, nextChildZone); err != nil {
			return errorResult(http.StatusInternalServerError, msg.T("Eine Zone dazwischen ließ sich nicht anlegen.", "A zone in between could not be created."), err)
		}
	}

	// This is the requested zone: adopted when PowerDNS already serves it, created otherwise. Never forced: forcing deletes whatever PowerDNS holds under this name first.
	var zoneResponse *ZoneDataResponse
	if adopt {
		app.Log.Infof("app.ZoneCreate: %s adopts the ownerless zone '%s'", username, name)
		zoneResponse, err = app.PowerDns.AdoptUserZone(ctx, username, name)
	} else {
		zoneResponse, err = app.PowerDns.CreateUserZone(ctx, username, name, false)
	}
	if err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Zone ließ sich nicht auf dem DNS-Server anlegen.", "The zone could not be created on the DNS server."), fmt.Errorf("app.ZoneCreate: %w", err))
	}

	if _, err := app.Storage.CreateZone(username, name, true); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Zone ließ sich nicht in der Datenbank anlegen.", "The zone could not be created in the database."), fmt.Errorf("app.ZoneCreate: %w", err))
	}

	// A subzone under a shared zone belongs to that zone's owners as well, so it
	// does not become invisible to the people who share the parent.
	if err := app.inheritOwnersFromParent(ctx, name, username); err != nil {
		return errorResult(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone darüber ließen sich nicht übernehmen.", "The owners of the zone above could not be taken over."), fmt.Errorf("app.ZoneCreate: %w", err))
	}

	return http.StatusCreated, gin.H{"success": zoneResponse}, nil
}

// deprecatedZoneText is the refusal for a zone only a deprecated rule grants, naming the zones the user can create instead when there are any.
func (app *AppData) deprecatedZoneText(user *UserClaims, zone string) msg.Text {
	var offers []string
	if zones, err := app.PolicyGetUserZones(user); err == nil {
		for _, z := range zones {
			if !z.Deprecated && z.Zone != zone {
				offers = append(offers, z.Zone)
			}
		}
	}
	if len(offers) == 0 {
		return msg.F("Die Regel für %s ist veraltet; neue Zonen bietet sie nicht mehr an.", "The rule for %s is deprecated; it no longer offers new zones.", zone)
	}
	return msg.F("Die Regel für %s ist veraltet; neue Zonen nur noch über die aktuellen Regeln, z. B. %s.", "The rule for %s is deprecated; new zones only through the current rules, e.g. %s.", zone, strings.Join(offers, ", "))
}

// reservedByPolicy reports whether a zone on the way to a subzone belongs to the policy rather than to whoever owns the zone above it: a rule's SOA (the base zone a whole rule delegates from), or a name some rule grants to someone other than `user`. A subzone created through allow_subdomains must not claim such a name or write delegations into it — that is the rule author's decision, not the parent owner's.
//
// Strict: a rule whose group entry cannot be checked for the user counts as somebody else's.
func reservedByPolicy(rules []PolicyRule, zone string, p principal) (PolicyRule, bool) {
	for _, r := range rules {
		if normalizeZone(r.ZoneSoa) == zone {
			return r, true
		}
		if zonePatternMatches(r.ZonePattern, zone) {
			if !matchFilter(p, r.TargetUserFilter).match {
				return r, true
			}
		}
	}
	return PolicyRule{}, false
}

// The placeholders a zone pattern may contain: %u is the whole e-mail address of the user made DNS-compliant (dennis@dhbw.de → dennis-at-dhbw-de), %l only its local part (dennis.pfisterer@dhbw.de → dennis-pfisterer). %l drops the domain, and making an address DNS-compliant can map two addresses to one name (max.mueller and max_mueller), so two people can be granted the same name; the first to create it owns it, the other is offered a variant with a short hash of their address (personal_zone_names.go).
const (
	placeholderUser      = "%u"
	placeholderLocalPart = "%l"
)

// hasPlaceholder reports whether a zone pattern contains a user placeholder (%u or %l).
func hasPlaceholder(pattern string) bool {
	return strings.Contains(pattern, placeholderUser) || strings.Contains(pattern, placeholderLocalPart)
}

// replacePlaceholders replaces both user placeholders in s with the same text; for the checks that only need some label in their place.
func replacePlaceholders(s, with string) string {
	return strings.NewReplacer(placeholderUser, with, placeholderLocalPart, with).Replace(s)
}

// expandZonePattern is the zone a rule pattern grants the user with this identity: %u becomes the whole address made DNS-compliant, %l its local part. ok is false when a placeholder in the pattern would expand to nothing (an address of nothing but special characters), which would not be a valid name.
func expandZonePattern(pattern, identity string) (zone string, ok bool) {
	user := helper.DnsMakeCompliant(identity)
	local := helper.DnsMakeCompliantLocalPart(identity)
	if (strings.Contains(pattern, placeholderUser) && user == "") || (strings.Contains(pattern, placeholderLocalPart) && local == "") {
		return "", false
	}
	return normalizeZone(strings.NewReplacer(placeholderUser, user, placeholderLocalPart, local).Replace(pattern)), true
}

// zonePatternMatches reports whether `zone` is a name the rule pattern can produce for SOME user (%u and %l stand for any DNS label text).
func zonePatternMatches(pattern, zone string) bool {
	p := normalizeZone(pattern)
	if !hasPlaceholder(p) {
		return p == zone
	}
	re, err := regexp.Compile("^" + replacePlaceholders(regexp.QuoteMeta(p), "[a-z0-9-]+") + "$")
	return err == nil && re.MatchString(zone)
}

// slicesIndex returns the position of v in s (callers make sure it is there).
func slicesIndex(s []string, v string) int {
	for i := range s {
		if s[i] == v {
			return i
		}
	}
	return 0
}

// errorResult is the answer of the older app methods: the status, an apierr answer as the body (the text for people in German and English and the code that follows from the status; writeResult renders it in the caller's language) and the cause for the log.
func errorResult(code int, text msg.Text, err error) (int, any, error) {
	return code, apiErr(code, text), err
}

// writeResult answers a request with what an older app method returned: an error answer (errorResult) in the request's language, anything else as JSON with its status.
func writeResult(c *gin.Context, status int, body any) {
	if e, ok := body.(*apierr.Error); ok {
		ginweb.AbortError(c, e)
		return
	}
	c.JSON(status, body)
}

// Helper to get next element in slice or empty string if at end
func next(slice []string, i int) string {
	if i+1 < len(slice) {
		return slice[i+1]
	}
	return ""
}

func toExternalDNSConfig(app *AppData, pdnsZone *ZoneDataResponse, externalDnsVersion string) (string, error) {
	tmpl, err := template.New("external-dns").Parse(helper.ExternalDNSValuesYamlTemplate)
	if err != nil {
		return "", fmt.Errorf("parse external-dns template: %w", err)
	}

	if len(pdnsZone.ZoneKeys) <= 0 {
		return "", fmt.Errorf("no zone keys available for zone %s", pdnsZone.Zone)
	}

	data := map[string]any{
		"txtPrefix":  "dynamic-zones-dns-",
		"txtOwnerId": "dynamic-zones-dns",
		// external-dns runs in the user's cluster; advertise the public NS
		// hostname (falls back to the literal IP when unset).
		"dnsServerAddress": app.Config.PowerDns.AdvertisedServer(),
		"dnsServerPort":    app.Config.PowerDns.DnsServerPort,
		"zone":             pdnsZone.Zone,
		"tsigKey":          pdnsZone.ZoneKeys[0].Key,
		"tsigAlgorithm":    pdnsZone.ZoneKeys[0].Algorithm,
		"tsigKeyname":      pdnsZone.ZoneKeys[0].Keyname,
		"secretName":       fmt.Sprintf("external-dns-rfc2136-%s-secret", pdnsZone.Zone),
		"imageVersion":     externalDnsVersion,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("execute external-dns template: %w", err)
	}

	return buf.String(), nil
}

// getAuthoritativeZones returns the slice of domain names (in “parent” chain) from fullName
// down to and including soaBase. E.g. fullName="a.b.c.d.e", soaBase="c.d.e" → ["c.d.e","b.c.d.e","a.b.c.d.e"]
// The returned slice is ordered shortest to longest.
func getAuthoritativeZones(fullName, soaBase string) []string {
	// Normalize: remove trailing dot, if any
	fullName = strings.TrimSuffix(fullName, ".")
	soaBase = strings.TrimSuffix(soaBase, ".")

	parts := strings.Split(fullName, ".")
	baseParts := strings.Split(soaBase, ".")

	// sanity: soaBase must be a suffix of fullName
	if len(baseParts) > len(parts) {
		return nil
	}

	// check suffix
	for i := 1; i <= len(baseParts); i++ {
		if parts[len(parts)-i] != baseParts[len(baseParts)-i] {
			return nil
		}
	}

	var result []string
	// build from fullName down to soaBase (longest to shortest)
	for i := 0; i <= len(parts)-len(baseParts); i++ {
		result = append(result, strings.Join(parts[i:], "."))
	}

	// Reverse the slice to order from shortest entry first (soaBase to fullName)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

func policyValidateRequest(req PolicyRuleRequest) error {

	if err := validateZonePattern(req.ZonePattern); err != nil {
		return err
	}

	if err := validateUserFilter(req.TargetUserFilter); err != nil {
		return err
	}

	if err := validatePatternWithinSoa(req.ZonePattern, req.ZoneSoa); err != nil {
		return err
	}

	return nil
}

// validatePatternWithinSoa enforces that the zone a rule hands out actually lies
// under the rule's own SOA.
//
// This is what confines a DELEGATE to their subtree: createPolicyRule authorizes
// against ZoneSoa, but the name a user ends up owning comes from ZonePattern.
// Without this check somebody delegated for projects.dhbw.site could write a rule
// with zone_pattern "victim.users.dhbw.site", create that zone, and hold its TSIG
// key — PowerDNS answers the more specific zone, so that is a takeover of a
// foreign name including DNS-01 certificate issuance.
func validatePatternWithinSoa(zonePattern, zoneSoa string) error {
	if strings.TrimSpace(zoneSoa) == "" {
		return invalid("zone_soa darf nicht leer sein.", "zone_soa must not be empty.")
	}
	// %u and %l expand to a user label; any label keeps the suffix relationship intact.
	zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(replacePlaceholders(zonePattern, "a"))), ".")
	soa := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zoneSoa)), ".")
	if zone != soa && !isSubdomainOf(zone, soa) {
		return invalid("zone_pattern %q muss gleich zone_soa %q sein oder darunter liegen.", "zone_pattern %q must be equal to zone_soa %q or lie below it.", zonePattern, zoneSoa)
	}
	return nil
}

// emailMatchesPattern matches an email against a single filter pattern — either
// an exact email or a one-'*' prefix/suffix wildcard (e.g. *@domain.com).
// Comparison is case-insensitive; surrounding whitespace is ignored.
func emailMatchesPattern(email, pattern string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	p := strings.ToLower(strings.TrimSpace(pattern))
	if p == "" || strings.Count(p, "*") > 1 {
		return false
	}
	if !strings.Contains(p, "*") {
		return e == p
	}
	parts := strings.SplitN(p, "*", 2)
	return strings.HasPrefix(e, parts[0]) && strings.HasSuffix(e, parts[1])
}

// validateUserFilter accepts a comma-separated list of e-mail addresses, patterns with one '*' (*@dhbw.de), and the role-provider tokens user:<email>, group:<id> and group:<id>#<relation>. At most 255 characters, the size of the column.
func validateUserFilter(filter string) error {
	errInvalidUserFilter := invalid("Der Benutzerfilter muss eine durch Kommas getrennte Liste sein aus E-Mail-Adressen, Mustern wie *@domain.de und Tokens wie user:name@domain.de, group:<gruppe> oder group:<gruppe>#<rolle>.", "The user filter must be a comma-separated list of e-mail addresses, patterns such as *@domain.com and tokens such as user:name@domain.com, group:<group> or group:<group>#<role>.")
	if len(filter) > 255 {
		return invalid("Der Benutzerfilter ist mit %d Zeichen zu lang (höchstens 255).", "The user filter is too long at %d characters (at most 255).", len(filter))
	}

	hasEntry := false
	for _, raw := range strings.Split(filter, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue // tolerate blank entries / trailing commas
		}
		hasEntry = true
		if !validFilterEntry(p) {
			return errInvalidUserFilter
		}
	}

	if !hasEntry {
		return errInvalidUserFilter
	}
	return nil
}

// The shapes of the role provider's ids (role-provider-service common.GroupIDPattern and its relation names), compared case-insensitively.
var (
	filterGroupIDRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	filterRelationRe = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
)

// validFilterEntry checks one entry of a user filter.
func validFilterEntry(entry string) bool {
	lower := strings.ToLower(entry)
	switch {
	case strings.HasPrefix(lower, tokenUserPrefix):
		addr := strings.TrimPrefix(lower, tokenUserPrefix)
		parsed, err := mail.ParseAddress(addr)
		return err == nil && parsed.Address == addr && !strings.Contains(addr, "*")
	case strings.HasPrefix(lower, tokenGroupPrefix):
		id, relation, hasRelation := strings.Cut(strings.TrimPrefix(lower, tokenGroupPrefix), "#")
		if !filterGroupIDRe.MatchString(id) {
			return false
		}
		return !hasRelation || filterRelationRe.MatchString(relation)
	case strings.Count(entry, "*") > 1:
		return false
	case strings.Contains(entry, "*"):
		return !strings.Contains(entry, ":")
	default:
		_, err := mail.ParseAddress(entry)
		return err == nil && !strings.Contains(entry, ":")
	}
}

func isSuperAdmin(app *AppData, user *UserClaims) bool {
	superAdmins := app.Config.DnsPolicyConfig.SuperAdminEmails

	if _, exists := superAdmins[strings.ToLower(user.Identity())]; exists {
		return true
	}

	return false
}

// validateZonePattern validates a zone pattern by temporarily replacing the placeholders %u and %l with a valid character ('A') before performing standard DNS label checks.
func validateZonePattern(value string) error {
	if value == "" {
		return invalid("Das Zonenmuster ist leer.", "The zone pattern is empty.")
	}

	// 1. Replace '%u' and '%l' with 'A' and trim whitespace
	s := replacePlaceholders(value, "A")
	s = strings.TrimSpace(s)

	// Use existing DNS domain validation
	return helper.DnsValidateName(s)
}

// filterUserRules keeps the rules whose user filter matches the person; optimistic as in policyZonesOf.
func filterUserRules(rules []PolicyRule, p principal, optimistic bool) []PolicyRule {
	filteredRules := make([]PolicyRule, 0, 10)
	for _, rule := range rules {
		if matchFilter(p, rule.TargetUserFilter).allowed(optimistic) {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules
}

// ruleToZoneResponse is the zone a rule grants the user, with %u and %l expanded by expand (expandZonePattern, or the collision-free personalZoneName); false when a placeholder would expand to nothing for this user.
func ruleToZoneResponse(rule PolicyRule, identity string, expand func(pattern, identity string) (string, bool)) (ZoneResponse, bool) {
	// Normalised like every requested name, or a rule written as "Lab.Example.com" would grant a zone no request can ever match.
	zone, ok := expand(rule.ZonePattern, identity)
	if !ok {
		return ZoneResponse{}, false
	}
	return ZoneResponse{
		Zone:            zone,
		ZoneSOA:         normalizeZone(rule.ZoneSoa),
		AllowSubdomains: rule.AllowSubdomains,
		SharingAllowed:  rule.SharingAllowed,
		Deprecated:      rule.Deprecated,
	}, true
}

// rulesToUserZones is the zones the rules grant the user, the placeholders expanded without looking at existing zones.
func rulesToUserZones(rules []PolicyRule, identity string) []ZoneResponse {
	return rulesToUserZonesWith(rules, identity, expandZonePattern)
}

// rulesToUserZonesWith is rulesToUserZones with the placeholders expanded by expand.
func rulesToUserZonesWith(rules []PolicyRule, identity string, expand func(pattern, identity string) (string, bool)) []ZoneResponse {
	zones := make([]ZoneResponse, 0, len(rules))

	for _, rule := range rules {
		zone, ok := ruleToZoneResponse(rule, identity, expand)
		if !ok {
			continue
		}

		// Check if the zone has already been added by another rule. A current rule wins over a deprecated one granting the same name, so the zone stays creatable.
		isDuplicate := false
		for i, existing := range zones {
			if existing.Zone == zone.Zone {
				isDuplicate = true
				if existing.Deprecated && !zone.Deprecated {
					zones[i] = zone
				}
				break
			}
		}

		if !isDuplicate {
			zones = append(zones, zone)
		}
	}

	return zones
}

// ZoneList assembles the zones a user may see: the ones their policy rules
// grant, plus the ones they own (delegated subzones, and zones shared with
// them), each with the status flags the callers render.
//
// Lifted out of the HTTP handler because it is the answer to "what zones do I
// have", and more than one kind of caller asks that question — the REST route
// and the MCP tool both, and neither should own the logic.
func (app *AppData) ZoneList(user *UserClaims) ([]ZoneStatus, error) {
	userZones, err := app.PolicyGetUserZones(user)
	if err != nil {
		return nil, fmt.Errorf("get user zones: %w", err)
	}

	zonesWithStatus := make([]ZoneStatus, 0, len(userZones))

	for _, zone := range userZones {
		existsInStorage, err := app.Storage.ZoneExists(zone.Zone)
		if err != nil {
			return nil, fmt.Errorf("check zone existence for %q: %w", zone.Zone, err)
		}

		// Exists (manageable) = created AND the user already owns it. A created
		// zone the user does not own is either joinable (policy-entitled +
		// sharing on -> explicit join) or "already taken" (sharing off).
		isOwner, owners, creator := false, []string(nil), ""
		if existsInStorage {
			if isOwner, err = app.Storage.IsZoneOwner(user.Identity(), zone.Zone); err != nil {
				return nil, fmt.Errorf("check zone ownership for %q: %w", zone.Zone, err)
			}
			// Only reveal the owner list to an actual owner. A policy-entitled
			// non-owner (including the "already taken by someone else" case)
			// must not be able to enumerate the current owners' emails.
			if isOwner {
				if owners, err = app.Storage.ListZoneOwners(zone.Zone); err != nil {
					return nil, fmt.Errorf("list zone owners for %q: %w", zone.Zone, err)
				}
				if creator, err = app.Storage.ZoneCreator(zone.Zone); err != nil {
					return nil, fmt.Errorf("get the creator of %q: %w", zone.Zone, err)
				}
			}
		}
		// A deprecated rule only keeps what the user already owns; it offers nothing new — no zone to create, none to join, and no "taken" entry either.
		if zone.Deprecated && !(existsInStorage && isOwner) {
			continue
		}
		canJoin := existsInStorage && !isOwner && zone.SharingAllowed

		zonesWithStatus = append(zonesWithStatus, ZoneStatus{
			Name:                      zone.Zone,
			Exists:                    existsInStorage && isOwner,
			CanJoin:                   canJoin,
			AlreadyTakenBySomeoneElse: existsInStorage && !isOwner && !zone.SharingAllowed,
			AllowSubdomains:           zone.AllowSubdomains,
			SharingAllowed:            zone.SharingAllowed,
			Owners:                    owners,
			Creator:                   creator,
			ZoneSoa:                   zone.ZoneSOA,
			Deprecated:                zone.Deprecated,
		})
	}

	// Add the user's created subzones (delegated under an allow_subdomains base
	// zone) so a caller can show them indented under their parent.
	baseNames := make(map[string]bool, len(userZones))
	baseSharing := make(map[string]bool, len(userZones))
	allowSubBases := make([]string, 0)
	for _, z := range userZones {
		baseNames[z.Zone] = true
		baseSharing[z.Zone] = z.SharingAllowed
		if z.AllowSubdomains {
			allowSubBases = append(allowSubBases, z.Zone)
		}
	}

	createdZones, err := app.Storage.ListUserZones(user.Identity())
	if err != nil {
		return nil, fmt.Errorf("list user zones: %w", err)
	}

	// A zone held through SHARING rather than policy is a base zone too, so
	// resolve the governing rule of every owned zone up front and let those
	// that allow subdomains act as parents below. Without this a co-owner's
	// subzones would render top-level instead of indented under their parent.
	govDefs := make(map[string]*ZoneResponse, len(createdZones))
	for _, cz := range createdZones {
		if baseNames[cz.Zone] {
			continue
		}
		def, err := app.zoneGoverningDef(cz.Zone)
		if err != nil {
			return nil, fmt.Errorf("resolve governing rule for %q: %w", cz.Zone, err)
		}
		govDefs[cz.Zone] = def
		if def != nil && def.AllowSubdomains {
			allowSubBases = append(allowSubBases, cz.Zone)
			baseSharing[cz.Zone] = def.SharingAllowed
		}
	}

	for _, cz := range createdZones {
		if baseNames[cz.Zone] {
			continue // already listed as a policy base zone
		}
		// Find the most specific allow_subdomains parent this zone sits under.
		parent := ""
		for _, base := range allowSubBases {
			if isSubdomainOf(cz.Zone, base) && len(base) > len(parent) {
				parent = base
			}
		}
		zOwners, err := app.Storage.ListZoneOwners(cz.Zone)
		if err != nil {
			return nil, fmt.Errorf("list zone owners for %q: %w", cz.Zone, err)
		}
		zCreator, err := app.Storage.ZoneCreator(cz.Zone)
		if err != nil {
			return nil, fmt.Errorf("get the creator of %q: %w", cz.Zone, err)
		}
		if parent == "" {
			// A zone the user owns that is neither a policy base zone nor a
			// subzone of one -> a zone SHARED with them (or orphaned). Show it
			// as a top-level managed zone, using its governing rule's flags.
			def := govDefs[cz.Zone]
			soa := ""
			if def != nil {
				soa = def.ZoneSOA
			}
			zonesWithStatus = append(zonesWithStatus, ZoneStatus{
				Name:            cz.Zone,
				Exists:          true,
				AllowSubdomains: def != nil && def.AllowSubdomains,
				SharingAllowed:  def != nil && def.SharingAllowed,
				Owners:          zOwners,
				Creator:         zCreator,
				ZoneSoa:         soa,
			})
			continue
		}
		zonesWithStatus = append(zonesWithStatus, ZoneStatus{
			Name:            cz.Zone,
			Exists:          true,
			AllowSubdomains: true,                // subzones inherit the parent's allow_subdomains
			SharingAllowed:  baseSharing[parent], // and the parent's sharing setting
			Parent:          parent,
			Owners:          zOwners,
			Creator:         zCreator,
		})
	}

	return zonesWithStatus, nil
}

// ZoneCreateAuthorized decides whether a user may create a zone and creates it.
//
// The decision used to live in the HTTP handler, which was fine while HTTP was
// the only way in. It is not any more: an MCP tool has to reach the same verdict
// through the same code, or "who may create this zone" has two answers.
//
// Two paths lead to yes, and the second is easy to miss: a policy rule that
// grants the zone, OR ownership of a zone above it that allows subdomains — a
// co-owner shared into a zone manages it, so they may delegate below it without
// an entitlement of their own.
func (app *AppData) ZoneCreateAuthorized(ctx context.Context, user *UserClaims, zone string) (*ZoneDataResponse, error) {
	zone, err := canonicalZoneName(zone)
	if err != nil {
		return nil, statusErr(http.StatusBadRequest, msg.TextOf(err), err)
	}

	isAllowed, zoneDef, err := app.PolicyIsZoneAllowedForUser(zone, user)
	if err != nil {
		return nil, statusErr(http.StatusInternalServerError, msg.T("Die eigenen Zonen ließen sich nicht laden.", "Your zones could not be loaded."), err)
	}

	if !isAllowed {
		zoneDef, err = app.subzoneDefViaOwnedParent(zone, user.Identity())
		if err != nil {
			return nil, statusErr(http.StatusInternalServerError, msg.T("Die übergeordnete Zone ließ sich nicht ermitteln.", "The parent zone could not be determined."), err)
		}
		isAllowed = zoneDef != nil
	}

	if !isAllowed && app.refusedForUnknownGroups(zone, user) {
		return nil, statusErr(http.StatusServiceUnavailable, msgGroupsUnavailable,
			fmt.Errorf("app.ZoneCreateAuthorized: %q for %q needs group tokens, which are unknown", zone, user.Identity()))
	}

	if !isAllowed {
		return nil, statusErr(http.StatusForbidden, msg.T("Keine Berechtigung, diese Zone anzulegen.", "No permission to create this zone."),
			fmt.Errorf("app.ZoneCreateAuthorized: %q not allowed for %q", zone, user.Identity()))
	}

	status, body, err := app.ZoneCreate(ctx, user, *zoneDef)
	if err != nil || status >= http.StatusBadRequest {
		return nil, statusErr(status, messageFromBody(body, msg.T("Die Zone ließ sich nicht anlegen.", "The zone could not be created.")), err)
	}

	// The body carries the created zone INCLUDING its TSIG key. Callers that may
	// see it (the REST handler) pass the body on; callers that may not (MCP) take
	// only the name from it, which is why this returns the typed value rather
	// than the gin.H.
	if h, ok := body.(gin.H); ok {
		if zoneData, ok := h["success"].(*ZoneDataResponse); ok {
			return zoneData, nil
		}
	}
	return nil, nil
}

// ZoneDeleteAuthorized deletes a zone for everyone, if the caller created it
// (or is a super admin).
//
// Ownership alone is not enough: a co-owner shared in — by joining or by being
// added — manages the zone's records, but the zone is not theirs to destroy for
// the person who created it. They leave instead (ZoneRemoveOwner on themself).
func (app *AppData) ZoneDeleteAuthorized(ctx context.Context, user *UserClaims, zone string) error {
	authority, err := app.zoneAuthorityOf(user, zone)
	if err != nil {
		return statusErr(http.StatusInternalServerError, msg.T("Die Eigentümer der Zone ließen sich nicht prüfen.", "The owners of the zone could not be checked."), err)
	}
	if !authority.owner && !authority.superAdmin {
		return statusErr(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."),
			fmt.Errorf("app.ZoneDeleteAuthorized: %q not owned by %q", zone, user.Identity()))
	}
	if !authority.manages() {
		return statusErr(http.StatusForbidden, msg.T("Löschen kann die Zone nur, wer sie angelegt hat; das eigene Konto lässt sich aber als Eigentümer entfernen.", "Only whoever created the zone can delete it; your own account can be removed as an owner, though."),
			fmt.Errorf("app.ZoneDeleteAuthorized: %q is not the creator of %q", user.Identity(), zone))
	}
	if !authority.owner {
		exists, err := app.Storage.ZoneExists(zone)
		if err != nil {
			return statusErr(http.StatusInternalServerError, msg.T("Ob es die Zone gibt, ließ sich nicht prüfen.", "Whether the zone exists could not be checked."), err)
		}
		if !exists {
			return statusErr(http.StatusNotFound, msg.T("Die Zone gibt es nicht.", "The zone does not exist."), nil)
		}
	}

	status, body, err := app.ZoneDelete(ctx, user.Identity(), zone)
	if err != nil || status >= http.StatusBadRequest {
		return statusErr(status, messageFromBody(body, msg.T("Die Zone ließ sich nicht löschen.", "The zone could not be deleted.")), err)
	}
	return nil
}

// messageFromBody digs the message out of the gin.H the older app methods
// answer with, so a caller that has no HTTP response to write still gets the
// sentence that would have been in one.
func messageFromBody(body any, fallback msg.Text) msg.Text {
	if e, ok := body.(*apierr.Error); ok && !e.Msg.IsZero() {
		return e.Msg
	}
	return fallback
}
