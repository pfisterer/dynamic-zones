package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"text/template"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/gin-gonic/gin"
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
	ZonePattern      string `json:"zone_pattern" binding:"required"`
	ZoneSoa          string `json:"zone_soa" binding:"required"`
	TargetUserFilter string `json:"target_user_filter" binding:"required"`
	AllowSubdomains  bool   `json:"allow_subdomains"`
	SharingAllowed   bool   `json:"sharing_allowed"`
	Description      string `json:"description"`
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
	var userDelegations []DelegationPolicy
	for _, d := range delegations {
		if ok, _ := userCanAccessRule(user.Email, d.TargetUserFilter); ok {
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
	return &PolicyRulesResponse{Rules: filterUserRules(rules, user), EditAllowed: false}, nil
}

func (app *AppData) PolicyGetUserZones(user *UserClaims) ([]ZoneResponse, error) {
	// Get all rules that are applicable to the user
	rules, err := app.Storage.PolicyGetAll()
	if err != nil {
		app.Log.Errorf("Error retrieving policy rules: %v", err)
		return nil, err
	}

	// Filter the rules based on user email
	filteredRules := filterUserRules(rules, user)
	zones := rulesToUserZones(filteredRules, user)

	return zones, nil
}

func (app *AppData) PolicyIsZoneAllowedForUser(zone string, user *UserClaims) (bool, *ZoneResponse, error) {
	zones, err := app.PolicyGetUserZones(user)
	if err != nil {
		app.Log.Errorf("Error getting user zones: %v", err)
		return false, nil, err
	}

	// Exact match: the requested zone is one of the user's base zones.
	for i := range zones {
		if zones[i].Zone == zone {
			app.Log.Debugf("User %s is allowed to use zone %s", user.PreferredUsername, zone)
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
		app.Log.Debugf("User %s is allowed to use subzone %s under %s", user.PreferredUsername, zone, bestParent.Zone)
		// Delegate the subzone under its parent (ZoneSOA = parent zone); the
		// subzone inherits the parent's sharing setting.
		return true, &ZoneResponse{Zone: zone, ZoneSOA: bestParent.Zone, AllowSubdomains: true, SharingAllowed: bestParent.SharingAllowed}, nil
	}

	app.Log.Debugf("User %s is not allowed to use zone %s", user.PreferredUsername, zone)
	return false, nil, nil
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
		return nil, err
	}

	// Create and store the new rule
	newRule := PolicyRule{
		ZonePattern:      req.ZonePattern,
		ZoneSoa:          req.ZoneSoa,
		TargetUserFilter: req.TargetUserFilter,
		AllowSubdomains:  req.AllowSubdomains,
		SharingAllowed:   req.SharingAllowed,
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
		return nil, err
	}

	// Check if rule exists before update attempt
	existingRule, err := app.Storage.PolicyGetByID(id)
	if err != nil {
		app.Log.Errorf("Error retrieving existing policy rule #%d: %v", id, err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("rule not found")
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
	existingRule.Description = req.Description

	app.Log.Infof("Updating policy rule #%d to: %+v", id, existingRule)
	updatedRule, err := app.Storage.PolicyUpdate(existingRule)
	if err != nil {
		app.Log.Errorf("Error updating policy rule #%d: %v", id, err)
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("rule not found")
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
			return fmt.Errorf("rule not found")
		}
		return fmt.Errorf("failed to delete rule: %w", err)
	}

	return nil
}

// ZoneGet returns a zone (with the caller's own TSIG key + the current owner
// list). Access = the caller is an owner OR is policy-entitled to this exact
// zone and the governing rule has sharing enabled — in which case the caller
// auto-joins as a co-owner (own row + own TSIG key created lazily here).
func (app *AppData) ZoneGet(ctx context.Context, user *UserClaims, zone, externalDnsVersion string) (int, any, error) {
	username := user.PreferredUsername

	// The zone must have been created by someone.
	exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check zone existence", fmt.Errorf("app.getZone: %w", err))
	}
	if !exists {
		return errorResult(http.StatusNotFound, "Zone does not exist", fmt.Errorf("app.getZone: zone %s not found", zone))
	}

	// Access requires being an owner. Policy-entitled users of a shareable zone
	// must first JOIN it explicitly (POST /zones/:zone/join) — no implicit
	// self-join on read.
	isOwner, err := app.Storage.IsZoneOwner(username, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check zone ownership", fmt.Errorf("app.getZone: %w", err))
	}
	if !isOwner {
		return errorResult(http.StatusForbidden, "You are not an owner of this zone", fmt.Errorf("app.getZone: %s not owned by %s", zone, username))
	}

	// Get from PowerDNS — scoped to the caller's own key only.
	pdnsZone, err := app.PowerDns.GetZone(ctx, zone, username)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to get zone from DNS server", fmt.Errorf("app.getZone: %w", err))
	}

	// Generate external-dns config
	valuesYaml, err := toExternalDNSConfig(app, pdnsZone, externalDnsVersion)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to get external-dns config", fmt.Errorf("app.getZone: %w", err))
	}

	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to list zone owners", fmt.Errorf("app.getZone: %w", err))
	}

	sharingAllowed, err := app.zoneSharingAllowed(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to evaluate sharing", fmt.Errorf("app.getZone: %w", err))
	}

	// Return zone data
	app.Log.Infof("app.getZone: returning zone %s", zone)

	return http.StatusOK, gin.H{
		"zoneData":              pdnsZone,
		"externalDnsValuesYaml": valuesYaml,
		"owners":                owners,
		"sharing_allowed":       sharingAllowed,
	}, nil
}

func (app *AppData) ZoneDelete(ctx context.Context, username, zone string) (int, any, error) {
	// Refuse to delete a zone that still has delegated subzones under it — the
	// user must delete the subzones first.
	userZones, err := app.Storage.ListUserZones(username)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to list user zones", fmt.Errorf("app.ZoneDelete: %w", err))
	}
	for _, z := range userZones {
		if isSubdomainOf(z.Zone, zone) {
			return errorResult(http.StatusConflict, "Zone still has subzones — delete them first",
				fmt.Errorf("app.ZoneDelete: %s still has subzone %s", zone, z.Zone))
		}
	}

	if err := app.PowerDns.DeleteZone(ctx, zone, true); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to delete zone from DNS server",
			fmt.Errorf("app.ZoneDelete: %w", err))
	}

	// Deleting the zone removes it for ALL owners (their per-owner keys are gone
	// with the pdns zone above), so drop every owner row, not just the caller's.
	if err := app.Storage.DeleteAllZoneOwners(zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to delete zone from storage",
			fmt.Errorf("app.ZoneDelete: %w", err))
	}

	app.Log.Infof("app.ZoneDelete: %s deleted for user %s", zone, username)
	return http.StatusNoContent, nil, nil
}

// ZoneJoin makes the caller a co-owner of an existing shareable zone (own row +
// own TSIG key). Requires the zone to exist, the caller to be policy-entitled to
// it, and sharing to be enabled. Idempotent for existing owners.
func (app *AppData) ZoneJoin(ctx context.Context, user *UserClaims, zone string) (int, any, error) {
	username := user.PreferredUsername

	exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check zone existence", err)
	}
	if !exists {
		return errorResult(http.StatusNotFound, "Zone does not exist", nil)
	}

	if isOwner, err := app.Storage.IsZoneOwner(username, zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check ownership", err)
	} else if isOwner {
		owners, _ := app.Storage.ListZoneOwners(zone)
		return http.StatusOK, gin.H{"owners": owners}, nil // already a member
	}

	allowed, zoneDef, err := app.PolicyIsZoneAllowedForUser(zone, user)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to evaluate policy", err)
	}
	if !allowed || zoneDef == nil || !zoneDef.SharingAllowed {
		return errorResult(http.StatusForbidden, "You are not entitled to join this zone", nil)
	}

	refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
	if _, err := app.Storage.CreateZone(username, zone, refreshTime); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to join zone", err)
	}
	if err := app.PowerDns.AddOwnerKey(ctx, zone, username); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to provision zone key", err)
	}
	app.Log.Infof("app.ZoneJoin: %s joined shared zone %s", username, zone)

	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to list owners", err)
	}
	return http.StatusOK, gin.H{"owners": owners}, nil
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
		allowed, def, err := app.PolicyIsZoneAllowedForUser(zone, &UserClaims{Email: o, PreferredUsername: o})
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
		return errorResult(http.StatusBadRequest, "Invalid owner email", fmt.Errorf("app.ZoneAddOwner: %w", err))
	}

	isOwner, err := app.Storage.IsZoneOwner(caller.PreferredUsername, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check ownership", err)
	}
	if !isOwner {
		return errorResult(http.StatusForbidden, "You are not an owner of this zone", nil)
	}

	shareable, err := app.zoneSharingAllowed(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to evaluate sharing", err)
	}
	if !shareable {
		return errorResult(http.StatusForbidden, "Sharing is not enabled for this zone", nil)
	}

	if already, err := app.Storage.IsZoneOwner(newOwner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check ownership", err)
	} else if !already {
		refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
		if _, err := app.Storage.CreateZone(newOwner, zone, refreshTime); err != nil {
			return errorResult(http.StatusInternalServerError, "Failed to add owner", err)
		}
		if err := app.PowerDns.AddOwnerKey(ctx, zone, newOwner); err != nil {
			return errorResult(http.StatusInternalServerError, "Failed to provision owner key", err)
		}
		app.Log.Infof("app.ZoneAddOwner: %s added %s as owner of %s", caller.PreferredUsername, newOwner, zone)
	}

	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to list owners", err)
	}
	return http.StatusOK, gin.H{"owners": owners}, nil
}

// ZoneRemoveOwner removes an owner (row + their TSIG key, revoking access at
// once). The caller must be an owner; the last owner cannot be removed.
func (app *AppData) ZoneRemoveOwner(ctx context.Context, caller *UserClaims, zone, owner string) (int, any, error) {
	owner = strings.ToLower(strings.TrimSpace(owner))

	isOwner, err := app.Storage.IsZoneOwner(caller.PreferredUsername, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check ownership", err)
	}
	if !isOwner {
		return errorResult(http.StatusForbidden, "You are not an owner of this zone", nil)
	}

	if targetIsOwner, err := app.Storage.IsZoneOwner(owner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check ownership", err)
	} else if !targetIsOwner {
		return errorResult(http.StatusNotFound, "Not an owner of this zone", nil)
	}

	count, err := app.Storage.CountZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to count owners", err)
	}
	if count <= 1 {
		return errorResult(http.StatusConflict, "Cannot remove the last owner — delete the zone instead", nil)
	}

	if err := app.Storage.DeleteZone(owner, zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to remove owner", err)
	}
	if err := app.PowerDns.RemoveOwnerKey(ctx, zone, owner); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to remove owner key", err)
	}
	app.Log.Infof("app.ZoneRemoveOwner: %s removed %s from %s", caller.PreferredUsername, owner, zone)

	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to list owners", err)
	}
	return http.StatusOK, gin.H{"owners": owners}, nil
}

// ZoneRotateKeys regenerates the TSIG key of every owner of `zone` (e.g. after a
// suspected key compromise). The caller must be an owner; all owners must
// re-fetch their key afterwards.
func (app *AppData) ZoneRotateKeys(ctx context.Context, caller *UserClaims, zone string) (int, any, error) {
	isOwner, err := app.Storage.IsZoneOwner(caller.PreferredUsername, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check ownership", err)
	}
	if !isOwner {
		return errorResult(http.StatusForbidden, "You are not an owner of this zone", nil)
	}
	owners, err := app.Storage.ListZoneOwners(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to list owners", err)
	}
	if err := app.PowerDns.RotateZoneKeys(ctx, zone, owners); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to rotate keys", err)
	}
	app.Log.Infof("app.ZoneRotateKeys: %s rotated %d key(s) for %s", caller.PreferredUsername, len(owners), zone)
	return http.StatusOK, gin.H{"rotated": len(owners)}, nil
}

// OrphanedZone is a stored zone that is no longer covered by any policy rule for
// its owner (e.g. because the policy was later deleted or changed).
type OrphanedZone struct {
	Zone string `json:"zone"`
	User string `json:"user"`
}

// OrphanedZones returns all stored zones that no current policy would grant to
// their owner anymore. Ownership is checked against the stored username.
func (app *AppData) OrphanedZones() ([]OrphanedZone, error) {
	zones, err := app.Storage.ListAllZones()
	if err != nil {
		return nil, err
	}
	orphaned := make([]OrphanedZone, 0)
	for _, z := range zones {
		owner := &UserClaims{Email: z.Username, PreferredUsername: z.Username}
		allowed, _, err := app.PolicyIsZoneAllowedForUser(z.Zone, owner)
		if err != nil {
			return nil, err
		}
		if !allowed {
			orphaned = append(orphaned, OrphanedZone{Zone: z.Zone, User: z.Username})
		}
	}
	return orphaned, nil
}

func (app *AppData) ZoneCreate(ctx context.Context, username string, zone ZoneResponse) (int, any, error) {
	// Check if zone exists
	if status, msg, err := app.checkZoneExists(zone.Zone); err != nil {
		return status, msg, err
	}

	// Check which zones this nameserver is authoritative for
	authoritative := getAuthoritativeZones(zone.Zone, zone.ZoneSOA)

	// Create all  intermediates zones
	for i, z := range authoritative {
		// Skip the requested zone itself
		if z == zone.Zone {
			continue
		}

		// Determine next child zone
		nextChildZone := next(authoritative, i)

		app.Log.Infof("app.ZoneCreate: Creating intermediate zone '%s' I'm authoritative for (with child zone delegation to %s)", z, nextChildZone)
		if err := app.PowerDns.EnsureIntermediateZoneExists(ctx, z, nextChildZone); err != nil {
			return errorResult(http.StatusInternalServerError, "Failed to ensure intermediate zone exists", err)
		}
	}

	// This is the requested zone, create it
	zoneResponse, err := app.PowerDns.CreateUserZone(ctx, username, zone.Zone, true)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to create zone in DNS server", fmt.Errorf("app.ZoneCreate: %w", err))
	}

	refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
	if _, err := app.Storage.CreateZone(username, zone.Zone, refreshTime); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to create zone in storage", fmt.Errorf("app.ZoneCreate: %w", err))
	}

	return http.StatusCreated, gin.H{"success": zoneResponse}, nil
}

// Generic helper for consistent error returns
func errorResult(code int, msg string, err error) (int, gin.H, error) {
	return code, gin.H{"error": msg}, err
}

// Helper to get next element in slice or empty string if at end
func next(slice []string, i int) string {
	if i+1 < len(slice) {
		return slice[i+1]
	}
	return ""
}

func (app *AppData) checkZoneExists(zone string) (int, any, error) {
	exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to check if zone exists",
			fmt.Errorf("app.checkZoneExists: %w", err))
	}
	if exists {
		return errorResult(http.StatusConflict, "Zone already exists",
			fmt.Errorf("app.checkZoneExists: %s exists", zone))
	}
	return http.StatusOK, nil, nil
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
		"txtPrefix":        "dynamic-zones-dns-",
		"txtOwnerId":       "dynamic-zones-dns",
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

// userCanAccessRule reports whether the email matches the target user filter.
// The filter may be a comma-separated list of patterns; access is granted if
// the email matches ANY entry.
func userCanAccessRule(email string, filter string) (bool, error) {
	for _, p := range strings.Split(filter, ",") {
		if emailMatchesPattern(email, p) {
			return true, nil
		}
	}
	return false, nil
}

func validateUserFilter(filter string) error {
	errInvalidUserFilter := errors.New("user filter must be a comma-separated list of valid emails or wildcard patterns like *@domain.com")

	hasEntry := false
	for _, raw := range strings.Split(filter, ",") {
		p := strings.TrimSpace(raw)
		if p == "" {
			continue // tolerate blank entries / trailing commas
		}
		hasEntry = true

		// At most one wildcard asterisk allowed per entry.
		if strings.Count(p, "*") > 1 {
			return errInvalidUserFilter
		}

		// No wildcard: the entry must be a standard email address.
		if !strings.Contains(p, "*") {
			if _, err := mail.ParseAddress(p); err != nil {
				return errInvalidUserFilter
			}
		}
	}

	if !hasEntry {
		return errInvalidUserFilter
	}
	return nil
}

func isSuperAdmin(app *AppData, user *UserClaims) bool {
	superAdmins := app.Config.DnsPolicyConfig.SuperAdminEmails

	if _, exists := superAdmins[strings.ToLower(user.Email)]; exists {
		return true
	}

	return false
}

// isValidZonePattern converts the provided JavaScript function to Go.
// It validates a zone pattern by temporarily replacing the custom '%u' placeholder
// with a valid character ('A') before performing standard DNS label checks.
func validateZonePattern(value string) error {
	if value == "" {
		return errors.New("No value supplied")
	}

	// 1. Replace '%u' with 'A' and trim whitespace
	s := strings.ReplaceAll(value, "%u", "A")
	s = strings.TrimSpace(s)

	// Use existing DNS domain validation
	return helper.DnsValidateName(s)
}

func filterUserRules(rules []PolicyRule, user *UserClaims) []PolicyRule {
	// Make a new slice to hold filtered rules
	filteredRules := make([]PolicyRule, 0, 10)

	// Only include rules the user can access
	for _, rule := range rules {
		if canAccess, err := userCanAccessRule(user.Email, rule.TargetUserFilter); err == nil && canAccess {
			filteredRules = append(filteredRules, rule)
		}
	}

	return filteredRules
}

func ruleToZoneResponse(rule PolicyRule, user *UserClaims) ZoneResponse {
	// Prepare data for pattern replacement
	userDnsLabel := helper.DnsMakeCompliant(user.Email)
	zone := strings.ReplaceAll(rule.ZonePattern, "%u", userDnsLabel)

	return ZoneResponse{
		Zone:            zone,
		ZoneSOA:         rule.ZoneSoa,
		AllowSubdomains: rule.AllowSubdomains,
		SharingAllowed:  rule.SharingAllowed,
	}
}

func rulesToUserZones(rules []PolicyRule, user *UserClaims) []ZoneResponse {
	zones := make([]ZoneResponse, 0, len(rules))

	for _, rule := range rules {
		zone := ruleToZoneResponse(rule, user)

		// Check if the zone has already been added by another rule
		isDuplicate := false
		for _, existing := range zones {
			if existing.Zone == zone.Zone {
				isDuplicate = true
				break
			}
		}

		if !isDuplicate {
			zones = append(zones, zone)
		}
	}

	return zones
}
