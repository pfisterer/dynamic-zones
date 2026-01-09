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
	Description      string `json:"description"`
}

// PolicyRulesResponse wraps policy rules for list endpoint.
type PolicyRulesResponse struct {
	EditAllowed bool         `json:"edit_allowed"`
	Rules       []PolicyRule `json:"rules"`
}

func (app *AppData) PolicyGetAllUserRules(user *UserClaims) (*PolicyRulesResponse, error) {
	// Get all rules from storage
	rules, err := app.Storage.PolicyGetAll()
	if err != nil {
		app.Log.Errorf("Error retrieving policy rules: %v", err)
		return nil, err
	}

	// Filter the rules based on user email
	is_super_admin := isSuperAdmin(app, user)

	if !is_super_admin {
		filteredRules := make([]PolicyRule, 0)
		for _, rule := range rules {
			if canAccess, err := userCanAccessRule(user.Email, rule.TargetUserFilter); err == nil && canAccess {
				filteredRules = append(filteredRules, rule)
			}
		}
		rules = filteredRules
	}

	return &PolicyRulesResponse{Rules: rules, EditAllowed: is_super_admin}, nil
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

func (app *AppData) ZoneGet(ctx context.Context, username, zone, externalDnsVersion string) (int, any, error) {
	// Get from storage
	storedZone, err := app.Storage.GetZone(username, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to get zone from storage", fmt.Errorf("app.getZone: %w", err))
	}
	if storedZone == nil {
		return errorResult(http.StatusNotFound, "Zone does not exist", fmt.Errorf("app.getZone: zone %s not found", zone))
	}

	// Get from PowerDNS
	pdnsZone, err := app.PowerDns.GetZone(ctx, zone)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to get zone from DNS server", fmt.Errorf("app.getZone: %w", err))
	}

	// Generate external-dns config
	valuesYaml, err := toExternalDNSConfig(app, pdnsZone, externalDnsVersion)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to get external-dns config", fmt.Errorf("app.getZone: %w", err))
	}

	// Return zone data
	app.Log.Infof("app.getZone: returning zone %s", zone)

	return http.StatusOK, gin.H{
		"zoneData":              pdnsZone,
		"externalDnsValuesYaml": valuesYaml,
	}, nil
}

func (app *AppData) ZoneDelete(ctx context.Context, username, zone string) (int, any, error) {
	if err := app.PowerDns.DeleteZone(ctx, zone, true); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to delete zone from DNS server",
			fmt.Errorf("app.ZoneDelete: %w", err))
	}

	if err := app.Storage.DeleteZone(username, zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to delete zone from storage",
			fmt.Errorf("app.ZoneDelete: %w", err))
	}

	app.Log.Infof("app.ZoneDelete: %s deleted for user %s", zone, username)
	return http.StatusNoContent, nil, nil
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
		"dnsServerAddress": app.Config.PowerDns.DnsServerAddress,
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

// userCanAccessRule checks if a user has access to a given policy rule based on the target user filter.
func userCanAccessRule(email string, pattern string) (bool, error) {
	// Normalize both to lowercase for case-insensitive comparison
	patternLower := strings.ToLower(pattern)
	emailLower := strings.ToLower(email)

	// Check that the pattern contains at most one asterisk
	if strings.Count(patternLower, "*") > 1 {
		return false, errors.New("user filter can contain at most one wildcard asterisk")
	}

	// Check if the pattern contains the wildcard
	if !strings.Contains(patternLower, "*") {
		// No asterisk: must be an exact match
		return emailLower == patternLower, nil
	}

	// Split the pattern by the asterisk
	parts := strings.Split(patternLower, "*")

	// A single asterisk splits into two parts
	prefix := parts[0]
	suffix := strings.Join(parts[1:], "")

	// Rule: Match prefix AND match suffix
	// HasPrefix/HasSuffix handle empty strings correctly.
	return strings.HasPrefix(emailLower, prefix) && strings.HasSuffix(emailLower, suffix), nil
}

func validateUserFilter(filter string) error {
	errInvalidUserFilter := errors.New("user filter must be a valid email or a wildcard pattern like *@domain.com")

	// Non-empty check
	if filter == "" {
		return errInvalidUserFilter
	}

	// At most one wildcard asterisk allowed
	if strings.Count(filter, "*") > 1 {
		return errInvalidUserFilter
	}

	// No wildcard: validate as a standard email address
	if !strings.Contains(filter, "*") {
		_, err := mail.ParseAddress(filter)
		if err != nil {
			return errInvalidUserFilter
		}
		return nil
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
