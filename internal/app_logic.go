package app

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/farberg/dynamic-zones/internal/zones"
	"github.com/gin-gonic/gin"
)

const AppLogicKey = "AppLogicKey"

func InjectAppLogic(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(AppLogicKey, app)
	}
}

func (app *AppData) GetZone(ctx context.Context, username, zone, externalDnsVersion string) (int, any, error) {
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

func (app *AppData) DeleteZone(ctx context.Context, username, zone string) (int, any, error) {
	if err := app.PowerDns.DeleteZone(ctx, zone, true); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to delete zone from DNS server",
			fmt.Errorf("app.DeleteZone: %w", err))
	}

	if err := app.Storage.DeleteZone(username, zone); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to delete zone from storage",
			fmt.Errorf("app.DeleteZone: %w", err))
	}

	app.Log.Infof("app.DeleteZone: %s deleted for user %s", zone, username)
	return http.StatusNoContent, nil, nil
}

func (app *AppData) CreateZone(ctx context.Context, username string, zone zones.ZoneResponse) (int, any, error) {
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

		app.Log.Infof("app.CreateZone: Creating intermediate zone '%s' I'm authoritative for (with child zone delegation to %s)", z, nextChildZone)
		if err := app.PowerDns.EnsureIntermediateZoneExists(ctx, z, nextChildZone); err != nil {
			return errorResult(http.StatusInternalServerError, "Failed to ensure intermediate zone exists", err)
		}
	}

	// This is the requested zone, create it
	zoneResponse, err := app.PowerDns.CreateUserZone(ctx, username, zone.Zone, true)
	if err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to create zone in DNS server", fmt.Errorf("app.CreateZone: %w", err))
	}

	refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
	if _, err := app.Storage.CreateZone(username, zone.Zone, refreshTime); err != nil {
		return errorResult(http.StatusInternalServerError, "Failed to create zone in storage", fmt.Errorf("app.CreateZone: %w", err))
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

func toExternalDNSConfig(app *AppData, pdnsZone *zones.ZoneDataResponse, externalDnsVersion string) (string, error) {
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
