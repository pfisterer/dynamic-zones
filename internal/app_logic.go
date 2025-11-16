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

func (app *AppData) GetZone(ctx context.Context, username, zone, externalDnsVersion string) (statusCode int, message any, err error) {
	// Get zone from storage (if it exists, the user is allowed to access it)
	stored_zone, err := app.Storage.GetZone(username, zone)
	if err != nil {
		return http.StatusInternalServerError, gin.H{"error": "Failed to get zone from storage"}, fmt.Errorf("💥 app.getZone: Failed to get zone from storage: %v", err)
	}

	if stored_zone == nil {
		return http.StatusNotFound,
			gin.H{"error": "Zone does not exist"}, fmt.Errorf("💥 app.getZone: Zone %s does not exist", zone)
	}

	// Get zone from PowerDNS
	pnds_zone, err := app.PowerDns.GetZone(ctx, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get zone from DNS server"}, fmt.Errorf("💥 app.getZone: Failed to get zone from PowerDNS: %v", err)
	}

	// Get the external-dns config for the zone
	valuesYaml, err := toExternalDNSConfig(app, pnds_zone, externalDnsVersion)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get external-dns config"}, fmt.Errorf("💥 app.getZone: Failed to get external-dns config: %v", err)
	}

	// Return the data to the client
	returnValue := map[string]any{
		"zoneData":              pnds_zone,
		"externalDnsValuesYaml": valuesYaml,
	}

	app.Log.Info("app.getZone: returning response: ", pnds_zone)
	return http.StatusOK, returnValue, nil
}

func (app *AppData) checkZoneExissts(zone string) (statusCode int, message any, err error) {
	//Check if the zone already exists
	zone_exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to check if zone exists"},
			fmt.Errorf("💥 app.CreateZone zone: Failed to check if zone exists: %v", zone)

	} else if zone_exists {
		return http.StatusConflict,
			gin.H{"error": "Zone already exists"},
			fmt.Errorf("💥 app.CreateZone zone: Zone %s already exists", zone)
	}

	return http.StatusOK, nil, nil
}

func (app *AppData) CreateZone(ctx context.Context, username string, zone zones.ZoneResponse) (statusCode int, message any, err error) {
	// Check if the zone already exists
	if statusCode, message, err := app.checkZoneExissts(zone.Zone); err != nil {
		return statusCode, message, err
	}

	var zoneResponse *zones.ZoneDataResponse

	// Check which Zones we are authoritative for
	authoritative_zones := collectAuthoritativeZones(zone.Zone, zone.ZoneSOA)
	for _, auth_zone := range authoritative_zones {
		is_requested := auth_zone == zone.Zone
		app.Log.Info("app.CreateZone: We are authoritative for: ", auth_zone)

		// Create all zones we are authoritative for in PowerDNS
		// Only store the requested zone in our Storage
		if !is_requested {
			app.Log.Debugf("Creating intermediate zone %s without storage entry", auth_zone)
			err = app.PowerDns.EnsureIntermediateZoneExists(ctx, auth_zone)
			if err != nil {
				return http.StatusInternalServerError,
					gin.H{"error": "Failed to ensure intermediate zone " + auth_zone + " exists in DNS server"},
					fmt.Errorf("💥 app.CreateZone zone: Failed to ensure intermediate zone %s exists in PowerDNS: %v", auth_zone, err)
			}
		} else {
			app.Log.Debugf("Creating requested zone %s", auth_zone)

			// Create in PowerDNS
			zoneResponse, err = app.PowerDns.CreateZone(ctx, username, auth_zone /* force = */, true)
			if err != nil {
				return http.StatusInternalServerError,
					gin.H{"error": "Failed to create zone " + auth_zone + " in DNS server"},
					fmt.Errorf("💥 app.CreateZone zone: Failed to create %s zone in PowerDNS: %v", auth_zone, err)
			}
			// Create in Storage
			refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
			_, err = app.Storage.CreateZone(username, auth_zone, refreshTime)
			if err != nil {
				return http.StatusInternalServerError,
					gin.H{"error": "Failed to create zone " + auth_zone + " in storage"},
					fmt.Errorf("💥 app.CreateZone zone: Failed to create zone %s: %v", auth_zone, err)
			}
		}

	}

	return http.StatusCreated, gin.H{"success": zoneResponse}, nil
}

func (app *AppData) DeleteZone(ctx context.Context, username string, zone string) (statusCode int, message any, err error) {
	// Delete the zone from PowerDNS
	err = app.PowerDns.DeleteZone(ctx, zone, true)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to delete zone from DNS server"},
			fmt.Errorf("💥 app.Delete zone: Failed to delete zone from PowerDNS: %v", err)
	}

	// Delete the zone
	err = app.Storage.DeleteZone(username, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to delete zone from storage"},
			fmt.Errorf("💥 app.Delete zone: Failed to delete zone from storage: %v", err)
	}

	app.Log.Info("app.Delete zone: Deleted zone: ", zone, " for user: ", username)
	return http.StatusNoContent,
		nil,
		nil
}

func toExternalDNSConfig(app *AppData, pnds_zone *zones.ZoneDataResponse, externalDnsVersion string) (string, error) {
	txtPrefix := "dynamic-zones-dns-"
	txtOwnerId := "dynamic-zones-dns"

	templateData := map[string]any{
		"txtPrefix":        txtPrefix,
		"txtOwnerId":       txtOwnerId,
		"dnsServerAddress": app.Config.PowerDns.DnsServerAddress,
		"dnsServerPort":    app.Config.PowerDns.DnsServerPort,
		"zone":             pnds_zone.Zone,
		"tsigKey":          pnds_zone.ZoneKeys[0].Key,
		"tsigAlgorithm":    pnds_zone.ZoneKeys[0].Algorithm,
		"tsigKeyname":      pnds_zone.ZoneKeys[0].Keyname,
		"secretName":       fmt.Sprintf("external-dns-rfc2136-%s-secret", pnds_zone.Zone),
		"imageVersion":     externalDnsVersion,
	}

	// Create the values yaml file
	tmpl, err := template.New("external-dns").Parse(helper.ExternalDNSValuesYamlTemplate)

	if err != nil {
		app.Log.Panicf("toExternalDNSConfig: Unable to parse the external-dns template: ", err)
		return "", fmt.Errorf("toExternalDNSConfig: Unable to parse the external-dns template: %v", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, templateData); err != nil {
		app.Log.Panicf("toExternalDNSConfig: Unable to execute the external-dns template: ", err)
		return "", fmt.Errorf("toExternalDNSConfig: Unable to execute the external-dns template: %v", err)
	}

	return buf.String(), nil
}

// collectAuthoritativeZones returns the slice of domain names (in “parent” chain) from fullName
// down to and including soaBase. E.g. fullName="a.b.c.d.e", soaBase="c.d.e" → ["c.d.e","b.c.d.e","a.b.c.d.e"]
// The returned slice is ordered shortest to longest.
func collectAuthoritativeZones(fullName, soaBase string) []string {
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
		candidate := strings.Join(parts[i:], ".")
		result = append(result, candidate)
	}

	// Reverse the slice to order from shortest entry first (soaBase to fullName)
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}
