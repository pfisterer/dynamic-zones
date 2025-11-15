package app

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
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

func (app *AppData) GetZone(ctx context.Context, username string, zone string, externalDnsVersion string) (statusCode int, message any, err error) {
	// Get zone from storage (if it exists, the user is allowed to access it)
	stored_zone, err := app.Storage.GetZone(username, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get zone from storage"},
			fmt.Errorf("💥 app.getZone: Failed to get zone from storage: %v", err)
	}

	if stored_zone == nil {
		return http.StatusNotFound,
			gin.H{"error": "Zone does not exist"},
			fmt.Errorf("💥 app.getZone: Zone %s does not exist", zone)
	}

	// Get zone from PowerDNS
	pnds_zone, err := zones.GetZone(ctx, app.Pdns, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get zone from DNS server"},
			fmt.Errorf("💥 app.getZone: Failed to get zone from PowerDNS: %v", err)
	}

	// Get the external-dns config for the zone
	valuesYaml, err := toExternalDNSConfig(app, pnds_zone, externalDnsVersion)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get external-dns config"},
			fmt.Errorf("💥 app.getZone: Failed to get external-dns config: %v", err)
	}

	// Return the data to the client
	returnValue := map[string]any{
		"zoneData":              pnds_zone,
		"externalDnsValuesYaml": valuesYaml,
	}

	app.Log.Info("app.getZone: returning response: ", pnds_zone)
	return http.StatusOK, returnValue, nil
}

func (app *AppData) CreateZone(ctx context.Context, username string, zone string) (statusCode int, message any, err error) {

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

	// Create the zone in PowerDNS
	if (app.Config.UpstreamDns.Name == "") || (app.Config.UpstreamDns.Zone == "") {
		return http.StatusInternalServerError,
			gin.H{"error": "Upstream DNS configuration is incomplete, unable to create zone"},
			fmt.Errorf("💥 app.CreateZone zone: Upstream DNS configuration is incomplete (Name: '%s', Zone: '%s')", app.Config.UpstreamDns.Name, app.Config.UpstreamDns.Zone)
	}

	thisNsServer := fmt.Sprintf("%s.%s", app.Config.UpstreamDns.Name, app.Config.UpstreamDns.Zone)
	zoneResponse, err := zones.CreateZone(ctx, app.Pdns, username, zone, true, []string{thisNsServer})
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to create zone in DNS server"},
			fmt.Errorf("💥 app.CreateZone zone: Failed to create zone in PowerDNS: %v", err)
	}

	// Create the new zone in storage
	refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
	_, err = app.Storage.CreateZone(username, zone, refreshTime)
	if err != nil {
		return http.StatusInternalServerError,

			gin.H{"error": "Failed to create zone"},
			fmt.Errorf("💥 app.CreateZone zone: Failed to create zone: %v", err)
	}

	return http.StatusCreated,
		gin.H{"success": zoneResponse},
		nil
}

func (app *AppData) DeleteZone(ctx context.Context, username string, zone string) (statusCode int, message any, err error) {
	// Delete the zone from PowerDNS
	err = zones.DeleteZone(ctx, app.Pdns, zone, true)
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
