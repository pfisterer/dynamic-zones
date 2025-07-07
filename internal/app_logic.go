package app

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/farberg/dynamic-zones/internal/zones"
	"github.com/gin-gonic/gin"
)

const AppLogicKey = "AppLogicKey"

func InjectAppLogic(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(AppLogicKey, app)
	}
}

func (app *AppData) GetZone(ctx context.Context, username string, zone string) (statusCode int, message any, err error) {
	// Get zone from storage (if it exists, the user is allowed to access it)
	stored_zone, err := app.Storage.GetZone(username, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get zone from storage"},
			fmt.Errorf("app.getZone: Failed to get zone from storage: %v", err)
	}

	if stored_zone == nil {
		return http.StatusNotFound,
			gin.H{"error": "Zone does not exist"},
			fmt.Errorf("app.getZone: Zone %s does not exist", zone)
	}

	// Get zone from PowerDNS
	pnds_zone, err := zones.GetZone(ctx, app.Pdns, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to get zone from DNS server"},
			fmt.Errorf("app.getZone: Failed to get zone from PowerDNS: %v", err)
	}

	app.Log.Info("app.getZone: returning response: ", pnds_zone)
	return http.StatusOK, pnds_zone, nil
}

func (app *AppData) CreateZone(ctx context.Context, username string, zone string) (statusCode int, message any, err error) {

	//Check if the zone already exists
	zone_exists, err := app.Storage.ZoneExists(zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to check if zone exists"},
			fmt.Errorf("app.CreateZone zone: Failed to check if zone exists: %v", zone)

	} else if zone_exists {
		return http.StatusConflict,
			gin.H{"error": "Zone already exists"},
			fmt.Errorf("app.CreateZone zone: Zone %s already exists", zone)
	}

	// Create the zone in PowerDNS
	zoneResponse, err := zones.CreateZone(ctx, app.Pdns, username, zone, true)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to create zone in DNS server"},
			fmt.Errorf("app.CreateZone zone: Failed to create zone in PowerDNS: %v", err)
	}

	// Create the new zone in storage
	refreshTime := time.Now().Add(time.Duration(app.RefreshTime) * time.Second)
	_, err = app.Storage.CreateZone(username, zone, refreshTime)
	if err != nil {
		return http.StatusInternalServerError,

			gin.H{"error": "Failed to create zone"},
			fmt.Errorf("app.CreateZone zone: Failed to create zone: %v", err)
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
			fmt.Errorf("app.Delete zone: Failed to delete zone from PowerDNS: %v", err)
	}

	// Delete the zone
	err = app.Storage.DeleteZone(username, zone)
	if err != nil {
		return http.StatusInternalServerError,
			gin.H{"error": "Failed to delete zone from storage"},
			fmt.Errorf("app.Delete zone: Failed to delete zone from storage: %v", err)
	}

	app.Log.Info("app.Delete zone: Deleted zone: ", zone, " for user: ", username)
	return http.StatusNoContent,
		nil,
		nil
}
