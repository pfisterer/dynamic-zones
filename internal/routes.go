package app

import (
	"net/http"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/gin-gonic/gin"
)

func CreateApiV1Group(v1 *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	v1.GET("/zones/", getZones(app))
	v1.GET("/zones/:zone/", getZone(app))
	v1.POST("/zones/:zone", postZone(app))
	v1.DELETE("/zones/:zone", deleteZone(app))

	return v1
}

// AvailableZonesResponse defines the structure of the response for the /v1/zones/ endpoint.
type AvailableZonesResponse struct {
	Zones []ZoneStatus `json:"zones"`
}

type ZoneStatus struct {
	Name   string `json:"name"`
	Exists bool   `json:"exists"`
}

// getZones returns a list of available DNS zones for the authenticated user.
//
//	@Summary		Get available zones
//	@Description	Retrieves a list of DNS zones that the user is allowed to access.
//	@Tags			zones
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@Success		200	{object}	AvailableZonesResponse	"A list of available zones."
//	@Router			/v1/zones/ [get]
func getZones(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		app.Log.Debug("routes.getZones: Called with user: ", user.PreferredUsername)
		userZones := app.Uzp.GetUserZones(user)
		zonesWithStatus := make([]ZoneStatus, 0, len(userZones))

		for _, zone := range userZones {
			_, _, err := app.GetZone(c.Request.Context(), user.PreferredUsername, zone)
			zonesWithStatus = append(zonesWithStatus, ZoneStatus{Name: zone, Exists: err == nil})
		}

		zones := AvailableZonesResponse{Zones: zonesWithStatus}

		c.JSON(http.StatusOK, zones)
	}
}

// getZone retrieves a specific DNS zone.
//
//	@Summary		Get a DNS zone
//	@Description	Retrieves a specific DNS zone by its name.
//	@Tags			zones
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@Param		zone	path	string	true	"The name of the zone to retrieve."
//	@Success		200	{object}	zones.ZoneDataResponse	"The requested DNS zone."
//	@Failure		404	{object}	map[string]any	"Zone not found."
//	@Failure		500	{object}	map[string]any	"Internal server error."
//	@Router			/v1/zones/{zone} [get]
func getZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		zone := c.Param("zone")
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		app.Log.Debug("routes.getZone: called with zone: ", zone, " and user: ", user.PreferredUsername)

		statusCode, returnValue, err := app.GetZone(ctx, user.PreferredUsername, zone)
		if err != nil {
			app.Log.Warnf("routes.getZone: zone '%s' does not exist: %w", zone, err)
		}

		c.JSON(statusCode, returnValue)
	}
}

// postZone creates a new DNS zone.
//
//	@Summary		Create a DNS zone
//	@Description	Creates a new DNS zone with the given name.
//	@Tags			zones
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@Param		zone	path	string	true	"The name of the zone to create."
//	@Success		201	{object}	zones.ZoneDataResponse	"The created DNS zone."
//	@Failure		400	{object}	map[string]any	"Bad request."
//	@Failure		403	{object}	map[string]any	"Forbidden."
//	@Failure		409	{object}	map[string]any	"Conflict."
//	@Failure		500	{object}	map[string]any	"Internal server error."
//	@Router			/v1/zones/{zone} [post]
func postZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		zone := c.Param("zone")
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		// Ensure the user is allowed to create the zone
		if !app.Uzp.IsAllowedZone(user, zone) {
			app.Log.Error("routes.postZone: User is not allowed to create zone: ", zone, " for user: ", user.PreferredUsername)
			c.JSON(http.StatusForbidden, gin.H{"error": "User is not allowed to create this zone"})
			return
		}
		app.Log.Infof("routes.postZone: User is allowed to create zone: %s for user: %s", zone, user.PreferredUsername)

		statusCode, returnValue, err := app.CreateZone(ctx, user.PreferredUsername, zone)
		if err != nil {
			app.Log.Error("routes.postZone: failed: ", err)
		}
		c.JSON(statusCode, returnValue)
	}
}

// deleteZone deletes a DNS zone.
//
//	@Summary		Delete a DNS zone
//	@Description	Deletes a DNS zone by its name.
//	@Tags			zones
//	@Security		Bearer
//	@Param		zone	path	string	true	"The name of the zone to delete."
//	@Success		204	"No content."
//	@Failure		403	{object}	map[string]any	"Forbidden."
//	@Failure		500	{object}	map[string]any	"Internal server error."
//	@Router			/v1/zones/{zone} [delete]
func deleteZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		zone := c.Param("zone")
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		app.Log.Debug("routes.deleteZone: Delete zone called for zone: ", zone, " and user: ", user.PreferredUsername)

		// Check if the user is allowed to delete the zone
		if !app.Uzp.IsAllowedZone(user, zone) {
			app.Log.Error("routes.deleteZone: User is not allowed to delete zone: ", zone, " for user: ", user.PreferredUsername)
			c.JSON(http.StatusForbidden, gin.H{"error": "User is not allowed to delete this zone"})
			return
		}

		statusCode, returnValue, err := app.DeleteZone(ctx, user.PreferredUsername, zone)
		if err != nil {
			app.Log.Error("routes.deleteZone: deleteZone failed: ", err)
		}

		c.JSON(statusCode, returnValue)
	}
}
