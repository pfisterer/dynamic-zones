package app

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func CreateApiV1Zones(v1 *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	v1.GET("/zones/", getZones(app))
	v1.GET("/zones/:zone", getZone(app))
	v1.POST("/zones/:zone", postZone(app))
	v1.DELETE("/zones/:zone", deleteZone(app))

	// Explicit join: a policy-entitled user becomes a co-owner of a shareable zone.
	v1.POST("/zones/:zone/join", joinZone(app))

	// Zone sharing: manage co-owners and rotate keys (owner-only).
	v1.GET("/zones/:zone/owners", listZoneOwners(app))
	v1.POST("/zones/:zone/owners", addZoneOwner(app))
	v1.DELETE("/zones/:zone/owners/:owner", removeZoneOwner(app))
	v1.POST("/zones/:zone/keys/rotate", rotateZoneKeys(app))

	return v1
}

// AddOwnerRequest is the request body for adding a zone owner.
type AddOwnerRequest struct {
	Email string `json:"email" binding:"required"`
}

// joinZone lets a policy-entitled user become a co-owner of a shareable zone.
//
//	@Summary		Join a shared zone
//	@Description	Makes the caller a co-owner (own row + own TSIG key) of an existing zone they are policy-entitled to and whose rule allows sharing.
//	@Tags			zones
//	@Produce		json
//	@Security		Bearer
//	@Param			zone	path		string			true	"The zone name."
//	@Success		200		{object}	map[string]any	"The updated owner list."
//	@ID				joinZone
//	@Router			/v1/zones/{zone}/join [post]
func joinZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		zone := c.Param("zone")
		status, resp, _ := app.ZoneJoin(c.Request.Context(), user, zone)
		c.JSON(status, resp)
	}
}

// listZoneOwners lists the owners of a zone.
//
//	@Summary		List zone owners
//	@Description	Lists the users that currently manage (own) a zone.
//	@Tags			zones
//	@Produce		json
//	@Security		Bearer
//	@Param			zone	path		string			true	"The zone name."
//	@Success		200		{object}	map[string]any	"The zone owners."
//	@ID				listZoneOwners
//	@Router			/v1/zones/{zone}/owners [get]
func listZoneOwners(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		zone := c.Param("zone")
		isOwner, err := app.Storage.IsZoneOwner(user.Identity(), zone)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check ownership"})
			return
		}
		if !isOwner {
			c.JSON(http.StatusForbidden, gin.H{"error": "You are not an owner of this zone"})
			return
		}
		owners, err := app.Storage.ListZoneOwners(zone)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list owners"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"owners": owners})
	}
}

// addZoneOwner adds a co-owner to a zone.
//
//	@Summary		Add a zone owner
//	@Description	Adds a user as a co-owner (own row + own TSIG key). Owner-only; the zone must be shareable.
//	@Tags			zones
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@Param			zone	path		string			true	"The zone name."
//	@Param			body	body		AddOwnerRequest	true	"The owner to add."
//	@Success		200		{object}	map[string]any	"The updated owner list."
//	@ID				addZoneOwner
//	@Router			/v1/zones/{zone}/owners [post]
func addZoneOwner(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		zone := c.Param("zone")
		var req AddOwnerRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
			return
		}
		status, resp, _ := app.ZoneAddOwner(c.Request.Context(), user, zone, req.Email)
		c.JSON(status, resp)
	}
}

// removeZoneOwner removes a co-owner from a zone.
//
//	@Summary		Remove a zone owner
//	@Description	Removes a co-owner (row + their TSIG key). Owner-only; the last owner cannot be removed.
//	@Tags			zones
//	@Produce		json
//	@Security		Bearer
//	@Param			zone	path		string			true	"The zone name."
//	@Param			owner	path		string			true	"The owner email to remove."
//	@Success		200		{object}	map[string]any	"The updated owner list."
//	@ID				removeZoneOwner
//	@Router			/v1/zones/{zone}/owners/{owner} [delete]
func removeZoneOwner(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		zone := c.Param("zone")
		owner := c.Param("owner")
		status, resp, _ := app.ZoneRemoveOwner(c.Request.Context(), user, zone, owner)
		c.JSON(status, resp)
	}
}

// rotateZoneKeys regenerates every owner's TSIG key for a zone.
//
//	@Summary		Rotate zone keys
//	@Description	Regenerates the TSIG key of every owner (e.g. after a suspected key compromise). Owner-only; all owners must re-fetch their key.
//	@Tags			zones
//	@Produce		json
//	@Security		Bearer
//	@Param			zone	path		string			true	"The zone name."
//	@Success		200		{object}	map[string]any	"Rotation result."
//	@ID				rotateZoneKeys
//	@Router			/v1/zones/{zone}/keys/rotate [post]
func rotateZoneKeys(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		zone := c.Param("zone")
		status, resp, _ := app.ZoneRotateKeys(c.Request.Context(), user, zone)
		c.JSON(status, resp)
	}
}

// AvailableZonesResponse defines the structure of the response for the /v1/zones/ endpoint.
type AvailableZonesResponse struct {
	Zones []ZoneStatus `json:"zones"`
}

type ZoneStatus struct {
	Name                      string `json:"name"`
	Exists                    bool   `json:"exists"`
	AlreadyTakenBySomeoneElse bool   `json:"already_taken_by_someone_else,omitempty"`
	// CanJoin: the zone exists, the user is policy-entitled and sharing is on, but
	// they are not yet an owner -> they may explicitly join it.
	CanJoin bool `json:"can_join,omitempty"`
	// AllowSubdomains: the user may create delegated subzones under this zone.
	AllowSubdomains bool `json:"allow_subdomains"`
	// Parent: for a created subzone, the base zone it is delegated under
	// (empty for policy base zones). Lets the UI indent subzones under their parent.
	Parent string `json:"parent,omitempty"`
	// Owners: the users currently managing this (existing) zone. Shown in the UI
	// so a shared zone's co-owners are visible before opening it.
	Owners []string `json:"owners,omitempty"`
	// SharingAllowed: whether this zone may be shared (governing rule opt-in).
	SharingAllowed bool `json:"sharing_allowed"`
}

// getZones returns a list of available DNS zones for the authenticated user.
//
//	@Summary		Get available zones
//	@Description	Retrieves a list of DNS zones that the user is allowed to access.
//	@Tags			zones
//	@Accept			json
//	@Produce		json
//	@Security		Bearer
//	@ID				listZones
//	@Success		200	{object}	AvailableZonesResponse	"A list of available zones."
//	@Router			/v1/zones/ [get]
func getZones(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 Called with user: ", user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		zonesWithStatus, err := app.ZoneList(user)
		if err != nil {
			app.Log.Errorf("Error listing zones: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user zones"})
			return
		}

		zones := AvailableZonesResponse{Zones: zonesWithStatus}

		app.Log.Debug("🟢 Returning zones: ", zones)
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
//	@Query	  format  string    "The format of the response. If 'external-dns' is specified, the response will be formatted for ExternalDNS."
//	@Success		200	{object}	ZoneDataResponse	"The requested DNS zone."
//	@Failure		404	{object}	map[string]any	"Zone not found."
//	@Failure		500	{object}	map[string]any	"Internal server error."
//	@ID				getZone
//	@Router			/v1/zones/{zone} [get]
func getZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		zone := c.Param("zone")
		format := c.Query("format")
		user := c.MustGet(UserDataKey).(*UserClaims)
		externalDnsVersion := c.DefaultQuery("image-version", app.Config.WebServer.ExternalDnsVersion)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 getZone: called with zone: ", zone, " and user: ", user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		statusCode, returnValue, err := app.ZoneGet(ctx, user, zone, externalDnsVersion)

		if err != nil {
			app.Log.Warnf("getZone: zone '%s' error: %w", zone, err)
		}

		if format == "external-dns" && statusCode == http.StatusOK {
			app.Log.Debugf("getZone: format=external-dns for part '%s' requested, transforming response to plain YAML", zone)

			var returnMap map[string]any

			if hMap, ok := returnValue.(gin.H); ok {
				returnMap = map[string]any(hMap)
			} else if genericMap, ok := returnValue.(map[string]any); ok {
				returnMap = genericMap
			} else {
				app.Log.Errorf("getZone: Failed to cast success returnValue (%T) to map[string]any or gin.H", returnValue)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal configuration error: Invalid response format from GetZone"})
				return
			}

			yamlValue, exists := returnMap["externalDnsValuesYaml"]
			if !exists {
				app.Log.Errorf("getZone: Key 'externalDnsValuesYaml' missing from successful response map")
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal configuration error: Missing external-dns data in response"})
				return
			}

			yamlString, ok := yamlValue.(string)
			if !ok {
				app.Log.Errorf("getZone: Failed to cast externalDnsValuesYaml value (%T) to string", yamlValue)
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal configuration error: external-dns data is not a string"})
				return
			}

			c.String(http.StatusOK, yamlString)
			return
		}

		// Default return for JSON format or any non-200 status code
		app.Log.Debug("🟢 getZoneReturning zone with status ", statusCode)
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
//	@Success		201	{object}	ZoneDataResponse	"The created DNS zone."
//	@Failure		400	{object}	map[string]any	"Bad request."
//	@Failure		403	{object}	map[string]any	"Forbidden."
//	@Failure		409	{object}	map[string]any	"Conflict."
//	@Failure		500	{object}	map[string]any	"Internal server error."
//	@ID				createZone
//	@Router			/v1/zones/{zone} [post]
func postZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		zone := c.Param("zone")
		user := c.MustGet(UserDataKey).(*UserClaims)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 Create zone called for zone: ", zone, " and user: ", user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		zoneData, err := app.ZoneCreateAuthorized(ctx, user, zone)
		if err != nil {
			app.Log.Warnf("postZone: %v", err)
			c.JSON(StatusOf(err), gin.H{"error": MessageOf(err)})
			return
		}

		app.Log.Debugf("🟢 Created zone '%s'", zone)
		c.JSON(http.StatusCreated, gin.H{"success": zoneData})
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
//	@ID				deleteZone
//	@Router			/v1/zones/{zone} [delete]
func deleteZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := c.Request.Context()
		zone := c.Param("zone")
		user := c.MustGet(UserDataKey).(*UserClaims)

		app.Log.Debug("-------------------------------------------------------------------------------")
		app.Log.Debug("🚀 Delete zone called for zone: ", zone, " and user: ", user.Identity())
		app.Log.Debug("-------------------------------------------------------------------------------")

		if err := app.ZoneDeleteAuthorized(ctx, user, zone); err != nil {
			app.Log.Warnf("deleteZone: %v", err)
			c.JSON(StatusOf(err), gin.H{"error": MessageOf(err)})
			return
		}

		app.Log.Debugf("🟢 Deleted zone '%s'", zone)
		c.Status(http.StatusNoContent)
	}
}
