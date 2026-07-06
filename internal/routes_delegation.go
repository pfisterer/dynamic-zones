package app

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const errNotSuperAdmin = "Only super admins can manage delegations"

func listDelegations(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": errNotSuperAdmin})
			return
		}
		delegations, err := app.DelegationGetAll()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve delegations"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"delegations": delegations})
	}
}

func createDelegation(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": errNotSuperAdmin})
			return
		}
		var req DelegationPolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}
		created, err := app.DelegationCreate(req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusCreated, created)
	}
}

func updateDelegation(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": errNotSuperAdmin})
			return
		}
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid delegation ID"})
			return
		}
		var req DelegationPolicyRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}
		updated, err := app.DelegationUpdate(id, req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, updated)
	}
}

func deleteDelegation(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": errNotSuperAdmin})
			return
		}
		id, err := strconv.ParseInt(c.Param("id"), 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid delegation ID"})
			return
		}
		if err := app.DelegationDelete(id); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}

// --- Orphaned zones (super-admin only): zones that exist but are no longer
//     covered by any policy for their owner (policy deleted/changed).

func listOrphanedZones(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can view orphaned zones"})
			return
		}
		zones, err := app.OrphanedZones()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list orphaned zones"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"zones": zones})
	}
}

func deleteOrphanedZone(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can delete orphaned zones"})
			return
		}
		zoneName := c.Param("zone")
		z, err := app.Storage.GetZoneByName(zoneName)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to look up zone"})
			return
		}
		if z == nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Zone not found"})
			return
		}
		// Safety: only delete through this endpoint if the zone really is orphaned.
		owner := &UserClaims{Email: z.Username, PreferredUsername: z.Username}
		allowed, _, err := app.PolicyIsZoneAllowedForUser(zoneName, owner)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check zone"})
			return
		}
		if allowed {
			c.JSON(http.StatusConflict, gin.H{"error": "Zone is covered by a policy; delete it via Zone Management instead"})
			return
		}
		statusCode, returnValue, err := app.ZoneDelete(c.Request.Context(), z.Username, zoneName)
		if err != nil {
			app.Log.Error("deleteOrphanedZone failed: ", err)
		}
		c.JSON(statusCode, returnValue)
	}
}
