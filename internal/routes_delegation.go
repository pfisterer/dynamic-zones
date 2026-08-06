package app

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const errNotSuperAdmin = "Only super admins can manage delegations"

// DelegationsResponse is the body of GET /v1/policies/delegations.
type DelegationsResponse struct {
	Delegations []DelegationPolicy `json:"delegations"`
}

// OrphanedZonesResponse is the body of GET /v1/policies/orphaned-zones.
type OrphanedZonesResponse struct {
	Zones []OrphanedZone `json:"zones"`
}

// StatusResponse is the body of the endpoints that only report that they ran.
type StatusResponse struct {
	Status string `json:"status" example:"deleted"`
}

// listDelegations lists all delegation policies.
// @Summary List delegation policies
// @Description List every delegation policy. Super-admins only.
// @Tags policies
// @Produce json
// @Success 200 {object} DelegationsResponse "List of delegation policies"
// @Failure 403 {object} ErrorResponse "Caller is not a super admin"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @ID listDelegations
// @Router /v1/policies/delegations [get]
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
		c.JSON(http.StatusOK, DelegationsResponse{Delegations: delegations})
	}
}

// createDelegation creates a delegation policy.
// @Summary Create a delegation policy
// @Description Grant a user (or wildcard filter) the right to manage policy rules for a zone and its subdomains. Super-admins only.
// @Tags policies
// @Accept json
// @Produce json
// @Param delegation body DelegationPolicyRequest true "Delegation policy to create"
// @Success 201 {object} DelegationPolicy "The created delegation policy"
// @Failure 400 {object} ErrorResponse "Invalid request payload"
// @Failure 403 {object} ErrorResponse "Caller is not a super admin"
// @Security ApiKeyAuth
// @ID createDelegation
// @Router /v1/policies/delegations [post]
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

// updateDelegation replaces a delegation policy.
// @Summary Update a delegation policy
// @Description Replace an existing delegation policy. Super-admins only.
// @Tags policies
// @Accept json
// @Produce json
// @Param id path int true "ID of the delegation policy"
// @Param delegation body DelegationPolicyRequest true "New contents of the delegation policy"
// @Success 200 {object} DelegationPolicy "The updated delegation policy"
// @Failure 400 {object} ErrorResponse "Invalid ID or request payload"
// @Failure 403 {object} ErrorResponse "Caller is not a super admin"
// @Security ApiKeyAuth
// @ID updateDelegation
// @Router /v1/policies/delegations/{id} [put]
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

// deleteDelegation removes a delegation policy.
// @Summary Delete a delegation policy
// @Description Revoke a delegated rule-management permission. Existing zones and rules are unaffected. Super-admins only.
// @Tags policies
// @Produce json
// @Param id path int true "ID of the delegation policy"
// @Success 200 {object} StatusResponse "Delegation deleted"
// @Failure 400 {object} ErrorResponse "Invalid ID"
// @Failure 403 {object} ErrorResponse "Caller is not a super admin"
// @Security ApiKeyAuth
// @ID deleteDelegation
// @Router /v1/policies/delegations/{id} [delete]
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
		c.JSON(http.StatusOK, StatusResponse{Status: "deleted"})
	}
}

// --- Orphaned zones (super-admin only): zones that exist but are no longer
//     covered by any policy for their owner (policy deleted/changed).

// listOrphanedZones lists zones no policy covers anymore.
// @Summary List orphaned zones
// @Description Zones that still exist but are no longer covered by any policy for their owner (the policy was deleted or changed). Super-admins only.
// @Tags policies
// @Produce json
// @Success 200 {object} OrphanedZonesResponse "List of orphaned zones"
// @Failure 403 {object} ErrorResponse "Caller is not a super admin"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @ID listOrphanedZones
// @Router /v1/policies/orphaned-zones [get]
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
		c.JSON(http.StatusOK, OrphanedZonesResponse{Zones: zones})
	}
}

// deleteOrphanedZone deletes a zone that no policy covers anymore.
// @Summary Delete an orphaned zone
// @Description Permanently delete an orphaned zone and all of its DNS records. Refuses if a policy still covers the zone — use Zone Management for those. Super-admins only.
// @Tags policies
// @Produce json
// @Param zone path string true "Name of the zone"
// @Success 204 "Zone deleted"
// @Failure 403 {object} ErrorResponse "Caller is not a super admin"
// @Failure 404 {object} ErrorResponse "Zone not found"
// @Failure 409 {object} ErrorResponse "Zone is covered by a policy"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Security ApiKeyAuth
// @ID deleteOrphanedZone
// @Router /v1/policies/orphaned-zones/{zone} [delete]
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
