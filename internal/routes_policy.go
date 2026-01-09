package app

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

type ZoneResponse struct {
	// The DNS zone name (e.g., "my-user.users.example.com")
	Zone string `json:"zone"`
	// The zone name from which on this nameserver is authoritative (e.g., "users.example.com")
	ZoneSOA string `json:"zone_soa"`
}

// CreatePolicyApiGroup sets up the /policies API group and its routes.
func CreatePolicyApiGroup(group *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	// Assuming the group is mounted at /v1/policies
	group.GET("/policies/rules", listPolicyRules(app))
	group.POST("/policies/rules", createPolicyRule(app))
	group.PUT("/policies/rules/:id", updatePolicyRule(app))
	group.DELETE("/policies/rules/:id", deletePolicyRule(app))

	return group
}

// listPolicyRules lists all policy rules.
// @Summary List policy rules
// @Description List all DNS policy rules. Non-SuperAdmins only see rules matching their user filter.
// @Tags policies
// @Produce json
// @Success 200 {object} PolicyRulesResponse "List of policy rules"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules [get]
func listPolicyRules(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		response, err := app.PolicyGetAllUserRules(user)

		if err != nil {
			errorMessage := fmt.Sprintf("Failed to retrieve policy rules for user %s: %v", user.Email, err)
			app.Log.Warnf(errorMessage)
			c.JSON(http.StatusInternalServerError, gin.H{"error": errorMessage})
			return
		}

		// Return the rules
		c.JSON(http.StatusOK, *response)
	}
}

// createPolicyRule creates a new policy rule (super-admin only).
// @Summary Create a policy rule
// @Description Creates a new DNS policy rule. Only SuperAdmins are authorized.
// @Tags policies
// @Accept json
// @Produce json
// @Param rule body PolicyRuleRequest true "Policy rule payload"
// @Success 201 {object} PolicyRule "The newly created policy rule"
// @Failure 400 {object} map[string]string "Invalid request or validation error"
// @Failure 403 {object} map[string]string "Forbidden: Not a SuperAdmin"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules [post]
func createPolicyRule(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		// Only super admins can manage rules
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can manage rules"})
			return
		}

		// Unmarshal and validate request body
		var req PolicyRuleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Create Policy
		createdRule, err := app.PolicyCreateRule(req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, createdRule)
	}
}

// updatePolicyRule updates an existing policy rule (super-admin only).
// @Summary Update a policy rule
// @Description Updates an existing DNS policy rule by ID. Only SuperAdmins are authorized.
// @Tags policies
// @Accept json
// @Produce json
// @Param id path int true "Rule ID"
// @Param rule body PolicyRuleRequest true "Policy rule payload"
// @Success 200 {object} PolicyRule "The updated policy rule"
// @Failure 400 {object} map[string]string "Invalid rule ID, request payload, or validation error"
// @Failure 403 {object} map[string]string "Forbidden: Not a SuperAdmin"
// @Failure 404 {object} map[string]string "Rule not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules/{id} [put]
func updatePolicyRule(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		// Only super admins can manage rules
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can manage rules"})
			return
		}

		// Get rule ID to update from path
		idStr := c.Param("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
			return
		}

		// Unmarshal and validate the request
		var req PolicyRuleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Update the rule
		updatedRule, err := app.PolicyUpdateRule(id, req)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, updatedRule)
	}
}

// deletePolicyRule deletes a policy rule (super-admin only).
// @Summary Delete a policy rule
// @Description Deletes a DNS policy rule by ID. Only SuperAdmins are authorized.
// @Tags policies
// @Produce json
// @Param id path int true "Rule ID"
// @Success 200 {object} map[string]string "Rule successfully deleted"
// @Failure 400 {object} map[string]string "Invalid rule ID"
// @Failure 403 {object} map[string]string "Forbidden: Not a SuperAdmin"
// @Failure 404 {object} map[string]string "Rule not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules/{id} [delete]
func deletePolicyRule(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)

		// Only super admins can manage rules
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can manage rules"})
			return
		}

		// Get rule ID to update from path
		idStr := c.Param("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
			return
		}

		// Delete the rule
		err = app.PolicyDeleteRule(id)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}

// --- Validation Helpers
