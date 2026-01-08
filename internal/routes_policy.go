package app

import (
	"errors"
	"net/http"
	"net/mail"
	"strconv"
	"strings"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/farberg/dynamic-zones/internal/storage"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// PolicyRuleRequest is used for create/update operations.
type PolicyRuleRequest struct {
	ZonePattern      string `json:"zone_pattern" binding:"required"`
	ZoneSoa          string `json:"zone_soa" binding:"required"`
	TargetUserFilter string `json:"target_user_filter" binding:"required"`
	Description      string `json:"description"`
}

// RulesResponse wraps policy rules for list endpoint.
type RulesResponse struct {
	EditAllowed bool                 `json:"edit_allowed"`
	Rules       []storage.PolicyRule `json:"rules"`
}

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

func listUserRules(app *AppData, user *auth.UserClaims, is_super_admin bool) ([]storage.PolicyRule, error) {
	// Get all rules from storage
	rules, err := app.Storage.PolicyGetAll()
	if err != nil {
		// Log the error (not shown here)
		return nil, err
	}

	// Filter the rules based on user email
	if !is_super_admin {
		filteredRules := make([]storage.PolicyRule, 0)
		for _, rule := range rules {
			if canAccess, err := userCanAccessRule(user.Email, rule.TargetUserFilter); err == nil && canAccess {
				filteredRules = append(filteredRules, rule)
			}
		}
		rules = filteredRules
	}

	return rules, nil
}

// listPolicyRules lists all policy rules.
// @Summary List policy rules
// @Description List all DNS policy rules. Non-SuperAdmins only see rules matching their user filter.
// @Tags policies
// @Produce json
// @Success 200 {object} RulesResponse "List of policy rules"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules [get]
func listPolicyRules(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)
		is_super_admin := isSuperAdmin(app, user)

		// Get all rules from storage
		rules, err := listUserRules(app, user, is_super_admin)
		if err != nil {
			// Log the error
			app.Log.Warnf("Failed to retrieve policy rules: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve rules"})
			return
		}

		// Return the rules
		app.Log.Debugf("Returning %d policy rules to user %s (super admin: %v)", len(rules), user.Email, is_super_admin)
		c.JSON(http.StatusOK, RulesResponse{Rules: rules, EditAllowed: is_super_admin})
	}
}

// createPolicyRule creates a new policy rule (super-admin only).
// @Summary Create a policy rule
// @Description Creates a new DNS policy rule. Only SuperAdmins are authorized.
// @Tags policies
// @Accept json
// @Produce json
// @Param rule body PolicyRuleRequest true "Policy rule payload"
// @Success 201 {object} storage.PolicyRule "The newly created policy rule"
// @Failure 400 {object} map[string]string "Invalid request or validation error"
// @Failure 403 {object} map[string]string "Forbidden: Not a SuperAdmin"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules [post]
func createPolicyRule(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can create rules"})
			return
		}

		var req PolicyRuleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Validation
		if !validateZonePattern(req.ZonePattern) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid zone pattern"})
			return
		}
		if err := validateUserFilter(req.TargetUserFilter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		newRule := storage.PolicyRule{
			ZonePattern:      req.ZonePattern,
			ZoneSoa:          req.ZoneSoa,
			TargetUserFilter: req.TargetUserFilter,
			Description:      req.Description,
		}

		createdRule, err := app.Storage.PolicyCreate(&newRule)
		if err != nil {
			// Log the error
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create rule"})
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
// @Success 200 {object} storage.PolicyRule "The updated policy rule"
// @Failure 400 {object} map[string]string "Invalid rule ID, request payload, or validation error"
// @Failure 403 {object} map[string]string "Forbidden: Not a SuperAdmin"
// @Failure 404 {object} map[string]string "Rule not found"
// @Failure 500 {object} map[string]string "Internal server error"
// @Security ApiKeyAuth
// @Router /v1/policies/rules/{id} [put]
func updatePolicyRule(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)

		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can update rules"})
			return
		}

		idStr := c.Param("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
			return
		}

		var req PolicyRuleRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Validation
		if !validateZonePattern(req.ZonePattern) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid zone pattern"})
			return
		}
		if err := validateUserFilter(req.TargetUserFilter); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Check if rule exists before update attempt
		existingRule, err := app.Storage.PolicyGetByID(id)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve rule"})
			}
			return
		}

		// Update the fields on the existing rule object
		existingRule.ZonePattern = req.ZonePattern
		existingRule.ZoneSoa = req.ZoneSoa
		existingRule.TargetUserFilter = req.TargetUserFilter
		existingRule.Description = req.Description

		updatedRule, err := app.Storage.PolicyUpdate(existingRule)
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update rule"})
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
		user := c.MustGet(auth.UserDataKey).(*auth.UserClaims)
		if !isSuperAdmin(app, user) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Only super admins can delete rules"})
			return
		}

		idStr := c.Param("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rule ID"})
			return
		}

		if err := app.Storage.PolicyDelete(id); err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "Rule not found"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete rule"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "deleted"})
	}
}

// --- Validation Helpers

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

func isSuperAdmin(app *AppData, user *auth.UserClaims) bool {
	superAdmins := app.Config.DnsPolicyConfig.SuperAdminEmails

	if _, exists := superAdmins[strings.ToLower(user.Email)]; exists {
		return true
	}

	return false
}

// isValidZonePattern converts the provided JavaScript function to Go.
// It validates a zone pattern by temporarily replacing the custom '%u' placeholder
// with a valid character ('A') before performing standard DNS label checks.
func validateZonePattern(value string) bool {
	if value == "" {
		return false
	}

	// 1. Replace '%u' with 'A' and trim whitespace
	s := strings.ReplaceAll(value, "%u", "A")
	s = strings.TrimSpace(s)

	// Use existing DNS domain validation
	return helper.DnsValidateName(s)
}
