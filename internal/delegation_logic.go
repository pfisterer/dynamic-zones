package app

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
)

// DelegationPolicyRequest is used for create/update of delegation policies.
type DelegationPolicyRequest struct {
	TargetUserFilter string `json:"target_user_filter" binding:"required"`
	ZoneSuffix       string `json:"zone_suffix" binding:"required"`
	Description      string `json:"description"`
}

func (app *AppData) DelegationGetAll() ([]DelegationPolicy, error) {
	return app.Storage.DelegationGetAll()
}

func (app *AppData) DelegationCreate(req DelegationPolicyRequest) (*DelegationPolicy, error) {
	if err := validateUserFilter(req.TargetUserFilter); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ZoneSuffix) == "" {
		return nil, errors.New("zone_suffix is required")
	}
	d := DelegationPolicy{
		TargetUserFilter: req.TargetUserFilter,
		ZoneSuffix:       req.ZoneSuffix,
		Description:      req.Description,
	}
	return app.Storage.DelegationCreate(&d)
}

func (app *AppData) DelegationUpdate(id int64, req DelegationPolicyRequest) (*DelegationPolicy, error) {
	if err := validateUserFilter(req.TargetUserFilter); err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.ZoneSuffix) == "" {
		return nil, errors.New("zone_suffix is required")
	}
	existing, err := app.Storage.DelegationGetByID(id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fmt.Errorf("delegation not found")
		}
		return nil, err
	}
	existing.TargetUserFilter = req.TargetUserFilter
	existing.ZoneSuffix = req.ZoneSuffix
	existing.Description = req.Description
	return app.Storage.DelegationUpdate(existing)
}

func (app *AppData) DelegationDelete(id int64) error {
	if err := app.Storage.DelegationDelete(id); err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("delegation not found")
		}
		return err
	}
	return nil
}

// userCanManageZoneSoa reports whether the user may create/edit/delete a policy
// rule whose ZoneSoa is the given value: true for super-admins, or if a
// delegation matches the user's email and covers the zone (zone + subdomains).
func (app *AppData) userCanManageZoneSoa(user *UserClaims, zoneSoa string) (bool, error) {
	if isSuperAdmin(app, user) {
		return true, nil
	}
	delegations, err := app.Storage.DelegationGetAll()
	if err != nil {
		return false, err
	}
	for _, d := range delegations {
		if ok, _ := userCanAccessRule(user.Email, d.TargetUserFilter); ok && zoneInScope(zoneSoa, d.ZoneSuffix) {
			return true, nil
		}
	}
	return false, nil
}

// zoneInScope reports whether zone is at or below suffix (exact match or a
// subdomain). Case and trailing dots are normalized.
func zoneInScope(zone, suffix string) bool {
	z := strings.ToLower(strings.TrimSuffix(zone, "."))
	s := strings.ToLower(strings.TrimSuffix(suffix, "."))
	return z == s || isSubdomainOf(z, s)
}
