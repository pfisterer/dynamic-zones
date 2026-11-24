package app

import (
	"fmt"
	"time"

	"gorm.io/gorm/clause"
)

// ZoneGroupShare shares a zone with a group of the role provider: everybody holding Subject (group:<id> or group:<id>#<relation>) is an owner of the zone and of the zones delegated below it, for as long as they hold it. The owner rows of the members carry the subject in Zone.Via; syncGroupAccess keeps them in step. One row per zone and subject.
type ZoneGroupShare struct {
	ID        uint      `gorm:"primaryKey" json:"-"`
	CreatedAt time.Time `json:"created_at"`
	Zone      string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_zone_group_share" json:"zone"`
	Subject   string    `gorm:"type:varchar(255);not null;uniqueIndex:idx_zone_group_share" json:"group"`
	// SharedBy is who added the share, for the record.
	SharedBy string `gorm:"type:varchar(255);not null;default:''" json:"shared_by"`
}

// AddGroupShare stores a group share; sharing a zone with a group it is already shared with is a no-op.
func (s *Storage) AddGroupShare(zone, subject, by string) error {
	share := &ZoneGroupShare{Zone: zone, Subject: subject, SharedBy: by}
	if err := s.db.Clauses(clause.OnConflict{DoNothing: true}).Create(share).Error; err != nil {
		return fmt.Errorf("storage.AddGroupShare: Failed to share zone ('%s') with ('%s'): %w", zone, subject, err)
	}
	return nil
}

// RemoveGroupShare deletes a group share; reports whether there was one.
func (s *Storage) RemoveGroupShare(zone, subject string) (bool, error) {
	res := s.db.Where("zone = ? AND subject = ?", zone, subject).Delete(&ZoneGroupShare{})
	if res.Error != nil {
		return false, fmt.Errorf("storage.RemoveGroupShare: Failed to remove share of zone ('%s') with ('%s'): %w", zone, subject, res.Error)
	}
	return res.RowsAffected > 0, nil
}

// ListGroupShares returns the group shares of one zone, oldest first.
func (s *Storage) ListGroupShares(zone string) ([]ZoneGroupShare, error) {
	var shares []ZoneGroupShare
	if err := s.db.Where("zone = ?", zone).Order("id").Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("storage.ListGroupShares: Failed to list shares of zone ('%s'): %w", zone, err)
	}
	return shares, nil
}

// ListAllGroupShares returns every group share, oldest first.
func (s *Storage) ListAllGroupShares() ([]ZoneGroupShare, error) {
	var shares []ZoneGroupShare
	if err := s.db.Order("id").Find(&shares).Error; err != nil {
		return nil, fmt.Errorf("storage.ListAllGroupShares: %w", err)
	}
	return shares, nil
}

// DeleteGroupSharesOfZone removes every group share of a zone (the zone is deleted).
func (s *Storage) DeleteGroupSharesOfZone(zone string) error {
	if err := s.db.Where("zone = ?", zone).Delete(&ZoneGroupShare{}).Error; err != nil {
		return fmt.Errorf("storage.DeleteGroupSharesOfZone: Failed to remove shares of zone ('%s'): %w", zone, err)
	}
	return nil
}

// CreateZoneVia inserts an owner row that exists through the group share `via` (never the creator).
func (s *Storage) CreateZoneVia(user, zone, via string) (*Zone, error) {
	d := &Zone{Username: user, Zone: zone, Via: via}
	if err := s.db.Create(d).Error; err != nil {
		return nil, fmt.Errorf("storage.CreateZoneVia: Failed to create zone ('%s') for user ('%s') via ('%s'): %w", zone, user, via, err)
	}
	return d, nil
}

// ListZoneOwnerRows returns the owner rows of a zone, oldest first.
func (s *Storage) ListZoneOwnerRows(zone string) ([]Zone, error) {
	var rows []Zone
	if err := s.db.Where("zone = ?", zone).Order("id").Find(&rows).Error; err != nil {
		return nil, fmt.Errorf("storage.ListZoneOwnerRows: Failed to list owners of zone ('%s'): %w", zone, err)
	}
	return rows, nil
}

// UsersWithGroupAccess returns everybody holding at least one owner row through a group share.
func (s *Storage) UsersWithGroupAccess() ([]string, error) {
	var users []string
	if err := s.db.Model(&Zone{}).Where("via <> ''").Distinct().Pluck("username", &users).Error; err != nil {
		return nil, fmt.Errorf("storage.UsersWithGroupAccess: %w", err)
	}
	return users, nil
}

// CountGroupZones is how many zones `user` holds through a group share (subzones included), for the limit of zones per person.
func (s *Storage) CountGroupZones(user string) (int64, error) {
	var count int64
	if err := s.db.Model(&Zone{}).Where("username = ? AND via <> '' AND creator = ?", user, false).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("storage.CountGroupZones: Failed to count the group zones of '%s': %w", user, err)
	}
	return count, nil
}

// ClearVia makes the group row of `user` on `zone` a row of their own (they were added by address while holding the zone through a group), so leaving the group no longer takes the zone.
func (s *Storage) ClearVia(user, zone string) error {
	if err := s.db.Model(&Zone{}).Where("username = ? AND zone = ?", user, zone).Update("via", "").Error; err != nil {
		return fmt.Errorf("storage.ClearVia: Failed to update zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return nil
}
