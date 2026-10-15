package app

import (
	"fmt"

	"gorm.io/gorm"
)

// backfillZoneCreators gives every zone that has owners but no creator one: the owner whose row is the oldest (CreatedAt, then ID). Before the creator column existed every owner could do everything, so the zones already in the database carry no record of who created them — but the creator's row is written first (ZoneCreate stores it before anyone can join or inherit), so the earliest row is the creator in every case this service produced itself.
//
// Runs at every start and is idempotent: a zone that already has a creator is left alone, so it only ever does work once per zone (or after somebody edited the table by hand).
func backfillZoneCreators(db *gorm.DB) error {
	var zones []string
	if err := db.Model(&Zone{}).Distinct().Pluck("zone", &zones).Error; err != nil {
		return fmt.Errorf("backfillZoneCreators: listing zones: %w", err)
	}
	for _, zone := range zones {
		if err := ensureZoneCreator(db, zone); err != nil {
			return fmt.Errorf("backfillZoneCreators: %w", err)
		}
	}
	return nil
}

// ensureZoneCreator marks the earliest owner of `zone` as its creator unless some owner already is one. A zone without rows is left alone.
func ensureZoneCreator(db *gorm.DB, zone string) error {
	var count int64
	if err := db.Model(&Zone{}).Where("zone = ? AND creator = ?", zone, true).Count(&count).Error; err != nil {
		return fmt.Errorf("ensureZoneCreator: counting creators of %q: %w", zone, err)
	}
	if count > 0 {
		return nil
	}

	var earliest []Zone
	if err := db.Where("zone = ?", zone).Order("created_at asc").Order("id asc").Limit(1).Find(&earliest).Error; err != nil {
		return fmt.Errorf("ensureZoneCreator: finding the earliest owner of %q: %w", zone, err)
	}
	if len(earliest) == 0 {
		return nil
	}
	if err := db.Model(&Zone{}).Where("zone = ? AND id = ?", zone, earliest[0].ID).Update("creator", true).Error; err != nil {
		return fmt.Errorf("ensureZoneCreator: marking %q as creator of %q: %w", earliest[0].Username, zone, err)
	}
	return nil
}
