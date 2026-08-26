package app

import (
	"fmt"

	"gorm.io/gorm"
)

// The columns that left the Zone model, removed from the database as well.
//
// Same reason dropSoftDelete exists: AutoMigrate adds and widens but never
// removes, so a field deleted from a struct lives on in the table forever unless
// something says otherwise out loud. The difference is the risk. dropSoftDelete
// destroys rows and its step order is a safety property; this one destroys two
// columns that were measured to be empty first:
//
//   - requires_refresh_at was declared in January 2026 and never written by
//     anything. On production all 102 rows held the zero time. What it was
//     reaching for exists already — every SOA record in PowerDNS carries a
//     YYYYMMDDnn serial, so the date a zone last changed is a substring away.
//   - updated_at was maintained by GORM and still said nothing: on those same
//     102 rows, not one had an updated_at later than its created_at. A zone row
//     is written once; every later change happens to records in PowerDNS and
//     never touches this table.
//
// Deliberately NOT generalised into "drop every column the model no longer has".
// That would turn a rename into silent data loss the first time someone spells a
// field differently, and it would run against a table whose contents nobody
// looked at. Each column dropped here was counted first.
//
// Idempotent: on a database that has already been through it, both lookups miss
// and nothing happens.
func dropUnusedZoneColumns(db *gorm.DB) error {
	m := db.Migrator()

	for _, col := range []string{"requires_refresh_at", "updated_at"} {
		if !m.HasColumn(&Zone{}, col) {
			continue
		}
		if err := m.DropColumn(&Zone{}, col); err != nil {
			return fmt.Errorf("dropUnusedZoneColumns: dropping zones.%s: %w", col, err)
		}
	}

	return nil
}
