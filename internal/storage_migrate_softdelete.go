package app

import (
	"context"
	"fmt"

	"gorm.io/gorm"
)

// The one-way migration off soft delete.
//
// It exists because AutoMigrate does not: GORM adds tables and columns and
// widens them, but it never removes anything. A column that leaves the model
// stays in the database for good, so dropping `deleted_at` has to be said out
// loud, once, in code that runs at startup — the same reason tokengorm.Migrate
// renames `username` to `subject` by hand.
//
// Two tables carry the column, for two different reasons:
//
//   - zones had it through an embedded gorm.Model, which is what made every
//     delete here a soft delete. The rows already marked deleted are removed for
//     real BEFORE the column goes: drop it first and they would reappear as live
//     zones the moment the filter disappears with it, which is the one way this
//     migration could do damage.
//   - tokens has it left over from before the token code moved to the shared
//     library. The model there declares its fields one by one and has no
//     DeletedAt, so nothing has read or written this column since;
//     openstack-management-api, whose tokens table was created after the move,
//     does not have it at all.
//
// Idempotent: on a database that has already been through it, both columns are
// absent and the whole thing is a pair of catalogue lookups.
func dropSoftDelete(db *gorm.DB) error {
	m := db.Migrator()

	// zones: purge, then drop. The order is the safety property.
	if m.HasColumn(&Zone{}, "deleted_at") {
		// Raw SQL, not db.Delete: the model no longer has the field, so GORM
		// would neither know the column nor add the "IS NULL" clause that a
		// soft-deleting model gets. Unscoped() would not help — there is
		// nothing left to scope.
		res := db.Exec("DELETE FROM zones WHERE deleted_at IS NOT NULL")
		if res.Error != nil {
			return fmt.Errorf("dropSoftDelete: purging soft-deleted zones: %w", res.Error)
		}
		if res.RowsAffected > 0 {
			// Worth a line in the log: this is the one moment rows disappear,
			// and the number should match what was counted beforehand.
			// context.Background(), not db.Statement.Context: this runs during
			// startup, outside any request, and that field can be nil there.
			db.Logger.Info(context.Background(),
				"dropSoftDelete: removed %d zone row(s) that were marked deleted", res.RowsAffected)
		}
		if err := m.DropColumn(&Zone{}, "deleted_at"); err != nil {
			return fmt.Errorf("dropSoftDelete: dropping zones.deleted_at: %w", err)
		}
	}

	// tokens: the column was never used, so there is nothing to purge. Named as
	// a table rather than through a model, because the model it belonged to
	// lives in another module now and no longer describes this column.
	if m.HasTable("tokens") && m.HasColumn("tokens", "deleted_at") {
		if err := m.DropColumn("tokens", "deleted_at"); err != nil {
			return fmt.Errorf("dropSoftDelete: dropping tokens.deleted_at: %w", err)
		}
	}

	return nil
}
