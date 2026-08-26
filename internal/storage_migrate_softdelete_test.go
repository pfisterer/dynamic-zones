package app

import (
	"context"
	"testing"
	"time"

	"github.com/pfisterer/cloud-self-service-golib/token"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// legacyZone is the model as it was: gorm.Model embedded, and with it the
// DeletedAt that made every delete here a soft delete. A test needs it to build
// the old schema, which is the only starting point where this migration does
// anything.
type legacyZone struct {
	gorm.Model
	Zone              string `gorm:"primaryKey"`
	Username          string `gorm:"index"`
	RequiresRefreshAt time.Time
}

func (legacyZone) TableName() string { return "zones" }

// openLegacy builds a database in the old shape: zones with deleted_at, two live
// rows and two marked deleted.
func openLegacy(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&legacyZone{}); err != nil {
		t.Fatalf("migrate legacy schema: %v", err)
	}

	rows := []legacyZone{
		{Zone: "alive-one.example.com", Username: "alice@example.com"},
		{Zone: "alive-two.example.com", Username: "bob@example.com"},
		{Zone: "deleted-one.example.com", Username: "alice@example.com"},
		{Zone: "deleted-two.example.com", Username: "carol@example.com"},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	// Delete through the soft-deleting model, so the rows are marked exactly the
	// way the running service marked them.
	if err := db.Where("zone LIKE 'deleted-%'").Delete(&legacyZone{}).Error; err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	return db
}

func countZones(t *testing.T, db *gorm.DB) int64 {
	t.Helper()
	var n int64
	if err := db.Table("zones").Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// The failure this migration has to avoid, and the only way it could destroy
// something: dropping the column first would strip the marking off the deleted
// rows, and they would come back as live zones — pointing at zones PowerDNS no
// longer has.
func TestDropSoftDelete_DeletedRowsDoNotComeBack(t *testing.T) {
	db := openLegacy(t)

	if n := countZones(t, db); n != 4 {
		t.Fatalf("fixture holds %d rows, want 4 (2 live, 2 marked)", n)
	}

	if err := dropSoftDelete(db); err != nil {
		t.Fatalf("dropSoftDelete: %v", err)
	}

	if n := countZones(t, db); n != 2 {
		t.Errorf("%d rows left, want the 2 live ones — a marked row survived the migration", n)
	}
	if db.Migrator().HasColumn(&Zone{}, "deleted_at") {
		t.Error("zones.deleted_at is still there")
	}

	var names []string
	if err := db.Table("zones").Order("zone").Pluck("zone", &names).Error; err != nil {
		t.Fatalf("list: %v", err)
	}
	want := []string{"alive-one.example.com", "alive-two.example.com"}
	if len(names) != len(want) {
		t.Fatalf("got %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("got %v, want %v", names, want)
		}
	}
}

// After the migration a delete is a delete. Without this the change would be
// cosmetic: the column could be gone while the model still soft-deleted.
func TestDropSoftDelete_DeletesAreRealAfterwards(t *testing.T) {
	db := openLegacy(t)
	if err := dropSoftDelete(db); err != nil {
		t.Fatalf("dropSoftDelete: %v", err)
	}

	if err := db.Where("zone = ?", "alive-one.example.com").Delete(&Zone{}).Error; err != nil {
		t.Fatalf("delete: %v", err)
	}
	if n := countZones(t, db); n != 1 {
		t.Errorf("%d rows left, want 1 — the delete did not remove the row", n)
	}
}

// Running it twice must be uneventful, because it runs on every start.
func TestDropSoftDelete_IsIdempotent(t *testing.T) {
	db := openLegacy(t)
	if err := dropSoftDelete(db); err != nil {
		t.Fatalf("first run: %v", err)
	}
	before := countZones(t, db)

	if err := dropSoftDelete(db); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if after := countZones(t, db); after != before {
		t.Errorf("second run changed the row count from %d to %d", before, after)
	}
}

// The tokens column is dropped too, and — unlike zones — without touching any
// rows: nothing has written it since the token code moved to the shared library.
func TestDropSoftDelete_LeavesTokensIntactWhileDroppingTheirColumn(t *testing.T) {
	store, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	if _, err := store.Tokens.Issue(context.Background(), "alice", token.IssueOptions{TTL: time.Hour}); err != nil {
		t.Fatalf("issue: %v", err)
	}

	// NewStorage already ran the migration; a token issued afterwards must still
	// be there, and the column must be gone.
	if store.db.Migrator().HasColumn("tokens", "deleted_at") {
		t.Error("tokens.deleted_at is still there")
	}
	var n int64
	if err := store.db.Table("tokens").Count(&n).Error; err != nil {
		t.Fatalf("count tokens: %v", err)
	}
	if n != 1 {
		t.Errorf("%d tokens, want 1", n)
	}
}
