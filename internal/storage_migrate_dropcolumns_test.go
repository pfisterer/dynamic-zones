package app

import (
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// zoneWithDeadColumns is the model as it was before the two fields left it. The
// test needs it to build the old schema, which is the only starting point where
// this migration does anything at all.
type zoneWithDeadColumns struct {
	ID                uint `gorm:"primaryKey"`
	CreatedAt         time.Time
	UpdatedAt         time.Time
	Zone              string `gorm:"primaryKey"`
	Username          string `gorm:"index"`
	RequiresRefreshAt time.Time
}

func (zoneWithDeadColumns) TableName() string { return "zones" }

func openWithDeadColumns(t *testing.T) *gorm.DB {
	t.Helper()

	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&zoneWithDeadColumns{}); err != nil {
		t.Fatalf("migrate old schema: %v", err)
	}
	rows := []zoneWithDeadColumns{
		{Zone: "a.example.com", Username: "alice"},
		{Zone: "b.example.com", Username: "bob"},
	}
	if err := db.Create(&rows).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	return db
}

func TestDropUnusedZoneColumns_RemovesThemAndKeepsTheRows(t *testing.T) {
	db := openWithDeadColumns(t)

	if err := dropUnusedZoneColumns(db); err != nil {
		t.Fatalf("dropUnusedZoneColumns: %v", err)
	}

	m := db.Migrator()
	for _, col := range []string{"requires_refresh_at", "updated_at"} {
		if m.HasColumn(&Zone{}, col) {
			t.Errorf("zones.%s is still there", col)
		}
	}

	// The point of the whole exercise: the columns go, the zones stay. A
	// migration that dropped the table would satisfy the check above.
	var zones []Zone
	if err := db.Order("zone").Find(&zones).Error; err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(zones) != 2 || zones[0].Zone != "a.example.com" || zones[1].Username != "bob" {
		t.Fatalf("rows did not survive: %+v", zones)
	}

	// created_at must NOT be collateral damage — it is the one timestamp on this
	// table that carries a real value, and it sits next to the two that go.
	if !m.HasColumn(&Zone{}, "created_at") {
		t.Error("zones.created_at was dropped too")
	}
	if zones[0].CreatedAt.IsZero() {
		t.Error("created_at lost its value")
	}
}

// Running it twice has to be as harmless as running it once: it executes on
// every start, and all but the first find nothing to do.
func TestDropUnusedZoneColumns_IsIdempotent(t *testing.T) {
	db := openWithDeadColumns(t)

	for i := range 3 {
		if err := dropUnusedZoneColumns(db); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}

	var n int64
	if err := db.Model(&Zone{}).Count(&n).Error; err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 2 {
		t.Fatalf("zones after three runs = %d, want 2", n)
	}
}

// A database that never had the columns — a fresh install — must not error.
func TestDropUnusedZoneColumns_OnAFreshSchema(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.AutoMigrate(&Zone{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	if err := dropUnusedZoneColumns(db); err != nil {
		t.Fatalf("dropUnusedZoneColumns on a fresh schema: %v", err)
	}
}
