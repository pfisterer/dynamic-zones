package storage

import (
	"context"
	"fmt"
	"time"

	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Zone struct {
	gorm.Model
	Zone              string    `gorm:"primaryKey" json:"domain"`
	User              string    `gorm:"index" json:"user"`
	RequiresRefreshAt time.Time `json:"requires_refresh_at"`
}

type Storage struct {
	db *gorm.DB
}

func NewStorage(dbType string, connectionString string) (*Storage, error) {
	var dialector gorm.Dialector
	var err error

	switch dbType {
	case "sqlite":
		dialector = sqlite.Open(connectionString)
	case "postgres":
		dialector = postgres.Open(connectionString)
	case "mysql":
		dialector = mysql.Open(connectionString)
	default:
		return nil, fmt.Errorf("storage.NewStorage: Unsupported database type: %s", dbType)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("storage.NewStorage: Failed to connect to %s database: %w", dbType, err)
	}

	err = db.AutoMigrate(&Zone{})
	if err != nil {
		return nil, fmt.Errorf("storage.NewStorage: Failed to auto-migrate database: %w", err)
	}

	return &Storage{db: db}, nil
}

func (storage *Storage) GetAllZones(ctx context.Context, ch chan<- Zone) error {
	defer close(ch)

	batchSize := 100
	var zones []Zone
	result := storage.db.Model(&Zone{}).FindInBatches(&zones, batchSize, func(tx *gorm.DB, batch int) error {
		for _, domain := range zones {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ch <- domain:
				// domain has been sent to the channel
			}
		}
		return nil
	})

	if result.Error != nil {
		return fmt.Errorf("storage.GetAllZones: failed to fetch all zones in batches: %w", result.Error)
	}
	return nil
}

func (storage *Storage) ListUserZones(user string) ([]Zone, error) {
	var zone []Zone
	if err := storage.db.Where("user = ?", user).Find(&zone).Error; err != nil {
		return nil, fmt.Errorf("storage.ListUserZones: Failed to list user ('%s') zones: %w", user, err)
	}
	return zone, nil
}

func (storage *Storage) ZoneExists(zone string) (bool, error) {
	var count int64
	var d Zone
	err := storage.db.Model(&d).Where("zone = ?", zone).Count(&count).Error

	if err != nil {
		return false, fmt.Errorf("storage.ZoneExists: Failed to get zone ('%s'): %w", zone, err)
	} else if count <= 0 {
		return false, nil
	}

	return true, nil
}

func (storage *Storage) GetZone(user string, zone string) (*Zone, error) {
	var d Zone

	// Check if the zone exists in the database to avoid warnings from gorm
	zoneExists, err := storage.ZoneExists(zone)
	if err != nil {
		return nil, fmt.Errorf("storage.GetZone: Failed to check if zone ('%s') exists: %w", zone, err)
	} else if !zoneExists {
		return nil, nil
	}

	// Get the zone from the database
	if err := storage.db.Where("user = ? AND zone = ?", user, zone).First(&d).Error; err != nil {
		return nil, fmt.Errorf("storage.GetZone: Failed to get zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return &d, nil
}

func (storage *Storage) CreateZone(user string, zone string, requiresRefreshAt time.Time) (*Zone, error) {
	d := &Zone{
		User: user,
		Zone: zone,
	}
	if err := storage.db.Create(d).Error; err != nil {
		return nil, fmt.Errorf("storage.CreateZone: Failed to create zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return d, nil
}

func (storage *Storage) DeleteZone(user string, zone string) error {
	if err := storage.db.Where("user = ? AND zone = ?", user, zone).Delete(&Zone{}).Error; err != nil {
		return fmt.Errorf("storage.CreateZone: Failed to delete zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return nil
}
