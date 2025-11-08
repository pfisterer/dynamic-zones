package storage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

const ApiTokenPrefix = "dynz_token_"

type Zone struct {
	gorm.Model
	Zone              string    `gorm:"primaryKey" json:"domain"`
	Username          string    `gorm:"index" json:"user"`
	RequiresRefreshAt time.Time `json:"requires_refresh_at"`
}

type Token struct {
	ID        uint       `gorm:"primaryKey" json:"id" example:"1" swagger:"desc(The token ID)"`
	CreatedAt time.Time  `json:"created_at" example:"2025-11-04T12:00:00Z" swagger:"desc(Creation timestamp)"`
	UpdatedAt time.Time  `json:"updated_at" example:"2025-11-04T12:00:00Z" swagger:"desc(Last update timestamp)"`
	DeletedAt *time.Time `gorm:"index" json:"deleted_at,omitempty" example:"2025-12-31T23:59:59Z" swagger:"desc(Deletion timestamp, if soft-deleted)"`

	Username    string    `gorm:"index" json:"user" example:"alice" swagger:"desc(User that owns the token)"`
	TokenString string    `gorm:"uniqueIndex" json:"token_string" example:"dynz_abcdef123456" swagger:"desc(The API token string)"`
	ExpiresAt   time.Time `json:"expires_at" example:"2025-12-31T23:59:59Z" swagger:"desc(Token expiration date and time)"`
	ReadOnly    bool      `json:"read_only" gorm:"default:false" example:"false"`
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

	err = db.AutoMigrate(&Zone{}, &Token{})
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
	if err := storage.db.Where("username = ?", user).Find(&zone).Error; err != nil {
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
	if err := storage.db.Where("username = ? AND zone = ?", user, zone).First(&d).Error; err != nil {
		return nil, fmt.Errorf("storage.GetZone: Failed to get zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return &d, nil
}

func (storage *Storage) CreateZone(user string, zone string, requiresRefreshAt time.Time) (*Zone, error) {
	d := &Zone{
		Username: user,
		Zone:     zone,
	}
	if err := storage.db.Create(d).Error; err != nil {
		return nil, fmt.Errorf("storage.CreateZone: Failed to create zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return d, nil
}

func (storage *Storage) DeleteZone(user string, zone string) error {
	if err := storage.db.Where("username = ? AND zone = ?", user, zone).Delete(&Zone{}).Error; err != nil {
		return fmt.Errorf("storage.CreateZone: Failed to delete zone ('%s') for user ('%s'): %w", zone, user, err)
	}
	return nil
}

func (storage *Storage) GetToken(ctx context.Context, tokenString string) (*Token, error) {
	var token Token
	err := storage.db.WithContext(ctx).
		Where("token_string = ?", tokenString).
		Take(&token).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("storage.GetToken: failed to get token '%s': %w", tokenString, err)
	}

	return &token, nil
}

func (storage *Storage) GetTokens(ctx context.Context, username string) ([]Token, error) {
	var tokens []Token

	err := storage.db.WithContext(ctx).
		Where("username = ?", username).
		Find(&tokens).Error

	if err != nil {
		return nil, fmt.Errorf("storage.GetTokens: failed to get tokens for user '%s': %w", username, err)
	}

	// Delete expired tokens before returning them
	now := time.Now()
	var validTokens []Token

	for _, token := range tokens {
		if token.ExpiresAt.After(now) {
			validTokens = append(validTokens, token)
		} else {
			// Token is expired, delete it
			if delErr := storage.db.WithContext(ctx).
				Where("id = ?", token.ID).
				Delete(&Token{}).Error; delErr != nil {
				return nil, fmt.Errorf("storage.GetTokens: failed to delete expired token ID %d for user '%s': %w", token.ID, username, delErr)
			}
		}
	}

	return validTokens, nil
}

func (storage *Storage) CreateToken(ctx context.Context, username string, ttl time.Duration, readOnly bool) (*Token, error) {
	// Generate a secure random token string
	b := make([]byte, 16) // 16 bytes → 32 hex chars
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("storage.CreateToken: failed to generate token: %w", err)
	}

	tokenString := ApiTokenPrefix + hex.EncodeToString(b)

	token := &Token{
		Username:    username,
		TokenString: tokenString,
		ExpiresAt:   time.Now().Add(ttl),
		ReadOnly:    readOnly,
	}

	if err := storage.db.WithContext(ctx).Create(token).Error; err != nil {
		return nil, fmt.Errorf("storage.CreateToken: failed to create token for user '%s': %w", username, err)
	}

	return token, nil
}

func (storage *Storage) DeleteToken(ctx context.Context, username string, id int) (int, gin.H, error) {
	result := storage.db.WithContext(ctx).
		Where("username = ? AND id = ?", username, id).
		Delete(&Token{})

	if result.Error != nil {
		return http.StatusInternalServerError, gin.H{"error": "Failed to delete token"}, fmt.Errorf(
			"storage.DeleteToken: delete failed for user '%s' token '%d': %w",
			username, id, result.Error,
		)
	}

	if result.RowsAffected == 0 {
		return http.StatusNotFound, gin.H{"status": "not found"}, nil
	}

	return http.StatusOK, gin.H{"status": "deleted"}, nil
}
