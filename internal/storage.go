package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	Username string `gorm:"index" json:"user" example:"alice" swagger:"desc(User that owns the token)"`
	// TokenHash is the SHA-256 of the token. The token itself is NEVER stored:
	// whoever reads the database (backup, pgweb, a pod in the same network) would
	// otherwise hold working DNS write credentials for every user. Tokens carry
	// 128 bits of entropy from crypto/rand, so a plain hash is enough — there is
	// nothing to brute-force and no need for a slow KDF.
	TokenHash string `gorm:"uniqueIndex" json:"-"`
	// TokenPrefix is the first few characters of the token, kept in the clear so
	// the UI can tell two tokens apart in a list without holding either of them.
	TokenPrefix string `json:"token_prefix" example:"dynz_token_ab12cd34" swagger:"desc(First characters of the token, for identification)"`
	// TokenString carries the generated token OUT of CreateToken exactly once and
	// is never persisted (gorm:"-"): after the response it cannot be recovered.
	TokenString string    `gorm:"-" json:"token_string,omitempty" example:"dynz_token_abcdef123456" swagger:"desc(The API token — returned ONLY when it is created)"`
	ExpiresAt   time.Time `json:"expires_at" example:"2025-12-31T23:59:59Z" swagger:"desc(Token expiration date and time)"`
	ReadOnly    bool      `json:"read_only" gorm:"default:false" example:"false"`
}

// PolicyRule represents a DNS policy rule.
type PolicyRule struct {
	// GORM field tags are usually preferred for primary keys
	ID               int64  `gorm:"primaryKey" json:"id"`
	ZonePattern      string `gorm:"type:varchar(255);not null" json:"zone_pattern"`
	ZoneSoa          string `gorm:"type:varchar(255);not null" json:"zone_soa"`
	TargetUserFilter string `gorm:"type:varchar(255);not null" json:"target_user_filter"`
	// AllowSubdomains lets owners of a matched zone also create/manage delegated
	// subzones under it (e.g. sub.example.com under example.com). Added via GORM
	// AutoMigrate (new column, defaults to false).
	AllowSubdomains bool `gorm:"not null;default:false" json:"allow_subdomains"`
	// SharingAllowed lets owners of a matched zone share it with additional users
	// (and policy-entitled users auto-join). Off by default (opt-in per rule);
	// added via GORM AutoMigrate (new column, defaults to false -> backfills
	// existing rules to false, preserving the old single-owner behaviour).
	SharingAllowed bool      `gorm:"not null;default:false" json:"sharing_allowed"`
	Description    string    `gorm:"type:text;default:null" json:"description,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// DelegationPolicy grants a user (or wildcard filter) the right to manage
// PolicyRules whose ZoneSoa is at or below ZoneSuffix (zone + subdomains).
// Managed by super-admins only.
type DelegationPolicy struct {
	ID               int64     `gorm:"primaryKey" json:"id"`
	TargetUserFilter string    `gorm:"type:varchar(255);not null" json:"target_user_filter"`
	ZoneSuffix       string    `gorm:"type:varchar(255);not null" json:"zone_suffix"`
	Description      string    `gorm:"type:text;default:null" json:"description,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
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

	// Cap how many connections this service may hold open.
	//
	// GORM has no pool of its own — the driver hands gorm.Open a plain *sql.DB, so
	// the pool is database/sql's, and its default for MaxOpenConns is UNLIMITED.
	// Gin runs one goroutine per request and nothing here bounds concurrency, so a
	// burst or a hot loop could open as many connections as there are in-flight
	// requests.
	//
	// That matters because this is a single shared Postgres with max_connections
	// 100 (3 reserved), and PowerDNS reads its zones from it: exhausting the
	// instance would not read as "the API is slow", it would read as "DNS stopped
	// answering". Three services at 10 each leaves the rest of the cluster ample
	// room, and 10 is far above anything measured (the idle floor is 2).
	//
	// MaxIdleConns is raised from the default 2 so a handful of concurrent
	// requests does not pay for a new connection each.
	//
	// Deliberately NOT setting ConnMaxLifetime: the usual Kubernetes argument for
	// it — stale connections after a Postgres restart or a service-IP change — is
	// already handled by pgx, whose ResetSession discards closed connections and
	// pings any that sat idle for more than a second before reuse.
	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("storage.NewStorage: Failed to reach the underlying sql.DB: %w", err)
	}
	sqlDB.SetMaxOpenConns(10)
	sqlDB.SetMaxIdleConns(5)

	err = db.AutoMigrate(&Zone{}, &Token{}, &PolicyRule{}, &DelegationPolicy{})
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

// ---- Zone owners (a zone can have several owner rows, one per user) --------

// ListZoneOwners returns the usernames that manage (own) a zone.
func (storage *Storage) ListZoneOwners(zone string) ([]string, error) {
	var owners []string
	if err := storage.db.Model(&Zone{}).Where("zone = ?", zone).Distinct().Pluck("username", &owners).Error; err != nil {
		return nil, fmt.Errorf("storage.ListZoneOwners: Failed to list owners of zone ('%s'): %w", zone, err)
	}
	return owners, nil
}

// IsZoneOwner reports whether `user` manages `zone`.
func (storage *Storage) IsZoneOwner(user string, zone string) (bool, error) {
	var count int64
	if err := storage.db.Model(&Zone{}).Where("zone = ? AND username = ?", zone, user).Count(&count).Error; err != nil {
		return false, fmt.Errorf("storage.IsZoneOwner: Failed to check owner ('%s') of zone ('%s'): %w", user, zone, err)
	}
	return count > 0, nil
}

// CountZoneOwners returns how many users own a zone.
func (storage *Storage) CountZoneOwners(zone string) (int64, error) {
	var count int64
	if err := storage.db.Model(&Zone{}).Where("zone = ?", zone).Count(&count).Error; err != nil {
		return 0, fmt.Errorf("storage.CountZoneOwners: Failed to count owners of zone ('%s'): %w", zone, err)
	}
	return count, nil
}

// DeleteAllZoneOwners removes every owner row for a zone (used when the whole
// zone is deleted, as opposed to removing a single owner via DeleteZone).
func (storage *Storage) DeleteAllZoneOwners(zone string) error {
	if err := storage.db.Where("zone = ?", zone).Delete(&Zone{}).Error; err != nil {
		return fmt.Errorf("storage.DeleteAllZoneOwners: Failed to delete owners of zone ('%s'): %w", zone, err)
	}
	return nil
}

// GetToken looks up a token for authentication. Expired tokens are treated as
// absent: the lazy cleanup in GetTokens only runs when the OWNER happens to list
// their tokens, so without this condition an expired token kept authenticating
// indefinitely — an expiry date that nothing enforces is not an expiry date.
func (storage *Storage) GetToken(ctx context.Context, tokenString string) (*Token, error) {
	var token Token
	err := storage.db.WithContext(ctx).
		Where("token_hash = ? AND expires_at > ?", HashToken(tokenString), time.Now()).
		Take(&token).Error

	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		// The token string itself is never part of the error: this error is logged
		// by the auth middleware, and a credential does not belong in a log line.
		return nil, fmt.Errorf("storage.GetToken: lookup failed: %w", err)
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

// HashToken is the one-way mapping from a token to what the database stores.
func HashToken(tokenString string) string {
	sum := sha256.Sum256([]byte(tokenString))
	return hex.EncodeToString(sum[:])
}

// tokenDisplayPrefix returns the identifying head of a token: the fixed prefix
// plus the first 8 random characters. Short enough to reveal nothing usable
// (2^96 remain), long enough to pick a token out of a list.
func tokenDisplayPrefix(tokenString string) string {
	const shown = len(ApiTokenPrefix) + 8
	if len(tokenString) <= shown {
		return tokenString
	}
	return tokenString[:shown]
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
		TokenHash:   HashToken(tokenString),
		TokenPrefix: tokenDisplayPrefix(tokenString),
		ExpiresAt:   time.Now().Add(ttl),
		ReadOnly:    readOnly,
	}

	if err := storage.db.WithContext(ctx).Create(token).Error; err != nil {
		return nil, fmt.Errorf("storage.CreateToken: failed to create token for user '%s': %w", username, err)
	}

	// The only moment the caller can ever see the token. It is not persisted.
	token.TokenString = tokenString
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

// --- CRUD Operations for PolicyRule ---

// PolicyCreate inserts a new PolicyRule into the database.
func (s *Storage) PolicyCreate(rule *PolicyRule) (*PolicyRule, error) {
	// Set creation timestamp manually if not using GORM's default fields
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now()
	}

	result := s.db.Create(rule)
	if result.Error != nil {
		// Handle potential unique constraint violation (e.g., if ZonePattern is marked unique)
		return nil, fmt.Errorf("storage.Create: Failed to create rule: %w", result.Error)
	}
	return rule, nil
}

// PolicyGetAll retrieves all PolicyRules from the database.
func (s *Storage) PolicyGetAll() ([]PolicyRule, error) {
	var rules []PolicyRule
	// Order by ID or Creation Time for consistent results
	result := s.db.Order("id asc").Find(&rules)
	if result.Error != nil {
		return nil, fmt.Errorf("storage.GetAll: Failed to retrieve rules: %w", result.Error)
	}
	return rules, nil
}

// PolicyGetByID retrieves a single PolicyRule by its ID.
func (s *Storage) PolicyGetByID(id int64) (*PolicyRule, error) {
	var rule PolicyRule
	result := s.db.First(&rule, id)

	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, gorm.ErrRecordNotFound // Return GORM's specific error for Not Found
		}
		return nil, fmt.Errorf("storage.GetByID: Failed to retrieve rule %d: %w", id, result.Error)
	}
	return &rule, nil
}

// PolicyUpdate modifies an existing PolicyRule.
// The rule parameter should contain the ID of the rule to update and the new values.
func (s *Storage) PolicyUpdate(rule *PolicyRule) (*PolicyRule, error) {
	// GORM will use the primary key (ID) of the struct to determine which record to update.
	// We use Select to specify only the fields we allow the user to modify. Listing a
	// field here also forces GORM to write its ZERO value (Updates skips zero fields of a
	// struct otherwise) — required for booleans like SharingAllowed/AllowSubdomains so
	// that toggling them OFF actually persists (SEC #9: sharing must be revocable).
	result := s.db.Model(rule).Select("ZonePattern", "ZoneSoa", "TargetUserFilter", "AllowSubdomains", "Description", "SharingAllowed").Updates(rule)

	if result.Error != nil {
		return nil, fmt.Errorf("storage.Update: Failed to update rule %d: %w", rule.ID, result.Error)
	}

	if result.RowsAffected == 0 {
		// Double check if the record was actually found and updated
		// Fetch the record again to return a complete, updated object (optional but safer)
		if _, err := s.PolicyGetByID(rule.ID); err != nil {
			if err == gorm.ErrRecordNotFound {
				return nil, gorm.ErrRecordNotFound
			}
			return nil, fmt.Errorf("storage.Update: Rule %d was not found after attempted update: %w", rule.ID, err)
		}
	}

	// Return the rule object, which now has the updated fields and original ID/timestamps.
	return rule, nil
}

// PolicyDelete removes a PolicyRule from the database by its ID.
func (s *Storage) PolicyDelete(id int64) error {
	// Delete the record matching the ID
	result := s.db.Delete(&PolicyRule{}, id)

	if result.Error != nil {
		return fmt.Errorf("storage.Delete: Failed to delete rule %d: %w", id, result.Error)
	}

	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound // Indicate that no record with that ID was found
	}

	return nil
}

// --- DelegationPolicy storage ---

func (s *Storage) DelegationCreate(d *DelegationPolicy) (*DelegationPolicy, error) {
	if d.CreatedAt.IsZero() {
		d.CreatedAt = time.Now()
	}
	if result := s.db.Create(d); result.Error != nil {
		return nil, fmt.Errorf("storage.DelegationCreate: %w", result.Error)
	}
	return d, nil
}

func (s *Storage) DelegationGetAll() ([]DelegationPolicy, error) {
	var ds []DelegationPolicy
	if result := s.db.Order("id asc").Find(&ds); result.Error != nil {
		return nil, fmt.Errorf("storage.DelegationGetAll: %w", result.Error)
	}
	return ds, nil
}

func (s *Storage) DelegationGetByID(id int64) (*DelegationPolicy, error) {
	var d DelegationPolicy
	if result := s.db.First(&d, id); result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, gorm.ErrRecordNotFound
		}
		return nil, fmt.Errorf("storage.DelegationGetByID: %w", result.Error)
	}
	return &d, nil
}

func (s *Storage) DelegationUpdate(d *DelegationPolicy) (*DelegationPolicy, error) {
	result := s.db.Model(d).Select("TargetUserFilter", "ZoneSuffix", "Description").Updates(d)
	if result.Error != nil {
		return nil, fmt.Errorf("storage.DelegationUpdate: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		if _, err := s.DelegationGetByID(d.ID); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (s *Storage) DelegationDelete(id int64) error {
	result := s.db.Delete(&DelegationPolicy{}, id)
	if result.Error != nil {
		return fmt.Errorf("storage.DelegationDelete: %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// ListAllZones returns every stored zone (across all users).
func (s *Storage) ListAllZones() ([]Zone, error) {
	var zones []Zone
	if result := s.db.Order("zone asc").Find(&zones); result.Error != nil {
		return nil, fmt.Errorf("storage.ListAllZones: %w", result.Error)
	}
	return zones, nil
}

// GetZoneByName looks up a zone by its name (zone names are unique/primary key).
// Returns (nil, nil) if no such zone exists.
func (s *Storage) GetZoneByName(zone string) (*Zone, error) {
	var z Zone
	result := s.db.Where("zone = ?", zone).First(&z)
	if result.Error != nil {
		if result.Error == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, fmt.Errorf("storage.GetZoneByName: %w", result.Error)
	}
	return &z, nil
}
