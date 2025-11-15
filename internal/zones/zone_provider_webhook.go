package zones

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/jellydator/ttlcache/v3"
	"go.uber.org/zap"
)

type ZoneProviderWebhook struct {
	url         string
	bearerToken string
	cache       *ttlcache.Cache[string, []ZoneResponse]
	logger      *zap.Logger
}

func NewWebhookZoneProvider(url string, bearerToken string, logger *zap.Logger) *ZoneProviderWebhook {

	cache := ttlcache.New(
		ttlcache.WithTTL[string, []ZoneResponse](5*time.Minute),
		ttlcache.WithCapacity[string, []ZoneResponse](500),
	)

	go cache.Start()

	return &ZoneProviderWebhook{
		url:         url,
		bearerToken: bearerToken,
		cache:       cache,
		logger:      logger,
	}
}

func (m *ZoneProviderWebhook) GetUserZones(user *auth.UserClaims) ([]ZoneResponse, error) {

	// Check cache first
	cacheKey := user.PreferredUsername
	cachedItem := m.cache.Get(cacheKey)
	if cachedItem != nil {
		m.logger.Debug("zones.GetUserZones: cache hit", zap.String("user", user.PreferredUsername))
		return cachedItem.Value(), nil
	}

	// Not in cache, make webhook request
	m.logger.Debug("zones.GetUserZones: cache miss, making webhook request", zap.String("user", user.PreferredUsername))

	result, err := fetchZonesFromWebhook(m.url, m.bearerToken, user, m.logger)
	if err != nil {
		m.logger.Error("zones.GetUserZones: error fetching zones from webhook", zap.String("user", user.PreferredUsername), zap.Error(err))
		return []ZoneResponse{}, err
	}

	// Store in cache
	m.cache.Set(cacheKey, result, ttlcache.DefaultTTL)
	return result, nil
}

func (m *ZoneProviderWebhook) IsAllowedZone(user *auth.UserClaims, zone string) (bool, error) {
	userZones, err := m.GetUserZones(user)
	if err != nil {
		return false, err
	}

	for _, uz := range userZones {
		if uz.Zone == zone {
			return true, nil
		}
	}
	return false, nil
}

func fetchZonesFromWebhook(url string, bearerToken string, user *auth.UserClaims, logger *zap.Logger) ([]ZoneResponse, error) {
	// Marshal the user object to JSON
	userJSON, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshaling user to JSON: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(userJSON))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	if bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+bearerToken)
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("performing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	var zones []ZoneResponse
	if err := json.NewDecoder(resp.Body).Decode(&zones); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	logger.Debug("fetchZonesFromWebhook: fetched zones", zap.Int("count", len(zones)), zap.String("user", user.PreferredUsername))
	return zones, nil
}
