package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"go.uber.org/zap"
)

type ZoneProviderWebhook struct {
	url         string
	bearerToken string
	cache       *ttlcache.Cache[string, []ZoneResponse]
	logger      *zap.Logger
	log         *zap.SugaredLogger
	httpClient  *http.Client
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
		log:         logger.Sugar(),
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				IdleConnTimeout:     90 * time.Second,
				MaxIdleConnsPerHost: 20,
			},
		},
	}
}

func (m *ZoneProviderWebhook) GetUserZones(ctx context.Context, user *UserClaims) ([]ZoneResponse, error) {
	cacheKey := user.PreferredUsername
	if cacheKey == "" {
		m.log.Error("user claims missing preferred username")
		return nil, fmt.Errorf("invalid user claims: missing username")
	}

	// Check cache first
	cachedItem := m.cache.Get(cacheKey)
	if cachedItem != nil {
		m.log.Debug("cache hit for user zones", zap.String("user", cacheKey))
		return cachedItem.Value(), nil
	}

	// Fetch from webhook
	result, err := m.fetchZonesFromWebhook(ctx, user)
	if err != nil {
		m.log.Errorf("failed to fetch zones from webhook (%s) for user %s: %v", m.url, cacheKey, err)
		return nil, err
	}

	// Store in cache
	m.log.Debugf("caching user zones for user %s: %v+", cacheKey, result)
	m.cache.Set(cacheKey, result, ttlcache.DefaultTTL)
	return result, nil
}

func (m *ZoneProviderWebhook) IsAllowedZone(ctx context.Context, user *UserClaims, zone string) (bool, ZoneResponse, error) {
	userZones, err := m.GetUserZones(ctx, user)

	//Return on error fetching zones
	if err != nil {
		return false, ZoneResponse{}, err
	}

	// Check if the zone is in the user's allowed zones
	for _, uz := range userZones {
		if uz.Zone == zone {
			return true, uz, nil
		}
	}

	return false, ZoneResponse{}, nil
}

func (m *ZoneProviderWebhook) fetchZonesFromWebhook(ctx context.Context, user *UserClaims) ([]ZoneResponse, error) {
	// Create JSON payload
	userJSON, err := json.Marshal(user)
	if err != nil {
		return nil, fmt.Errorf("marshaling user: %w", err)
	}

	// Create request with context for cancellation/timeout support
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.url, bytes.NewReader(userJSON))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set headers and bearer token if provided
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if m.bearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+m.bearerToken)
	}

	// Execute request
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	// Check for non-200 status codes
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("webhook returned unexpected status: %d", resp.StatusCode)
	}

	var zones []ZoneResponse
	one_megabyte_limit := int64(1048576)
	limitReader := http.MaxBytesReader(nil, resp.Body, one_megabyte_limit)
	if err := json.NewDecoder(limitReader).Decode(&zones); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return zones, nil
}

// Close gracefully stops the cache background worker
func (m *ZoneProviderWebhook) Close() {
	m.cache.Stop()
}
