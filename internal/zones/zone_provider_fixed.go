package zones

import (
	"context"
	"regexp"
	"strings"

	"github.com/farberg/dynamic-zones/internal/auth"
	"go.uber.org/zap"
)

type FixedZoneProvider struct {
	zone_suffixes []string
	zone_soa      []string
	logger        *zap.Logger
	log           *zap.SugaredLogger
}

func NewFixedZoneProvider(suffixes, soa string, logger *zap.Logger) *FixedZoneProvider {
	// Split config by comma and trim spaces
	zones := strings.Split(suffixes, ",")
	zones_soa := strings.Split(soa, ",")
	log := logger.Sugar()

	if len(zones) != len(zones_soa) {
		log.Fatalf("Length of suffixes (%d) and soa (%d) must match", len(zones), len(zones_soa))
	}

	for i, zone := range zones {
		zones[i] = strings.TrimSpace(zone)
		zones_soa[i] = strings.TrimSpace(zones_soa[i])
	}

	logger.Info("zones.NewFixedZoneProvider: initialized FixedZoneProvider",
		zap.Int("num_zones", len(zones)), zap.Strings("zones", zones))

	return &FixedZoneProvider{
		zone_suffixes: zones,
		zone_soa:      zones_soa,
		logger:        logger,
		log:           log,
	}
}

func (m *FixedZoneProvider) GetUserZones(ctx context.Context, user *auth.UserClaims) ([]ZoneResponse, error) {
	result := make([]ZoneResponse, 0, len(m.zone_suffixes))

	for i, zone := range m.zone_suffixes {
		name := makeDnsCompliant(user.PreferredUsername) + "." + zone
		result = append(result, ZoneResponse{
			Zone:    name,
			ZoneSOA: m.zone_soa[i],
		})
	}

	m.log.Debugf("zones.GetUserZones: returning zones for user %s: %v", user.PreferredUsername, result)

	return result, nil
}

func (m *FixedZoneProvider) IsAllowedZone(ctx context.Context, user *auth.UserClaims, zone string) (bool, ZoneResponse, error) {
	userZones, err := m.GetUserZones(ctx, user)
	if err != nil {
		return false, ZoneResponse{}, err
	}

	for _, uz := range userZones {
		if uz.Zone == zone {
			return true, uz, nil
		}
	}
	return false, ZoneResponse{}, nil
}

func makeDnsCompliant(input string) string {
	//Replace "@" with "-at-"
	dnsName := strings.ReplaceAll(input, "@", "-at-")

	//Replace invalid characters with "-"
	// This regex matches any character that is NOT a letter, a digit, or a hyphen.
	// It will replace characters like '.', '_', '!', ' ', etc., with a hyphen.
	regInvalidChars := regexp.MustCompile("[^a-zA-Z0-9-]+")
	dnsName = regInvalidChars.ReplaceAllString(dnsName, "-")

	// Collapse multiple consecutive hyphens into a single hyphen
	// This cleans up cases where multiple invalid characters were next to each other,
	// or where an invalid character was next to an existing hyphen.
	regConsecutiveHyphens := regexp.MustCompile("-{2,}")
	dnsName = regConsecutiveHyphens.ReplaceAllString(dnsName, "-")

	// Remove invalid prefix and suffix (leading/trailing hyphens)
	dnsName = strings.TrimPrefix(dnsName, "-")
	dnsName = strings.TrimSuffix(dnsName, "-")

	// Convert the entire string to lowercase
	dnsName = strings.ToLower(dnsName)

	return dnsName
}
