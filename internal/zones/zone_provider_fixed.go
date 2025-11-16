package zones

import (
	"regexp"
	"strings"

	"github.com/farberg/dynamic-zones/internal/auth"
	"go.uber.org/zap"
)

type FixedZoneProvider struct {
	zone_suffixes []string
	logger        *zap.Logger
	log           *zap.SugaredLogger
}

func NewFixedZoneProvider(config string, logger *zap.Logger) *FixedZoneProvider {
	// Split config by comma and trim spaces
	zones := strings.Split(config, ",")
	for i, zone := range zones {
		zones[i] = strings.TrimSpace(zone)
	}

	logger.Info("zones.NewFixedZoneProvider: initialized FixedZoneProvider",
		zap.Int("num_zones", len(zones)), zap.Strings("zones", zones))

	return &FixedZoneProvider{
		zone_suffixes: zones,
		logger:        logger,
		log:           logger.Sugar(),
	}
}

func (m *FixedZoneProvider) GetUserZones(user *auth.UserClaims) ([]ZoneResponse, error) {
	result := make([]ZoneResponse, 0, len(m.zone_suffixes))

	for _, zone := range m.zone_suffixes {
		name := makeDnsCompliant(user.PreferredUsername) + "." + zone
		result = append(result, ZoneResponse{
			Zone:    name,
			ZoneSOA: zone,
		})
	}

	m.log.Debugf("zones.GetUserZones: returning zones for user %s: %v", user.PreferredUsername, result)

	return result, nil
}

func (m *FixedZoneProvider) IsAllowedZone(user *auth.UserClaims, zone string) (bool, ZoneResponse, error) {
	userZones, err := m.GetUserZones(user)
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
