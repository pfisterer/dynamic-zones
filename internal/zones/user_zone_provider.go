package zones

import (
	"regexp"
	"slices"
	"strings"

	"github.com/farberg/dynamic-zones/internal/auth"
	"go.uber.org/zap"
)

type UserZoneProvider struct {
	zone_suffixes []string
	logger        *zap.Logger
}

func NewUserZoneProvider(config string, logger *zap.Logger) *UserZoneProvider {
	// Split config by comma and trim spaces
	zones := strings.Split(config, ",")
	for i, zone := range zones {
		zones[i] = strings.TrimSpace(zone)
	}

	return &UserZoneProvider{
		zone_suffixes: zones,
		logger:        logger,
	}
}

func (m *UserZoneProvider) GetUserZones(user *auth.UserClaims) []string {
	result := make([]string, 0, len(m.zone_suffixes))

	for _, zone := range m.zone_suffixes {
		result = append(result, makeDnsCompliant(user.PreferredUsername)+"."+zone)
	}

	m.logger.Debug("zones.GetUserZones: ", zap.String("username", user.PreferredUsername), zap.Strings("result", result))

	return result
}

func (m *UserZoneProvider) IsAllowedZone(user *auth.UserClaims, zone string) bool {
	return slices.Contains(m.GetUserZones(user), zone)
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
