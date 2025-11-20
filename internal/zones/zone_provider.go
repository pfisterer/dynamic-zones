package zones

import (
	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/config"
	"go.uber.org/zap"
)

type ZoneResponse struct {
	// The DNS zone name (e.g., "my-user.users.example.com")
	Zone string `json:"zone"`
	// The zone name from which on this nameserver is authoritative (e.g., "users.example.com")
	ZoneSOA string `json:"zone_soa"`
}

type ZoneProvider interface {
	GetUserZones(user *auth.UserClaims) ([]ZoneResponse, error)
	IsAllowedZone(user *auth.UserClaims, zone string) (bool, ZoneResponse, error)
}

func NewUserZoneProvider(appConfig *config.AppConfig, logger *zap.Logger) ZoneProvider {
	c := appConfig.UserZoneProvider

	switch c.Provider {
	case "fixed":
		return NewFixedZoneProvider(c.FixedDomainSuffixes, c.FixedDomainSoa, logger)

	case "webhook":
		return NewWebhookZoneProvider(c.WebhookUrl, c.WebhookBearerToken, logger)

	default:
		logger.Fatal("zones.CreateUserZoneProvider: unknown UserZoneProvider type",
			zap.String("type", appConfig.UserZoneProvider.Provider))
		return nil
	}

}
