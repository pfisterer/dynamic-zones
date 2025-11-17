package zones

import (
	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/config"
	"go.uber.org/zap"
)

type ZoneResponse struct {
	Zone    string `json:"zone"`
	ZoneSOA string `json:"zone_soa"`
}

type ZoneProvider interface {
	GetUserZones(user *auth.UserClaims) ([]ZoneResponse, error)
	IsAllowedZone(user *auth.UserClaims, zone string) (bool, ZoneResponse, error)
}

func NewUserZoneProvider(appConfig *config.AppConfig, logger *zap.Logger) ZoneProvider {

	switch appConfig.UserZoneProvider.Provider {
	case "fixed":
		return NewFixedZoneProvider(appConfig.UserZoneProvider.FixedDomainSuffixes, appConfig.UserZoneProvider.FixedDomainSoa, logger)

	case "webhook":
		return NewWebhookZoneProvider(appConfig.UserZoneProvider.WebhookUrl, appConfig.UserZoneProvider.WebhookBearerToken, logger)

	default:
		logger.Fatal("zones.CreateUserZoneProvider: unknown UserZoneProvider type",
			zap.String("type", appConfig.UserZoneProvider.Provider))
		return nil
	}

}
