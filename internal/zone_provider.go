package app

import (
	"context"

	"go.uber.org/zap"
)

type ZoneProvider interface {
	GetUserZones(ctx context.Context, user *UserClaims) ([]ZoneResponse, error)
	IsAllowedZone(ctx context.Context, user *UserClaims, zone string) (bool, ZoneResponse, error)
}

func NewUserZoneProvider(appConfig *AppConfig, logger *zap.Logger) ZoneProvider {
	c := appConfig.UserZoneProvider

	switch c.Provider {
	case "fixed":
		return NewFixedZoneProvider(c.FixedDomainSuffixes, c.FixedDomainSoa, logger)

	case "webhook":
		return NewWebhookZoneProvider(c.WebhookUrl, c.WebhookBearerToken, logger)

	case "script":
		provider, err := NewZoneProviderJavaScript(&c, logger)
		if err != nil {
			logger.Fatal("zones.CreateUserZoneProvider: failed to initialize ZoneProviderJavaScript", // <-- RENAMED
				zap.String("script_path", c.ScriptPath), zap.Error(err))
		}
		return provider

	default:
		logger.Fatal("zones.CreateUserZoneProvider: unknown UserZoneProvider type",
			zap.String("type", appConfig.UserZoneProvider.Provider))
		return nil
	}

}
