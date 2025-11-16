package config

import (
	"fmt"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/go-playground/validator/v10"
)

type UpstreamDnsUpdateConfig struct {
	// The DNS server to which updates will be sent
	Server string `json:"server"`
	// TSIG key name for authenticating DNS updates
	Tsig_Name string `json:"tsig_name"`
	// TSIG algorithm for DNS updates
	Tsig_Alg string `json:"tsig_alg"`
	// TSIG secret for authenticating DNS updates
	Tsig_Secret string `json:"tsig_secret" validate:"omitempty,base64"`
	// Port of the DNS server
	Port uint16 `json:"port" validate:"port"`
	// DNS zone to be updated, also the zone this server is authoritative for (e.g., "example.com")
	Zone string `json:"zone" validate:"required"`
	// Name within the DNS zone to be updated, also the name of this servers NS record (e.g, "ns1")
	Name string `json:"name"`
	// Time to live for DNS records
	Ttl int `json:"ttl"`
	// Interval in seconds between DNS updates
	UpdateIntervalSeconds int `json:"interval"`
}

type PowerDnsConfig struct {
	// The URL of the PowerDNS API (e.g., http://localhost:8080)
	PdnsUrl string `json:"pdns_url" validate:"required,url"`
	// The vhost header to use when connecting to PowerDNS
	PdnsVhost string `json:"pdns_vhost" validate:"required"`
	// The API key for authenticating with PowerDNS
	PdnsApiKey string `json:"pdns_api_key" validate:"required"`
	// The address where the Power DNS server listens for queries (e.g., 127.0.0.53)
	DnsServerAddress string `json:"dns_server_address" validate:"required,ip"`
	// The port where the Power DNS server listens for queries (e.g., 15353)
	DnsServerPort uint16 `json:"dns_server_port" validate:"required,port"`
	// The default TTL for DNS records served by PowerDNS when they are created by this application
	DefaultTTLSeconds uint32 `json:"default_ttl_seconds"`
}

type StorageConfig struct {
	// The type of database to use
	DbType string `json:"db_type" validate:"oneof=sqlite postgres mysql"`
	// The connection string for the database (using GORM format)
	DbConnectionString string `json:"db_connection_string" validate:"required"`
}

type WebServerConfig struct {
	// The authentication provider to use (e.g., "oidc", "fake")
	AuthProvider string `json:"auth_provider" validate:"oneof=fake oidc"`
	// The OIDC issuer URL for authentication
	OIDCIssuerURL string `json:"oidc_issuer_url" validate:"required_if=AuthProvider oidc,url"`
	// The OIDC client ID for authentication
	OIDCClientID string `json:"oidc_client_id" validate:"required_if=AuthProvider oidc"`
	// The bind string for the Gin web server (e.g., ":8082")
	GinBindString string `json:"gin_bind_string" validate:"required"`
	// The base URL for the web server (e.g., "http://localhost:8082")
	WebserverBaseUrl string `json:"webserver_base_url" validate:"required,url"`
	// The TTL (in hours) for API tokens
	ApiTokenTTLHours int `json:"api_token_ttl_hours"`
	// The version of the external DNS image to use
	ExternalDnsVersion string `json:"external_dns_version" validate:"required"`
}

type UserZoneProviderConfig struct {
	// The type of zone provider
	Provider string `json:"provider" validate:"oneof=fixed webhook"`
	// Comma-separated list of fixed domain suffixes for "fixed" provider (e.g., "example.com, example2.org")
	FixedDomainSuffixes string `json:"fixed_domain_suffixes" validate:"required_if=Provider fixed"`
	// The webhook URL for zone provider "webhook"
	WebhookUrl string `json:"webhook_url" validate:"required_if=Provider webhook,omitempty,url"`
	// The webhook bearer token for zone provider "webhook"
	WebhookBearerToken string `json:"webhook_bearer_token" validate:"required_if=Provider webhook"`
}

type AppConfig struct {
	UpstreamDns      UpstreamDnsUpdateConfig `json:"upstream_dns_config"`
	PowerDns         PowerDnsConfig          `json:"powerdns_config"`
	Storage          StorageConfig           `json:"storage_config"`
	WebServer        WebServerConfig         `json:"webserver_config"`
	UserZoneProvider UserZoneProviderConfig  `json:"user_zone_provider_config"`
	// Flag indicating if the application is running in development mode
	DevMode bool `json:"dev_mode"`
}

func GetAppConfigFromEnvironment() (AppConfig, error) {

	appConfig := AppConfig{
		UpstreamDns: UpstreamDnsUpdateConfig{
			Server:                helper.GetEnvString("UPSTREAM_DNS_SERVER", ""),
			Port:                  uint16(helper.GetEnvInt("UPSTREAM_DNS_PORT", 53)),
			Zone:                  helper.GetEnvString("UPSTREAM_DNS_ZONE", ""),
			Name:                  helper.GetEnvString("UPSTREAM_DNS_NAME", ""),
			Tsig_Name:             helper.GetEnvString("UPSTREAM_DNS_TSIG_NAME", ""),
			Tsig_Alg:              helper.GetEnvString("UPSTREAM_DNS_TSIG_ALG", ""),
			Tsig_Secret:           helper.GetEnvString("UPSTREAM_DNS_TSIG_SECRET", ""),
			Ttl:                   helper.GetEnvInt("UPSTREAM_DNS_TTL", 900),
			UpdateIntervalSeconds: helper.GetEnvInt("UPSTREAM_DNS_UPDATE_INTERVAL", 60*60),
		},
		PowerDns: PowerDnsConfig{
			PdnsUrl:           helper.GetEnvString("PDNS_URL", "http://localhost:8080"),
			PdnsVhost:         helper.GetEnvString("PDNS_VHOST", "localhost"),
			PdnsApiKey:        helper.GetEnvString("PDNS_API_KEY", "my-default-api-key"),
			DnsServerAddress:  helper.GetEnvString("PDNS_SERVER_ADDRESS", "localhost"),
			DnsServerPort:     uint16(helper.GetEnvInt("PDNS_SERVER_PORT", 15353)),
			DefaultTTLSeconds: uint32(helper.GetEnvInt("PDNS_SERVER_DEFAULT_TTL", int((365 * 24 * time.Hour).Seconds()))),
		},
		Storage: StorageConfig{
			DbType:             helper.GetEnvString("DB_TYPE", "sqlite"),
			DbConnectionString: helper.GetEnvString("DB_CONNECTION_STRING", "file::memory:?cache=shared"),
		},

		WebServer: WebServerConfig{
			GinBindString:      helper.GetEnvString("API_BIND", ":8082"),
			AuthProvider:       helper.GetEnvString("API_AUTH_PROVIDER", ""),
			WebserverBaseUrl:   helper.GetEnvString("API_BASE_URL", "http://localhost:8082"),
			OIDCIssuerURL:      helper.GetEnvString("OIDC_ISSUER_URL", ""),
			OIDCClientID:       helper.GetEnvString("OIDC_CLIENT_ID", ""),
			ExternalDnsVersion: helper.GetEnvString("EXTERNAL_DNS_IMAGE_VERSION", "v0.19.0"),
			ApiTokenTTLHours:   helper.GetEnvInt("API_TOKEN_TTL_HOURS", 24),
		},

		UserZoneProvider: UserZoneProviderConfig{
			Provider:            helper.GetEnvString("ZONE_PROVIDER_TYPE", "fixed"),
			FixedDomainSuffixes: helper.GetEnvString("ZONE_PROVIDER_FIXED_DOMAIN_SUFFIXES", "test.example.com, demo.example2.org"),
			WebhookUrl:          helper.GetEnvString("ZONE_PROVIDER_WEBHOOK_URL", ""),
			WebhookBearerToken:  helper.GetEnvString("ZONE_PROVIDER_WEBHOOK_BEARER_TOKEN", ""),
		},

		DevMode: helper.GetEnvString("API_MODE", "production") == "development",
	}

	//Validate the configuration
	err := appConfig.Validate()

	return appConfig, err

}

func (config *AppConfig) Validate() error {
	validate := validator.New(validator.WithRequiredStructEnabled())

	if err := validate.Struct(config); err != nil {

		// This part converts the generic error into a list of specific errors
		if validationErrors, ok := err.(validator.ValidationErrors); ok {

			// Format the errors for better readability
			return fmt.Errorf("configuration validation failed: %s", formatValidationErrors(validationErrors))
		}
		return err // Return other types of errors if any
	}
	return nil
}

// Helper to format validation errors
func formatValidationErrors(errs validator.ValidationErrors) string {
	var errorMessages string
	for _, e := range errs {
		errorMessages += fmt.Sprintf(
			"\n - Field '%s' failed on the '%s' tag (Value: '%v')",
			e.Field(),
			e.Tag(),
			e.Value(),
		)
	}
	return errorMessages
}
