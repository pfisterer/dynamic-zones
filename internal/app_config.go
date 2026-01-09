package app

import (
	"encoding/json"
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
	// The OIDC issuer URL for authentication
	OIDCIssuerURL string `json:"oidc_issuer_url" validate:"required,url"`
	// The OIDC client ID for authentication
	OIDCClientID string `json:"oidc_client_id" validate:"required"`
	// The bind string for the Gin web server (e.g., ":8082")
	GinBindString string `json:"gin_bind_string" validate:"required"`
	// The base URL for the web server (e.g., "http://localhost:8082")
	WebserverBaseUrl string `json:"webserver_base_url" validate:"required,url"`
	// The TTL (in hours) for API tokens
	ApiTokenTTLHours int `json:"api_token_ttl_hours"`
	// The version of the external DNS image to use
	ExternalDnsVersion string `json:"external_dns_version" validate:"required"`
}

type DefaultRecord struct {
	// The name of the record (relative to the zone, e.g., "_acme-challenge")
	Name string `json:"name"`
	// The type of record (e.g., "CNAME", "TXT", "A")
	Type string `json:"type"`
	// The content of the record (e.g., "auth.my-proxy.int")
	Content string `json:"content"`
	// Optional TTL, defaults to zone default if 0
	TTL uint32 `json:"ttl,omitempty"`
}

type UserZoneProviderConfig struct {
	// List of default records to create in each new zone for "fixed" provider (e.g., ""[{"name":"_acme-challenge","type":"CNAME","content":"auth.my-proxy.int","ttl":300}]"")
	DefaultRecords []DefaultRecord `json:"default_records" validate:"omitempty"`
	// TSIG key name for admin updates, added to all zones (intermediate and requested)provider
	DefaultAdminTsigKeyName string `json:"default_admin_tsig_name,omitempty" validate:"omitempty"`
	// TSIG key for for admin updates, added to all zones (intermediate and requested)provider
	DefaultAdminTsigKey string `json:"default_admin_tsig_key,omitempty" validate:"omitempty"`
	// TSIG algorithm for for admin updates, added to all zones (intermediate and requested)provider
	DefaultAdminTsigAlg string `json:"default_admin_tsig_alg,omitempty" validate:"omitempty"`

	// The type of zone provider
	Provider string `json:"provider" validate:"oneof=fixed webhook script"`
	// Comma-separated list of fixed domain suffixes for "fixed" provider (e.g., "test.example.com, example.example2.org")

	FixedDomainSuffixes string `json:"fixed_domain_suffixes" validate:"required_if=Provider fixed"`
	// Comma-separated list of fixed domains where SOA of this nameserver starts (in the same order as FixedDomainSuffixes, e.g., "example.com, example2.org")
	FixedDomainSoa string `json:"fixed_domain_soa" validate:"required_if=Provider fixed"`

	// The webhook URL for zone provider "webhook"
	WebhookUrl string `json:"webhook_url" validate:"required_if=Provider webhook,omitempty,url"`
	// The webhook bearer token for zone provider "webhook"
	WebhookBearerToken string `json:"webhook_bearer_token" validate:"required_if=Provider webhook"`

	// The script path for zone provider "script"
	ScriptPath string `json:"script_path" validate:"required_if=Provider script,omitempty"`
}

type DnsPolicyConfig struct {
	SuperAdminEmails map[string]struct{} `json:"super_admin_emails"`
	// Flag to indicate if dummy data should be added (for development/testing)
	AddDummyData bool `json:"add_dummy_data"`
}

type AppConfig struct {
	UpstreamDns      UpstreamDnsUpdateConfig `json:"upstream_dns_config"`
	PowerDns         PowerDnsConfig          `json:"powerdns_config"`
	Storage          StorageConfig           `json:"storage_config"`
	WebServer        WebServerConfig         `json:"webserver_config"`
	UserZoneProvider UserZoneProviderConfig  `json:"user_zone_provider_config"`
	DnsPolicyConfig  DnsPolicyConfig         `json:"dns_policy_config"`
	// Flag indicating if the application is running in development mode
	DevMode bool `json:"dev_mode"`
}

func GetAppConfigFromEnvironment() (AppConfig, error) {
	err := error(nil)

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
			OIDCIssuerURL:      helper.GetEnvString("OIDC_ISSUER_URL", ""),
			OIDCClientID:       helper.GetEnvString("OIDC_CLIENT_ID", ""),
			GinBindString:      helper.GetEnvString("API_BIND", ":8082"),
			WebserverBaseUrl:   helper.GetEnvString("API_BASE_URL", "http://localhost:8082"),
			ExternalDnsVersion: helper.GetEnvString("EXTERNAL_DNS_IMAGE_VERSION", "v0.19.0"),
			ApiTokenTTLHours:   helper.GetEnvInt("API_TOKEN_TTL_HOURS", 24),
		},
		UserZoneProvider: UserZoneProviderConfig{
			DefaultAdminTsigKeyName: helper.GetEnvString("ZONE_PROVIDER_DEFAULT_ADMIN_TSIG_NAME", ""),
			DefaultAdminTsigKey:     helper.GetEnvString("ZONE_PROVIDER_DEFAULT_ADMIN_TSIG_KEY", ""),
			DefaultAdminTsigAlg:     helper.GetEnvString("ZONE_PROVIDER_DEFAULT_ADMIN_TSIG_ALG", ""),
			DefaultRecords: func() []DefaultRecord {
				raw := helper.GetEnvString("ZONE_PROVIDER_DEFAULT_RECORDS", "[]")
				var records []DefaultRecord
				if err = json.Unmarshal([]byte(raw), &records); err != nil {
					err = fmt.Errorf("failed to parse ZONE_PROVIDER_DEFAULT_RECORDS: %w", err)
				}
				return records
			}(),

			Provider: helper.GetEnvString("ZONE_PROVIDER_TYPE", "fixed"),

			FixedDomainSuffixes: helper.GetEnvString("ZONE_PROVIDER_FIXED_DOMAIN_SUFFIXES", "test.example.com, demo.example2.org"),
			FixedDomainSoa:      helper.GetEnvString("ZONE_PROVIDER_FIXED_DOMAIN_SOA", "example.com, example2.org"),

			WebhookUrl:         helper.GetEnvString("ZONE_PROVIDER_WEBHOOK_URL", ""),
			WebhookBearerToken: helper.GetEnvString("ZONE_PROVIDER_WEBHOOK_BEARER_TOKEN", ""),

			ScriptPath: helper.GetEnvString("ZONE_PROVIDER_SCRIPT_PATH", ""),
		},
		DnsPolicyConfig: DnsPolicyConfig{
			SuperAdminEmails: helper.GetEnvStringSet("DNS_POLICY_SUPERADMIN_EMAILS", map[string]struct{}{}, ",", true),
			AddDummyData:     helper.GetEnvBool("DNS_POLICY_ADD_DUMMY_DATA", false),
		},

		DevMode: helper.GetEnvString("API_MODE", "production") == "development",
	}

	//Validate the configuration
	if err != nil {
		return AppConfig{}, err
	}

	err = appConfig.Validate()

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
