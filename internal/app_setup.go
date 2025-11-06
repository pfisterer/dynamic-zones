package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/farberg/dynamic-zones/internal/storage"
	"github.com/farberg/dynamic-zones/internal/zones"
	"github.com/gin-contrib/cors"
	"github.com/joeig/go-powerdns/v3"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
)

type UpstreamDnsUpdateConfig struct {
	Server                string `json:"server"`
	Tsig_Name             string `json:"tsig_name"`
	Tsig_Alg              string `json:"tsig_alg"`
	Tsig_Secret           string `json:"tsig_secret"`
	Port                  int    `json:"port"`
	Zone                  string `json:"zone"`
	Name                  string `json:"name"`
	Ttl                   int    `json:"ttl"`
	UpdateIntervalSeconds int    `json:"interval"`
}

type AppConfig struct {
	UpstreamDns        UpstreamDnsUpdateConfig `json:"upstream_dns_config"`
	DomainSuffixes     string                  `json:"domain_suffixes"`
	DevMode            bool                    `json:"dev_mode"`
	DefaultTTLSeconds  uint64                  `json:"default_ttl_seconds"`
	DbType             string                  `json:"db_type"`
	DbConnectionString string                  `json:"db_connection_string"`
	PdnsUrl            string                  `json:"pdns_url"`
	PdnsVhost          string                  `json:"pdns_vhost"`
	PdnsApiKey         string                  `json:"pdns_api_key"`
	GinBindString      string                  `json:"gin_bind_string"`
	AuthProvider       string                  `json:"auth_provider"`
	OIDCIssuerURL      string                  `json:"oidc_issuer_url"`
	OIDCClientID       string                  `json:"oidc_client_id"`
	WebserverBaseUrl   string                  `json:"webserver_base_url"`
	DnsServerAddress   string                  `json:"dns_server_address"`
	DnsServerPort      int32                   `json:"dns_server_port_string"`
	ApiTokenTTLHours   int                     `json:"api_token_ttl_hours"`
}

type AppData struct {
	Config      AppConfig
	Uzp         *zones.UserZoneProvider
	Storage     *storage.Storage
	Pdns        *powerdns.Client
	RefreshTime uint64
	Logger      *zap.Logger
	Log         *zap.SugaredLogger
}

func RunApplication() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("app.SetupComponents: Failed to load the env vars: %v", err)
	}

	// Get application configuration from environment variables
	appConfig := GetAppConfigFromEnvironment()

	// Initialize logger
	logger, log := helper.InitLogger(appConfig.DevMode)
	if appConfig.DevMode {
		log.Warn("app.SetupComponents: Running in development mode. This is not secure for production!")
	} else {
		log.Info("app.SetupComponents: Running in production mode.")
	}

	// Print application configuration
	LogAppConfig(appConfig, log)

	// Create componentes
	pdns := setupPowerDns(log, &appConfig)
	db := setupStorage(log, &appConfig)
	uzp := zones.NewUserZoneProvider(appConfig.DomainSuffixes, logger)

	appData := AppData{
		Config:  appConfig,
		Uzp:     uzp,
		Storage: db,
		Pdns:    pdns,
		Logger:  logger,
		Log:     log,
	}

	// Start application
	go RunPeriodicUpstreamDnsUpdateCheck(appData)

	// Create and run the web server server forever
	router := setupGinWebserver(&appData)
	err := router.Run(appConfig.GinBindString)
	if err != nil {
		log.Fatalf("app.RunApp: Failed to start server: %v", err)
	}

	log.Info("app.RunApp: Application stopped.")
}

func GetAppConfigFromEnvironment() AppConfig {

	return AppConfig{
		UpstreamDns: UpstreamDnsUpdateConfig{
			Server:                helper.GetEnvString("DYNAMIC_ZONES_UPSTREAM_DNS_SERVER", ""),
			Tsig_Name:             helper.GetEnvString("DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_NAME", ""),
			Tsig_Alg:              helper.GetEnvString("DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_ALG", ""),
			Tsig_Secret:           helper.GetEnvString("DYNAMIC_ZONES_UPSTREAM_DNS_TSIG_SECRET", ""),
			Port:                  helper.GetEnvInt("DYNAMIC_ZONES_UPSTREAM_DNS_PORT", 53),
			Zone:                  helper.GetEnvString("DYNAMIC_ZONES_UPSTREAM_DNS_ZONE", ""),
			Name:                  helper.GetEnvString("DYNAMIC_ZONES_UPSTREAM_DNS_NAME", ""),
			Ttl:                   helper.GetEnvInt("DYNAMIC_ZONES_UPSTREAM_DNS_TTL", 900),
			UpdateIntervalSeconds: helper.GetEnvInt("DYNAMIC_ZONES_UPSTREAM_DNS_UPDATE_INTERVAL", 60*60),
		},
		DomainSuffixes:     helper.GetEnvString("DYNAMIC_ZONES_API_DOMAIN_SUFFIXES", "example.com, example2.org"),
		DevMode:            helper.GetEnvString("DYNAMIC_ZONES_API_MODE", "production") == "development",
		DefaultTTLSeconds:  uint64(helper.GetEnvInt("DYNAMIC_ZONES_SERVER_DEFAULT_TTL", int((365 * 24 * time.Hour).Seconds()))),
		DbType:             helper.GetEnvString("DYNAMIC_ZONES_API_DB_TYPE", "sqlite"),
		DbConnectionString: helper.GetEnvString("DYNAMIC_ZONES_API_DB_CONNECTION_STRING", "file::memory:?cache=shared"),
		PdnsUrl:            helper.GetEnvString("PDNS_URL", "http://localhost:8080"),
		PdnsVhost:          helper.GetEnvString("PDNS_VHOST", "localhost"),
		PdnsApiKey:         helper.GetEnvString("PDNS_API_KEY", "my-default-api-key"),
		GinBindString:      helper.GetEnvString("DYNAMIC_ZONES_API_BIND", ":8082"),
		AuthProvider:       helper.GetEnvString("DYNAMIC_ZONES_API_AUTH_PROVIDER", ""),
		OIDCIssuerURL:      helper.GetEnvString("OIDC_ISSUER_URL", ""),
		OIDCClientID:       helper.GetEnvString("OIDC_CLIENT_ID", ""),
		WebserverBaseUrl:   helper.GetEnvString("DYNAMIC_ZONES_API_BASE_URL", "http://localhost:8082"),
		DnsServerAddress:   helper.GetEnvString("DYNAMIC_ZONES_SERVER_ADDRESS", "localhost"),
		DnsServerPort:      int32(helper.GetEnvInt("DYNAMIC_ZONES_SERVER_PORT", 15353)),
		ApiTokenTTLHours:   helper.GetEnvInt("DYNAMIC_ZONES_API_TOKEN_TTL_HOURS", 24),
	}

}

func setupStorage(log *zap.SugaredLogger, appConfig *AppConfig) *storage.Storage {
	storage, err := storage.NewStorage(appConfig.DbType, appConfig.DbConnectionString)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	return storage
}

func setupPowerDns(log *zap.SugaredLogger, appConfig *AppConfig) *powerdns.Client {
	pdns := powerdns.New(appConfig.PdnsUrl, appConfig.PdnsVhost, powerdns.WithAPIKey(appConfig.PdnsApiKey))
	if pdns == nil {
		log.Fatalf("app.setupPowerDns: Failed to create PowerDNS client")
	}

	return pdns
}

func setupGinWebserver(app *AppData) (router *gin.Engine) {
	auth_config := gin.H{"auth_provider": "not configured"}

	// Determine the Gin mode based on the dev_mode variable
	gin_mode := gin.ReleaseMode
	if app.Config.DevMode {
		gin_mode = gin.TestMode // Or gin.TestMode or gin.DebugMode
	}

	app.Log.Debugf("Running Gin web server in '%s' mode.", gin_mode)

	// Set up the Gin router
	router = gin.New()

	//Create router group for  API routes for v1
	apiV1Group := router.Group("/v1")

	// Set CORS configuration
	router.Use(cors.Default())

	if app.Config.DevMode {
		app.Log.Debugf("Completely disabling caching in development mode.")
		router.Use(disableCachingMiddleware())
	}

	// Direct Gin's standard and error output streams to our custom Zap writer
	ginLogWriter := &helper.ZapWriter{SugarLogger: app.Log, Level: app.Log.Level()}
	gin.DefaultWriter = ginLogWriter
	gin.DefaultErrorWriter = ginLogWriter
	router.Use(ginzap.RecoveryWithZap(app.Logger, true))

	// Render an index page for human consumption
	router.GET("/", func(c *gin.Context) {
		c.Redirect(http.StatusTemporaryRedirect, "/ui/index.html")
	})

	router.Static("/ui", "./web-ui")
	router.Static("/client/dist", "./docs/client-dist")
	router.Static("/client/typescript", "./docs/client-typescript")

	// Swagger UI
	router.StaticFile("/swagger.json", "./docs/swagger.json")

	// Inject authentication data into the context
	switch app.Config.AuthProvider {
	case "fake":
		app.Log.Warnf("Using fake authentication provider, do not use in production")
		router.Use(auth.InjectFakeAuthMiddleware())
		auth_config = gin.H{"auth_provider": "fake"}

	case "oidc":
		app.Log.Infof("Using OIDC authentication provider.")

		oidcConfig := auth.OIDCVerifierConfig{
			IssuerURL: app.Config.OIDCIssuerURL,
			ClientID:  app.Config.OIDCClientID,
		}

		// Validate that all required OIDC environment variables are set
		if oidcConfig.IssuerURL == "" || oidcConfig.ClientID == "" {
			app.Log.Fatalf("OIDC verification configuration missing. Please set OIDC_ISSUER_URL and OIDC_CLIENT_ID environment variables.")
		}

		// Initialize the OIDCAuthVerifier
		oidcAuthVerifier, err := auth.NewOIDCAuthVerifier(oidcConfig, app.Log)
		if err != nil {
			app.Log.Fatalf("Failed to initialize OIDCAuthVerifier: %v", err)
		}

		//apiV1Group.Use(oidcAuthVerifier.BearerTokenAuthMiddleware())
		apiV1Group.Use(auth.CombinedAuthMiddleware(oidcAuthVerifier, app.Storage, app.Log))

		auth_config = gin.H{
			"auth_provider": "oidc",
			"issuer_url":    oidcConfig.IssuerURL,
			"client_id":     oidcConfig.ClientID,
			"redirect_uri":  fmt.Sprintf("%s/ui/index.html", app.Config.WebserverBaseUrl),
			"logout_uri":    fmt.Sprintf("%s/ui/index.html", app.Config.WebserverBaseUrl),
		}

	default:
		app.Log.Fatalf("Unknown authentication provider '%s'. Supported providers: fake, oidc.", app.Config.AuthProvider)
	}

	// Expose authorization config to the frontend
	router.GET(("/auth_config.json"), func(c *gin.Context) {
		c.JSON(http.StatusOK, auth_config)
	})

	// Expose DNS server configuration
	router.GET(("/dns_config.json"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"server_address": app.Config.DnsServerAddress,
			"server_port":    app.Config.DnsServerPort,
		})
	})

	// Create the API routes for v1
	CreateApiV1Group(apiV1Group, app)
	CreateTokensApiGroup(apiV1Group, app)
	CreateRfc2136ClientApiGroup(apiV1Group, app)

	return router
}

func LogAppConfig(appConfig AppConfig, log *zap.SugaredLogger) {
	var appConfigJson []byte
	var err error

	if appConfig.DevMode {
		appConfigJson, err = json.MarshalIndent(appConfig, "", "  ")
	} else {
		// Redact sensitive information (print first 10 characters of the secret)
		appConfig.UpstreamDns.Tsig_Secret = fmt.Sprintf("%s**********", appConfig.UpstreamDns.Tsig_Secret[:10])
		// In production mode, we use a compact JSON format without indentation
		appConfigJson, err = json.Marshal(appConfig)
	}

	//marshall the appConfig to JSON for logging
	if err != nil {
		log.Errorf("app.LogAppConfig: Failed to marshal appConfig to JSON: %v", err)
		return
	}

	log.Infof("app.LogAppConfig: Application configuration: %s", appConfigJson)
}

func disableCachingMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Apply the Cache-Control header to the static files
		//if strings.HasPrefix(c.Request.URL.Path, "/static/") {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		//}
		// Continue to the next middleware or handler
		c.Next()
	}
}
