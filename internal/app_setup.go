package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/config"
	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/farberg/dynamic-zones/internal/storage"
	"github.com/farberg/dynamic-zones/internal/zones"
	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
)

type AppData struct {
	Config       config.AppConfig
	ZoneProvider zones.ZoneProvider
	Storage      *storage.Storage
	PowerDns     *zones.PowerDnsClient
	RefreshTime  uint64
	Logger       *zap.Logger
	Log          *zap.SugaredLogger
}

func CreateAppLogger(appConfig config.AppConfig) (*zap.Logger, *zap.SugaredLogger) {
	logger, log := helper.InitLogger(appConfig.DevMode)
	if appConfig.DevMode {
		log.Warn("app.SetupComponents: Running in development mode. This is not secure for production!")
	} else {
		log.Info("app.SetupComponents: Running in production mode.")
	}

	// Print application configuration
	logAppConfig(appConfig, log)

	return logger, log
}

func RunApplication() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("app.SetupComponents: Failed to load the env vars: %v", err)
	}

	// Get application configuration from environment variables
	appConfig, err := config.GetAppConfigFromEnvironment()
	if err != nil {
		log.Fatal("Error loading application configuration: ", err)
	}

	// Load application configuration and create logger
	logger, log := CreateAppLogger(appConfig)
	defer logger.Sync()

	// Create components

	thisNsServer := fmt.Sprintf("%s.%s", appConfig.UpstreamDns.Name, appConfig.UpstreamDns.Zone)

	pdns, err := zones.NewPowerDnsClient(
		appConfig.PowerDns.PdnsUrl, appConfig.PowerDns.PdnsVhost, appConfig.PowerDns.PdnsApiKey, appConfig.PowerDns.DefaultTTLSeconds,
		[]string{thisNsServer}, appConfig.UserZoneProvider.DefaultAdminTsigKeyName, appConfig.UserZoneProvider.DefaultAdminTsigKey,
		appConfig.UserZoneProvider.DefaultAdminTsigAlg,
		appConfig.UserZoneProvider.DefaultRecords,
		log,
	)
	if err != nil {
		log.Fatalf("Failed to create PowerDNS client: %v", err)
	}

	db, err := storage.NewStorage(appConfig.Storage.DbType, appConfig.Storage.DbConnectionString)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	zoneProvider := zones.NewUserZoneProvider(&appConfig, logger)

	appData := AppData{
		Config:       appConfig,
		ZoneProvider: zoneProvider,
		Storage:      db,
		PowerDns:     pdns,
		Logger:       logger,
		Log:          log,
	}

	// Start application
	go RunPeriodicUpstreamDnsUpdateCheck(appData)

	// Create and run the web server server forever
	router := setupGinWebserver(&appData)
	err = router.Run(appConfig.WebServer.GinBindString)
	if err != nil {
		log.Fatalf("app.RunApp: Failed to start server: %v", err)
	}

	log.Info("app.RunApp: Application stopped.")
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
	router.Use(cors.Default())

	if app.Config.DevMode {
		app.Log.Debugf("Completely disabling caching in development mode.")
		router.Use(disableCachingMiddleware())
		app.Log.Debugf("Enabling CORS origin reflection in development mode.")
	}

	// Direct Gin's standard and error output streams to our custom Zap writer
	ginLogWriter := &helper.ZapWriter{SugarLogger: app.Log, Level: app.Log.Level()}
	gin.DefaultWriter = ginLogWriter
	gin.DefaultErrorWriter = ginLogWriter
	router.Use(ginzap.RecoveryWithZap(app.Logger, true))

	// Expose index.html, client SDK and Swagger UI
	index_html := "./web/index.html"
	router.StaticFile("/", index_html)
	router.StaticFile("/index.html", index_html)
	router.Static("/client/dist", "./build/gen/client-dist")
	router.StaticFile("/swagger-index.html", "./web/swagger-index.html")
	router.StaticFile("/swagger.json", "./build/gen/swagger.json")

	// Inject authentication data into the context
	switch app.Config.WebServer.AuthProvider {
	case "fake":
		app.Log.Warnf("Using fake authentication provider, do not use in production")
		router.Use(auth.InjectFakeAuthMiddleware())
		auth_config = gin.H{"auth_provider": "fake"}

	case "oidc":
		app.Log.Infof("Using OIDC authentication provider.")

		oidcConfig := auth.OIDCVerifierConfig{
			IssuerURL: app.Config.WebServer.OIDCIssuerURL,
			ClientID:  app.Config.WebServer.OIDCClientID,
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
		}

	default:
		app.Log.Fatalf("Unknown authentication provider '%s'. Supported providers: fake, oidc.", app.Config.WebServer.AuthProvider)
	}

	// Expose DNS server configuration
	router.GET(("/config.json"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"dns_server_address": app.Config.PowerDns.DnsServerAddress,
			"dns_server_port":    app.Config.PowerDns.DnsServerPort,
			"version":            helper.AppVersion,
			"auth":               auth_config,
		})
	})

	// Create the API routes for v1
	enableCorsOriginReflectionConfig(apiV1Group)
	CreateApiV1Zones(apiV1Group, app)
	CreateTokensApiGroup(apiV1Group, app)
	CreateRfc2136ClientApiGroup(apiV1Group, app)

	return router
}

func logAppConfig(appConfig config.AppConfig, log *zap.SugaredLogger) {
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

func enableCorsOriginReflectionConfig(router *gin.RouterGroup) {

	corsConfig := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			fmt.Printf("CORS origin reflection: allowing origin: %s\n", origin)
			return true
		},
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-DNS-Key-Name", "X-DNS-Key-Algorithm", "X-DNS-Key"},
		MaxAge:           1 * time.Hour,
	}

	router.Use(cors.New(corsConfig))

	router.OPTIONS("/*path", func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization")
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", fmt.Sprint(int(time.Hour.Seconds())))
		c.Status(http.StatusNoContent)
	})

}
