package app

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/farberg/dynamic-zones/internal/auth"
	"github.com/farberg/dynamic-zones/internal/config"
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

type AppData struct {
	Config      config.AppConfig
	Uzp         zones.ZoneProvider
	Storage     *storage.Storage
	Pdns        *powerdns.Client
	RefreshTime uint64
	Logger      *zap.Logger
	Log         *zap.SugaredLogger
}

func CreateAppLogger(appConfig config.AppConfig) (*zap.Logger, *zap.SugaredLogger) {
	logger, log := helper.InitLogger(appConfig.DevMode)
	if appConfig.DevMode {
		log.Warn("app.SetupComponents: Running in development mode. This is not secure for production!")
	} else {
		log.Info("app.SetupComponents: Running in production mode.")
	}

	// Print application configuration
	LogAppConfig(appConfig, log)

	return logger, log
}

func RunApplication() {
	// Load environment variables from .env file
	if err := godotenv.Load(); err != nil {
		fmt.Printf("app.SetupComponents: Failed to load the env vars: %v", err)
	}

	// Get application configuration from environment variables
	appConfig := config.GetAppConfigFromEnvironment()

	// Load application configuration and create logger
	logger, log := CreateAppLogger(appConfig)
	defer logger.Sync()

	// Create componentes
	pdns := setupPowerDns(log, &appConfig)
	db := setupStorage(log, &appConfig)
	uzp := zones.CreateUserZoneProvider(&appConfig, logger)

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
	err := router.Run(appConfig.WebServer.GinBindString)
	if err != nil {
		log.Fatalf("app.RunApp: Failed to start server: %v", err)
	}

	log.Info("app.RunApp: Application stopped.")
}

func setupStorage(log *zap.SugaredLogger, appConfig *config.AppConfig) *storage.Storage {
	storage, err := storage.NewStorage(appConfig.Storage.DbType, appConfig.Storage.DbConnectionString)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	return storage
}

func setupPowerDns(log *zap.SugaredLogger, appConfig *config.AppConfig) *powerdns.Client {
	pdns := powerdns.New(appConfig.PowerDns.PdnsUrl, appConfig.PowerDns.PdnsVhost, powerdns.WithAPIKey(appConfig.PowerDns.PdnsApiKey))
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
			"redirect_uri":  fmt.Sprintf("%s/ui/index.html", app.Config.WebServer.WebserverBaseUrl),
			"logout_uri":    fmt.Sprintf("%s/ui/index.html", app.Config.WebServer.WebserverBaseUrl),
		}

	default:
		app.Log.Fatalf("Unknown authentication provider '%s'. Supported providers: fake, oidc.", app.Config.WebServer.AuthProvider)
	}

	// Expose authorization config to the frontend
	router.GET(("/auth_config.json"), func(c *gin.Context) {
		c.JSON(http.StatusOK, auth_config)
	})

	// Expose DNS server configuration
	router.GET(("/app_config.json"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"dns_server_address": app.Config.PowerDns.DnsServerAddress,
			"dns_server_port":    app.Config.PowerDns.DnsServerPort,
			"version":            helper.AppVersion,
		})
	})

	// Create the API routes for v1
	CreateApiV1Group(apiV1Group, app)
	CreateTokensApiGroup(apiV1Group, app)
	CreateRfc2136ClientApiGroup(apiV1Group, app)

	return router
}

func LogAppConfig(appConfig config.AppConfig, log *zap.SugaredLogger) {
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
