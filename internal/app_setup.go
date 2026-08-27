package app

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/logging"
	"github.com/pfisterer/cloud-self-service-golib/redact"
	"go.uber.org/zap"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
)

type AppData struct {
	Config   AppConfig
	Storage  *Storage
	PowerDns *PowerDnsClient
	Logger   *zap.Logger
	Log      *zap.SugaredLogger
}

func CreateAppLogger(appConfig AppConfig) (*zap.Logger, *zap.SugaredLogger) {
	logger, log := logging.Init(appConfig.DevMode)
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
	appConfig, err := GetAppConfigFromEnvironment()
	if err != nil {
		log.Fatal("Error loading application configuration: ", err)
	}

	// Load application configuration and create logger
	logger, log := CreateAppLogger(appConfig)
	defer logger.Sync()

	// Powerds client
	thisNsServer := fmt.Sprintf("%s.%s", appConfig.UpstreamDns.Name, appConfig.UpstreamDns.Zone)

	pdns, err := NewPowerDnsClient(
		appConfig.PowerDns.PdnsUrl, appConfig.PowerDns.PdnsVhost, appConfig.PowerDns.PdnsApiKey, appConfig.PowerDns.DefaultTTLSeconds,
		[]string{thisNsServer}, appConfig.ZoneDefaults.DefaultAdminTsigKeyName, appConfig.ZoneDefaults.DefaultAdminTsigKey,
		appConfig.ZoneDefaults.DefaultAdminTsigAlg,
		appConfig.ZoneDefaults.DefaultRecords,
		appConfig.ZoneDefaults.DefaultRecordsSoa,
		log,
	)
	if err != nil {
		log.Fatalf("Failed to create PowerDNS client: %v", err)
	}

	// Create storage component
	db, err := NewStorage(appConfig.Storage.DbType, appConfig.Storage.DbConnectionString)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v", err)
	}

	// Prepare application data
	appData := AppData{
		Config:   appConfig,
		Storage:  db,
		PowerDns: pdns,
		Logger:   logger,
		Log:      log,
	}

	// Start application
	go RunPeriodicUpstreamDnsUpdateCheck(appData)

	// If requested, insert initial data into the database
	if appConfig.InitialDataScriptPath != "" {
		// Read the file contents
		scriptContent, err := os.ReadFile(appConfig.InitialDataScriptPath)
		if err != nil {
			log.Fatalf("Failed to read initial data script file: %v", err)
			return
		}

		// Create initial data provider
		initialDataProvider, err := NewJavaScriptEngine(&appData)
		err = initialDataProvider.Run(scriptContent)
		if err != nil {
			log.Fatalf("Failed to run initial data script: %v", err)
			return
		}

		log.Infof("Successfully executed initial data script: %s", appConfig.InitialDataScriptPath)
	}

	// Create and run the web server server forever
	router := setupGinWebserver(&appData)
	err = router.Run(appConfig.WebServer.GinBindString)
	if err != nil {
		log.Fatalf("app.RunApp: Failed to start server: %v", err)
	}

	log.Info("app.RunApp: Application stopped.")
}

func setupGinWebserver(app *AppData) (router *gin.Engine) {
	// Determine the Gin mode based on the dev_mode variable
	gin_mode := gin.ReleaseMode
	if app.Config.DevMode {
		gin_mode = gin.TestMode // Or gin.TestMode or gin.DebugMode
	}

	app.Log.Debugf("Running Gin web server in '%s' mode.", gin_mode)

	// Set up the Gin router
	router = gin.New()

	if app.Config.DevMode {
		app.Log.Debugf("Completely disabling caching in development mode.")
		router.Use(ginweb.DisableCaching())
	}

	// Direct Gin's standard and error output streams to our custom Zap writer
	ginLogWriter := &logging.Writer{Logger: app.Log, Level: app.Log.Level()}
	gin.DefaultWriter = ginLogWriter
	gin.DefaultErrorWriter = ginLogWriter
	router.Use(ginzap.RecoveryWithZap(app.Logger, true))

	// Create OIDC Auth Verifier
	oidcConfig := OIDCVerifierConfig{
		IssuerURL: app.Config.WebServer.OIDCIssuerURL,
		ClientID:  app.Config.WebServer.OIDCClientID,
	}

	oidcAuthVerifier, err := NewOIDCAuthVerifier(oidcConfig, app.Log)
	if err != nil {
		app.Log.Fatalf("Failed to initialize OIDCAuthVerifier: %v", err)
	}

	// Create static file server
	homeGroup := router.Group("/")
	homeGroup.Use(cors.Default())
	// These routes serve the landing page, swagger.json and config.json — all of
	// which embed the running version. Served uncached so a deploy is visible on
	// the next reload instead of whenever a browser cache expires. (The generated
	// TypeScript client used to be served here too and had the same problem
	// harder; it is an npm package consumed at build time now.) In DevMode the
	// whole router already gets this middleware.
	if !app.Config.DevMode {
		homeGroup.Use(ginweb.DisableCaching())
	}
	CreateHomeRoutes(homeGroup, app)

	// Create router group for  API routes for v1
	apiV1Group := router.Group("/v1")
	ginweb.EnableCORS(apiV1Group, ginweb.CORSOptions{
		AllowedOrigins: app.Config.WebServer.CORSAllowedOrigins,
		DevMode:        app.Config.DevMode,
		AllowHeaders:   []string{"Origin", "Content-Type", "Authorization", "X-DNS-Key-Name", "X-DNS-Key-Algorithm", "X-DNS-Key", "X-Dummy-Auth-User"},
		Log:            app.Log,
	})
	apiV1Group.Use(CombinedAuthMiddleware(oidcAuthVerifier, app.Storage, app.Log, app.Config.DevMode))

	// The read-only rule for REST, mounted here rather than inside the auth
	// middleware: "anything but GET is a write" is true of these routes and of
	// nothing else, so it belongs to the group it describes.
	apiV1Group.Use(ginweb.RejectWritesForReadOnlyTokens(app.Log))
	CreateApiV1Zones(apiV1Group, app)
	CreateTokensApiGroup(apiV1Group, app)
	CreateRfc2136ClientApiGroup(apiV1Group, app)
	CreatePolicyApiGroup(apiV1Group, app)

	// The MCP endpoint: same authentication as /v1, deliberately WITHOUT
	// RejectWritesForReadOnlyTokens. Every MCP call is a POST, so the method
	// cannot say whether an operation writes — the tool does, and mcp.go checks
	// it there. No CORS: this is for an MCP client, not a browser.
	mcpGroup := router.Group("/mcp")
	mcpGroup.Use(CombinedAuthMiddleware(oidcAuthVerifier, app.Storage, app.Log, app.Config.DevMode))
	RegisterMCPRoutes(mcpGroup, app)

	return router
}

func logAppConfig(appConfig AppConfig, log *zap.SugaredLogger) {
	var appConfigJson []byte
	var err error

	if appConfig.DevMode {
		appConfigJson, err = json.MarshalIndent(appConfig, "", "  ")
	} else {
		// Redact every secret to a short preview before logging (SEC #10): these
		// logs are shipped to Loki, so full API keys / TSIG keys / DB passwords must
		// never appear. redact.Secret also length-guards the value, so an empty or
		// short secret can no longer panic on a slice (SEC #18).
		appConfig.UpstreamDns.Tsig_Secret = redact.Secret(appConfig.UpstreamDns.Tsig_Secret)
		appConfig.PowerDns.PdnsApiKey = redact.Secret(appConfig.PowerDns.PdnsApiKey)
		appConfig.ZoneDefaults.DefaultAdminTsigKey = redact.Secret(appConfig.ZoneDefaults.DefaultAdminTsigKey)
		appConfig.Storage.DbConnectionString = redact.ConnString(appConfig.Storage.DbConnectionString)
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
