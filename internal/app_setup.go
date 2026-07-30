package app

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
	"go.uber.org/zap"

	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
)

type AppData struct {
	Config      AppConfig
	Storage     *Storage
	PowerDns    *PowerDnsClient
	RefreshTime uint64
	Logger      *zap.Logger
	Log         *zap.SugaredLogger
}

func CreateAppLogger(appConfig AppConfig) (*zap.Logger, *zap.SugaredLogger) {
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
		router.Use(disableCachingMiddleware())
	}

	// Direct Gin's standard and error output streams to our custom Zap writer
	ginLogWriter := &helper.ZapWriter{SugarLogger: app.Log, Level: app.Log.Level()}
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
	// The generated API client (client/*.gen.mjs) is imported by the SPA at runtime and
	// MUST never be served stale: a browser holding a cached older SDK silently lacks any
	// newly added operation and the UI feature no-ops. In DevMode the whole router already
	// gets this; in production only the static assets need it.
	if !app.Config.DevMode {
		homeGroup.Use(disableCachingMiddleware())
	}
	CreateHomeRoutes(homeGroup, app)

	// Create router group for  API routes for v1
	apiV1Group := router.Group("/v1")
	enableCorsOriginReflectionConfig(apiV1Group)
	apiV1Group.Use(CombinedAuthMiddleware(oidcAuthVerifier, app.Storage, app.Log, app.Config.DevMode))
	CreateApiV1Zones(apiV1Group, app)
	CreateTokensApiGroup(apiV1Group, app)
	CreateRfc2136ClientApiGroup(apiV1Group, app)
	CreatePolicyApiGroup(apiV1Group, app)

	return router
}

// maskSecret returns a short, non-reversible preview of a secret for logs: the
// first few characters plus the total length, or "***" when it is too short to
// reveal safely. The length guard also means slicing can never panic on an empty
// or short secret (SEC #18).
func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	const shown = 4
	if len(s) <= shown {
		return "***"
	}
	return fmt.Sprintf("%s…(len %d)", s[:shown], len(s))
}

// maskConnString redacts only the password=… token of a space-separated DSN,
// keeping host/user/dbname visible for debugging.
func maskConnString(dsn string) string {
	fields := strings.Fields(dsn)
	for i, f := range fields {
		if k, v, ok := strings.Cut(f, "="); ok && strings.EqualFold(k, "password") {
			fields[i] = k + "=" + maskSecret(v)
		}
	}
	return strings.Join(fields, " ")
}

func logAppConfig(appConfig AppConfig, log *zap.SugaredLogger) {
	var appConfigJson []byte
	var err error

	if appConfig.DevMode {
		appConfigJson, err = json.MarshalIndent(appConfig, "", "  ")
	} else {
		// Redact every secret to a short preview before logging (SEC #10): these
		// logs are shipped to Loki, so full API keys / TSIG keys / DB passwords must
		// never appear. maskSecret also length-guards the value, so an empty or
		// short secret can no longer panic on a slice (SEC #18).
		appConfig.UpstreamDns.Tsig_Secret = maskSecret(appConfig.UpstreamDns.Tsig_Secret)
		appConfig.PowerDns.PdnsApiKey = maskSecret(appConfig.PowerDns.PdnsApiKey)
		appConfig.ZoneDefaults.DefaultAdminTsigKey = maskSecret(appConfig.ZoneDefaults.DefaultAdminTsigKey)
		appConfig.Storage.DbConnectionString = maskConnString(appConfig.Storage.DbConnectionString)
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
	allowedHeaders := []string{"Origin", "Content-Type", "Authorization", "X-DNS-Key-Name", "X-DNS-Key-Algorithm", "X-DNS-Key", "X-Dummy-Auth-User"}

	corsConfig := cors.Config{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowCredentials: true,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     allowedHeaders,
		MaxAge:           1 * time.Hour,
	}

	router.Use(cors.New(corsConfig))

	router.OPTIONS("/*path", func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin != "" {
			c.Header("Access-Control-Allow-Origin", origin)
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", strings.Join(allowedHeaders, ", "))
		c.Header("Access-Control-Allow-Credentials", "true")
		c.Header("Access-Control-Max-Age", fmt.Sprint(int(time.Hour.Seconds())))
		c.Status(http.StatusNoContent)
	})

}
