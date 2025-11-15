package app

import (
	"fmt"
	"net"
	"testing"

	"github.com/farberg/dynamic-zones/internal/config"
	"github.com/joho/godotenv"
)

func TestUpstreamDnsUpdate(t *testing.T) {
	// Load environment variables from .env file
	if err := godotenv.Load("../.env"); err != nil {
		fmt.Printf("app.SetupComponents: Failed to load the env vars: %v", err)
	}

	// Get application configuration from environment variables
	appConfig := config.GetAppConfigFromEnvironment()

	// Load application configuration and create logger
	logger, log := CreateAppLogger(appConfig)
	defer logger.Sync()

	log.Info("Starting upstream DNS update test")
	dynamicZonesDnsIPAddress := net.ParseIP(appConfig.PowerDns.DnsServerAddress)

	err := PerformSingleUpstreamDnsUpdateCheck(&appConfig.UpstreamDns, dynamicZonesDnsIPAddress, log, true)
	if err != nil {
		log.Errorf("Upstream DNS update test failed: %v", err)
		t.Fatalf("Upstream DNS update test failed: %v", err)
	}

	log.Info("Done")
}
