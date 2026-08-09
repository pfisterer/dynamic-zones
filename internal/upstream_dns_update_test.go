package app

import (
	"fmt"
	"net"
	"testing"

	"github.com/joho/godotenv"
)

// TestUpstreamDnsUpdate exercises the periodic upstream announcement against a
// REAL nameserver — the one UPSTREAM_DNS_* points at, which in this project is
// the university's. That makes it useful only where someone has deliberately
// configured an upstream:
//
//   - without a TSIG secret it cannot work at all; it used to fail with
//     "dns: bad key algorithm", which reads like a bug in the code rather than
//     an absent configuration,
//   - with one it writes to whatever that server is, so it must never run
//     unattended (CI has no business sending RFC 2136 updates to production).
//
// So it skips unless an upstream is configured, exactly like the application
// itself, which disables the updater in that case. Making this a real test
// means pointing it at the PowerDNS test container the other tests already
// start, and giving that container a TSIG key — see d8 in the deployment repo.
func TestUpstreamDnsUpdate(t *testing.T) {
	// Load environment variables from .env file
	if err := godotenv.Load("../.env"); err != nil {
		fmt.Printf("app.SetupComponents: Failed to load the env vars: %v", err)
	}

	// Get application configuration from environment variables
	appConfig, err := GetAppConfigFromEnvironment()
	if err != nil {
		fmt.Printf("Failed to get app config from environment: %v", err)
		return
	}

	upstream := appConfig.UpstreamDns
	if upstream.Server == "" || upstream.Tsig_Secret == "" {
		t.Skipf("no upstream nameserver configured (UPSTREAM_DNS_SERVER=%q, TSIG secret %s) — nothing to announce to",
			upstream.Server, map[bool]string{true: "set", false: "empty"}[upstream.Tsig_Secret != ""])
	}

	// Load application configuration and create logger
	logger, log := CreateAppLogger(appConfig)
	defer logger.Sync()

	log.Info("Starting upstream DNS update test")
	dynamicZonesDnsIPAddress := net.ParseIP(appConfig.PowerDns.DnsServerAddress)

	err = PerformSingleUpstreamDnsUpdateCheck(&appConfig.UpstreamDns, dynamicZonesDnsIPAddress, log, true)
	if err != nil {
		log.Errorf("Upstream DNS update test failed: %v", err)
		t.Fatalf("Upstream DNS update test failed: %v", err)
	}

	log.Info("Done")
}
