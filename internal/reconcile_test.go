package app

import (
	"testing"
	"time"
)

func TestMissingZonesInPdns(t *testing.T) {
	// Set up the test environment
	pdns_docker := StartEphemeralContainerAndAppForTests(t)
	defer pdns_docker.Cleanup()

	// Create some regular zones (in db and pdns)

	// Create some zones in the database only

	// Run reconcile

	// Verify that reconcile reports the missing zones

	// Sleep for a few seconds to allow the container to start
	time.Sleep(5 * time.Second)

}
