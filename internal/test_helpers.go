package app

import (
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/farberg/dynamic-zones/internal/test_helpers"
)

var baseURL = "http://localhost:8082"

var expectedZones = []string{"example1.com", "test.org"}

var expectedUserName = "fakestudent"

func GetExpectedZonesForTests() []string {
	return expectedZones
}

func GetExpectedUserNameForTests() string {
	return expectedUserName
}

func GetBaseURLForTests() string {
	return baseURL
}

func SetupEnvironmentForTests(t *testing.T) {
	// Change the working directory to the base of the project
	err := os.Chdir("../")
	if err != nil {
		t.Fatalf("app.SetupEnvironmentForTests: Failed to change working directory: %v", err)
	}

	os.Setenv("DYNAMIC_ZONES_API_MODE", "dev")
	os.Setenv("DYNAMIC_ZONES_API_DB_TYPE", "sqlite")
	os.Setenv("DYNAMIC_ZONES_API_DB_CONNECTION_STRING", "file::memory:?cache=shared")
	os.Setenv("DYNAMIC_ZONES_API_BIND", ":8082")
	os.Setenv("DYNAMIC_ZONES_API_DOMAIN_SUFFIXES", strings.Join(expectedZones[:], ", "))
}

func StartEphemeralContainerAndAppForTests(t *testing.T) *test_helpers.PdnsContainerTestInstance {
	ctx := t.Context()
	SetupEnvironmentForTests(t)

	// Start the server in a separate container
	pdns_docker, err := test_helpers.StartPndsTestContainer(ctx)
	if err != nil {
		t.Fatalf("app.StartEphemeralContainerAndAppForTests: Failed to start PDNS test container: %v", err)
	}

	baseUrl := pdns_docker.GetBaseUrl()
	t.Logf("app.StartEphemeralContainerAndAppForTests: PDNS test container started at %s", baseUrl)

	//extract hostname from baseurl
	u, err := url.Parse(baseUrl)
	if err != nil {
		t.Fatal("app.StartEphemeralContainerAndAppForTests: Error parsing URL:", err)
	}
	hostname := u.Hostname()

	os.Setenv("PDNS_URL", baseUrl)
	os.Setenv("PDNS_VHOST", hostname)
	os.Setenv("PDNS_API_KEY", pdns_docker.GetApiKey())

	t.Logf("app.StartEphemeralContainerAndAppForTests: Updated env to use PDNS test container: PDNS_URL=%s, PDNS_VHOST=%s, PDNS_API_KEY=%s", baseUrl, hostname, pdns_docker.GetApiKey())

	// Start the application
	go RunApplication()

	return pdns_docker
}
