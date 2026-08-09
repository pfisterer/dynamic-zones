package app

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/farberg/dynamic-zones/internal/test_helpers"
)

var baseURL = "http://localhost:8082"

var expectedZones = []string{"example1.com", "test.org"}

// The identity the roundtrip test acts as. It is used verbatim as the email,
// because %u in a zone pattern expands to helper.DnsMakeCompliant(email) and
// this one already is a valid DNS label — so the expected zones stay readable
// as "fakestudent.example1.com" instead of "fakestudent-at-example-com...".
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

// DoRequestForTests performs an AUTHENTICATED request against the test server.
//
// Every /v1 route is behind authentication, and in development mode the API
// trusts the X-Dummy-Auth-User header instead of verifying a bearer token.
// Without it the answer is 401 — which a test that unmarshals the body into
// its expected response type reads as "empty result", failing on a value
// comparison while the real cause (not authenticated) goes unmentioned.
func DoRequestForTests(t *testing.T, method, path string, body io.Reader) (*http.Response, error) {
	t.Helper()

	req, err := http.NewRequest(method, GetBaseURLForTests()+path, body)
	if err != nil {
		return nil, fmt.Errorf("app.DoRequestForTests: building %s %s: %w", method, path, err)
	}
	req.Header.Set("X-Dummy-Auth-User", expectedUserName)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	return http.DefaultClient.Do(req)
}

func SetupEnvironmentForTests(t *testing.T) {
	// Change the working directory to the base of the project
	err := os.Chdir("../")
	if err != nil {
		t.Fatalf("app.SetupEnvironmentForTests: Failed to change working directory: %v", err)
	}

	// These are the names the configuration actually reads. They used to carry a
	// DYNAMIC_ZONES_API_ prefix that nothing has looked at for a long time, so
	// the fixture configured nothing at all: on a developer machine the .env
	// happened to supply working values, and on a clean checkout the tests ran
	// against production defaults.
	//
	// Note that .env still wins where it exists — the app loads it with
	// godotenv.Overload — but it sets the same development values, and on a
	// machine without one (CI) these apply.
	t.Setenv("API_MODE", "development")
	t.Setenv("DB_TYPE", "sqlite")
	t.Setenv("DB_CONNECTION_STRING", "file::memory:?cache=shared")
	t.Setenv("API_BIND", ":8082")
}

// SeedPolicyRulesForTests gives the test user the zones the roundtrip expects.
//
// Written straight into the store rather than through the API: creating a rule
// requires a super admin, and that list comes from DNS_POLICY_SUPERADMIN_EMAILS
// — which a developer's .env overrides, so a fixture cannot rely on setting it.
// The store is the same shared in-memory SQLite the application opened.
func SeedPolicyRulesForTests(t *testing.T) {
	t.Helper()

	store, err := NewStorage("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("app.SeedPolicyRulesForTests: opening the test store: %v", err)
	}

	for _, zone := range expectedZones {
		rule := PolicyRule{
			ZonePattern:      "%u." + zone,
			ZoneSoa:          zone,
			TargetUserFilter: expectedUserName,
		}
		if err := store.db.Create(&rule).Error; err != nil {
			t.Fatalf("app.SeedPolicyRulesForTests: creating rule for %q: %v", zone, err)
		}
	}
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

	os.Setenv("PDNS_URL", baseUrl)
	// PDNS_VHOST is PowerDNS' SERVER ID, not a network host — the API path is
	// /api/v1/servers/<id>, and that id is "localhost" in every stock install.
	// It used to be derived from the base URL's hostname, which only happened
	// to work while that hostname read "localhost" too.
	os.Setenv("PDNS_VHOST", "localhost")
	os.Setenv("PDNS_API_KEY", pdns_docker.GetApiKey())

	t.Logf("app.StartEphemeralContainerAndAppForTests: Updated env to use PDNS test container: PDNS_URL=%s, PDNS_API_KEY=%s", baseUrl, pdns_docker.GetApiKey())

	// Start the application
	go RunApplication()

	return pdns_docker
}
