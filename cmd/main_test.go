package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	app "github.com/farberg/dynamic-zones/internal"
	"github.com/farberg/dynamic-zones/internal/zones"
	"github.com/stretchr/testify/assert"
)

func TestRoundtrip(t *testing.T) {
	// Set up the test environment
	pdns_docker := app.StartEphemeralContainerAndAppForTests(t)
	defer pdns_docker.Cleanup()

	time.Sleep(2 * time.Second) // Wait for the server to start

	// Run the tests
	testGetIndexPage(t)
	available_zones := testGetAvailableZones(t)
	testCreateZone(t, available_zones[0])
	zoneResponse := testGetZone(t, available_zones[0])
	testDnsUpdate(t, zoneResponse, pdns_docker.GetExternalDnsPort())
	testDeleteZone(t, available_zones[0])
}

func testGetIndexPage(t *testing.T) {
	resp, err := http.Get(app.GetBaseURLForTests() + "/")
	if err != nil {
		t.Fatalf("testGetIndexPage: Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("testGetIndexPage: Expected status code 200, got %d", resp.StatusCode)
	}
}

// Get the available zones
func testGetAvailableZones(t *testing.T) []string {
	// Send a GET request to the available zones endpoint
	resp, err := http.Get(app.GetBaseURLForTests() + "/v1/zones/")
	if err != nil {
		t.Fatalf("testGetAvailableZones: Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testGetAvailableZones: Failed to read response body: %v", err)
	}

	// Unmarshal the response body to AvailableZonesResponse
	var response app.AvailableZonesResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("testGetAvailableZones: Failed to unmarshal response body: %v", err)
	}

	// Check if the response contains the expected zones
	expectedZones := app.GetExpectedZonesForTests()[:]
	for i, zone := range expectedZones {
		expectedZones[i] = app.GetExpectedUserNameForTests() + "." + zone
	}

	assert.ElementsMatch(t, expectedZones, response.Zones, "testGetAvailableZones: Expected zones do not match the response zones")

	// Check if the status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("testGetAvailableZones: Expected status code 200, got %d", resp.StatusCode)
	}

	return response.Zones
}

func testCreateZone(t *testing.T, zone string) {
	// Send a POST request to create a new zone
	resp, err := http.Post(app.GetBaseURLForTests()+"/v1/zones/"+zone, "application/json", nil)
	if err != nil {
		t.Fatalf("testCreateZone: Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the status code is 200 OK
	if resp.StatusCode == http.StatusCreated {
		t.Logf("testCreateZone: Zone %s created successfully", zone)
	} else {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("testCreateZone: Expected status code 200, got %d, response body: %s", resp.StatusCode, b)
	}

}

func testGetZone(t *testing.T, zone string) zones.ZoneDataResponse {
	resp, err := http.Get(app.GetBaseURLForTests() + "/v1/zones/" + zone)
	if err != nil {
		t.Fatalf("testGetZone: ailed to send request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("testGetZone: Failed to read response body: %v", err)
	}

	// Check if the status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("testGetZone: Expected status code 200, got %d", resp.StatusCode)
	}

	// unmarshal the response body
	var response zones.ZoneDataResponse
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("testGetZone: Failed to unmarshal response body: %v, response body = %s", err, body)
	}

	// Check if the response contains the expected zone
	if response.Zone != zone {
		t.Fatalf("testGetZone: Expected zone %s, got %s", zone, response.Zone)
	}

	return response
}

func testDeleteZone(t *testing.T, zone string) {
	// Send a DELETE request to delete the zone
	req, err := http.NewRequest(http.MethodDelete, app.GetBaseURLForTests()+"/v1/zones/"+zone, nil)
	if err != nil {
		t.Fatalf("testDeleteZone: Failed to create request: %v", err)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("testDeleteZone: Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Check if the status code is 200 OK
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("testDeleteZone: Expected status code 200, got %d", resp.StatusCode)
	}

	t.Logf("testDeleteZone: Zone %s deleted successfully", zone)

	// Check if the zone is deleted
	resp, err = http.Get(app.GetBaseURLForTests() + "/v1/zones/" + zone)
	if err != nil {
		t.Fatalf("testDeleteZone: Failed to send request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("testDeleteZone: Expected status code 404, got %d", resp.StatusCode)
	}

	t.Logf("testDeleteZone: Ok, Zone %s not found as expected", zone)
}

func testDnsUpdate(t *testing.T, zone zones.ZoneDataResponse, nameserverPort int) {
	testname := "test." + zone.Zone + "."
	testcontent := "111.222.33.44"
	testttl := uint32(3600)
	nameserver := "127.0.0.1"

	// DNS-Lookup a non-existing record
	ips, err := zones.PerformALookup(nameserver, nameserverPort, testname)
	if err != nil {
		t.Fatalf("testDnsUpdate: Failed to perform 1st DNS lookup: %v", err)
	} else if len(ips) > 0 {
		t.Fatalf("testDnsUpdate: The hostname '%s' unexpectedly has an A record: %v\n", testname, ips)
	} else {
		t.Logf("testDnsUpdate: The hostname '%s' does not have an A record (as expected).\n", testname)
	}

	// Create a new DNS record using RFC 2136 update
	t.Logf("testDnsUpdate: Using data from zone %s for DNS update test. Zone name: %s, Zone keys: %+v", zone.Zone, zone.Zone, zone.ZoneKeys)

	_, err = zones.Rfc2136AddARecord(zone.ZoneKeys[0].Keyname, zone.ZoneKeys[0].Algorithm, zone.ZoneKeys[0].Key, nameserver+":"+strconv.Itoa(nameserverPort), zone.Zone+".", testname, testcontent, testttl)
	if err != nil {
		t.Fatalf("testDnsUpdate: Failed to create DNS record: %v", err)
	}
	t.Logf("testDnsUpdate: Created DNS record %s with content %s and TTL %d\n", testname, testcontent, testttl)

	// DNS-Lookup a non-existing record
	ips, err = zones.PerformALookup(nameserver, nameserverPort, testname)
	if err != nil {
		t.Fatalf("testDnsUpdate: Failed to perform 2nd DNS lookup: %v", err)
	} else if len(ips) == 1 {
		t.Logf("testDnsUpdate: The hostname '%s' has an A record: %v\n", testname, ips)
		if ips[0].String() != testcontent {
			t.Fatalf("testDnsUpdate: The hostname '%s' has an A record with unexpected content: %s (expected: %s)\n", testname, ips[0].String(), testcontent)
		} else {
			t.Logf("testDnsUpdate: The hostname '%s' has an A record with expected content: %s\n", testname, ips[0].String())
		}
	} else {
		t.Fatalf("testDnsUpdate: The hostname '%s' does not have an A record (NOT expected).\n", testname)
	}

}
