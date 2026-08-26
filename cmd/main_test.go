package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	app "github.com/pfisterer/dynamic-zones/internal"
	"github.com/pfisterer/dynamic-zones/internal/helper"
	"github.com/stretchr/testify/assert"
)

func TestRoundtrip(t *testing.T) {
	// Set up the test environment
	pdns_docker := app.StartEphemeralContainerAndAppForTests(t)
	defer pdns_docker.Cleanup()

	time.Sleep(2 * time.Second) // Wait for the server to start

	// The zones this test expects come from policy rules; nothing seeds them.
	app.SeedPolicyRulesForTests(t)

	// Run the tests
	testGetIndexPage(t)
	available_zones := testGetAvailableZones(t)
	testCreateZone(t, available_zones[0].Name)
	zoneResponse := testGetZone(t, available_zones[0].Name)
	testDnsUpdate(t, zoneResponse, pdns_docker.GetExternalDnsPort())
	testDeleteZone(t, available_zones[0].Name)
}

func testGetIndexPage(t *testing.T) {
	resp, err := app.DoRequestForTests(t, http.MethodGet, "/", nil)
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
func testGetAvailableZones(t *testing.T) []app.ZoneStatus {
	// Send a GET request to the available zones endpoint
	resp, err := app.DoRequestForTests(t, http.MethodGet, "/v1/zones/", nil)
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

	// Compare NAMES: the endpoint answers with ZoneStatus values, and comparing
	// those against a list of strings could never match. Built into a fresh
	// slice, because `expectedZones[:]` shares its array with the package-level
	// list and the loop used to rewrite it in place.
	expectedZones := make([]string, 0, len(app.GetExpectedZonesForTests()))
	for _, zone := range app.GetExpectedZonesForTests() {
		expectedZones = append(expectedZones, app.GetExpectedUserNameForTests()+"."+zone)
	}

	actualZones := make([]string, 0, len(response.Zones))
	for _, zone := range response.Zones {
		actualZones = append(actualZones, zone.Name)
	}

	assert.ElementsMatch(t, expectedZones, actualZones, "testGetAvailableZones: Expected zones do not match the response zones")

	// Check if the status code is 200 OK
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("testGetAvailableZones: Expected status code 200, got %d", resp.StatusCode)
	}

	return response.Zones
}

func testCreateZone(t *testing.T, zone string) {
	// Send a POST request to create a new zone
	resp, err := app.DoRequestForTests(t, http.MethodPost, "/v1/zones/"+zone, nil)
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

func testGetZone(t *testing.T, zone string) app.ZoneDataResponse {
	resp, err := app.DoRequestForTests(t, http.MethodGet, "/v1/zones/"+zone, nil)
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

	// The zone itself is nested under "zoneData"; the response also carries the
	// external-dns snippet, the owners and the sharing flag. Unmarshalling the
	// whole body into ZoneDataResponse silently produced an empty struct.
	var response struct {
		ZoneData app.ZoneDataResponse `json:"zoneData"`
	}
	err = json.Unmarshal(body, &response)
	if err != nil {
		t.Fatalf("testGetZone: Failed to unmarshal response body: %v, response body = %s", err, body)
	}

	// Check if the response contains the expected zone
	if response.ZoneData.Zone != zone {
		t.Fatalf("testGetZone: Expected zone %s, got %s", zone, response.ZoneData.Zone)
	}

	return response.ZoneData
}

func testDeleteZone(t *testing.T, zone string) {
	// Send a DELETE request to delete the zone
	resp, err := app.DoRequestForTests(t, http.MethodDelete, "/v1/zones/"+zone, nil)
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
	resp, err = app.DoRequestForTests(t, http.MethodGet, "/v1/zones/"+zone, nil)
	if err != nil {
		t.Fatalf("testDeleteZone: Failed to send request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("testDeleteZone: Expected status code 404, got %d", resp.StatusCode)
	}

	t.Logf("testDeleteZone: Ok, Zone %s not found as expected", zone)
}

func testDnsUpdate(t *testing.T, zone app.ZoneDataResponse, nameserverPort uint16) {
	testname := "test." + zone.Zone + "."
	testcontent := "111.222.33.44"
	testttl := uint32(3600)
	nameserver := "127.0.0.1"

	// DNS-Lookup a non-existing record
	ips, err := helper.PerformALookup(nameserver, nameserverPort, testname)
	if err != nil {
		t.Fatalf("testDnsUpdate: Failed to perform 1st DNS lookup: %v", err)
	} else if len(ips) > 0 {
		t.Fatalf("testDnsUpdate: The hostname '%s' unexpectedly has an A record: %v\n", testname, ips)
	} else {
		t.Logf("testDnsUpdate: The hostname '%s' does not have an A record (as expected).\n", testname)
	}

	// Create a new DNS record using RFC 2136 update
	t.Logf("testDnsUpdate: Using data from zone %s for DNS update test. Zone name: %s, Zone keys: %+v", zone.Zone, zone.Zone, zone.ZoneKeys)

	_, err = helper.Rfc2136AddARecord(zone.ZoneKeys[0].Keyname, zone.ZoneKeys[0].Algorithm, zone.ZoneKeys[0].Key, nameserver+":"+strconv.Itoa(int(nameserverPort)), zone.Zone+".", testname, testcontent, testttl)
	if err != nil {
		t.Fatalf("testDnsUpdate: Failed to create DNS record: %v", err)
	}
	t.Logf("testDnsUpdate: Created DNS record %s with content %s and TTL %d\n", testname, testcontent, testttl)

	// DNS-Lookup a non-existing record
	ips, err = helper.PerformALookup(nameserver, nameserverPort, testname)
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
