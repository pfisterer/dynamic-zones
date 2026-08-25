package app

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// The point of the record tools, against a real PowerDNS: a caller writes and
// reads records WITHOUT ever being given the zone's TSIG key.
//
// That property is the reason RecordsList/RecordUpsert/RecordDelete exist as
// service methods at all. The REST routes take the key from the request, because
// the browser holds it already; a model must not be put in that position, since
// anything it is handed lands in its context, its transcript and its client's
// storage. So these assert both halves: the calls work with no key in them, and
// no answer contains the key.

// mcpRecordsTestApp is newPdnsTestApp plus the two things the record path needs:
// where to send its own DNS traffic, and a policy rule that entitles the test
// user to a zone.
func mcpRecordsTestApp(t *testing.T, user, zone, soa string) *AppData {
	t.Helper()

	app, container := newPdnsTestAppWithContainer(t)
	// GetServerAddress reads this from the configuration, not from the PowerDNS
	// client: it is where the service sends its OWN AXFR and RFC 2136 traffic.
	app.Config.PowerDns.DnsQueryTarget = fmt.Sprintf("127.0.0.1:%d", container.GetExternalDnsPort())
	app.Config.DnsPolicyConfig.SuperAdminEmails = map[string]struct{}{}

	rule := PolicyRule{ZonePattern: zone, ZoneSoa: soa, TargetUserFilter: user}
	if err := app.Storage.db.Create(&rule).Error; err != nil {
		t.Fatalf("seed policy rule: %v", err)
	}
	return app
}

func TestMCP_RecordToolsNeverSeeTheZoneKey(t *testing.T) {
	const user = "alice"
	const zone = "alice.users.example.com"
	const soa = "users.example.com"

	app := mcpRecordsTestApp(t, user, zone, soa)
	ctx := context.Background()

	claims := &UserClaims{Subject: user, Email: user, PreferredUsername: user}
	if _, err := app.ZoneCreateAuthorized(ctx, claims, zone); err != nil {
		t.Fatalf("create zone: %v", err)
	}

	// The key the tools must never reveal — read here so the assertions below
	// can look for the actual secret rather than for a shape.
	creds, err := app.OwnerTSIG(ctx, user, zone)
	if err != nil {
		t.Fatalf("resolve owner key: %v", err)
	}
	if creds.Key == "" {
		t.Fatal("the zone has no key, so this test would prove nothing")
	}

	srv, _, writeSecret := mcpTestServerFor(t, app, user)
	session := mcpSession(t, srv, writeSecret)

	// A write with no credential anywhere in the arguments.
	written := callToolJSON(t, session, "set_dns_record", map[string]any{
		"zone": zone, "name": "www", "type": "A", "value": "192.0.2.10", "ttl": 300,
	})
	if !strings.Contains(written, "192.0.2.10") {
		t.Errorf("set_dns_record did not report the record it wrote: %s", written)
	}
	if strings.Contains(written, creds.Key) {
		t.Error("set_dns_record returned the zone's TSIG key")
	}

	listed := callToolJSON(t, session, "list_dns_records", map[string]any{"zone": zone})
	if !strings.Contains(listed, "192.0.2.10") {
		t.Errorf("the record just written is missing from the listing: %s", listed)
	}
	if strings.Contains(listed, creds.Key) {
		t.Error("list_dns_records returned the zone's TSIG key")
	}

	deleted := callToolJSON(t, session, "delete_dns_record", map[string]any{
		"zone": zone, "name": "www", "type": "A",
	})
	if strings.Contains(deleted, creds.Key) {
		t.Error("delete_dns_record returned the zone's TSIG key")
	}

	after := callToolJSON(t, session, "list_dns_records", map[string]any{"zone": zone})
	if strings.Contains(after, "192.0.2.10") {
		t.Errorf("the record survived its deletion: %s", after)
	}

	// And the zone tools must not leak it either: get_zone answers with metadata
	// where the REST route serves the browser a payload containing the key.
	if got := callToolJSON(t, session, "get_zone", map[string]any{"zone": zone}); strings.Contains(got, creds.Key) {
		t.Error("get_zone returned the zone's TSIG key")
	}
}

// A record tool must refuse a zone the caller does not own, even though the
// service could resolve a key for it.
func TestMCP_RecordToolsRefuseAZoneTheCallerDoesNotOwn(t *testing.T) {
	const user = "alice"
	const zone = "alice.users.example.com"

	app := mcpRecordsTestApp(t, user, zone, "users.example.com")
	ctx := context.Background()
	claims := &UserClaims{Subject: user, Email: user, PreferredUsername: user}
	if _, err := app.ZoneCreateAuthorized(ctx, claims, zone); err != nil {
		t.Fatalf("create zone: %v", err)
	}

	// A token belonging to somebody else entirely.
	srv, _, writeSecret := mcpTestServerFor(t, app, "mallory")
	session := mcpSession(t, srv, writeSecret)

	msg := callToolErr(t, session, "set_dns_record", map[string]any{
		"zone": zone, "name": "www", "type": "A", "value": "192.0.2.66",
	})
	if msg == "" {
		t.Fatal("writing into someone else's zone was allowed")
	}
	if !strings.Contains(msg, "owner") {
		t.Errorf("got %q, want a refusal about ownership", msg)
	}
}

// callToolJSON returns the tool's structured result as JSON text, failing the
// test if the call errored.
func callToolJSON(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if res.IsError {
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		t.Fatalf("%s reported an error: %s", name, sb.String())
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal %s result: %v", name, err)
	}
	return string(raw)
}
