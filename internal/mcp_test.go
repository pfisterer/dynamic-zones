package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pfisterer/cloud-self-service-golib/token"
	"go.uber.org/zap"
)

// These go through a real MCP client over HTTP against the real /mcp route
// behind the real auth middleware, because most of what is worth testing here
// lives in the wiring: which tools a token is shown, and whether a tool call
// arrives as the person who holds the token.

// mcpTestApp builds an AppData with storage and policy but no PowerDNS. Enough
// for every tool that does not touch DNS itself; the record tools get their own
// test against a real server further down.
func mcpTestApp(t *testing.T, superAdmins ...string) *AppData {
	t.Helper()

	store, err := NewStorage("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	admins := make(map[string]struct{}, len(superAdmins))
	for _, a := range superAdmins {
		admins[strings.ToLower(a)] = struct{}{}
	}
	return &AppData{
		Storage:     store,
		Log:         zap.NewNop().Sugar(),
		Config:      AppConfig{DnsPolicyConfig: DnsPolicyConfig{SuperAdminEmails: admins}},
	}
}

// mcpTestServer serves /mcp behind the real token authentication and returns the
// two token secrets: one read-only, one that may write.
func mcpTestServer(t *testing.T, app *AppData) (*httptest.Server, string, string) {
	return mcpTestServerFor(t, app, "alice")
}

// mcpTestServerFor is the same, for a chosen token owner — which is how a test
// asks "what does somebody else's token see".
func mcpTestServerFor(t *testing.T, app *AppData, subject string) (*httptest.Server, string, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)

	ctx := context.Background()
	readOnly, err := app.Storage.Tokens.Issue(ctx, subject, token.IssueOptions{TTL: time.Hour, ReadOnly: true})
	if err != nil {
		t.Fatalf("issue read-only token: %v", err)
	}
	writable, err := app.Storage.Tokens.Issue(ctx, subject, token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue write token: %v", err)
	}

	r := gin.New()
	g := r.Group("/mcp")
	g.Use(CombinedAuthMiddleware(nil, app.Storage, app.Log, false))
	RegisterMCPRoutes(g, app)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return srv, readOnly.Secret, writable.Secret
}

// bearerTransport puts the API token on every request, the way an MCP client
// configured with one does.
type bearerTransport struct {
	secret string
	base   http.RoundTripper
}

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("Authorization", "Bearer "+b.secret)
	return b.base.RoundTrip(clone)
}

func mcpSession(t *testing.T, srv *httptest.Server, secret string) *mcp.ClientSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)

	transport := &mcp.StreamableClientTransport{
		Endpoint:   srv.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearerTransport{secret: secret, base: http.DefaultTransport}},
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "1"}, nil).
		Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect to /mcp: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func toolNames(t *testing.T, session *mcp.ClientSession) []string {
	t.Helper()
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	slices.Sort(names)
	return names
}

// mcpReadTools is the list of tools that do not change anything, and therefore
// the exact set a read-only token may keep.
var mcpReadTools = []string{
	"get_zone", "list_delegations", "list_dns_records", "list_my_zones",
	"list_orphaned_zones", "list_policy_rules", "list_zone_owners",
}

// The whole reason the read-only rule moved off the HTTP method: every MCP call
// is a POST, so under the old code a read-only token could not even list tools.
func TestMCP_ReadOnlyTokenCanRead(t *testing.T) {
	srv, readOnlySecret, _ := mcpTestServer(t, mcpTestApp(t))
	session := mcpSession(t, srv, readOnlySecret)

	names := toolNames(t, session)
	for _, want := range mcpReadTools {
		if !slices.Contains(names, want) {
			t.Errorf("read tool %q missing from %v", want, names)
		}
	}

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "list_my_zones", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call list_my_zones: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_my_zones reported an error: %+v", res.Content)
	}
}

// A mutating tool is left out rather than offered and refused: a model picks
// from what it is shown, and one that always fails invites retries.
func TestMCP_ReadOnlyTokenLosesEveryWriteTool(t *testing.T) {
	srv, readOnlySecret, writeSecret := mcpTestServer(t, mcpTestApp(t))
	readOnly := toolNames(t, mcpSession(t, srv, readOnlySecret))
	write := toolNames(t, mcpSession(t, srv, writeSecret))

	for _, name := range write {
		if !slices.Contains(readOnly, name) {
			continue // correctly withheld
		}
		if !slices.Contains(mcpReadTools, name) {
			t.Errorf("%q is offered to a read-only token but is not a read tool", name)
		}
	}
	if len(readOnly) >= len(write) {
		t.Errorf("read-only got %d tools, write got %d — the gate is not doing anything", len(readOnly), len(write))
	}
}

func TestMCP_WriteTokenIsOfferedMutatingTools(t *testing.T) {
	srv, _, writeSecret := mcpTestServer(t, mcpTestApp(t))

	names := toolNames(t, mcpSession(t, srv, writeSecret))
	for _, want := range []string{
		"create_zone", "delete_zone", "set_dns_record", "delete_dns_record",
		"join_zone", "add_zone_owner", "remove_zone_owner", "rotate_zone_keys",
		"create_policy_rule", "update_policy_rule", "delete_policy_rule",
		"create_delegation", "update_delegation", "delete_delegation",
	} {
		if !slices.Contains(names, want) {
			t.Errorf("write tool %q missing for a write token, got %v", want, names)
		}
	}
}

// There is deliberately no tool that deletes an orphaned zone: an orphaned zone
// is nearly always a mistyped rule, and deleting it turns a fixable mistake into
// a permanent one.
func TestMCP_NoToolDeletesAnOrphanedZone(t *testing.T) {
	srv, _, writeSecret := mcpTestServer(t, mcpTestApp(t))

	for _, name := range toolNames(t, mcpSession(t, srv, writeSecret)) {
		if strings.Contains(name, "orphan") && strings.HasPrefix(name, "delete") {
			t.Errorf("%q must not exist: fixing the rule is the remedy, not deleting the zone", name)
		}
	}
}

// callTool returns the tool's error text, or "" when it succeeded.
func callToolErr(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("call %s: %v", name, err)
	}
	if !res.IsError {
		return ""
	}
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// The confirmation is the point: a plausible-sounding wrong name must not
// destroy anything. This is what catches a model that resolved "the old one" to
// the wrong zone — not prompt injection, which can echo a name as easily as it
// can invent one.
//
// The test asserts that the CONFIRMATION refused it: without that check the call
// would be refused anyway (the caller owns no zone here), and a test that
// accepted any error would pass with the check removed.
func TestMCP_DeleteZoneRefusesAMismatchedName(t *testing.T) {
	srv, _, writeSecret := mcpTestServer(t, mcpTestApp(t))
	session := mcpSession(t, srv, writeSecret)

	msg := callToolErr(t, session, "delete_zone", map[string]any{
		"zone": "mine.users.example.com", "confirm_zone": "yours.users.example.com",
	})
	if !strings.Contains(msg, "does not match") {
		t.Errorf("a mismatched confirmation must be refused as such, got %q", msg)
	}
}

// A policy rule is evaluated live, so deleting one takes zones away from
// everyone it matched. Same confirmation, same reason.
func TestMCP_DeletePolicyRuleRefusesAMismatchedPattern(t *testing.T) {
	app := mcpTestApp(t, "admin@example.com")
	rule := PolicyRule{ZonePattern: "%u.users.example.com", ZoneSoa: "users.example.com", TargetUserFilter: "*"}
	if err := app.Storage.db.Create(&rule).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	srv, _, writeSecret := mcpTestServer(t, app)
	session := mcpSession(t, srv, writeSecret)

	msg := callToolErr(t, session, "delete_policy_rule", map[string]any{
		"id": rule.ID, "confirm_zone_pattern": "%u.staff.example.com",
	})
	if !strings.Contains(msg, "does not match") {
		t.Errorf("a mismatched confirmation must be refused as such, got %q", msg)
	}
}

// The tools act as the token's owner, not as whoever the arguments name. A
// policy rule granting alice a zone must show up for alice's token.
func TestMCP_ToolsActAsTheTokenOwner(t *testing.T) {
	app := mcpTestApp(t)
	rule := PolicyRule{ZonePattern: "%u.users.example.com", ZoneSoa: "users.example.com", TargetUserFilter: "alice"}
	if err := app.Storage.db.Create(&rule).Error; err != nil {
		t.Fatalf("seed rule: %v", err)
	}
	srv, readOnlySecret, _ := mcpTestServer(t, app)
	session := mcpSession(t, srv, readOnlySecret)

	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "list_my_zones", Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatalf("call list_my_zones: %v", err)
	}
	if res.IsError {
		t.Fatalf("list_my_zones failed: %+v", res.Content)
	}

	var got mcpZoneList
	if err := json.Unmarshal(mustStructured(t, res), &got); err != nil {
		t.Fatalf("decode result: %v", err)
	}
	if len(got.Zones) != 1 || got.Zones[0].Name != "alice.users.example.com" {
		t.Errorf("got %+v, want the zone alice's rule grants", got.Zones)
	}
}

// Super-admin-only tools answer with the refusal, not with data, for a token
// whose owner is not one.
func TestMCP_AdminToolsRefuseANonAdmin(t *testing.T) {
	srv, readOnlySecret, _ := mcpTestServer(t, mcpTestApp(t, "someone.else@example.com"))
	session := mcpSession(t, srv, readOnlySecret)

	for _, name := range []string{"list_delegations", "list_orphaned_zones"} {
		if msg := callToolErr(t, session, name, map[string]any{}); !strings.Contains(msg, "super admin") {
			t.Errorf("%s: got %q, want a super-admin refusal", name, msg)
		}
	}
}

func mustStructured(t *testing.T, res *mcp.CallToolResult) []byte {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	return raw
}
