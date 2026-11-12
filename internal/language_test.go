package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/cloud-self-service-golib/ginweb"
	"github.com/pfisterer/cloud-self-service-golib/mcpserve/mcptest"
	"github.com/pfisterer/cloud-self-service-golib/token"
)

// languages are the Accept-Language headers a test sends, and which of the two texts each must get: German without one and for anything that names neither language, English when the caller asks for it.
var languages = []struct {
	header  string
	english bool
}{
	{"", false},
	{"de-DE,de;q=0.9", false},
	{"fr", false},
	{"en", true},
	{"en-US,en;q=0.9,de;q=0.8", true},
}

// languageServer serves /v1 and /mcp as setupGinWebserver does — ginweb.Language on the engine, the real token authentication on both groups — for the token of admin@example.com, a super admin. It returns the server and that token's secret.
func languageServer(t *testing.T) (*AppData, *httptest.Server, string) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	app := mcpTestApp(t, "admin@example.com")
	issued, err := app.Storage.Tokens.Issue(context.Background(), "admin@example.com", token.IssueOptions{TTL: time.Hour})
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}

	r := gin.New()
	r.Use(ginweb.Language())
	v1 := r.Group("/v1")
	v1.Use(CombinedAuthMiddleware(nil, app.Storage, app.Log, "", ""))
	CreateApiV1Zones(v1, app)
	CreatePolicyApiGroup(v1, app)
	m := r.Group("/mcp")
	m.Use(CombinedAuthMiddleware(nil, app.Storage, app.Log, "", ""))
	RegisterMCPRoutes(m, app)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)
	return app, srv, issued.Secret
}

// doLang sends a request with the bearer secret (none when empty), a JSON body (none when empty) and an Accept-Language header (none when empty), and returns the status, the error body and the Vary header.
func doLang(t *testing.T, srv *httptest.Server, method, path, secret, body, lang string) (status int, text, code, vary string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if lang != "" {
		req.Header.Set("Accept-Language", lang)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	var got struct{ Error, Code string }
	raw, _ := io.ReadAll(res.Body)
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
	}
	return res.StatusCode, got.Error, got.Code, res.Header.Get("Vary")
}

// The same request answers in German without Accept-Language (and for a language that is neither) and in English with Accept-Language: en; the status and the code do not change.
func TestREST_AnswersInTheCallersLanguage(t *testing.T) {
	_, srv, secret := languageServer(t)
	for _, tc := range []struct {
		name, method, path, body string
		noAuth                   bool
		status                   int
		code, de, en             string
	}{
		{"no credential", http.MethodGet, "/v1/zones/", "", true, http.StatusUnauthorized, "unauthenticated", "Anmeldung erforderlich.", "Sign-in required."},
		{"a zone name that is none, with the reason inside", http.MethodGet, "/v1/zones/a..example.com/owners", "", false, http.StatusBadRequest, "invalid",
			`Ungültiger Zonenname "a..example.com": Jedes Label muss 1 bis 63 Zeichen lang sein, eines hat 0.`,
			`Invalid zone name "a..example.com": Every label must be 1 to 63 characters long, one has 0.`},
		{"not an owner", http.MethodGet, "/v1/zones/someone.example.com/owners", "", false, http.StatusForbidden, "forbidden", "Kein Eigentümer dieser Zone.", "Not an owner of this zone."},
		{"an answer of the older app methods", http.MethodPost, "/v1/zones/nope.example.com/join", "", false, http.StatusNotFound, "not_found", "Die Zone gibt es nicht.", "The zone does not exist."},
		{"a malformed id", http.MethodDelete, "/v1/policies/rules/abc", "", false, http.StatusBadRequest, "invalid", "Ungültige Regel-ID.", "Invalid rule ID."},
		{"validation of the service, with the values", http.MethodPost, "/v1/policies/rules", `{"zone_pattern":"%u.other.com","zone_soa":"users.example.com","target_user_filter":"*"}`, false, http.StatusBadRequest, "invalid",
			`zone_pattern "%u.other.com" muss gleich zone_soa "users.example.com" sein oder darunter liegen.`,
			`zone_pattern "%u.other.com" must be equal to zone_soa "users.example.com" or lie below it.`},
	} {
		for _, l := range languages {
			s := secret
			if tc.noAuth {
				s = ""
			}
			status, text, code, vary := doLang(t, srv, tc.method, tc.path, s, tc.body, l.header)
			want := tc.de
			if l.english {
				want = tc.en
			}
			if status != tc.status || code != tc.code || text != want {
				t.Errorf("%s, Accept-Language %q: got %d %q %q, want %d %q %q", tc.name, l.header, status, code, text, tc.status, tc.code, want)
			}
			if !strings.Contains(vary, "Accept-Language") {
				t.Errorf("%s: Vary = %q", tc.name, vary)
			}
		}
	}
}

// A tool's refusal, and the sentence a tool answers with, are in the language of the HTTP request that carried the call.
func TestMCP_AnswersInTheCallersLanguage(t *testing.T) {
	app, srv, secret := languageServer(t)
	if _, err := app.Storage.CreateZone("admin@example.com", "mine.example.com", true); err != nil {
		t.Fatalf("seed zone: %v", err)
	}
	for _, l := range languages {
		session := mcptest.DialLang(t, srv.URL+"/mcp", secret, l.header)
		for _, tc := range []struct {
			tool   string
			args   map[string]any
			de, en string
		}{
			// ConfirmEcho of golib, with dz's subject.
			{"delete_zone", map[string]any{"zone": "mine.example.com", "confirm_zone": "yours.example.com"},
				`confirm_zone "yours.example.com" stimmt nicht: die Zone ist "mine.example.com". Vor dem Löschen erst lesen und den aktuellen Wert zurückgeben.`,
				`confirm_zone "yours.example.com" does not match: the zone is "mine.example.com". Read it back before destroying it`},
			// Validation, with the reason inside.
			{"get_zone", map[string]any{"zone": "a..example.com"},
				`Ungültiger Zonenname "a..example.com": Jedes Label muss 1 bis 63 Zeichen lang sein, eines hat 0.`,
				`Invalid zone name "a..example.com": Every label must be 1 to 63 characters long, one has 0.`},
			// A refusal of the tool itself.
			{"list_zone_owners", map[string]any{"zone": "someone.example.com"}, `Kein Eigentümer von "someone.example.com".`, `Not an owner of "someone.example.com".`},
			{"delete_policy_rule", map[string]any{"id": 999, "confirm_zone_pattern": "x"}, "Keine Regel mit der ID 999.", "No rule with the ID 999."},
			// A refusal of the service, behind the operation it refused.
			{"create_zone", map[string]any{"zone": "nope.example.com"}, "Zone anlegen: Keine Berechtigung, diese Zone anzulegen.", "create zone: No permission to create this zone."},
			// The same through an older app method (errorResult).
			{"join_zone", map[string]any{"zone": "nope.example.com"}, "Zone beitreten: Die Zone gibt es nicht.", "join zone: The zone does not exist."},
		} {
			res := mcptest.Call(t, session, tc.tool, tc.args)
			want := tc.de
			if l.english {
				want = tc.en
			}
			if got := mcptest.Text(res); !res.IsError || got != want {
				t.Errorf("%s, Accept-Language %q: got %q (error %v), want %q", tc.tool, l.header, got, res.IsError, want)
			}
		}

		// The sentence of a result.
		res := mcptest.Call(t, session, "list_zone_owners", map[string]any{"zone": "mine.example.com"})
		var out mcpStatus
		raw, _ := json.Marshal(res.StructuredContent)
		if err := json.Unmarshal(raw, &out); err != nil || res.IsError {
			t.Fatalf("list_zone_owners: %s (error %v)", mcptest.Text(res), res.IsError)
		}
		want := "admin@example.com (angelegt von admin@example.com)"
		if l.english {
			want = "admin@example.com (created by admin@example.com)"
		}
		if out.Detail != want {
			t.Errorf("list_zone_owners, Accept-Language %q: detail %q, want %q", l.header, out.Detail, want)
		}
	}
}
