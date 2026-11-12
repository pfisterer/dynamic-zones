package app

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/pfisterer/cloud-self-service-golib/apierr"
	"github.com/pfisterer/cloud-self-service-golib/msg"
)

// A service error answers with its status, the code that follows from it and its own text, never the cause; anything else is a generic 500.
func TestServiceErrors(t *testing.T) {
	cause := errors.New("pq: connection refused to 10.0.0.5:5432")
	cases := []struct {
		name string
		err  error
		want apierr.Body
		code int
	}{
		{"refusal", statusErr(http.StatusForbidden, msg.T("Kein Eigentümer dieser Zone.", "Not an owner of this zone."), cause), apierr.Body{Error: "Kein Eigentümer dieser Zone.", Code: "forbidden"}, 403},
		{"wrapped", errors.Join(errors.New("x"), errRuleNotFound), apierr.Body{Error: "Die Regel gibt es nicht.", Code: "not_found"}, 404},
		{"no opinion", cause, apierr.Body{Error: "Interner Fehler.", Code: "internal"}, 500},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := serviceErrors.Classify(tc.err)
			if e.Body(msg.DE) != tc.want || e.Status != tc.code {
				t.Fatalf("got %d %+v, want %d %+v", e.Status, e.Body(msg.DE), tc.code, tc.want)
			}
			if StatusOf(tc.err) != tc.code || MessageOf(tc.err).String() != tc.want.Error {
				t.Fatalf("StatusOf/MessageOf = %d %q", StatusOf(tc.err), MessageOf(tc.err))
			}
		})
	}
}

// Authentication answers in German with a stable code, like the other services of the platform.
func TestAuthAnswersInGerman(t *testing.T) {
	h, _, _ := readOnlyFixture(t, false)
	for _, tc := range []struct {
		name, secret string
		want         apierr.Body
	}{
		{"no credential", "", apierr.Body{Error: "Anmeldung erforderlich.", Code: "unauthenticated"}},
		{"unknown API token", ApiTokenPrefix + "doesnotexist0000000000000000", apierr.Body{Error: "API-Token ungültig, abgelaufen oder gelöscht.", Code: "unauthenticated"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := callWithToken(t, h, http.MethodGet, "/v1/thing", tc.secret)
			var got apierr.Body
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || rr.Code != http.StatusUnauthorized || got != tc.want {
				t.Fatalf("got %d %s, want 401 %+v", rr.Code, rr.Body.String(), tc.want)
			}
		})
	}
}
