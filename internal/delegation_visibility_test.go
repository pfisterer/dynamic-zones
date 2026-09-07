package app

import (
	"fmt"
	"testing"

	"go.uber.org/zap"
)

func newDelegationTestApp(t *testing.T) *AppData {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	storage, err := NewStorage("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening test storage: %v", err)
	}
	return &AppData{
		Config: AppConfig{DnsPolicyConfig: DnsPolicyConfig{
			SuperAdminEmails: map[string]struct{}{"admin@dhbw.de": {}},
		}},
		Storage: storage,
		Log:     zap.NewNop().Sugar(),
	}
}

func TestDelegationsVisibleTo(t *testing.T) {
	app := newDelegationTestApp(t)
	seed := []DelegationPolicy{
		{TargetUserFilter: "alice@dhbw.de", ZoneSuffix: "alice.dhbw.site", Description: "for alice"},
		{TargetUserFilter: "*@partner.example", ZoneSuffix: "partner.dhbw.site", Description: "partner org"},
		{TargetUserFilter: "bob@dhbw.de", ZoneSuffix: "bob.dhbw.site"},
	}
	for i := range seed {
		if _, err := app.Storage.DelegationCreate(&seed[i]); err != nil {
			t.Fatalf("seeding: %v", err)
		}
	}

	t.Run("super-admin sees everything, including the filter", func(t *testing.T) {
		got, err := app.DelegationsVisibleTo(&UserClaims{Email: "admin@dhbw.de"})
		if err != nil {
			t.Fatalf("visible: %v", err)
		}
		if len(got) != 3 {
			t.Fatalf("expected all 3 delegations, got %d", len(got))
		}
		if got[0].TargetUserFilter == "" || got[0].ID == 0 {
			t.Errorf("admin view must keep filter and id, got %+v", got[0])
		}
	})

	t.Run("matching user sees only their delegations, reduced", func(t *testing.T) {
		got, err := app.DelegationsVisibleTo(&UserClaims{Email: "alice@dhbw.de"})
		if err != nil {
			t.Fatalf("visible: %v", err)
		}
		if len(got) != 1 {
			t.Fatalf("expected exactly alice's delegation, got %d: %+v", len(got), got)
		}
		d := got[0]
		if d.ZoneSuffix != "alice.dhbw.site" || d.Description != "for alice" {
			t.Errorf("expected suffix+description, got %+v", d)
		}
		if d.TargetUserFilter != "" || d.ID != 0 || !d.CreatedAt.IsZero() {
			t.Errorf("non-admin view must not carry filter/id/timestamp, got %+v", d)
		}
	})

	t.Run("pattern filters match too", func(t *testing.T) {
		got, err := app.DelegationsVisibleTo(&UserClaims{Email: "someone@partner.example"})
		if err != nil {
			t.Fatalf("visible: %v", err)
		}
		if len(got) != 1 || got[0].ZoneSuffix != "partner.dhbw.site" {
			t.Fatalf("expected the partner delegation, got %+v", got)
		}
	})

	t.Run("unmatched user gets an empty list, not an error", func(t *testing.T) {
		got, err := app.DelegationsVisibleTo(&UserClaims{Email: "stranger@elsewhere.org"})
		if err != nil {
			t.Fatalf("visible: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("expected no delegations, got %+v", got)
		}
	})
}
