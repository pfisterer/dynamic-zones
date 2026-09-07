package app

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/pfisterer/cloud-self-service-golib/token"
	"go.uber.org/zap"
)

// newZoneEventsTestApp returns an AppData with a private in-memory database.
//
// The database name is unique per test: a bare ":memory:" would give every
// pooled connection its OWN database (NewStorage sets MaxOpenConns 10), and
// the shared "file::memory:?cache=shared" would collide with the application
// instance other tests boot.
func newZoneEventsTestApp(t *testing.T, cfg ZoneEventsConfig) *AppData {
	t.Helper()
	dsn := fmt.Sprintf("file:%s?mode=memory&cache=shared", t.Name())
	storage, err := NewStorage("sqlite", dsn)
	if err != nil {
		t.Fatalf("opening test storage: %v", err)
	}
	return &AppData{
		Config:  AppConfig{ZoneEvents: cfg},
		Storage: storage,
		Log:     zap.NewNop().Sugar(),
	}
}

func defaultZoneEventsTestConfig() ZoneEventsConfig {
	return ZoneEventsConfig{
		IngestSubject:  "alertmanager@platform",
		AllowedClasses: map[string]struct{}{"DnsClientMisconfig": {}},
		TTLHours:       24,
	}
}

func TestZoneEventUpsertRefreshResolveAndExpiry(t *testing.T) {
	app := newZoneEventsTestApp(t, defaultZoneEventsTestConfig())
	now := time.Now()

	ev := ZoneEvent{
		Source: "alertmanager", Class: "DnsClientMisconfig", Zone: "a.example.org",
		Severity: "warning", Message: "first", FirstSeen: now, LastSeen: now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := app.Storage.UpsertZoneEvent(ev); err != nil {
		t.Fatalf("insert: %v", err)
	}

	// A second upsert refreshes the same row instead of adding one.
	ev.Message = "second"
	ev.LastSeen = now.Add(time.Minute)
	if err := app.Storage.UpsertZoneEvent(ev); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	events, err := app.Storage.ListZoneEventsForZones([]string{"a.example.org"}, now)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event after refresh, got %d", len(events))
	}
	if events[0].Count != 2 || events[0].Message != "second" {
		t.Fatalf("refresh did not bump count/message: count=%d message=%q", events[0].Count, events[0].Message)
	}

	// An expired event is invisible to reads and removed by the sweep.
	past := ZoneEvent{
		Source: "alertmanager", Class: "DnsClientMisconfig", Zone: "b.example.org",
		Severity: "warning", FirstSeen: now, LastSeen: now, ExpiresAt: now.Add(-time.Minute),
	}
	if err := app.Storage.UpsertZoneEvent(past); err != nil {
		t.Fatalf("insert expired: %v", err)
	}
	events, err = app.Storage.ListZoneEventsForZones([]string{"b.example.org"}, now)
	if err != nil {
		t.Fatalf("list expired: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expired event is visible: %+v", events)
	}
	deleted, err := app.Storage.DeleteExpiredZoneEvents(now)
	if err != nil {
		t.Fatalf("sweep: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected the sweep to delete 1 event, got %d", deleted)
	}

	// Resolve removes; resolving again is not an error.
	if err := app.Storage.ResolveZoneEvent("alertmanager", "DnsClientMisconfig", "a.example.org"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := app.Storage.ResolveZoneEvent("alertmanager", "DnsClientMisconfig", "a.example.org"); err != nil {
		t.Fatalf("resolve twice: %v", err)
	}
	events, err = app.Storage.ListZoneEventsForZones([]string{"a.example.org"}, now)
	if err != nil {
		t.Fatalf("list after resolve: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("resolved event is still visible: %+v", events)
	}
}

func TestApplyZoneEventsValidatesAndReports(t *testing.T) {
	app := newZoneEventsTestApp(t, defaultZoneEventsTestConfig())

	if _, err := app.Storage.CreateZone("alice@example.edu", "alice.example.org"); err != nil {
		t.Fatalf("seeding zone: %v", err)
	}

	sum, err := applyZoneEvents(app, "alertmanager", []zoneEventInput{
		// Applied: known zone (note trailing dot + case — canonicalized away).
		{Zone: "Alice.Example.ORG.", Class: "DnsClientMisconfig", Message: "m"},
		// Skipped: zone nobody manages here.
		{Zone: "stranger.example.org", Class: "DnsClientMisconfig"},
		// Skipped: class not whitelisted.
		{Zone: "alice.example.org", Class: "SomethingElse"},
		// Skipped: no zone at all.
		{Zone: "", Class: "DnsClientMisconfig"},
	})
	if err != nil {
		t.Fatalf("applyZoneEvents: %v", err)
	}
	if sum.Applied != 1 || sum.Resolved != 0 || sum.Skipped != 3 {
		t.Fatalf("unexpected summary: %+v", sum)
	}
	if len(sum.Reasons) != 3 {
		t.Fatalf("expected 3 skip reasons, got %v", sum.Reasons)
	}

	events, err := app.Storage.ListZoneEventsForZones([]string{"alice.example.org"}, time.Now())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(events) != 1 || events[0].Severity != "warning" {
		t.Fatalf("expected 1 event with default severity, got %+v", events)
	}

	// The resolved status removes the event again.
	sum, err = applyZoneEvents(app, "alertmanager", []zoneEventInput{
		{Zone: "alice.example.org", Class: "DnsClientMisconfig", Resolved: true},
	})
	if err != nil {
		t.Fatalf("applyZoneEvents resolve: %v", err)
	}
	if sum.Resolved != 1 {
		t.Fatalf("unexpected summary on resolve: %+v", sum)
	}
	events, err = app.Storage.ListZoneEventsForZones([]string{"alice.example.org"}, time.Now())
	if err != nil {
		t.Fatalf("list after resolve: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("event survived its resolution: %+v", events)
	}
}

func TestListOwnersForZones(t *testing.T) {
	app := newZoneEventsTestApp(t, defaultZoneEventsTestConfig())
	for user, zone := range map[string]string{
		"alice@example.edu": "shared.example.org",
		"carol@example.edu": "carol.example.org",
	} {
		if _, err := app.Storage.CreateZone(user, zone); err != nil {
			t.Fatalf("seeding %s: %v", zone, err)
		}
	}
	// A second owner on the shared zone.
	if _, err := app.Storage.CreateZone("bob@example.edu", "shared.example.org"); err != nil {
		t.Fatalf("seeding co-owner: %v", err)
	}

	owners, err := app.Storage.ListOwnersForZones([]string{"shared.example.org", "carol.example.org", "unknown.example.org"})
	if err != nil {
		t.Fatalf("ListOwnersForZones: %v", err)
	}
	if got := owners["shared.example.org"]; len(got) != 2 || got[0] != "alice@example.edu" || got[1] != "bob@example.edu" {
		t.Fatalf("shared zone owners wrong: %v", got)
	}
	if got := owners["carol.example.org"]; len(got) != 1 || got[0] != "carol@example.edu" {
		t.Fatalf("carol zone owners wrong: %v", got)
	}
	if _, ok := owners["unknown.example.org"]; ok {
		t.Fatal("unknown zone must not appear in the owners map")
	}

	// Empty input stays one cheap no-op, not a WHERE IN () syntax error.
	empty, err := app.Storage.ListOwnersForZones(nil)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty input: %v %v", empty, err)
	}
}

func TestReconcileZoneEventsIngestToken(t *testing.T) {
	app := newZoneEventsTestApp(t, defaultZoneEventsTestConfig())
	ctx := context.Background()
	subject := "alertmanager@platform"

	lookup := func(secret string) (*token.Record, error) {
		return app.Storage.Tokens.Lookup(ctx, secret)
	}

	// Provisioning: the configured secret authenticates as the subject.
	secretV1 := ApiTokenPrefix + "test-secret-version-1"
	cfg := defaultZoneEventsTestConfig()
	cfg.IngestToken = secretV1
	if err := ReconcileZoneEventsIngestToken(app.Storage, cfg); err != nil {
		t.Fatalf("provision: %v", err)
	}
	rec, err := lookup(secretV1)
	if err != nil {
		t.Fatalf("lookup after provision: %v", err)
	}
	if rec.Subject != subject {
		t.Fatalf("token belongs to %q, expected %q", rec.Subject, subject)
	}
	if !rec.ExpiresAt.IsZero() {
		t.Fatalf("ingest token must never expire, got %v", rec.ExpiresAt)
	}

	// Idempotent: reconciling the same value again leaves one working token.
	if err := ReconcileZoneEventsIngestToken(app.Storage, cfg); err != nil {
		t.Fatalf("re-provision: %v", err)
	}
	if _, err := lookup(secretV1); err != nil {
		t.Fatalf("lookup after re-provision: %v", err)
	}

	// Rotation: the new value works, the old one is gone.
	secretV2 := ApiTokenPrefix + "test-secret-version-2"
	cfg.IngestToken = secretV2
	if err := ReconcileZoneEventsIngestToken(app.Storage, cfg); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if _, err := lookup(secretV2); err != nil {
		t.Fatalf("lookup of rotated token: %v", err)
	}
	if _, err := lookup(secretV1); !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("old token still authenticates (err=%v)", err)
	}

	// Revocation: an empty value removes the token.
	cfg.IngestToken = ""
	if err := ReconcileZoneEventsIngestToken(app.Storage, cfg); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := lookup(secretV2); !errors.Is(err, token.ErrNotFound) {
		t.Fatalf("revoked token still authenticates (err=%v)", err)
	}

	// A value without the service prefix could never authenticate — that is a
	// startup error, not a quiet misconfiguration.
	cfg.IngestToken = "wrong-prefix-token-value"
	if err := ReconcileZoneEventsIngestToken(app.Storage, cfg); err == nil {
		t.Fatal("expected an error for a token without the service prefix")
	}

	// A configured token without a subject is a contradiction, not a default.
	cfg = defaultZoneEventsTestConfig()
	cfg.IngestSubject = ""
	cfg.IngestToken = secretV1
	if err := ReconcileZoneEventsIngestToken(app.Storage, cfg); err == nil {
		t.Fatal("expected an error for a token without an ingest subject")
	}
}
