package app

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pfisterer/cloud-self-service-golib/token"
	"github.com/pfisterer/cloud-self-service-golib/tokengorm"
	"gorm.io/gorm"
)

// Zone events: problems observed with a zone, shown to its owners in the UI.
//
// This service deliberately knows NOTHING about where an event comes from. The
// only producer today is the Alertmanager (a Loki rule watches the pdns logs
// and fires per zone), but neither LogQL, nor the log patterns, nor alerting
// thresholds appear anywhere in this file — the contract is "an event about a
// zone", and the Alertmanager adapter in routes_zone_events.go is a thin
// translator at the edge. A future feeder (a correlation CronJob, a dnstap
// pipeline) posts into the same store without this code changing.
//
// Events are ephemeral state, not history: one row per (source, class, zone),
// refreshed while the producer keeps reporting it and gone when it resolves it
// — or when it expires. The expiry is the safety net for the producer's
// delivery semantics: the Alertmanager delivers at-least-once and a lost
// "resolved" notification would otherwise pin a warning to the zone forever.

// ZoneEvent is one active problem with a zone, keyed by (source, class, zone).
type ZoneEvent struct {
	ID uint `gorm:"primaryKey" json:"-"`
	// Source names the producer ("alertmanager", later "correlator", ...).
	Source string `gorm:"size:64;not null;uniqueIndex:idx_zone_event_key" json:"source"`
	// Class is the kind of problem. For alert-fed events this is the alert
	// name (e.g. "DnsClientMisconfig"); only whitelisted classes are accepted.
	Class string `gorm:"size:64;not null;uniqueIndex:idx_zone_event_key" json:"class"`
	// Zone is the affected zone, canonical form (lower case, no trailing dot)
	// — the same form the zones table stores, which is what makes the
	// existence check and the per-user query joins work.
	Zone     string `gorm:"size:255;not null;uniqueIndex:idx_zone_event_key;index" json:"zone"`
	Severity string `gorm:"size:32;not null" json:"severity"`
	// Message is the short, human-readable line (an alert's summary).
	Message string `gorm:"size:512" json:"message"`
	// Detail carries the longer explanation (an alert's description).
	Detail string `gorm:"type:text" json:"detail"`
	// Count is how many times the producer has (re-)reported this event.
	Count     int64     `gorm:"not null;default:1" json:"count"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	// ExpiresAt is when the event vanishes unless refreshed. Always set.
	ExpiresAt time.Time `gorm:"index" json:"-"`
}

// ZoneEventsConfig configures the ingest side of zone events.
type ZoneEventsConfig struct {
	// IngestSubject is the ONLY identity allowed to post events. The ingest
	// endpoints are part of the public /v1 surface, so "authenticated" is not
	// enough — any logged-in user could otherwise invent events for zones they
	// do not own.
	IngestSubject string `json:"ingest_subject"`
	// IngestToken is the API token the producer authenticates with. It is
	// provisioned INTO the token store at startup (see
	// ReconcileZoneEventsIngestToken) rather than issued through the token
	// API: a token issued there would carry the issuing admin's identity, and
	// rotation would be a manual ceremony. This way the deployment's secret
	// store is the single source of truth and rotation is "change the value,
	// redeploy". Empty disables ingest (and revokes a previously provisioned
	// token).
	IngestToken string `json:"ingest_token,omitempty"`
	// AllowedClasses is the whitelist of event classes the ingest accepts.
	// Part of the damage control for a leaked token: unknown classes are
	// dropped, so the blast radius is "plausible messages about existing
	// zones".
	AllowedClasses map[string]struct{} `json:"allowed_classes"`
	// TTLHours is how long an unrefreshed event lives. Must comfortably exceed
	// the producer's re-notification interval (the Alertmanager's
	// repeat_interval), or events flap out of the UI between refreshes.
	TTLHours int `json:"ttl_hours" validate:"min=1"`
}

func (c ZoneEventsConfig) ttl() time.Duration { return time.Duration(c.TTLHours) * time.Hour }

// canonicalZone maps a zone name to the form the zones table stores: lower
// case, no trailing dot. Producers disagree on both (dig and pdns log zones
// with the trailing dot, the API stores them without).
func canonicalZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

// --- storage --------------------------------------------------------------

// UpsertZoneEvent creates or refreshes the event row for (source, class,
// zone). A refresh bumps Count, LastSeen and the expiry and takes the
// producer's latest severity/message/detail.
func (s *Storage) UpsertZoneEvent(ev ZoneEvent) error {
	res := s.db.Model(&ZoneEvent{}).
		Where("source = ? AND class = ? AND zone = ?", ev.Source, ev.Class, ev.Zone).
		Updates(map[string]interface{}{
			"severity":   ev.Severity,
			"message":    ev.Message,
			"detail":     ev.Detail,
			"last_seen":  ev.LastSeen,
			"expires_at": ev.ExpiresAt,
			"count":      gorm.Expr("count + 1"),
		})
	if res.Error != nil {
		return fmt.Errorf("storage.UpsertZoneEvent: %w", res.Error)
	}
	if res.RowsAffected > 0 {
		return nil
	}
	ev.Count = 1
	if err := s.db.Create(&ev).Error; err != nil {
		return fmt.Errorf("storage.UpsertZoneEvent: %w", err)
	}
	return nil
}

// ResolveZoneEvent removes the event row for (source, class, zone). Removing
// what is not there is fine — the producer's "resolved" can arrive more than
// once, or after the expiry already did the job.
func (s *Storage) ResolveZoneEvent(source, class, zone string) error {
	if err := s.db.Where("source = ? AND class = ? AND zone = ?", source, class, zone).
		Delete(&ZoneEvent{}).Error; err != nil {
		return fmt.Errorf("storage.ResolveZoneEvent: %w", err)
	}
	return nil
}

// ListZoneEventsForZones returns the live (unexpired) events for the given
// zones, newest activity first.
func (s *Storage) ListZoneEventsForZones(zones []string, now time.Time) ([]ZoneEvent, error) {
	var events []ZoneEvent
	if len(zones) == 0 {
		return events, nil
	}
	if err := s.db.Where("zone IN ? AND expires_at > ?", zones, now).
		Order("last_seen desc").Find(&events).Error; err != nil {
		return nil, fmt.Errorf("storage.ListZoneEventsForZones: %w", err)
	}
	return events, nil
}

// ListAllZoneEvents returns every live event (super-admin view).
func (s *Storage) ListAllZoneEvents(now time.Time) ([]ZoneEvent, error) {
	var events []ZoneEvent
	if err := s.db.Where("expires_at > ?", now).
		Order("last_seen desc").Find(&events).Error; err != nil {
		return nil, fmt.Errorf("storage.ListAllZoneEvents: %w", err)
	}
	return events, nil
}

// DeleteExpiredZoneEvents removes events past their expiry. Called lazily on
// ingest (the same pattern the token store uses): reads filter on the expiry
// anyway, so cleanup needs no timer of its own.
func (s *Storage) DeleteExpiredZoneEvents(now time.Time) (int64, error) {
	res := s.db.Where("expires_at <= ?", now).Delete(&ZoneEvent{})
	if res.Error != nil {
		return 0, fmt.Errorf("storage.DeleteExpiredZoneEvents: %w", res.Error)
	}
	return res.RowsAffected, nil
}

// --- ingest logic ---------------------------------------------------------

// zoneEventInput is one normalized incoming event, whatever shape it arrived
// in (generic ingest or Alertmanager webhook).
type zoneEventInput struct {
	Zone     string
	Class    string
	Severity string
	Message  string
	Detail   string
	// Resolved marks the event as ended rather than active.
	Resolved bool
}

// ZoneEventsIngestSummary says what an ingest call did — and what it dropped,
// because a producer whose events silently vanish is undebuggable.
type ZoneEventsIngestSummary struct {
	Applied  int      `json:"applied"`
	Resolved int      `json:"resolved"`
	Skipped  int      `json:"skipped"`
	Reasons  []string `json:"skip_reasons,omitempty"`
}

// maxZoneEventBatch bounds one ingest request. The Alertmanager groups a
// handful of alerts per notification; hundreds means something is wrong.
const maxZoneEventBatch = 200

// truncate bounds producer-supplied text to what the column (and the UI) can
// sensibly hold.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}

// applyZoneEvents validates and stores a batch of events from `source`.
//
// The validation here is the real defense of this endpoint (the identity gate
// only says who may talk): the zone must exist in our own store, the class
// must be whitelisted, everything else is bounded and truncated. With that, a
// leaked ingest token cannot spam arbitrary text at arbitrary users.
func applyZoneEvents(app *AppData, source string, events []zoneEventInput) (ZoneEventsIngestSummary, error) {
	sum := ZoneEventsIngestSummary{}
	now := time.Now()

	// Lazy cleanup; a failure here must not lose the events we were handed.
	if _, err := app.Storage.DeleteExpiredZoneEvents(now); err != nil {
		app.Log.Warnf("zone-events: cleaning up expired events: %v", err)
	}

	skip := func(reason string) {
		sum.Skipped++
		sum.Reasons = append(sum.Reasons, reason)
	}

	for _, ev := range events {
		zone := canonicalZone(ev.Zone)
		if zone == "" {
			skip("event without a zone")
			continue
		}
		if _, ok := app.Config.ZoneEvents.AllowedClasses[ev.Class]; !ok {
			skip(fmt.Sprintf("class %q is not whitelisted", truncate(ev.Class, 64)))
			continue
		}
		exists, err := app.Storage.ZoneExists(zone)
		if err != nil {
			return sum, fmt.Errorf("applyZoneEvents: checking zone %q: %w", zone, err)
		}
		if !exists {
			skip(fmt.Sprintf("zone %q is not managed here", truncate(zone, 255)))
			continue
		}

		if ev.Resolved {
			if err := app.Storage.ResolveZoneEvent(source, ev.Class, zone); err != nil {
				return sum, err
			}
			sum.Resolved++
			continue
		}

		severity := strings.ToLower(strings.TrimSpace(ev.Severity))
		if severity == "" {
			severity = "warning"
		}
		if err := app.Storage.UpsertZoneEvent(ZoneEvent{
			Source:    source,
			Class:     ev.Class,
			Zone:      zone,
			Severity:  truncate(severity, 32),
			Message:   truncate(strings.TrimSpace(ev.Message), 512),
			Detail:    truncate(strings.TrimSpace(ev.Detail), 4000),
			FirstSeen: now,
			LastSeen:  now,
			ExpiresAt: now.Add(app.Config.ZoneEvents.ttl()),
		}); err != nil {
			return sum, err
		}
		sum.Applied++
	}

	// The producer never reads the response body (the Alertmanager discards
	// it), so the summary has to reach the log or a skipped event is
	// undiagnosable — the first E2E test of this endpoint returned a clean
	// 200 while silently applying nothing, and only the response said why.
	if sum.Skipped > 0 {
		app.Log.Warnf("zone-events: ingest from %s: applied=%d resolved=%d skipped=%d (%s)",
			source, sum.Applied, sum.Resolved, sum.Skipped, strings.Join(sum.Reasons, "; "))
	} else if sum.Applied > 0 || sum.Resolved > 0 {
		app.Log.Infof("zone-events: ingest from %s: applied=%d resolved=%d",
			source, sum.Applied, sum.Resolved)
	}
	return sum, nil
}

// --- ingest rate limit ----------------------------------------------------

// ingestLimiter is a coarse fixed-window limiter for the ingest endpoints.
// Not fairness, not precision — just a cap so a runaway or hostile producer
// cannot turn the ingest into a write amplifier. The window state is
// per-process, which is exactly right for a single-replica service.
type ingestLimiter struct {
	mu          sync.Mutex
	windowStart time.Time
	count       int
}

const ingestRequestsPerMinute = 120

func (l *ingestLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.windowStart) >= time.Minute {
		l.windowStart = now
		l.count = 0
	}
	l.count++
	return l.count <= ingestRequestsPerMinute
}

// --- ingest token provisioning ---------------------------------------------

// ReconcileZoneEventsIngestToken makes the token store match the configured
// ingest credential, at startup.
//
// Why not issue the token through the token API: a token issued there belongs
// to the admin who clicked, so the producer would act AS that admin — which
// ruins both the identity gate above and the audit trail — and every rotation
// would be a manual ceremony. Here the deployment's secret store holds the
// value, this reconcile makes the database agree with it, and rotation is
// "change the value, redeploy". Revocation is emptying the value.
//
// The token record never expires (token.NeverExpires semantics: zero
// ExpiresAt). That is deliberate: an expiring service token means "the zone
// warnings quietly disappear from the UI one night". Its lifetime is bounded
// by rotation of the configured value, not by the clock, and LastUsedAt shows
// whether it is alive.
func ReconcileZoneEventsIngestToken(storage *Storage, cfg ZoneEventsConfig) error {
	ctx := context.Background()
	subject := strings.TrimSpace(cfg.IngestSubject)
	secret := strings.TrimSpace(cfg.IngestToken)

	if subject == "" {
		if secret != "" {
			return fmt.Errorf("zone-events: an ingest token is configured but the ingest subject is empty")
		}
		return nil
	}

	store := tokengorm.NewStore(storage.db)

	// The subject is reserved for this mechanism, so everything it owns is
	// ours to replace. This also removes a token whose value was rotated away.
	existing, err := store.BySubject(ctx, subject)
	if err != nil {
		return fmt.Errorf("zone-events: listing tokens of %q: %w", subject, err)
	}
	for _, rec := range existing {
		if err := store.Delete(ctx, subject, rec.ID); err != nil {
			return fmt.Errorf("zone-events: removing stale token %d of %q: %w", rec.ID, subject, err)
		}
	}

	if secret == "" {
		// Ingest disabled; any previously provisioned token is revoked above.
		return nil
	}

	// The middleware routes a credential to the token store by its prefix; a
	// configured value without it would be treated as an OIDC JWT and could
	// never authenticate. Fail at startup, not at the first webhook.
	if !strings.HasPrefix(secret, ApiTokenPrefix) {
		return fmt.Errorf("zone-events: the ingest token must start with %q", ApiTokenPrefix)
	}
	if len(secret) < len(ApiTokenPrefix)+16 {
		return fmt.Errorf("zone-events: the ingest token is too short to be a credential")
	}

	display := secret
	if len(display) > len(ApiTokenPrefix)+8 {
		display = display[:len(ApiTokenPrefix)+8]
	}

	if _, err := store.Insert(ctx, token.Record{
		Subject:     subject,
		Hash:        token.Hash(secret),
		Prefix:      display,
		ReadOnly:    false,
		Description: "zone-events ingest (provisioned from configuration at startup)",
		CreatedAt:   time.Now(),
		// Zero ExpiresAt = never expires.
	}); err != nil {
		return fmt.Errorf("zone-events: provisioning the ingest token for %q: %w", subject, err)
	}
	return nil
}
