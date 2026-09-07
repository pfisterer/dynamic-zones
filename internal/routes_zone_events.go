package app

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// The zone-events API: owners see problems with their zones, producers post
// them. See zone_events.go for the design; this file is only HTTP shapes.
//
// Both ingest endpoints are part of the public /v1 surface (there is no
// "cluster-internal" here — the service routes through the public ingress,
// and the cluster has no NetworkPolicies), so they are gated on ONE identity:
// the configured ingest subject, authenticating with the startup-provisioned
// token. Any other caller — including every normally logged-in user — gets a
// 403, because "authenticated" alone would let anyone invent events for zones
// they do not own.

// CreateZoneEventsApiGroup adds the /v1/zone-events endpoints.
func CreateZoneEventsApiGroup(v1 *gin.RouterGroup, app *AppData) *gin.RouterGroup {
	limiter := &ingestLimiter{}
	v1.GET("/zone-events/", getZoneEvents(app))
	v1.POST("/zone-events/", ingestZoneEvents(app, limiter))
	v1.POST("/zone-events/alertmanager", ingestAlertmanagerZoneEvents(app, limiter))
	return v1
}

// ZoneEventInfo is the API shape of one zone event. Deliberately not the
// stored row: these field names are published via swagger.json and consumed
// by the UI client.
type ZoneEventInfo struct {
	Zone     string `json:"zone" example:"alice-at-example-edu.users.dhbw.site"`
	Class    string `json:"class" example:"DnsClientMisconfig"`
	Severity string `json:"severity" example:"warning"`
	// Message is the short human-readable line (an alert's summary).
	Message string `json:"message" example:"DNS-Client scheitert dauerhaft an Zone ..."`
	// Detail is the longer explanation (an alert's description).
	Detail string `json:"detail,omitempty"`
	// Count is how many times the producer has (re-)reported the event.
	Count     int64     `json:"count" example:"3"`
	FirstSeen time.Time `json:"first_seen" example:"2026-09-05T15:00:00Z"`
	LastSeen  time.Time `json:"last_seen" example:"2026-09-06T09:00:00Z"`
	// Source names the producer of the event (e.g. "alertmanager").
	Source string `json:"source" example:"alertmanager"`
	// Owners are the e-mail addresses managing the zone. For a zone's owner
	// this repeats what the zone list already shows; for the super-admin view
	// it is what makes an event actionable (contact the owner).
	Owners []string `json:"owners" example:"alice@example.edu"`
}

func toZoneEventInfos(events []ZoneEvent, owners map[string][]string) []ZoneEventInfo {
	out := make([]ZoneEventInfo, 0, len(events))
	for _, ev := range events {
		out = append(out, ZoneEventInfo{
			Zone:      ev.Zone,
			Class:     ev.Class,
			Severity:  ev.Severity,
			Message:   ev.Message,
			Detail:    ev.Detail,
			Count:     ev.Count,
			FirstSeen: ev.FirstSeen,
			LastSeen:  ev.LastSeen,
			Source:    ev.Source,
			Owners:    owners[ev.Zone],
		})
	}
	return out
}

// zonesOfEvents collects the distinct zone names of a list of events.
func zonesOfEvents(events []ZoneEvent) []string {
	seen := map[string]struct{}{}
	zones := make([]string, 0, len(events))
	for _, ev := range events {
		if _, ok := seen[ev.Zone]; ok {
			continue
		}
		seen[ev.Zone] = struct{}{}
		zones = append(zones, ev.Zone)
	}
	return zones
}

// ZoneEventsResponse is the answer to GET /v1/zone-events/.
type ZoneEventsResponse struct {
	Events []ZoneEventInfo `json:"events"`
}

// getZoneEvents lists the live events for the caller's zones
// @Summary List zone events
// @Description Live problems observed with the caller's zones (e.g. clients failing TSIG against a zone). Super-admins see events for all zones.
// @Tags zone-events
// @Produce json
// @Success 200 {object} ZoneEventsResponse
// @Failure 500 {object} map[string]string "Failed to list zone events"
// @Security ApiKeyAuth
// @ID listZoneEvents
// @Router /v1/zone-events/ [get]
func getZoneEvents(app *AppData) gin.HandlerFunc {
	return func(c *gin.Context) {
		user := c.MustGet(UserDataKey).(*UserClaims)
		now := time.Now()

		var events []ZoneEvent
		var err error
		if isSuperAdmin(app, user) {
			events, err = app.Storage.ListAllZoneEvents(now)
		} else {
			var zones []Zone
			zones, err = app.Storage.ListUserZones(user.Identity())
			if err == nil {
				names := make([]string, 0, len(zones))
				for _, z := range zones {
					names = append(names, z.Zone)
				}
				events, err = app.Storage.ListZoneEventsForZones(names, now)
			}
		}
		if err != nil {
			app.Log.Errorf("zone-events: listing for %s: %v", user.Identity(), err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list zone events"})
			return
		}

		// One bounded batch query, not one lookup per event: the event count
		// is structurally capped (one row per source+class+zone), which is
		// also why this endpoint has no pagination — the worst case is on the
		// order of the zone count, not of an unbounded log.
		owners, err := app.Storage.ListOwnersForZones(zonesOfEvents(events))
		if err != nil {
			app.Log.Errorf("zone-events: resolving owners: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list zone events"})
			return
		}
		c.JSON(http.StatusOK, ZoneEventsResponse{Events: toZoneEventInfos(events, owners)})
	}
}

// requireIngestIdentity aborts unless the caller is the configured ingest
// subject. 403 and not 404: the endpoint is documented, hiding it buys
// nothing, and a misconfigured producer deserves a diagnosable answer.
func requireIngestIdentity(app *AppData, c *gin.Context) bool {
	user := c.MustGet(UserDataKey).(*UserClaims)
	subject := app.Config.ZoneEvents.IngestSubject
	if subject == "" || user.Identity() != subject {
		app.Log.Warnf("zone-events: ingest refused for %q (not the ingest subject)", user.Identity())
		c.JSON(http.StatusForbidden, gin.H{"error": "this identity may not ingest zone events"})
		return false
	}
	return true
}

func requireIngestBudget(app *AppData, limiter *ingestLimiter, c *gin.Context) bool {
	if !limiter.allow(time.Now()) {
		app.Log.Warn("zone-events: ingest rate limit exceeded")
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "too many ingest requests"})
		return false
	}
	return true
}

// ZoneEventIngestItem is one event in a generic ingest request.
type ZoneEventIngestItem struct {
	Zone  string `json:"zone" binding:"required" example:"alice-at-example-edu.users.dhbw.site"`
	Class string `json:"class" binding:"required" example:"DnsClientMisconfig"`
	// Status is "firing" (default) or "resolved".
	Status   string `json:"status" example:"firing"`
	Severity string `json:"severity" example:"warning"`
	Message  string `json:"message" example:"a client keeps failing TSIG against this zone"`
	Detail   string `json:"detail,omitempty"`
}

// ZoneEventsIngestRequest is the body of the generic ingest endpoint.
type ZoneEventsIngestRequest struct {
	Events []ZoneEventIngestItem `json:"events" binding:"required"`
}

// ingestZoneEvents accepts generic zone events from the configured producer
// @Summary Ingest zone events
// @Description Create/refresh ("firing") or remove ("resolved") zone events. Only the configured ingest identity may call this; events for unknown zones or non-whitelisted classes are skipped and reported in the response.
// @Tags zone-events
// @Accept json
// @Produce json
// @Param request body ZoneEventsIngestRequest true "Events to apply"
// @Success 200 {object} ZoneEventsIngestSummary
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 403 {object} map[string]string "Not the ingest identity"
// @Failure 429 {object} map[string]string "Rate limited"
// @Failure 500 {object} map[string]string "Failed to store zone events"
// @Security ApiKeyAuth
// @ID ingestZoneEvents
// @Router /v1/zone-events/ [post]
func ingestZoneEvents(app *AppData, limiter *ingestLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireIngestIdentity(app, c) || !requireIngestBudget(app, limiter, c) {
			return
		}

		var req ZoneEventsIngestRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		if len(req.Events) > maxZoneEventBatch {
			c.JSON(http.StatusBadRequest, gin.H{"error": "too many events in one request"})
			return
		}

		events := make([]zoneEventInput, 0, len(req.Events))
		for _, item := range req.Events {
			events = append(events, zoneEventInput{
				Zone:     item.Zone,
				Class:    item.Class,
				Severity: item.Severity,
				Message:  item.Message,
				Detail:   item.Detail,
				Resolved: item.Status == "resolved",
			})
		}

		sum, err := applyZoneEvents(app, "generic", events)
		if err != nil {
			app.Log.Errorf("zone-events: generic ingest: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store zone events"})
			return
		}
		c.JSON(http.StatusOK, sum)
	}
}

// AlertmanagerAlert is one alert in an Alertmanager webhook notification.
type AlertmanagerAlert struct {
	Status      string            `json:"status" example:"firing"`
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
}

// AlertmanagerWebhook is the subset of the Alertmanager webhook payload this
// adapter reads. The version field is checked loosely on purpose: the "4"
// payload has been stable for years, and the adapter only touches fields that
// predate it.
type AlertmanagerWebhook struct {
	Version string              `json:"version" example:"4"`
	Status  string              `json:"status" example:"firing"`
	Alerts  []AlertmanagerAlert `json:"alerts"`
}

// ingestAlertmanagerZoneEvents translates an Alertmanager webhook into zone events
// @Summary Ingest zone events from an Alertmanager webhook
// @Description Thin adapter: every alert carrying a `zone` label becomes a zone event (class = alertname), firing upserts and resolved removes. Alerts without a zone label are skipped. Only the configured ingest identity may call this.
// @Tags zone-events
// @Accept json
// @Produce json
// @Param request body AlertmanagerWebhook true "Alertmanager webhook payload"
// @Success 200 {object} ZoneEventsIngestSummary
// @Failure 400 {object} map[string]string "Invalid request"
// @Failure 403 {object} map[string]string "Not the ingest identity"
// @Failure 429 {object} map[string]string "Rate limited"
// @Failure 500 {object} map[string]string "Failed to store zone events"
// @Security ApiKeyAuth
// @ID ingestAlertmanagerZoneEvents
// @Router /v1/zone-events/alertmanager [post]
func ingestAlertmanagerZoneEvents(app *AppData, limiter *ingestLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !requireIngestIdentity(app, c) || !requireIngestBudget(app, limiter, c) {
			return
		}

		var payload AlertmanagerWebhook
		if err := c.ShouldBindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
			return
		}
		if len(payload.Alerts) > maxZoneEventBatch {
			c.JSON(http.StatusBadRequest, gin.H{"error": "too many alerts in one request"})
			return
		}

		events := make([]zoneEventInput, 0, len(payload.Alerts))
		for _, alert := range payload.Alerts {
			zone := alert.Labels["zone"]
			if zone == "" {
				// Not an error: the route in the Alertmanager should only send
				// zone-labelled alerts here, but a broader route must not turn
				// every unrelated alert into a 4xx that Alertmanager retries.
				continue
			}
			message := alert.Annotations["summary"]
			if message == "" {
				message = alert.Annotations["description"]
			}
			events = append(events, zoneEventInput{
				Zone:     zone,
				Class:    alert.Labels["alertname"],
				Severity: alert.Labels["severity"],
				Message:  message,
				Detail:   alert.Annotations["description"],
				Resolved: alert.Status == "resolved",
			})
		}

		sum, err := applyZoneEvents(app, "alertmanager", events)
		if err != nil {
			app.Log.Errorf("zone-events: alertmanager ingest: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store zone events"})
			return
		}
		sum.Skipped += len(payload.Alerts) - len(events)
		c.JSON(http.StatusOK, sum)
	}
}
