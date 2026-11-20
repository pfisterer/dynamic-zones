package app

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/joeig/go-powerdns/v3"
	"github.com/miekg/dns"
	"github.com/pfisterer/cloud-self-service-golib/msg"
)

// The periodic CAA check.
//
// The enforced CAA (ZONE_DEFAULTS_SOA_RECORDS) lives in the base zones, where users cannot write. A CAA lookup, however, takes the CLOSEST CAA record set walking up from the name (RFC 8659), so a CAA record a user writes into their own zone overrides the enforced one for every name at and below it — e.g. allowing a CA the platform does not allow. Users can write any record type into their zone with its TSIG key, so this cannot be prevented at write time; it is detected here instead.
//
// Every run reads the record sets of all stored zones from PowerDNS and reports each zone with a CAA record set as a zone event (source caa-check), which its owners and the super admins see like every other zone event. A record set that only repeats entries of the enforced CAA (e.g. in a zone that was an intermediate zone before somebody adopted it) restricts nothing further and is not reported. With CAA_CHECK_DELETE_RECORDS the record sets are removed as well, and the event says so instead.

const (
	// caaCheckSource is the producer name of the events of this check.
	caaCheckSource = "caa-check"
	// caaClassFound is an event about CAA records that are in a user zone right now; resolved by the first run that finds none there.
	caaClassFound = "UserZoneCAA"
	// caaClassRemoved is an event about CAA records the check removed; it stays until it expires, so the owners learn why their records are gone.
	caaClassRemoved = "UserZoneCAARemoved"
)

// The texts of the events, per class: the message, and the introduction to the list of record sets that is stored as the event's detail. The event stores the German text and only the list as detail; caaEventText renders both in the language of the request that reads them.
var caaEventTexts = map[string]struct{ message, detail msg.Text }{
	caaClassFound: {
		message: msg.T("Die Zone enthält eigene CAA-Einträge, die die vorgegebene CAA-Regel außer Kraft setzen.", "The zone contains CAA records of its own that override the enforced CAA rule."),
		detail:  msg.T("Eine CAA-Abfrage nimmt den nächstgelegenen CAA-Eintrag, darum gelten diese Einträge statt der vorgegebenen Regel für alle Namen darunter. Bitte diese Einträge löschen:", "A CAA lookup takes the closest CAA record, so these records apply instead of the enforced rule to every name below them. Please delete them:"),
	},
	caaClassRemoved: {
		message: msg.T("Eigene CAA-Einträge wurden aus der Zone entfernt, weil sie die vorgegebene CAA-Regel außer Kraft setzen würden.", "CAA records of the zone's own were removed because they would override the enforced CAA rule."),
		detail:  msg.T("Für Zertifikate gilt die CAA-Regel der übergeordneten Zone; CAA-Einträge in der eigenen Zone sind nicht erlaubt und werden regelmäßig entfernt. Entfernt wurde:", "Certificates are governed by the CAA rule of the zone above; CAA records in the zone itself are not allowed and are removed regularly. Removed:"),
	},
}

// caaEventText renders an event of this check in the given language; false for events of other producers.
func caaEventText(ev ZoneEvent, l msg.Lang) (message, detail string, ok bool) {
	texts, ok := caaEventTexts[ev.Class]
	if ev.Source != caaCheckSource || !ok {
		return "", "", false
	}
	return texts.message.In(l), texts.detail.In(l) + "\n" + ev.Detail, true
}

// caaRecordSet is one CAA record set of a zone: its owner name (FQDN) and its records' contents.
type caaRecordSet struct {
	Name     string
	Contents []string
}

// caaZoneSource is what the check needs from PowerDNS; an interface so the logic can be tested without one.
type caaZoneSource interface {
	CAARecordSets(ctx context.Context, zone string) ([]caaRecordSet, error)
	DeleteCAARecordSet(ctx context.Context, zone, name string) error
	EnforcedCAAContents() []string
}

// CAARecordSets returns the CAA record sets of a zone.
func (p *PowerDnsClient) CAARecordSets(ctx context.Context, zone string) ([]caaRecordSet, error) {
	z, err := p.powerdns.Zones.Get(ctx, dns.Fqdn(zone))
	if err != nil {
		return nil, fmt.Errorf("reading zone %s: %w", zone, err)
	}
	var sets []caaRecordSet
	for _, rr := range z.RRsets {
		if rr.Type == nil || *rr.Type != powerdns.RRTypeCAA || rr.Name == nil {
			continue
		}
		set := caaRecordSet{Name: *rr.Name}
		for _, r := range rr.Records {
			if r.Content != nil {
				set.Contents = append(set.Contents, *r.Content)
			}
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// DeleteCAARecordSet removes the CAA record set at name (FQDN) from a zone.
func (p *PowerDnsClient) DeleteCAARecordSet(ctx context.Context, zone, name string) error {
	return p.powerdns.Records.Delete(ctx, dns.Fqdn(zone), dns.Fqdn(name), powerdns.RRTypeCAA)
}

// EnforcedCAAContents is the contents of the CAA records configured for the base zones.
func (p *PowerDnsClient) EnforcedCAAContents() []string {
	var out []string
	for _, r := range p.defaultSoaZoneRecords {
		if strings.EqualFold(r.Type, "CAA") {
			out = append(out, r.Content)
		}
	}
	return out
}

// normalizeCAA makes two spellings of one CAA content comparable: single spaces, lower case (flags, tag and the CA's domain are case-insensitive in practice).
func normalizeCAA(content string) string {
	return strings.ToLower(strings.Join(strings.Fields(content), " "))
}

// caaOverrides reports whether a record set has an entry that is not part of the enforced CAA — only such a set changes what the enforced one allows.
func caaOverrides(set caaRecordSet, enforced map[string]struct{}) bool {
	for _, c := range set.Contents {
		if _, ok := enforced[normalizeCAA(c)]; !ok {
			return true
		}
	}
	return false
}

// relativeName is a record's owner name relative to its zone ("@" for the apex), as people write it.
func relativeName(name, zone string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	z := strings.TrimSuffix(strings.ToLower(zone), ".")
	if n == z {
		return "@"
	}
	return strings.TrimSuffix(n, "."+z)
}

// describeCAASets lists record sets as "name: content; content", one per line.
func describeCAASets(sets []caaRecordSet, zone string) string {
	lines := make([]string, 0, len(sets))
	for _, s := range sets {
		lines = append(lines, fmt.Sprintf("%s CAA %s", relativeName(s.Name, zone), strings.Join(s.Contents, " | ")))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// CaaCheckSummary says what one run did.
type CaaCheckSummary struct {
	Checked  int
	Findings int
	Removed  int
	Failed   int
}

// CheckUserZoneCAA runs the check once over all stored zones.
func (app *AppData) CheckUserZoneCAA(ctx context.Context, source caaZoneSource) (CaaCheckSummary, error) {
	sum := CaaCheckSummary{}
	now := time.Now()

	rows, err := app.Storage.ListAllZones()
	if err != nil {
		return sum, err
	}
	enforced := map[string]struct{}{}
	for _, c := range source.EnforcedCAAContents() {
		enforced[normalizeCAA(c)] = struct{}{}
	}

	// An event outlives a few missed runs, so it does not flap when a run fails; and it vanishes on its own when the check is switched off.
	interval := time.Duration(app.Config.CaaCheck.IntervalMinutes) * time.Minute
	foundTTL := max(3*interval, time.Hour)
	removedTTL := max(app.Config.ZoneEvents.ttl(), foundTTL)

	seen := map[string]struct{}{}
	for _, row := range rows {
		zone := row.Zone
		if _, done := seen[zone]; done {
			continue
		}
		seen[zone] = struct{}{}

		sets, err := source.CAARecordSets(ctx, zone)
		if err != nil {
			// A stored zone PowerDNS does not serve is the reconcile's business; its events stay until they expire.
			sum.Failed++
			app.Log.Warnf("caa-check: %v", err)
			continue
		}
		sum.Checked++

		var offending []caaRecordSet
		for _, s := range sets {
			if caaOverrides(s, enforced) {
				offending = append(offending, s)
			}
		}
		if len(offending) == 0 {
			if err := app.Storage.ResolveZoneEvent(caaCheckSource, caaClassFound, zone); err != nil {
				return sum, err
			}
			continue
		}
		sum.Findings++
		listing := describeCAASets(offending, zone)

		if app.Config.CaaCheck.DeleteRecords {
			var failed []string
			for _, s := range offending {
				if err := source.DeleteCAARecordSet(ctx, zone, s.Name); err != nil {
					app.Log.Warnf("caa-check: removing the CAA records at %s in %s: %v", s.Name, zone, err)
					failed = append(failed, s.Name)
				}
			}
			if len(failed) == 0 {
				sum.Removed++
				app.Log.Infof("caa-check: removed CAA records from zone %s: %s", zone, strings.ReplaceAll(listing, "\n", "; "))
				if err := app.Storage.ResolveZoneEvent(caaCheckSource, caaClassFound, zone); err != nil {
					return sum, err
				}
				if err := app.Storage.UpsertZoneEvent(ZoneEvent{
					Source:    caaCheckSource,
					Class:     caaClassRemoved,
					Zone:      zone,
					Severity:  "warning",
					Message:   truncate(caaEventTexts[caaClassRemoved].message.String(), 512),
					Detail:    truncate(listing, 3000),
					FirstSeen: now,
					LastSeen:  now,
					ExpiresAt: now.Add(removedTTL),
				}); err != nil {
					return sum, err
				}
				continue
			}
		}

		app.Log.Warnf("caa-check: zone %s has CAA records that override the enforced CAA: %s", zone, strings.ReplaceAll(listing, "\n", "; "))
		if err := app.Storage.UpsertZoneEvent(ZoneEvent{
			Source:    caaCheckSource,
			Class:     caaClassFound,
			Zone:      zone,
			Severity:  "warning",
			Message:   truncate(caaEventTexts[caaClassFound].message.String(), 512),
			Detail:    truncate(listing, 3000),
			FirstSeen: now,
			LastSeen:  now,
			ExpiresAt: now.Add(foundTTL),
		}); err != nil {
			return sum, err
		}
	}
	return sum, nil
}

// RunPeriodicCaaCheck runs CheckUserZoneCAA every CaaCheck.IntervalMinutes, the first time a minute after startup; an interval of 0 switches it off.
func RunPeriodicCaaCheck(app *AppData) {
	minutes := app.Config.CaaCheck.IntervalMinutes
	if minutes <= 0 {
		app.Log.Info("caa-check: switched off (CAA_CHECK_INTERVAL_MINUTES=0)")
		return
	}
	app.Log.Infof("caa-check: checking user zones for CAA records every %d minutes (removing them: %v)", minutes, app.Config.CaaCheck.DeleteRecords)
	time.Sleep(time.Minute)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		sum, err := app.CheckUserZoneCAA(ctx, app.PowerDns)
		cancel()
		if err != nil {
			app.Log.Errorf("caa-check: %v", err)
		} else {
			app.Log.Infof("caa-check: checked %d zones, %d with CAA records, %d cleaned, %d not readable", sum.Checked, sum.Findings, sum.Removed, sum.Failed)
		}
		time.Sleep(time.Duration(minutes) * time.Minute)
	}
}
