package app

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pfisterer/dynamic-zones/internal/helper"
)

// A zone has exactly one spelling here: trimmed, lower-case, without the trailing root dot. PowerDNS does not care about either — "X.P", "x.p" and "x.p." are one zone to it — so every second spelling this service let through named the SAME zone in PowerDNS while looking like a different, unclaimed one to the ownership table. That was enough to take a zone over: Bob asked for "X.P" (or "x.p.") while Alice owned "x.p", the table said nobody owned that name, and creating it replaced Alice's zone and key in PowerDNS with Bob's.
//
// So every entry point (REST routes, MCP tools, the records endpoints) reduces the name with canonicalZoneName before anything else looks at it, and only canonical names are ever stored.

// normalizeZone reduces a zone name to its canonical spelling without judging it: surrounding space trimmed, lower-cased, ONE trailing dot removed. Use canonicalZoneName wherever the name comes from a caller.
func normalizeZone(zone string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
}

// canonicalZoneName normalises a caller-supplied zone name and refuses anything that is not a plain host name: labels of [a-z0-9-] without a leading or trailing hyphen, 1–63 characters each, at most 253 in total and at least two labels. Underscores, wildcards and empty labels ("a..b", or a second trailing dot) are rejected rather than repaired, because a repaired name is a guess about which zone was meant.
func canonicalZoneName(raw string) (string, error) {
	zone := normalizeZone(raw)
	if err := helper.DnsValidateName(zone); err != nil {
		return "", fmt.Errorf("invalid zone name %q: %w", raw, err)
	}
	return zone, nil
}

// zoneParam reads a zone name from a route parameter in its canonical form, answering 400 itself when the name is not one. The second result says whether the handler may go on.
func zoneParam(c *gin.Context, param string) (string, bool) {
	zone, err := canonicalZoneName(c.Param(param))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return "", false
	}
	return zone, true
}

// nonCanonicalZoneNames lists the stored zone names that are not in canonical form. Only names from before canonicalisation can be: since then every name is reduced before it is stored. Such a row is not renamed automatically, because its owner's TSIG key name is derived from the stored spelling (renaming would detach the key), and a row like "X.P" next to "x.p" is the trace of a takeover that someone has to look at: PowerDNS holds ONE zone for both, with whichever key was written last.
func (app *AppData) nonCanonicalZoneNames() ([]Zone, error) {
	zones, err := app.Storage.ListAllZones()
	if err != nil {
		return nil, err
	}
	odd := make([]Zone, 0)
	for _, z := range zones {
		if canonical, err := canonicalZoneName(z.Zone); err != nil || canonical != z.Zone {
			odd = append(odd, z)
		}
	}
	return odd, nil
}

// warnAboutNonCanonicalZoneNames logs every stored zone row whose name is not canonical, once at startup. These zones can no longer be reached through the API (every request is canonicalised first), so they need an administrator: compare with the canonical zone in PowerDNS, then delete the stray row and rotate the remaining owners' keys.
func (app *AppData) warnAboutNonCanonicalZoneNames() {
	odd, err := app.nonCanonicalZoneNames()
	if err != nil {
		app.Log.Errorf("Failed to check stored zone names: %v", err)
		return
	}
	for _, z := range odd {
		app.Log.Warnf("Stored zone %q (owner %s) is not a canonical zone name and cannot be managed through the API; check it against %q in PowerDNS, remove the row and rotate the keys of that zone", z.Zone, z.Username, normalizeZone(z.Zone))
	}
}
