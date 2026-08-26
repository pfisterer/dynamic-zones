package app

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pfisterer/dynamic-zones/internal/helper"
	"github.com/miekg/dns"
)

// The record operations, as service methods rather than as HTTP handlers.
//
// They exist because the MCP endpoint needs the same operations the REST routes
// perform, and "the same" has to mean one implementation — an agent that writes
// a record through a second, parallel code path is an agent whose writes are
// authorised by a second, parallel set of rules.
//
// The one thing that differs between the two callers is where the TSIG key
// comes from. REST takes it from the request, because the browser already holds
// the zone's key. MCP must not: handing a model a credential puts it in that
// model's context, its transcript and whatever the client keeps. So the service
// can resolve the caller's OWN key itself (OwnerTSIG) and never return it.

// TSIGCredentials are what PowerDNS checks on an RFC 2136 update or an AXFR.
type TSIGCredentials struct {
	KeyName   string
	Algorithm string
	Key       string
}

// StatusError is an error that knows the HTTP status it should become. It lets
// the service layer own the rules ("you are not an owner" is 403) while the REST
// handlers stay a translation into a response and the MCP tools into a message.
type StatusError struct {
	Status int
	Msg    string
	Err    error
}

func (e *StatusError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Msg, e.Err)
	}
	return e.Msg
}

func (e *StatusError) Unwrap() error { return e.Err }

func statusErr(status int, msg string, err error) error {
	return &StatusError{Status: status, Msg: msg, Err: err}
}

// StatusOf reports the HTTP status an error asks for, defaulting to 500 for one
// that carries no opinion.
func StatusOf(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Status
	}
	return http.StatusInternalServerError
}

// MessageOf returns the caller-facing half of an error: the StatusError message
// without the wrapped cause, which belongs in the log and not in a response.
func MessageOf(err error) string {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Msg
	}
	return "internal error"
}

// normalizeZone trims a zone name to the form the ownership table stores.
func normalizeZone(zone string) string {
	return strings.TrimSuffix(strings.TrimSpace(zone), ".")
}

// requireZoneOwnership refuses to act on a zone the caller does not own.
//
// The TSIG key in a REST request is what PowerDNS checks, so these endpoints
// used to authorize on key possession alone — turning the API into an open
// RFC2136 relay that any logged-in user could point at any zone. Ownership is
// the same rule the zone endpoints apply, so nothing legitimate changes.
func (app *AppData) requireZoneOwnership(username, zone string) (string, error) {
	name := normalizeZone(zone)
	if name == "" {
		return "", statusErr(http.StatusBadRequest, "zone is required", nil)
	}
	isOwner, err := app.Storage.IsZoneOwner(username, name)
	if err != nil {
		return "", statusErr(http.StatusInternalServerError, "failed to check zone ownership", err)
	}
	if !isOwner {
		return "", statusErr(http.StatusForbidden, "you are not an owner of this zone",
			fmt.Errorf("user %q does not own zone %q", username, name))
	}
	return name, nil
}

// OwnerTSIG resolves the caller's own TSIG key for a zone.
//
// Only ever the caller's own: PowerDnsClient.GetZone scopes the key list to the
// user it is given, so this cannot hand back a co-owner's key even by accident.
// The result stays inside the service — it is passed to the RFC 2136 helpers and
// never put in a response or a tool result.
//
// Ownership is checked FIRST, and not only because the answer would be empty
// otherwise: a non-owner asking about a zone must be told they do not own it,
// not that it holds no key for them — the second sentence answers a question
// about a zone they have no business learning anything about.
func (app *AppData) OwnerTSIG(ctx context.Context, username, zone string) (TSIGCredentials, error) {
	name, err := app.requireZoneOwnership(username, zone)
	if err != nil {
		return TSIGCredentials{}, err
	}
	// The zone name as PowerDNS stores it — GetZone looks up metadata by this
	// string, and a trailing dot makes it a different one.
	zoneData, err := app.PowerDns.GetZone(ctx, name, username)
	if err != nil {
		return TSIGCredentials{}, statusErr(http.StatusInternalServerError, "failed to read the zone's keys", err)
	}
	if len(zoneData.ZoneKeys) == 0 {
		// An owner without a key is a zone in an inconsistent state, not a
		// permission problem: every owner gets one when they create or join.
		return TSIGCredentials{}, statusErr(http.StatusConflict, "no TSIG key for this zone and user",
			fmt.Errorf("zone %q has no key for %q", zone, username))
	}
	k := zoneData.ZoneKeys[0]
	return TSIGCredentials{KeyName: k.Keyname, Algorithm: k.Algorithm, Key: k.Key}, nil
}

// fqdn returns the credentials with the key name and algorithm fully qualified,
// which is what the DNS library expects.
func (c TSIGCredentials) fqdn() TSIGCredentials {
	name := c.KeyName
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return TSIGCredentials{KeyName: name, Algorithm: dns.Fqdn(c.Algorithm), Key: c.Key}
}

func (c TSIGCredentials) complete() bool {
	return c.KeyName != "" && c.Algorithm != "" && c.Key != ""
}

// RecordsList performs an AXFR for a zone and returns its records, minus the
// DNSSEC and SOA plumbing no caller here asked about.
func (app *AppData) RecordsList(ctx context.Context, username, zone string, creds TSIGCredentials) ([]DNSRecord, error) {
	name, err := app.requireZoneOwnership(username, zone)
	if err != nil {
		return nil, err
	}
	if !creds.complete() {
		return nil, statusErr(http.StatusBadRequest, "TSIG credentials required", nil)
	}
	creds = creds.fqdn()
	zoneFQDN := dns.Fqdn(name)

	msg := new(dns.Msg)
	msg.SetAxfr(zoneFQDN)
	msg.SetTsig(creds.KeyName, creds.Algorithm, 300, time.Now().Unix())

	tr := new(dns.Transfer)
	tr.TsigSecret = map[string]string{creds.KeyName: creds.Key}

	envChan, err := tr.In(msg, GetServerAddress(app))
	if err != nil {
		return nil, statusErr(http.StatusInternalServerError, "zone transfer failed", err)
	}

	var records []DNSRecord
	for env := range envChan {
		if env.Error != nil {
			return nil, statusErr(http.StatusInternalServerError, "zone transfer failed", env.Error)
		}
		for _, rr := range env.RR {
			h := rr.Header()
			if h.Rrtype == dns.TypeSOA || h.Rrtype == dns.TypeRRSIG || h.Rrtype == dns.TypeDNSKEY {
				continue
			}
			records = append(records, DNSRecord{
				Zone:  zoneFQDN,
				Name:  axfrRecordName(h.Name, zoneFQDN),
				Type:  dns.TypeToString[h.Rrtype],
				TTL:   h.Ttl,
				Value: recordValue(rr),
			})
		}
	}
	return records, nil
}

// axfrRecordName normalizes the apex, which a transfer can deliver under more
// than one spelling.
func axfrRecordName(name, zoneFQDN string) string {
	if name == zoneFQDN || strings.Trim(name, ".") == strings.Trim(zoneFQDN, ".") {
		return zoneFQDN
	}
	if strings.HasPrefix(name, `\@`) {
		return zoneFQDN
	}
	return name
}

// recordValue renders the payload of a record as the API reports it.
func recordValue(rr dns.RR) string {
	switch t := rr.(type) {
	case *dns.A:
		return t.A.String()
	case *dns.AAAA:
		return t.AAAA.String()
	case *dns.CNAME:
		return t.Target
	case *dns.NS:
		return t.Ns
	case *dns.MX:
		// MX records need both the preference and the target.
		return fmt.Sprintf("%d %s", t.Preference, t.Mx)
	case *dns.TXT:
		// TXT records have multiple strings in the slice 'Txt'.
		return strings.Join(t.Txt, " ")
	default:
		return rr.String()
	}
}

// RecordUpsert writes a record, replacing one of the same name and type.
//
// A and AAAA only, because those are the record types the RFC 2136 helpers
// implement. Anything else is refused here rather than half-attempted.
func (app *AppData) RecordUpsert(ctx context.Context, username string, rec DNSRecord, creds TSIGCredentials) (DNSRecord, error) {
	name, err := app.requireZoneOwnership(username, rec.Zone)
	if err != nil {
		return DNSRecord{}, err
	}
	if !creds.complete() {
		return DNSRecord{}, statusErr(http.StatusBadRequest, "TSIG credentials required", nil)
	}
	creds = creds.fqdn()

	zoneFQDN := dns.Fqdn(name)
	recordName := canonicalRecordName(rec.Name, name)
	server := GetServerAddress(app)
	recType := strings.ToUpper(strings.TrimSpace(rec.Type))

	// UPSERT = delete first, then add. The delete may legitimately find nothing.
	switch recType {
	case "A":
		_, _ = helper.Rfc2136DeleteARecord(creds.KeyName, creds.Algorithm, creds.Key, server, zoneFQDN, recordName)
		if _, err := helper.Rfc2136AddARecord(creds.KeyName, creds.Algorithm, creds.Key, server, zoneFQDN, recordName, rec.Value, rec.TTL); err != nil {
			return DNSRecord{}, statusErr(http.StatusInternalServerError, "failed to write the record", err)
		}
	case "AAAA":
		_, _ = helper.Rfc2136DeleteAAAARecord(creds.KeyName, creds.Algorithm, creds.Key, server, zoneFQDN, recordName)
		if _, err := helper.Rfc2136AddAAAARecord(creds.KeyName, creds.Algorithm, creds.Key, server, zoneFQDN, recordName, rec.Value, rec.TTL); err != nil {
			return DNSRecord{}, statusErr(http.StatusInternalServerError, "failed to write the record", err)
		}
	default:
		return DNSRecord{}, statusErr(http.StatusBadRequest, "unsupported type (supported: A, AAAA)", nil)
	}

	return DNSRecord{Zone: zoneFQDN, Name: recordName, Type: recType, TTL: rec.TTL, Value: rec.Value}, nil
}

// RecordDelete removes a record by name and type.
func (app *AppData) RecordDelete(ctx context.Context, username string, rec DNSRecord, creds TSIGCredentials) (DNSRecord, error) {
	name, err := app.requireZoneOwnership(username, rec.Zone)
	if err != nil {
		return DNSRecord{}, err
	}
	if !creds.complete() {
		return DNSRecord{}, statusErr(http.StatusBadRequest, "TSIG credentials required", nil)
	}
	creds = creds.fqdn()

	zoneFQDN := dns.Fqdn(name)
	recordName := canonicalRecordName(rec.Name, name)
	server := GetServerAddress(app)
	recType := strings.ToUpper(strings.TrimSpace(rec.Type))

	switch recType {
	case "A":
		if _, err := helper.Rfc2136DeleteARecord(creds.KeyName, creds.Algorithm, creds.Key, server, zoneFQDN, recordName); err != nil {
			return DNSRecord{}, statusErr(http.StatusInternalServerError, "failed to delete the record", err)
		}
	case "AAAA":
		if _, err := helper.Rfc2136DeleteAAAARecord(creds.KeyName, creds.Algorithm, creds.Key, server, zoneFQDN, recordName); err != nil {
			return DNSRecord{}, statusErr(http.StatusInternalServerError, "failed to delete the record", err)
		}
	default:
		return DNSRecord{}, statusErr(http.StatusBadRequest, "unsupported type (supported: A, AAAA)", nil)
	}

	return DNSRecord{Zone: zoneFQDN, Name: recordName, Type: recType, TTL: rec.TTL, Value: rec.Value}, nil
}
