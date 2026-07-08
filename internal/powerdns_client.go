package app

import (
	"context"
	"fmt"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/gin-gonic/gin"
	"github.com/joeig/go-powerdns/v3"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const PowerdnsKey = "DYNAMIC_ZONES_pdns_client"
const userKeyPrefix = "user-key-"

type ZoneKey struct {
	Keyname   string `json:"keyname"`
	Algorithm string `json:"algorithm"`
	Key       string `json:"key"`
}

type ZoneDataResponse struct {
	Zone     string    `json:"zone"`
	ZoneKeys []ZoneKey `json:"zone_keys"`
}

func InjectPdnsMiddleware(client *powerdns.Client) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set(PowerdnsKey, client)
		c.Next()
	}
}

type PowerDnsClient struct {
	powerdns                *powerdns.Client
	log                     *zap.SugaredLogger
	defaultTTLSeconds       uint32
	zoneNsNames             []string
	defaultUserZoneRecords  []DefaultRecord
	defaultSoaZoneRecords   []DefaultRecord
	defaultAdminTsigKeyName string
	defaultAdminTsigKey     string
	defaultAdminTsigAlg     string
}

func NewPowerDnsClient(url, vhost, apiKey string, defaultTtlSecs uint32, zoneNsNames []string,
	defaultAdminTsigKeyName, defaultAdminTsigKey, defaultAdminTsigAlg string,
	defaultUserZoneRecords []DefaultRecord,
	defaultSoaZoneRecords []DefaultRecord,
	log *zap.SugaredLogger) (*PowerDnsClient, error) {
	pdns := powerdns.New(url, vhost, powerdns.WithAPIKey(apiKey))

	if pdns == nil {
		log.Fatalf("app.setupPowerDns: Failed to create PowerDNS client")
		return nil, fmt.Errorf("failed to create PowerDNS client")
	}

	return &PowerDnsClient{
		powerdns:                pdns,
		log:                     log,
		defaultTTLSeconds:       defaultTtlSecs,
		zoneNsNames:             zoneNsNames,
		defaultUserZoneRecords:  defaultUserZoneRecords,
		defaultSoaZoneRecords:   defaultSoaZoneRecords,
		defaultAdminTsigKeyName: defaultAdminTsigKeyName,
		defaultAdminTsigKey:     defaultAdminTsigKey,
		defaultAdminTsigAlg:     defaultAdminTsigAlg,
	}, nil

}

func (p *PowerDnsClient) keyNameFor(user, zone string) string {
	return "user-key-" + helper.Sha1Hash("user-"+user+"-zone-"+zone+"-key")
}

func (p *PowerDnsClient) isUserKey(keyname string) bool {
	return len(keyname) > len(userKeyPrefix) && keyname[:len(userKeyPrefix)] == userKeyPrefix
}

// GetZone returns the zone's user TSIG keys. When forUser is non-empty, ONLY that
// user's own key (keyNameFor(forUser, zone)) is returned — so a co-owner never
// sees another owner's key, which is what makes owner removal an effective
// revocation. An empty forUser returns all user keys (internal/admin callers).
func (p *PowerDnsClient) GetZone(ctx context.Context, zone string, forUser string) (*ZoneDataResponse, error) {
	// Get zone metadata from PowerDNS
	zonemeta, err := p.powerdns.Metadata.Get(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate)
	if err != nil {
		p.log.Errorf("Failed to get metadata for zone %s: %v", zone, err)
		return nil, fmt.Errorf("failed to get metadata from PowerDNS: %v", err)
	}

	// Scope to the caller's own key when a user is given.
	wantKey := ""
	if forUser != "" {
		wantKey = p.keyNameFor(forUser, zone)
	}

	// Generate the response
	response := ZoneDataResponse{
		Zone:     zone,
		ZoneKeys: make([]ZoneKey, 0, len(zonemeta.Metadata)),
	}

	// Get keys listed in the metadata
	for _, keyname := range zonemeta.Metadata {
		if !p.isUserKey(keyname) {
			p.log.Debugf("Skipping non-user TSIG key '%s' for zone '%s'", keyname, zone)
			continue
		}
		if wantKey != "" && keyname != wantKey {
			continue // only the caller's own key
		}

		tsigkey, err := p.powerdns.TSIGKeys.Get(ctx, keyname)
		if err != nil {
			p.log.Errorf("Failed to get TSIG key '%s': %v", keyname, err)
			return nil, fmt.Errorf("failed to get TSIG key '%s' from PowerDNS: %v", keyname, err)
		}

		response.ZoneKeys = append(response.ZoneKeys, ZoneKey{
			Keyname:   *tsigkey.Name,
			Algorithm: *tsigkey.Algorithm,
			Key:       *tsigkey.Key,
		})
	}

	return &response, nil
}

// removeValueFromMetadata rewrites a zone's metadata list of `kind`, dropping `value`.
func (p *PowerDnsClient) removeValueFromMetadata(ctx context.Context, zone string, kind powerdns.MetadataKind, value string) error {
	existing, err := p.powerdns.Metadata.Get(ctx, zone, kind)
	if err != nil {
		return fmt.Errorf("getting metadata %s failed: %v", kind, err)
	}
	final := make([]string, 0)
	if existing != nil && existing.Metadata != nil {
		for _, v := range existing.Metadata {
			if v != value {
				final = append(final, v)
			}
		}
	}
	_, err = p.powerdns.Metadata.Set(ctx, zone, kind, final)
	return err
}

// AddOwnerKey ensures `user` has their own TSIG key on `zone` (generating one if
// absent). Idempotent — re-adding an existing owner keeps their key.
func (p *PowerDnsClient) AddOwnerKey(ctx context.Context, zone, user string) error {
	zoneFQDN := dns.Fqdn(zone)
	keyname := p.keyNameFor(user, zone)

	// Reuse the existing key if it is already present.
	if existing, err := p.powerdns.TSIGKeys.Get(ctx, keyname); err == nil && existing != nil && existing.Key != nil && existing.Algorithm != nil {
		return p.addKeyToZone(ctx, zoneFQDN, keyname, *existing.Algorithm, *existing.Key)
	}

	key, err := helper.GenerateTSIGKeyHMACSHA512()
	if err != nil {
		return fmt.Errorf("AddOwnerKey: failed to generate TSIG key: %w", err)
	}
	return p.addKeyToZone(ctx, zoneFQDN, keyname, "hmac-sha512", key)
}

// RemoveOwnerKey deletes `user`'s TSIG key from `zone`: it is dropped from the
// update and AXFR metadata and the key object is deleted, so it stops validating
// immediately. Other owners' keys are untouched.
func (p *PowerDnsClient) RemoveOwnerKey(ctx context.Context, zone, user string) error {
	zoneFQDN := dns.Fqdn(zone)
	keyname := p.keyNameFor(user, zone)

	_ = p.removeValueFromMetadata(ctx, zoneFQDN, powerdns.MetadataTSIGAllowDNSUpdate, keyname)
	_ = p.removeValueFromMetadata(ctx, zoneFQDN, powerdns.MetadataTSIGAllowAXFR, keyname)

	if err := p.powerdns.TSIGKeys.Delete(ctx, keyname); err != nil {
		return fmt.Errorf("RemoveOwnerKey: failed to delete TSIG key '%s': %w", keyname, err)
	}
	return nil
}

// RotateZoneKeys regenerates the TSIG key of every given owner (delete + create),
// e.g. after a suspected key compromise. All owners must re-fetch their key.
func (p *PowerDnsClient) RotateZoneKeys(ctx context.Context, zone string, owners []string) error {
	for _, owner := range owners {
		if err := p.RemoveOwnerKey(ctx, zone, owner); err != nil {
			return fmt.Errorf("RotateZoneKeys: %w", err)
		}
		if err := p.AddOwnerKey(ctx, zone, owner); err != nil {
			return fmt.Errorf("RotateZoneKeys: %w", err)
		}
	}
	return nil
}

func (p *PowerDnsClient) DeleteZone(ctx context.Context, zone string, delete_all_keys bool) error {

	if delete_all_keys {
		// Get the TSIG key name from the zone metadata
		metadata, err := p.powerdns.Metadata.Get(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate)
		if err != nil {
			return fmt.Errorf("error getting metadata kind 'powerdns.MetadataTSIGAllowDNSUpdate' for zone %s: %v", zone, err)
		}

		// Delete the TSIG key if it's a user key
		for _, keyname := range metadata.Metadata {
			if !p.isUserKey(keyname) {
				p.log.Debugf("Skipping non-user TSIG key deletion '%s' for zone '%s'", keyname, zone)
				continue
			}
			err = p.powerdns.TSIGKeys.Delete(ctx, keyname)
			if err != nil {
				return fmt.Errorf("error deleting TSIG key: %v", err)
			}
		}
	}

	// Delete the zone
	err := p.powerdns.Zones.Delete(ctx, zone)
	if err != nil {
		return fmt.Errorf("powerdns.DeleteZone: Error deleting zone: %v", err)
	}

	return nil
}

func (p *PowerDnsClient) EnsureIntermediateZoneExists(ctx context.Context, zone, nextChildZone string) error {
	// zone name as FQDN
	zoneFQDN := dns.Fqdn(zone)

	// Check if zone already exists, if not, create it
	_, err := p.powerdns.Zones.Get(ctx, zoneFQDN)
	if err == nil {
		p.log.Debugf("Intermediate zone %s already exists, skipping creation", zoneFQDN)
	} else {
		p.log.Debugf("Intermediate zone %s does not exist (%v), will create it", zoneFQDN, err)

		// Create zone via API with SOA + NS. Intermediate/base (SOA) zones get the
		// SOA default records (e.g. the enforced CAA) — the user cannot write here.
		zoneDef := p.prepareZoneForCreation(zoneFQDN, p.defaultSoaZoneRecords)
		_, err = p.powerdns.Zones.Add(ctx, zoneDef)

		if err != nil {
			return fmt.Errorf("CreateZone: error creating zone: %v, definition: %+v", err, zoneDef)
		}
	}

	// Make sure the access rights for intermediate zone are set correctly
	if p.defaultAdminTsigKeyName != "" && p.defaultAdminTsigKey != "" && p.defaultAdminTsigAlg != "" {
		p.addKeyToZone(ctx, zoneFQDN, p.defaultAdminTsigKeyName, p.defaultAdminTsigAlg, p.defaultAdminTsigKey)
	}

	// In any case, ensure that the NS delegation for the next child zone exists
	if nextChildZone != "" {
		childFQDN := dns.Fqdn(nextChildZone)

		contents := make([]string, len(p.zoneNsNames))
		for i, ns := range p.zoneNsNames {
			contents[i] = dns.Fqdn(ns)
		}

		// Remove any existing delegation (ignore errors if none exist)
		_ = p.powerdns.Records.Delete(ctx, zoneFQDN, childFQDN, powerdns.RRTypeNS)

		// Add the correct delegation
		p.log.Debugf("Adding delegation record in %s to the next child-zone %s with contents %v", zoneFQDN, childFQDN, contents)
		err := p.powerdns.Records.Add(ctx, zoneFQDN, childFQDN, powerdns.RRTypeNS, p.defaultTTLSeconds, contents)
		if err != nil {
			return fmt.Errorf("failed to add NS delegation for %s in %s: %w", childFQDN, zoneFQDN, err)
		}
	}

	return nil
}

func (p *PowerDnsClient) CreateUserZone(ctx context.Context, user, zone string, force bool) (*ZoneDataResponse, error) {
	// zone name as FQDN
	zoneFQDN := dns.Fqdn(zone)

	// Compute TSIG key name, etc.
	keyname := p.keyNameFor(user, zone)

	// If force is set, delete existing zone and key (if they exist)
	if force {
		_ = p.powerdns.Zones.Delete(ctx, zoneFQDN)
		_ = p.powerdns.TSIGKeys.Delete(ctx, keyname)
	}

	// Create zone via API with SOA + NS. User (leaf) zones get the user default
	// records only — NOT the SOA records (e.g. CAA), which live in the base zone
	// so the user's zone TSIG key cannot delete or override them.
	zoneDef := p.prepareZoneForCreation(zoneFQDN, p.defaultUserZoneRecords)
	p.log.Debugf("Creating zone with definition: %+v", zoneDef)
	_, err := p.powerdns.Zones.Add(ctx, zoneDef)
	if err != nil {
		return nil, fmt.Errorf("error creating zone: %v, definition: %+v", err, zoneDef)
	}

	// Add the admin TSIG key to the zone
	if p.defaultAdminTsigKeyName != "" && p.defaultAdminTsigKey != "" && p.defaultAdminTsigAlg != "" {
		p.log.Debugf("Adding admin TSIG key '%s' to zone '%s'", p.defaultAdminTsigKeyName, zoneFQDN)

		err = p.addKeyToZone(ctx, zoneFQDN, p.defaultAdminTsigKeyName, p.defaultAdminTsigAlg, p.defaultAdminTsigKey)
		if err != nil {
			return nil, fmt.Errorf("failed to add admin TSIG key to zone: %v", err)
		}
	}

	// Generate a TSIG key
	key, err := helper.GenerateTSIGKeyHMACSHA512()
	if err != nil {
		return nil, fmt.Errorf("failed to generate TSIG key: %v", err)
	}

	// Create (if required) and assign the TSIG key to the zone
	err = p.addKeyToZone(ctx, zoneFQDN, keyname, "hmac-sha512", key)
	if err != nil {
		return nil, fmt.Errorf("failed to add TSIG key to zone: %v", err)
	}

	return p.GetZone(ctx, zone, user)
}

func (p *PowerDnsClient) addKeyToZone(ctx context.Context, zone, keyname, algorithm, key string) error {
	var tsigkey *powerdns.TSIGKey

	if algorithm == "" || key == "" || keyname == "" {
		p.log.Warn("TSIG keyname, algorithm, or key is empty, skipping TSIG key creation")
		return fmt.Errorf("tsig keyname, algorithm, or key is empty")
	}

	// Check if the key already exists
	existingKey, err := p.powerdns.TSIGKeys.Get(ctx, keyname)

	// Check if existing key matches the desired key
	existingKeyFound := err == nil && existingKey.Algorithm != nil && existingKey.Key != nil
	existingKeyMatches := existingKeyFound && *existingKey.Algorithm == algorithm && *existingKey.Key == key

	if existingKeyMatches {
		p.log.Debugf("TSIG key %s already exists and matches desired key, skipping creation", keyname)
		tsigkey = existingKey
	} else {
		// Delete existing key if it does not match
		if existingKeyFound {
			p.log.Debugf("Deleting existing TSIG key '%s' as it does not match the requested data", keyname)

			err = p.powerdns.TSIGKeys.Delete(ctx, keyname)
			if err != nil {
				return fmt.Errorf("powerdns.CreateZone: Error deleting existing TSIG key: %v", err)
			}
		}

		// Create the TSIG key in PowerDNS
		p.log.Debugf("Adding TSIG key %s to PowerDNS", keyname)
		tsigkey, err = p.powerdns.TSIGKeys.Create(ctx, keyname, algorithm, key)
		if err != nil {
			return fmt.Errorf("powerdns.CreateZone: Error creating TSIG key: %v", err)
		}
	}

	// --- helper to append a metadata entry safely without losing the old ones ---
	appendMetadata := func(kind powerdns.MetadataKind, value string) error {
		// Get existing metadata (may be nil)
		existing, err := p.powerdns.Metadata.Get(ctx, zone, kind)
		if err != nil {
			return fmt.Errorf("getting metadata %s failed: %v", kind, err)
		}

		// Build a unique-set list
		final := make([]string, 0)
		existingSet := make(map[string]bool)

		// Add existing values
		if existing != nil && existing.Metadata != nil {
			for _, v := range existing.Metadata {
				existingSet[v] = true
				final = append(final, v)
			}
		}

		// Append only if not present
		if !existingSet[value] {
			final = append(final, value)
		}

		_, err = p.powerdns.Metadata.Set(ctx, zone, kind, final)
		return err
	}

	// Allow the TSIG key to perform AXFR
	if err := appendMetadata(powerdns.MetadataTSIGAllowAXFR, *tsigkey.Name); err != nil {
		return fmt.Errorf("powerdns.CreateZone: Error setting ALLOW-AXFR-TSIG metadata: %v", err)
	}

	// Allow dynamic updates from any IP, required for TSIG updates
	// From the documentation (https://doc.powerdns.com/authoritative/dnsupdate.html): The semantics are
	// that first a dynamic update has to be allowed either by the global allow-dnsupdate-from setting,
	// or by a per-zone ALLOW-DNSUPDATE-FROM metadata setting.
	// Secondly, if a zone has a TSIG-ALLOW-DNSUPDATE metadata setting, that must match too.
	if err := appendMetadata(powerdns.MetadataAllowDNSUpdateFrom, "0.0.0.0/0"); err != nil {
		return fmt.Errorf("powerdns.CreateZone: Error setting AllowDNSUpdateFrom metadata: %v", err)
	}
	if err := appendMetadata(powerdns.MetadataAllowDNSUpdateFrom, "::/0"); err != nil {
		return fmt.Errorf("powerdns.CreateZone: Error setting AllowDNSUpdateFrom metadata: %v", err)
	}

	// Allow the TSIG key to perform dynamic updates
	if err := appendMetadata(powerdns.MetadataTSIGAllowDNSUpdate, *tsigkey.Name); err != nil {
		return fmt.Errorf("powerdns.CreateZone: Error setting TSIG dynamic update metadata: %v", err)
	}

	return nil
}

// prepareZoneForCreation builds the zone definition (SOA + NS + the given
// default records). `records` differs by zone kind: leaf/user zones get
// defaultUserZoneRecords, SOA/base (intermediate) zones get defaultSoaZoneRecords
// — so e.g. the enforced CAA lives only in the base zone the user cannot write.
func (p *PowerDnsClient) prepareZoneForCreation(zoneFQDN string, records []DefaultRecord) *powerdns.Zone {
	// Build your SOA serial in YYYYMMDDnn
	serial := time.Now().Format("20060102") + "01"
	soaNameserver := dns.Fqdn(p.zoneNsNames[0])
	refresh := uint32(10800)
	retry := uint32(3600)
	expire := uint32(604800)
	minimum := p.defaultTTLSeconds
	soaContent := fmt.Sprintf("%s hostmaster.%s %s %d %d %d %d", soaNameserver, zoneFQDN, serial, refresh, retry, expire, minimum)

	// Create the given default records. Group by (name, type) so that several
	// values sharing a name+type (e.g. multiple CAA records at the apex) end up in
	// ONE RRset instead of overwriting each other. An empty or "@" name targets the
	// zone apex (needed for zone-wide CAA records).
	defaultRecordsRRSets := make([]powerdns.RRset, 0, len(records))
	rrsetByKey := make(map[string]*powerdns.RRset, len(records))
	for _, record := range records {
		name := zoneFQDN
		if record.Name != "" && record.Name != "@" {
			name = record.Name + "." + zoneFQDN
		}
		fqdn := dns.Fqdn(name)
		key := fqdn + "|" + record.Type
		rec := powerdns.Record{
			Content:  powerdns.String(record.Content),
			Disabled: powerdns.Bool(false),
		}
		if existing, ok := rrsetByKey[key]; ok {
			existing.Records = append(existing.Records, rec)
			continue
		}
		rrset := powerdns.RRset{
			Name:       powerdns.String(fqdn),
			Type:       powerdns.RRTypePtr(powerdns.RRType(record.Type)),
			TTL:        powerdns.Uint32(record.TTL),
			ChangeType: powerdns.ChangeTypePtr(powerdns.ChangeTypeReplace),
			Records:    []powerdns.Record{rec},
		}
		defaultRecordsRRSets = append(defaultRecordsRRSets, rrset)
		rrsetByKey[key] = &defaultRecordsRRSets[len(defaultRecordsRRSets)-1]
	}

	// Build the RRsets: SOA + NS
	soaRRSet := powerdns.RRset{
		Name:       powerdns.String(zoneFQDN),
		Type:       powerdns.RRTypePtr(powerdns.RRTypeSOA),
		TTL:        powerdns.Uint32(p.defaultTTLSeconds),
		ChangeType: powerdns.ChangeTypePtr(powerdns.ChangeTypeReplace),
		Records: []powerdns.Record{
			{
				Content:  powerdns.String(soaContent),
				Disabled: powerdns.Bool(false),
			},
		},
	}

	// Build the zone definition with rrsets
	zoneDef := powerdns.Zone{
		Name:        powerdns.String(zoneFQDN),
		Kind:        powerdns.ZoneKindPtr(powerdns.NativeZoneKind),
		DNSsec:      powerdns.Bool(false),
		SOAEdit:     powerdns.String("DEFAULT"),
		SOAEditAPI:  powerdns.String("DEFAULT"),
		APIRectify:  powerdns.Bool(true),
		Nameservers: p.zoneNsNames,
		RRsets:      append([]powerdns.RRset{soaRRSet}, defaultRecordsRRSets...),
	}

	return &zoneDef
}
