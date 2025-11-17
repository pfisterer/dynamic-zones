package zones

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
	powerdns          *powerdns.Client
	log               *zap.SugaredLogger
	defaultTTLSeconds uint32
	zoneNsNames       []string
}

func NewPowerDnsClient(url, vhost, apiKey string, defaultTtlSecs uint32, zoneNsNames []string, log *zap.SugaredLogger) (*PowerDnsClient, error) {
	pdns := powerdns.New(url, vhost, powerdns.WithAPIKey(apiKey))

	if pdns == nil {
		log.Fatalf("app.setupPowerDns: Failed to create PowerDNS client")
		return nil, fmt.Errorf("failed to create PowerDNS client")
	}

	return &PowerDnsClient{
		powerdns:          pdns,
		log:               log,
		defaultTTLSeconds: defaultTtlSecs,
		zoneNsNames:       zoneNsNames,
	}, nil

}

func (p *PowerDnsClient) GetZone(ctx context.Context, zone string) (*ZoneDataResponse, error) {
	// Get zone metadata from PowerDNS
	zonemeta, err := p.powerdns.Metadata.Get(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate)
	if err != nil {
		return nil, fmt.Errorf("powerdns.GetZone: Failed to get metadata from PowerDNS: %v", err)
	}

	// Generate the response
	response := ZoneDataResponse{
		Zone:     zone,
		ZoneKeys: make([]ZoneKey, 0, len(zonemeta.Metadata)),
	}

	// Get keys listed in the metadata
	for _, keyname := range zonemeta.Metadata {
		tsigkey, err := p.powerdns.TSIGKeys.Get(ctx, keyname)
		if err != nil {
			return nil, fmt.Errorf("powerdns.GetZone: Failed to get TSIG key '%s' from PowerDNS: %v", keyname, err)
		}
		response.ZoneKeys = append(response.ZoneKeys, ZoneKey{
			Keyname:   *tsigkey.Name,
			Algorithm: *tsigkey.Algorithm,
			Key:       *tsigkey.Key,
		})
	}

	return &response, nil
}

func (p *PowerDnsClient) prepareZoneForCreation(zoneFQDN string) *powerdns.Zone {
	// Build your SOA serial in YYYYMMDDnn
	serial := time.Now().Format("20060102") + "01"
	soaNameserver := dns.Fqdn(p.zoneNsNames[0])
	refresh := uint32(10800)
	retry := uint32(3600)
	expire := uint32(604800)
	minimum := p.defaultTTLSeconds
	soaContent := fmt.Sprintf("%s hostmaster.%s %s %d %d %d %d", soaNameserver, zoneFQDN, serial, refresh, retry, expire, minimum)

	// Prepare NS records
	nsRecords := make([]powerdns.Record, len(p.zoneNsNames))
	for i, ns := range p.zoneNsNames {
		nsRecords[i] = powerdns.Record{
			Content:  powerdns.String(dns.Fqdn(ns)),
			Disabled: powerdns.Bool(false),
		}
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
		RRsets:      []powerdns.RRset{soaRRSet},
	}

	return &zoneDef
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

		// Create zone via API with SOA + NS
		zoneDef := p.prepareZoneForCreation(zoneFQDN)
		_, err = p.powerdns.Zones.Add(ctx, zoneDef)

		if err != nil {
			return fmt.Errorf("CreateZone: error creating zone: %v, definition: %+v", err, zoneDef)
		}
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

func (p *PowerDnsClient) CreateZone(ctx context.Context, user, zone string, force bool) (*ZoneDataResponse, error) {
	// zone name as FQDN
	zoneFQDN := dns.Fqdn(zone)

	// Compute TSIG key name, etc.
	keyname := "key-" + helper.Sha1Hash("user-"+user+"-zone-"+zone+"-key")

	// If force is set, delete existing zone and key (if they exist)
	if force {
		_ = p.powerdns.Zones.Delete(ctx, zoneFQDN)
		_ = p.powerdns.TSIGKeys.Delete(ctx, keyname)
	}

	// Create zone via API with SOA + NS
	zoneDef := p.prepareZoneForCreation(zoneFQDN)
	p.log.Debugf("powerdns.CreateZone: Creating zone with definition: %+v", zoneDef)
	_, err := p.powerdns.Zones.Add(ctx, zoneDef)
	if err != nil {
		return nil, fmt.Errorf("CreateZone: error creating zone: %v, definition: %+v", err, zoneDef)
	}

	// Generate a TSIG key
	algorithm := "hmac-sha512"
	key, err := helper.GenerateTSIGKeyHMACSHA512()
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Failed to generate TSIG key: %v", err)
	}

	// Create the TSIG key in PowerDNS
	tsigkey, err := p.powerdns.TSIGKeys.Create(ctx, keyname, algorithm, key)
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error creating TSIG key: %v", err)
	}

	// Allow the TSIG key to perform AXFR
	_, err = p.powerdns.Metadata.Set(ctx, zone, powerdns.MetadataTSIGAllowAXFR, []string{*tsigkey.Name})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting ALLOW-AXFR-TSIG metadata: %v", err)
	}

	// Allow dynamic updates from any IP, required for TSIG updates
	// From the documentation (https://doc.powerdns.com/authoritative/dnsupdate.html): The semantics are
	// that first a dynamic update has to be allowed either by the global allow-dnsupdate-from setting,
	// or by a per-zone ALLOW-DNSUPDATE-FROM metadata setting.
	// Secondly, if a zone has a TSIG-ALLOW-DNSUPDATE metadata setting, that must match too.
	_, err = p.powerdns.Metadata.Set(ctx, zone, powerdns.MetadataAllowDNSUpdateFrom, []string{"0.0.0.0/0", "::/0"})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting AllowDNSUpdateFrom metadata: %v", err)
	}

	// Allow the TSIG key to perform dynamic updates
	_, err = p.powerdns.Metadata.Set(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate, []string{*tsigkey.Name})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting TSIG dynamic update metadata: %v", err)
	}

	return p.GetZone(ctx, zone)
}

func (p *PowerDnsClient) DeleteZone(ctx context.Context, zone string, delete_all_keys bool) error {

	if delete_all_keys {
		// Get the TSIG key name from the zone metadata
		metadata, err := p.powerdns.Metadata.Get(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate)
		if err != nil {
			return fmt.Errorf("powerdns.DeleteZone: Error getting metadata kind 'powerdns.MetadataTSIGAllowDNSUpdate' for zone %s: %v", zone, err)
		}

		// Delete the TSIG key
		for _, keyname := range metadata.Metadata {
			err = p.powerdns.TSIGKeys.Delete(ctx, keyname)
			if err != nil {
				return fmt.Errorf("powerdns.DeleteZone: Error deleting TSIG key: %v", err)
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
