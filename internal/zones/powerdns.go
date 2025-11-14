package zones

import (
	"context"
	"fmt"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/gin-gonic/gin"
	"github.com/joeig/go-powerdns/v3"
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

func GetZone(ctx context.Context, pdns *powerdns.Client, zone string) (*ZoneDataResponse, error) {
	// Get zone metadata from PowerDNS
	zonemeta, err := pdns.Metadata.Get(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate)
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
		tsigkey, err := pdns.TSIGKeys.Get(ctx, keyname)
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

func CreateZone(ctx context.Context, pdns *powerdns.Client, user string, zone string, force bool, nameservers []string) (*ZoneDataResponse, error) {
	// Construct the new, compliant key name
	// Replace all dots with dashes to comply with PowerDNS key name requirements
	keyname := "key-" + helper.Sha1Hash("user-"+user+"-zone-"+zone+"-key")

	// Delete potentially existing zone and key if forcing
	if force {
		_ = pdns.Zones.Delete(ctx, zone)
		_ = pdns.TSIGKeys.Delete(ctx, keyname)
	}

	// Construct a valid SOA record (serial in YYYYMMDDnn format)
	serial := time.Now().Format("20060102") + "01"
	soaNameserver := nameservers[0]

	// make sure that soaNameserver ends with .
	if soaNameserver[len(soaNameserver)-1] != '.' {
		soaNameserver += "."
	}

	// Create SOA record
	// <primary-ns> <hostmaster-email> <serial> <refresh> <retry> <expire> <minimum>
	refresh := 10800 // 3 hours; Tells secondary/slave servers how often they should check with the master for updates.
	retry := 3600    // 1 hour; If a secondary fails to contact the master, retry after this interval.
	expire := 604800 // 1 week; How long a secondary will continue serving old data if it cannot reach the master.
	minimum := 60    // 1 minute;  Used as the negative caching TTL: how long a resolver caches “no such record” answers (NXDOMAIN).
	soa := fmt.Sprintf("%s. hostmaster.%s. %s %d %d %d %d", soaNameserver, zone, serial, refresh, retry, expire, minimum)

	// Create the zone in PowerDNS
	zoneDef := powerdns.Zone{
		Name:        powerdns.String(zone),
		Kind:        powerdns.ZoneKindPtr(powerdns.NativeZoneKind),
		DNSsec:      powerdns.Bool(false),
		SOAEdit:     powerdns.String(soa),
		SOAEditAPI:  powerdns.String(soa),
		APIRectify:  powerdns.Bool(true),
		Nameservers: nameservers,
	}

	_, err := pdns.Zones.Add(ctx, &zoneDef)
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error creating zone: %v with zone definition: %+v", err, zoneDef)
	}

	// Generate a TSIG key
	algorithm := "hmac-sha512"
	key, err := helper.GenerateTSIGKeyHMACSHA512()
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Failed to generate TSIG key: %v", err)
	}

	// Create the TSIG key in PowerDNS
	tsigkey, err := pdns.TSIGKeys.Create(ctx, keyname, algorithm, key)
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error creating TSIG key: %v", err)
	}

	// Allow the TSIG key to perform AXFR
	_, err = pdns.Metadata.Set(ctx, zone, powerdns.MetadataTSIGAllowAXFR, []string{*tsigkey.Name})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting ALLOW-AXFR-TSIG metadata: %v", err)
	}

	// Allow dynamic updates from any IP, required for TSIG updates
	// From the documentation (https://doc.powerdns.com/authoritative/dnsupdate.html): The semantics are
	// that first a dynamic update has to be allowed either by the global allow-dnsupdate-from setting,
	// or by a per-zone ALLOW-DNSUPDATE-FROM metadata setting.
	// Secondly, if a zone has a TSIG-ALLOW-DNSUPDATE metadata setting, that must match too.
	_, err = pdns.Metadata.Set(ctx, zone, powerdns.MetadataAllowDNSUpdateFrom, []string{"0.0.0.0/0", "::/0"})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting AllowDNSUpdateFrom metadata: %v", err)
	}

	// Allow the TSIG key to perform dynamic updates
	_, err = pdns.Metadata.Set(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate, []string{*tsigkey.Name})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting TSIG dynamic update metadata: %v", err)
	}

	return GetZone(ctx, pdns, zone)
}

func DeleteZone(ctx context.Context, pdns *powerdns.Client, zone string, delete_all_keys bool) error {

	if delete_all_keys {
		// Get the TSIG key name from the zone metadata
		metadata, err := pdns.Metadata.Get(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate)
		if err != nil {
			return fmt.Errorf("powerdns.DeleteZone: Error getting metadata kind 'powerdns.MetadataTSIGAllowDNSUpdate' for zone %s: %v", zone, err)
		}

		// Delete the TSIG key
		for _, keyname := range metadata.Metadata {
			err = pdns.TSIGKeys.Delete(ctx, keyname)
			if err != nil {
				return fmt.Errorf("powerdns.DeleteZone: Error deleting TSIG key: %v", err)
			}
		}
	}

	// Delete the zone
	err := pdns.Zones.Delete(ctx, zone)
	if err != nil {
		return fmt.Errorf("powerdns.DeleteZone: Error deleting zone: %v", err)
	}

	return nil
}
