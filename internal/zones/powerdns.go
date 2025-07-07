package zones

import (
	"context"
	"fmt"

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

func CreateZone(ctx context.Context, pdns *powerdns.Client, user string, zone string, force bool) (*ZoneDataResponse, error) {
	keyname := "user-" + user + "-zone-" + zone + "-key"

	//Delete a potentially existing zone and key
	if force {
		_ = pdns.Zones.Delete(ctx, zone)
		_ = pdns.TSIGKeys.Delete(ctx, keyname)
	}

	// Create the zone in PowerDNS
	_, err := pdns.Zones.Add(ctx, &powerdns.Zone{
		Name:        powerdns.String(zone),
		Kind:        powerdns.ZoneKindPtr(powerdns.NativeZoneKind),
		DNSsec:      powerdns.Bool(false),
		SOAEdit:     powerdns.String(""),
		SOAEditAPI:  powerdns.String(""),
		APIRectify:  powerdns.Bool(true),
		Nameservers: []string{"localhost."}, // TODO...
	})
	fmt.Println("powerdns.CreateZone: XXXXXXXXXXXXXXXX TODO: Use some sensible nameservers for the zone")
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error creating zone: %v", err)
	}

	// Generate a random TSIG key
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

	// Set the TSIG key in the zone metadata
	_, err = pdns.Metadata.Set(ctx, zone, powerdns.MetadataTSIGAllowDNSUpdate, []string{*tsigkey.Name})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting metadata: %v", err)
	}

	// Allow DNS updates from everywhere now that the key is set
	_, err = pdns.Metadata.Set(ctx, zone, powerdns.MetadataAllowDNSUpdateFrom, []string{"0.0.0.0/0", "::/0"})
	if err != nil {
		return nil, fmt.Errorf("powerdns.CreateZone: Error setting metadata: %v", err)
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
