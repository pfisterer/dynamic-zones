package app

import (
	"context"

	"go.uber.org/zap"
)

type MissingOrInvalidZoneInPdns struct {
	Zone              Zone
	invalidInPowerDNS bool
}

func Reconcile(ctx context.Context, db *Storage, powerdns *PowerDnsClient, nameservers []string, defaultTTL uint32, log *zap.SugaredLogger) error {
	// Handle invalid and missing zones in PowerDNS
	{
		// Create channels for missing and invalid zones
		ch := make(chan MissingOrInvalidZoneInPdns, 100)

		// Start goroutines to check for missing and invalid zones
		go MissingOrInvalidZonesInPdns(ctx, db, powerdns, ch, log)

		// Collect results from channels
		for {
			select {
			case todo := <-ch:
				log.Debugf("Reconcile: Handling invalid (= %v) or missing zone '%s' in PowerDNS", todo.Zone.Zone, todo.invalidInPowerDNS)

				// Delete zone (and keys) before re-creating it because it is invalid
				if todo.invalidInPowerDNS {
					err := powerdns.DeleteZone(ctx, todo.Zone.Zone, true)
					if err != nil {
						log.Warnf("Reconcile: Failed to delete invalid zone '%s' in PowerDNS: %v", todo.Zone, err)
						continue
					}
					log.Debugf("Reconcile: Deleted invalid zone '%s' in PowerDNS", todo.Zone)
				}

				// Create Zone in PowerDNS as it is missing or invalid and has been deleted above
				_, err := powerdns.CreateUserZone(ctx, todo.Zone.Username, todo.Zone.Zone, true)
				if err != nil {
					log.Warnf("Reconcile: Failed to re-create zone '%s' invalid in PowerDNS: %v", todo.Zone, err)
					continue
				}
				log.Debugf("Reconcile: Re-created zone '%s' that was invalid in PowerDNS", todo.Zone)

			default:
				return nil
			}
		}

	}

}

func MissingOrInvalidZonesInPdns(ctx context.Context, db *Storage, powerdns *PowerDnsClient, out chan<- MissingOrInvalidZoneInPdns, log *zap.SugaredLogger) {
	// Create a channel to receive zones from the database
	ch := make(chan Zone, 100)

	// Close channels when done
	defer close(out)

	// Start a goroutine to fetch zones from the database
	go func() {
		if err := db.GetAllZones(ctx, ch); err != nil {
			log.Errorf("Failed to fetch zones from database: %v", err)
		}
	}()

	// Process zones from the channel
	for zone := range ch {
		// Check if the zone exists in PowerDNS
		pdnsZone, err := powerdns.GetZone(ctx, zone.Zone)
		if err != nil {
			out <- MissingOrInvalidZoneInPdns{Zone: zone, invalidInPowerDNS: false}
			continue
		}

		// Check if the zone is invalid in PowerDNS
		if len(pdnsZone.ZoneKeys) == 0 {
			out <- MissingOrInvalidZoneInPdns{Zone: zone, invalidInPowerDNS: true}
			continue
		}

		for _, key := range pdnsZone.ZoneKeys {
			if key.Keyname == "" || key.Algorithm == "" || key.Key == "" {
				out <- MissingOrInvalidZoneInPdns{Zone: zone, invalidInPowerDNS: true}
				break
			}
		}
	}

}
