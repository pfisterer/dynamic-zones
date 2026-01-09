package app

import (
	"bytes"
	"fmt"
	"net"
	"text/template"
	"time"

	"github.com/farberg/dynamic-zones/internal/helper"
	"github.com/miekg/dns"
	"go.uber.org/zap"
)

const tmplString string = `nsupdate -d -y "{{.KeydataAlgorithm}}:{{.KeydataKeyname}}:{{.KeydataSecret}}" -v <<EOF
server {{.ServerAddress}} {{.ServerPort}}
zone {{.ZoneName}}
{{.Commands}}
send
EOF`

func RunPeriodicUpstreamDnsUpdateCheck(app AppData) {
	log := app.Log
	log.Infof("Starting periodic upstream DNS updater with interval %d seconds", app.Config.UpstreamDns.UpdateIntervalSeconds)

	// Get the IP address to this DNS server to publish to the upstream DNS server
	c := app.Config.UpstreamDns
	dynamicZonesDnsIPAddress := net.ParseIP(app.Config.PowerDns.DnsServerAddress)

	// Check configuration for validity
	if dynamicZonesDnsIPAddress == nil {
		log.Warnf("Invalid DNS server address: %s, skipping periodic update", app.Config.PowerDns.DnsServerAddress)
		return
	}

	// Check required upstream DNS configuration
	if c.Server == "" || c.Tsig_Name == "" || c.Tsig_Alg == "" ||
		c.Tsig_Secret == "" || c.Zone == "" || c.Name == "" || c.Ttl <= 0 {
		log.Warn("Invalid upstream DNS configuration. Please check your environment variables. Exiting upstream DNS updater.")
		return
	}

	// Run periodic DNS update checks
	for {
		err := PerformSingleUpstreamDnsUpdateCheck(&app.Config.UpstreamDns, dynamicZonesDnsIPAddress, log, false)
		if err != nil {
			log.Errorf("Error during upstream DNS update check: %v", err)
		}

		// Sleep for the configured interval before the next update check
		log.Debugf("Sleep for %d seconds before next update check", app.Config.UpstreamDns.UpdateIntervalSeconds)
		time.Sleep(time.Duration(app.Config.UpstreamDns.UpdateIntervalSeconds) * time.Second)
	}

}

func PerformSingleUpstreamDnsUpdateCheck(c *UpstreamDnsUpdateConfig, dynamicZonesDnsIPAddress net.IP, log *zap.SugaredLogger, forceUpdate bool) error {
	log.Debug("Performing upstream DNS update check")

	// Make sure FQDNs are properly formatted
	c.Tsig_Name = dns.Fqdn(c.Tsig_Name)
	c.Zone = dns.Fqdn(c.Zone)
	dnsNameFQDN := dns.Fqdn(fmt.Sprintf("%s.%s", c.Name, c.Zone))

	log.Debugf("FQDN setup: Zone=%s, TSIG Name=%s, DNS Record=%s", c.Zone, c.Tsig_Name, dnsNameFQDN)

	// Lookup the current DNS record for the server
	ips, err := helper.PerformALookup(c.Server, c.Port, dnsNameFQDN)
	if err != nil {
		return fmt.Errorf("failed to perform DNS lookup of %s (on DNS server %s:%d): %v", dnsNameFQDN, c.Server, c.Port, err)
	}

	// Logging
	if len(ips) > 0 {
		log.Debugf("Got %d IPs for %s: %v", len(ips), dnsNameFQDN, ips)
	} else {
		log.Infof("No DNS records found for %s", dnsNameFQDN)
	}

	// Verify that DNS record matches the expected address
	if len(ips) > 0 && dynamicZonesDnsIPAddress.Equal(ips[0]) && !forceUpdate {
		log.Infof("DNS address '%s' matches expected address. No update needed.", dynamicZonesDnsIPAddress)
	} else {
		// If the DNS record does not match, delete the existing record and add the new one
		log.Infof("DNS address does not match expected address (%s). Updating upstream DNS record...", dynamicZonesDnsIPAddress)

		if len(ips) > 0 {
			err := deleteRecords(c, dnsNameFQDN, log)
			if err != nil {
				return fmt.Errorf("failed to delete existing DNS records for %s: %v", dnsNameFQDN, err)
			}
		}

		if err := addRecord(dynamicZonesDnsIPAddress, c, dnsNameFQDN, log); err != nil {
			return fmt.Errorf("failed to add new DNS record for %s: %v", dnsNameFQDN, err)
		}
	}

	return nil
}

func addRecord(ipAddr net.IP, c *UpstreamDnsUpdateConfig, recordNameFQDN string, log *zap.SugaredLogger) error {
	remoteDnsServer := fmt.Sprintf("%s:%d", c.Server, c.Port)

	if ipAddr.To4() != nil { //IPv4
		log.Debugf("Adding new A record for '%s' in zone '%s' with address '%s'", recordNameFQDN, c.Zone, ipAddr)

		log.Debugf("Equivalent nsupdate command: %s",
			toNsUpdateCommand(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, c.Server, c.Port, c.Zone, "update add "+recordNameFQDN+" "+fmt.Sprintf("%d", c.Ttl)+" IN A "+ipAddr.String()))

		// Pass the FQDN name to the zones library
		msg, err := helper.Rfc2136AddARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, recordNameFQDN, ipAddr.String(), uint32(c.Ttl))
		if err != nil {
			log.Errorf("Failed to add A record for %s in zone %s: %v", recordNameFQDN, c.Zone, err)
			return err
		}
		log.Debugf("Successfully added A record for %s in zone %s: %v", recordNameFQDN, c.Zone, msg)

	} else if ipAddr.To16() != nil { //IPv6
		log.Debugf("Adding new AAAA record for %s in zone %s with address %s", recordNameFQDN, c.Zone, ipAddr)
		// Pass the FQDN name to the zones library
		msg, err := helper.Rfc2136AddAAAARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, recordNameFQDN, ipAddr.String(), uint32(c.Ttl))
		if err != nil {
			log.Errorf("Failed to add AAAA record for %s in zone %s: %v", recordNameFQDN, c.Zone, err)
			return err
		}
		log.Debugf("Successfully added AAAA record for %s in zone %s: %v", recordNameFQDN, c.Zone, msg)

	} else {
		return fmt.Errorf("invalid IP address format: %s", ipAddr)
	}

	return nil
}

func deleteRecords(c *UpstreamDnsUpdateConfig, recordNameFQDN string, log *zap.SugaredLogger) error {
	remoteDnsServer := fmt.Sprintf("%s:%d", c.Server, c.Port)

	log.Debugf("Deleting existing records for %s in zone %s on server %s", recordNameFQDN, c.Zone, remoteDnsServer)

	log.Debugf("Equivalent nsupdate command: %s",
		toNsUpdateCommand(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, c.Server, c.Port, c.Zone, "update delete "+recordNameFQDN))

	// Delete A records
	msgA, err := helper.Rfc2136DeleteARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, recordNameFQDN)
	if err != nil {
		log.Errorf("Failed to delete A record for %s in zone %s: %v", recordNameFQDN, c.Zone, err)
		return err
	}
	log.Debugf("Successfully deleted A records for %s in zone %s: %v", recordNameFQDN, c.Zone, msgA)

	// Delete AAAA records
	msgAAAA, err := helper.Rfc2136DeleteAAAARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, recordNameFQDN)
	if err != nil {
		log.Errorf("Failed to delete AAAA record for %s in zone %s: %v", recordNameFQDN, c.Zone, err)
		return err
	}
	log.Debugf("Successfully deleted AAAA records for %s in zone %s: %v", recordNameFQDN, c.Zone, msgAAAA)

	return nil

}

func toNsUpdateCommand(tsigName, tsigAlg, tsigSecret, serverAddr string, serverPort uint16, zoneName, commands string) string {
	tmpl, err := template.New("nsupdate").Parse(tmplString)
	if err != nil {
		return "<error parsing template>"
	}
	data := map[string]any{
		"KeydataAlgorithm": tsigAlg,
		"KeydataKeyname":   dns.Fqdn(tsigName),
		"KeydataSecret":    tsigSecret,
		"ServerAddress":    serverAddr,
		"ServerPort":       serverPort,
		"ZoneName":         dns.Fqdn(zoneName),
		"Commands":         commands,
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return fmt.Sprintf("<error executing template: %v>", err)
	}

	return buf.String()
}
