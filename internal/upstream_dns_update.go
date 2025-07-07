package app

import (
	"bytes"
	"fmt"
	"net"
	"text/template"
	"time"

	"github.com/farberg/dynamic-zones/internal/zones"
	"go.uber.org/zap"
)

func RunPeriodicUpstreamDnsUpdateCheck(app AppData) {
	log := app.Log
	log.Infof("Starting periodic upstream DNS updater with interval %d seconds", app.Config.UpstreamDns.UpdateIntervalSeconds)

	//Get the IP address to this DNS server to publish to the upstream DNS server
	c := app.Config.UpstreamDns
	thisDnsAddress := net.ParseIP(app.Config.DnsServerAddress)

	// Check configuration for validity
	if thisDnsAddress == nil {
		log.Warnf("Invalid DNS server address: %s, skipping periodic update", app.Config.DnsServerAddress)
		return
	}

	if c.Server == "" || c.Tsig_Name == "" || c.Tsig_Alg == "" ||
		c.Tsig_Secret == "" || c.Zone == "" || c.Name == "" || c.Ttl <= 0 {
		log.Warn("Invalid upstream DNS configuration. Please check your environment variables. Exiting upstream DNS updater.")
	}

	// Run periodic DNS update checks
	for {
		log.Debug("Performing upstream DNS update check")

		// Lookup the current DNS record for the server
		dnsName := fmt.Sprintf("%s.%s", c.Name, c.Zone)
		ips, err := zones.PerformALookup(c.Server, c.Port, dnsName)
		if err != nil {
			log.Errorf("Failed to perform DNS lookup of %s (on DNS server %s:%d): %v", dnsName, c.Server, c.Port, err)
		}

		if len(ips) >= 0 {
			log.Debugf("Got %d IPs for %s: %v", len(ips), dnsName, ips)
		} else {
			log.Debug("No DNS records found for %s", dnsName)

		}

		// Verify that DNS record matches the expected address
		if len(ips) > 0 && thisDnsAddress.Equal(ips[0]) {
			log.Infof("DNS address '%s' matches expected address. No update needed.", thisDnsAddress)
		} else {
			// If the DNS record does not match, delete the existing record and add the new one
			log.Infof("DNS address does not match expected address (%s). Updating upstream DNS record...", thisDnsAddress)

			if len(ips) > 0 {
				if delete(ips[0], c, log) != nil {
					log.Errorf("Failed to delete existing DNS record for %s: %v", dnsName, err)
				}
			}

			if add(thisDnsAddress, c, log) != nil {
				log.Errorf("Failed to add new DNS record for %s: %v", dnsName, err)
			}
		}

		// Sleep for the configured interval before the next update check
		log.Debugf("Sleep for %d seconds before next update check", app.Config.UpstreamDns.UpdateIntervalSeconds)
		time.Sleep(time.Duration(app.Config.UpstreamDns.UpdateIntervalSeconds) * time.Second)
	}

}

func add(ipAddr net.IP, c UpstreamDnsUpdateConfig, log *zap.SugaredLogger) error {
	remoteDnsServer := fmt.Sprintf("%s:%d", c.Server, c.Port)
	nameToAdd := fmt.Sprintf("%s.%s", c.Name, c.Zone)

	if ipAddr.To4() != nil { //IPv4
		log.Debugf("Adding new A record for '%s' in zone '%s' with address '%s'", nameToAdd, c.Zone, ipAddr)
		log.Debugf("Equivalent nsupdate command: %s",
			toNsUpdateCommand(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, c.Server, c.Port, c.Zone, "update add "+nameToAdd+" "+fmt.Sprintf("%d", c.Ttl)+" IN A "+ipAddr.String()))

		msg, err := zones.Rfc2136AddARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, nameToAdd, ipAddr.String(), uint32(c.Ttl))
		if err != nil {
			log.Errorf("Failed to add A record for %s in zone %s: %v", c.Name, c.Zone, err)
			return err
		}
		log.Debugf("Successfully added A record for %s in zone %s: %v", c.Name, c.Zone, msg)

	} else if ipAddr.To16() != nil { //IPv6
		log.Debugf("Adding new AAAA record for %s in zone %s with address %s", c.Name, c.Zone, ipAddr)
		msg, err := zones.Rfc2136AddAAAARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, nameToAdd, ipAddr.String(), uint32(c.Ttl))
		if err != nil {
			log.Errorf("Failed to add AAAA record for %s in zone %s: %v", c.Name, c.Zone, err)
			return err
		}
		log.Debugf("Successfully added AAAA record for %s in zone %s: %v", c.Name, c.Zone, msg)

	} else {
		return fmt.Errorf("invalid IP address format: %s", ipAddr)
	}

	return nil
}

func delete(ipAddr net.IP, c UpstreamDnsUpdateConfig, log *zap.SugaredLogger) error {
	remoteDnsServer := fmt.Sprintf("%s:%d", c.Server, c.Port)

	if ipAddr.To4() != nil { //IPv4
		log.Debugf("Deleting existing IPv4 A record for %s in zone %s on server %s", c.Name, c.Zone, remoteDnsServer)
		log.Debugf("Equivalent nsupdate command: %s",
			toNsUpdateCommand(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, c.Server, c.Port, c.Zone, "update delete "+c.Name+" "+fmt.Sprintf("%d", c.Ttl)+" IN A "+ipAddr.String()))

		msg, err := zones.Rfc2136DeleteARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, c.Name)
		if err != nil {
			log.Errorf("Failed to delete A record for %s in zone %s: %v", c.Name, c.Zone, err)
			return err
		}
		log.Debugf("Successfully deleted A record for %s in zone %s: %v", c.Name, c.Zone, msg)

	} else if ipAddr.To16() != nil { //IPv6
		log.Debugf("Deleting existing IPv6 A record for %s in zone %s on server", c.Name, c.Zone, remoteDnsServer)
		msg, err := zones.Rfc2136DeleteAAAARecord(c.Tsig_Name, c.Tsig_Alg, c.Tsig_Secret, remoteDnsServer, c.Zone, c.Name)
		if err != nil {
			log.Errorf("Failed to delete AAAA record for %s in zone %s: %v", c.Name, c.Zone, err)
			return err
		}
		log.Debugf("Successfully deleted AAAA record for %s in zone %s: %v", c.Name, c.Zone, msg)
	} else {
		return fmt.Errorf("invalid IP address format: %s", ipAddr)
	}

	return nil
}

func toNsUpdateCommand(tsigName, tsigAlg, tsigSecret, serverAddr string, serverPort int, zoneName, commands string) string {
	tmplString := `nsupdate -d -y "{{.KeydataAlgorithm}}:{{.KeydataKeyname}}:{{.KeydataKey}}" -v <<EOF
server {{.ServerAddress}} {{.ServerPort}}
zone {{.ZoneName}}
{{.Commands}}
send
EOF`

	tmpl, err := template.New("nsupdate").Parse(tmplString)
	if err != nil {
		return "<error parsing template>"
	}
	data := map[string]any{
		"KeydataAlgorithm": tsigAlg,
		"KeydataKeyname":   tsigName,
		"KeydataKey":       tsigSecret,
		"ServerAddress":    serverAddr,
		"ServerPort":       serverPort,
		"ZoneName":         zoneName,
		"Commands":         commands,
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, data)
	if err != nil {
		return fmt.Sprintf("<error executing template: %v>", err)
	}

	return buf.String()
}
