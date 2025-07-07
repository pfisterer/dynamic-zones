package zones

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// PerformALookup queries both A (IPv4) and AAAA (IPv6) records using a custom nameserver.
// It ignores NXDOMAIN errors for individual record types and returns whatever results are available.
func PerformALookup(nameserverAddress string, nameserverPort int, hostname string) ([]net.IP, error) {
	var ips []net.IP
	addr := net.JoinHostPort(nameserverAddress, fmt.Sprintf("%d", nameserverPort))
	client := &dns.Client{Timeout: 5 * time.Second}

	// Helper to query a single record type
	query := func(qtype uint16) {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(hostname), qtype)

		resp, _, err := client.Exchange(m, addr)
		if err != nil {
			fmt.Printf("PerformALookup: DNS query for type %d failed: %v\n", qtype, err)
			return
		}

		if resp.Rcode == dns.RcodeNameError {
			// Ingnore NXDOMAIN errors for individual record types
			return
		}
		if resp.Rcode != dns.RcodeSuccess {
			fmt.Printf("PerformALookup: DNS query for type %d returned Rcode %d\n", qtype, resp.Rcode)
			return
		}

		for _, ans := range resp.Answer {
			switch rr := ans.(type) {
			case *dns.A:
				ips = append(ips, rr.A)
			case *dns.AAAA:
				ips = append(ips, rr.AAAA)
			}
		}
	}

	// Perform both A and AAAA lookups
	query(dns.TypeA)
	query(dns.TypeAAAA)

	return ips, nil
}
