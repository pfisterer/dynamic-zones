package helper

import (
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// sendDNSUpdate is a helper function to handle the common DNS client setup,
// TSIG signing, and message exchange for RFC 2136 updates.
func sendDNSUpdate(tsigName, tsigAlg, tsigSecret, serverAddr string, m *dns.Msg) (*dns.Msg, error) {
	// Create a DNS client
	client := new(dns.Client)
	client.TsigSecret = map[string]string{dns.Fqdn(tsigName): tsigSecret}

	// Set the TSIG for the message
	m.SetTsig(dns.Fqdn(tsigName), dns.Fqdn(tsigAlg), 300, time.Now().Unix())

	// Send the signed update message
	msg, _, err := client.Exchange(m, serverAddr)
	if err != nil {
		return msg, fmt.Errorf("sendDNSUpdate: failed to send update: %v", err)
	}

	if msg.Rcode != dns.RcodeSuccess {
		return msg, fmt.Errorf("sendDNSUpdate: received error response: %s", dns.RcodeToString[msg.Rcode])
	}

	return msg, nil
}

// Rfc2136AddARecord adds an A record to a DNS zone using RFC 2136 dynamic updates.
// tsigName: The FQDN of the TSIG key.
// tsigAlg: The TSIG algorithm (e.g., "hmac-md5.sig-alg.reg.int.").
// tsigSecret: The base64 encoded TSIG secret.
// serverAddr: The address of the DNS server (e.g., "192.0.2.1:53").
// zoneName: The FQDN of the zone to update (e.g., "example.com.").
// recordName: The FQDN of the record to add (e.g., "host.example.com.").
// recordType: The DNS record type (e.g., dns.TypeA).
// recordValue: The IP address for the A record (e.g., "192.0.2.10").
// ttl: The TTL for the record in seconds.
func Rfc2136AddARecord(tsigName, tsigAlg, tsigSecret, serverAddr, zoneName, recordName string, recordValue string, ttl uint32) (*dns.Msg, error) {
	// Create a new DNS UPDATE message.
	m := new(dns.Msg)
	m.SetUpdate(zoneName)

	// Add an A record to be added.
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(recordName), // Ensure FQDN
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		A: net.ParseIP(recordValue),
	}
	m.Insert([]dns.RR{rr})

	return sendDNSUpdate(tsigName, tsigAlg, tsigSecret, serverAddr, m)
}

// Rfc2136DeleteARecord deletes an A record from a DNS zone using RFC 2136 dynamic updates.
// It removes all A records for the given recordName.
// tsigName, tsigAlg, tsigSecret, serverAddr, zoneName: Same as Rfc2136AddARecord.
// recordName: The FQDN of the record to delete (e.g., "host.example.com.").
func Rfc2136DeleteARecord(tsigName, tsigAlg, tsigSecret, serverAddr, zoneName, recordName string) (*dns.Msg, error) {
	// Create a new DNS UPDATE message.
	m := new(dns.Msg)
	m.SetUpdate(zoneName)

	// Remove all A records for the specified name.
	// To delete all records of a specific type for a name, use the ANY class (dns.ClassANY)
	// and a TTL of 0.
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(recordName),
			Rrtype: dns.TypeANY, // TypeANY indicates "delete all records of this type"
			Class:  dns.ClassINET,
			Ttl:    0, // TTL 0 is for deletion
		},
	}
	m.RemoveRRset([]dns.RR{rr})

	return sendDNSUpdate(tsigName, tsigAlg, tsigSecret, serverAddr, m)
}

// Rfc2136AddAAAARecord adds an AAAA record to a DNS zone using RFC 2136 dynamic updates.
// tsigName, tsigAlg, tsigSecret, serverAddr, zoneName: Same as Rfc2136AddARecord.
// recordName: The FQDN of the record to add (e.g., "host.example.com.").
// recordValue: The IPv6 address for the AAAA record (e.g., "2001:db8::1").
// ttl: The TTL for the record in seconds.
func Rfc2136AddAAAARecord(tsigName, tsigAlg, tsigSecret, serverAddr, zoneName, recordName string, recordValue string, ttl uint32) (*dns.Msg, error) {
	// Create a new DNS UPDATE message.
	m := new(dns.Msg)
	m.SetUpdate(zoneName)

	// Add an AAAA record to be added.
	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(recordName), // Ensure FQDN
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    ttl,
		},
		AAAA: net.ParseIP(recordValue),
	}
	m.Insert([]dns.RR{rr})

	return sendDNSUpdate(tsigName, tsigAlg, tsigSecret, serverAddr, m)
}

// Rfc2136DeleteAAAARecord deletes an AAAA record from a DNS zone using RFC 2136 dynamic updates.
// It removes all AAAA records for the given recordName.
// tsigName, tsigAlg, tsigSecret, serverAddr, zoneName: Same as Rfc2136AddARecord.
// recordName: The FQDN of the record to delete (e.g., "host.example.com.").
func Rfc2136DeleteAAAARecord(tsigName, tsigAlg, tsigSecret, serverAddr, zoneName, recordName string) (*dns.Msg, error) {
	// Create a new DNS UPDATE message.
	m := new(dns.Msg)
	m.SetUpdate(zoneName)

	// Remove all AAAA records for the specified name.
	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(recordName),
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassANY, // ClassANY indicates "delete all records of this type"
			Ttl:    0,            // TTL 0 is for deletion
		},
	}
	m.RemoveRRset([]dns.RR{rr})

	return sendDNSUpdate(tsigName, tsigAlg, tsigSecret, serverAddr, m)
}
