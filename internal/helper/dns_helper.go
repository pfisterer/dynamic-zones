package helper

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
)

var dnsLabelCharRegex = regexp.MustCompile("^[A-Za-z0-9-]+$")

func DnsValidateName(value string) error {
	if value == "" {
		return errors.New("Value is empty")
	}

	if len(value) == 0 || len(value) > 253 {
		return errors.New("Total length must be between 1 and 253 characters")
	}

	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return errors.New("Must have at least two parts (domain.tld)")
	}

	// 5. Label Validation Loop
	for _, label := range parts {
		err := DnsIsValidLabel(label)
		if err != nil {
			return err
		}
	}

	return nil
}

// IsValidLabel validates a single DNS label based on RFC rules.
func DnsIsValidLabel(label string) error {
	// 1. Check length constraints
	length := len(label)
	if length < 1 || length > 63 {
		return fmt.Errorf("Length (%d) must be >= 1 and <= 63", length)
	}

	// 2. Allowed characters: alphanumeric and hyphen (test with regex)
	if !dnsLabelCharRegex.MatchString(label) {
		return fmt.Errorf("Labels must conform to %v+", dnsLabelCharRegex)
	}

	// 3. Must start and end with an alphanumeric character
	if !IsAlphaNum(label[0]) || !IsAlphaNum(label[len(label)-1]) {
		return errors.New("Labels must start and end with an alphanumeric character")
	}

	return nil
}

func IsAlphaNum(b byte) bool {
	return (b >= '0' && b <= '9') ||
		(b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z')
}

func DnsMakeCompliant(input string) string {
	//Replace "@" with "-at-"
	dnsName := strings.ReplaceAll(input, "@", "-at-")

	//Replace invalid characters with "-"
	// This regex matches any character that is NOT a letter, a digit, or a hyphen.
	// It will replace characters like '.', '_', '!', ' ', etc., with a hyphen.
	regInvalidChars := regexp.MustCompile("[^a-zA-Z0-9-]+")
	dnsName = regInvalidChars.ReplaceAllString(dnsName, "-")

	// Collapse multiple consecutive hyphens into a single hyphen
	// This cleans up cases where multiple invalid characters were next to each other,
	// or where an invalid character was next to an existing hyphen.
	regConsecutiveHyphens := regexp.MustCompile("-{2,}")
	dnsName = regConsecutiveHyphens.ReplaceAllString(dnsName, "-")

	// Remove invalid prefix and suffix (leading/trailing hyphens)
	dnsName = strings.TrimPrefix(dnsName, "-")
	dnsName = strings.TrimSuffix(dnsName, "-")

	// Convert the entire string to lowercase
	dnsName = strings.ToLower(dnsName)

	return dnsName
}

// PerformALookup queries both A (IPv4) and AAAA (IPv6) records using a custom nameserver.
// It ignores NXDOMAIN errors for individual record types and returns whatever results are available.
func PerformALookup(nameserverAddress string, nameserverPort uint16, hostname string) ([]net.IP, error) {
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
