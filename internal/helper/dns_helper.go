package helper

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/pfisterer/cloud-self-service-golib/msg"
)

var dnsLabelCharRegex = regexp.MustCompile("^[A-Za-z0-9-]+$")

// DNS limits (RFC 1035): a label has at most 63 characters, a name in text form without the trailing root dot at most 253.
const (
	DnsMaxLabelLength = 63
	DnsMaxNameLength  = 253
)

func DnsValidateName(value string) error {
	if value == "" {
		return invalid("Der Name ist leer.", "The name is empty.")
	}

	if len(value) > DnsMaxNameLength {
		return invalid("Der Name hat %d Zeichen, erlaubt sind höchstens %d.", "The name has %d characters, at most %d are allowed.", len(value), DnsMaxNameLength)
	}

	parts := strings.Split(value, ".")
	if len(parts) < 2 {
		return invalid("Der Name braucht mindestens zwei Teile (domain.tld).", "The name needs at least two parts (domain.tld).")
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
	if length < 1 || length > DnsMaxLabelLength {
		return invalid("Jedes Label muss 1 bis %d Zeichen lang sein, eines hat %d.", "Every label must be 1 to %d characters long, one has %d.", DnsMaxLabelLength, length)
	}

	// 2. Allowed characters: alphanumeric and hyphen (test with regex)
	if !dnsLabelCharRegex.MatchString(label) {
		return invalid("Labels dürfen nur Buchstaben, Ziffern und '-' enthalten.", "Labels may only contain letters, digits and '-'.")
	}

	// 3. Must start and end with an alphanumeric character
	if !IsAlphaNum(label[0]) || !IsAlphaNum(label[len(label)-1]) {
		return invalid("Labels müssen mit einem Buchstaben oder einer Ziffer beginnen und enden.", "Labels must begin and end with a letter or a digit.")
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

// invalid is a validation message for people in German and English (msg.Errorf).
func invalid(de, en string, args ...any) error {
	return msg.Errorf(de, en, args...)
}
