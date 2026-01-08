package helper

import (
	"regexp"
	"strings"
)

var dnsLabelCharRegex = regexp.MustCompile("^[A-Za-z0-9-]+$")

func DnsValidateName(value string) bool {
	if value == "" {
		return false
	}

	// 2. Check total length constraints (max 253 octets)
	if len(value) == 0 || len(value) > 253 {
		return false
	}

	// 3. Split into labels (parts)
	parts := strings.Split(value, ".")

	// 4. Must have at least two parts (domain.tld)
	if len(parts) < 2 {
		return false
	}

	// 5. Label Validation Loop
	for _, label := range parts {
		if !DnsIsValidLabel(label) {
			return false
		}
	}

	return true
}

// IsValidLabel validates a single DNS label based on RFC rules.
func DnsIsValidLabel(label string) bool {
	// 1. Check length constraints
	if len(label) < 1 || len(label) > 63 {
		return false
	}

	// 2. Allowed characters: alphanumeric and hyphen (test with regex)
	if !dnsLabelCharRegex.MatchString(label) {
		return false
	}

	// 3. Must start and end with an alphanumeric character
	if !IsAlphaNum(label[0]) || !IsAlphaNum(label[len(label)-1]) {
		return false
	}

	return true
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
