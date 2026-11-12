package helper

import (
	"strings"
	"testing"
)

// The DNS limits are inclusive: a label of 63 and a name of 253 characters are valid, one more is refused with the length in the message.
func TestDnsValidateNameLengthLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	// 63+1+63+1+63+1+61 = 253 characters
	name253 := label63 + "." + label63 + "." + label63 + "." + strings.Repeat("b", 61)
	if len(name253) != 253 {
		t.Fatalf("test name has %d characters, want 253", len(name253))
	}

	for _, ok := range []string{label63 + ".example.com", name253, "data-eng-wdski24a.dennis-pfisterer-at-dhbw-de.users.dhbw.site"} {
		if err := DnsValidateName(ok); err != nil {
			t.Errorf("DnsValidateName(%q) = %v, want nil", ok, err)
		}
	}

	if err := DnsValidateName(strings.Repeat("a", 64) + ".example.com"); err == nil || !strings.Contains(err.Error(), "eines hat 64") {
		t.Errorf("a 64-character label: got %v, want an error naming 64", err)
	}
	if err := DnsValidateName(name253 + "b"); err == nil || !strings.Contains(err.Error(), "254 Zeichen") {
		t.Errorf("a 254-character name: got %v, want an error naming 254", err)
	}
}
