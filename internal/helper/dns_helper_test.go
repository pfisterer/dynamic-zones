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

// %l in a zone pattern expands to the local part of the address, made DNS-compliant by the same rules as %u (DnsMakeCompliant) but without "-at-<domain>".
func TestDnsMakeCompliantLocalPart(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"dennis.pfisterer@dhbw.de", "dennis-pfisterer"},
		{"s252690@student.dhbw-mannheim.de", "s252690"},
		{"Max.Mustermann@DHBW-Stuttgart.de", "max-mustermann"},
		{"max+dns@dhbw.de", "max-dns"},
		{"max_muster@dhbw.de", "max-muster"},
		{"_max__muster_@dhbw.de", "max-muster"},
		{"a.-b@dhbw.de", "a-b"},
		{"fakestudent", "fakestudent"}, // no '@': the whole identity
		{"\"a@b\"@dhbw.de", "a-at-b"},  // quoted local part: the domain is after the last '@'
		{"+@dhbw.de", ""},
	} {
		if got := DnsMakeCompliantLocalPart(tc.in); got != tc.want {
			t.Errorf("DnsMakeCompliantLocalPart(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// %u is unchanged: the whole address.
	if got := DnsMakeCompliant("Dennis.Pfisterer@dhbw.de"); got != "dennis-pfisterer-at-dhbw-de" {
		t.Errorf("DnsMakeCompliant = %q", got)
	}
}
