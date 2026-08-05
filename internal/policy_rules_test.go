package app

import "testing"

// A rule may only hand out names below its own SOA — that is what keeps a
// delegate inside the subtree they were delegated (see validatePatternWithinSoa).
func TestPolicyRuleMustStayWithinItsSoa(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		soa     string
		wantErr bool
	}{
		{"user zone under soa", "%u.users.dhbw.site", "users.dhbw.site", false},
		{"the soa itself", "projects.dhbw.site", "projects.dhbw.site", false},
		{"deep below soa", "%u.team.projects.dhbw.site", "projects.dhbw.site", false},
		{"trailing dots are normalized", "%u.users.dhbw.site.", "users.dhbw.site", false},
		{"foreign subtree", "victim.users.dhbw.site", "projects.dhbw.site", true},
		{"parent of the soa", "dhbw.site", "projects.dhbw.site", true},
		{"suffix look-alike", "%u.evil-users.dhbw.site", "users.dhbw.site", true},
		{"empty soa", "%u.users.dhbw.site", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePatternWithinSoa(tc.pattern, tc.soa)
			if tc.wantErr && err == nil {
				t.Errorf("expected %q under soa %q to be rejected", tc.pattern, tc.soa)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected %q under soa %q to be accepted, got %v", tc.pattern, tc.soa, err)
			}
		})
	}
}
