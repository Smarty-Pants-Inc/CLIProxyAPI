package config

import "testing"

// Auth files and directories use the same current-user-only policy as config
// publication. Keep this policy regression runnable on non-Windows hosts too.
func TestPrivateAuthOwnerAndDACLMatches(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1008"
	const exact = "D:P(A;;FA;;;" + user + ")"
	for _, tc := range []struct {
		name, owner, dacl string
		control           uint16
		want              bool
	}{
		{"current user only", user, exact, 0x1004, true},
		{"SYSTEM grant", user, exact + "(A;;FA;;;SY)", 0x1004, false},
		{"Everyone grant", user, exact + "(A;;FA;;;WD)", 0x1004, false},
		{"foreign owner", "S-1-5-21-1-2-3-1009", exact, 0x1004, false},
		{"unprotected", user, exact, 0x0004, false},
		{"inherited user grant", user, "D:P(A;ID;FA;;;" + user + ")", 0x1004, false},
		{"inherited Everyone grant", user, exact + "(A;ID;FA;;;WD)", 0x1004, false},
		{"inheritable user grant", user, "D:P(A;OICI;FA;;;" + user + ")", 0x1004, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := privateConfigOwnerAndDACLMatches(tc.control, true, tc.owner, user, tc.dacl, exact); got != tc.want {
				t.Fatalf("auth private owner/DACL policy = %t, want %t", got, tc.want)
			}
		})
	}
}
