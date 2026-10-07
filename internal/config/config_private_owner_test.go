package config

import "testing"

func TestPrivateConfigOwnerAndDACLMatches(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1008"
	const dacl = "D:P(A;;FA;;;" + user + ")"
	for _, tc := range []struct {
		name, owner, user, projected string
		control                      uint16
		nonNull, want                bool
	}{
		{"matching owner", user, user, dacl, 0x1004, true, true},
		{"auto inheritance metadata", user, user, dacl, 0x1404, true, true},
		{"Administrators owner", "S-1-5-32-544", user, dacl, 0x1004, true, false},
		{"other user owner", "S-1-5-21-1-2-3-1009", user, dacl, 0x1004, true, false},
		{"missing owner", "", user, dacl, 0x1004, true, false},
		{"missing current user", user, "", dacl, 0x1004, true, false},
		{"both missing", "", "", dacl, 0x1004, true, false},
		{"unprotected", user, user, dacl, 0x0004, true, false},
		{"absent DACL", user, user, dacl, 0x1000, true, false},
		{"null DACL", user, user, dacl, 0x1004, false, false},
		{"empty DACL", user, user, "D:P", 0x1004, true, false},
		{"extra trustee", user, user, dacl + "(A;;FA;;;WD)", 0x1004, true, false},
		{"system trustee", user, user, dacl + "(A;;FA;;;SY)", 0x1004, true, false},
		{"wrong user ACE", user, user, "D:P(A;;FA;;;S-1-5-21-1-2-3-1009)", 0x1004, true, false},
		{"inherited ACE", user, user, "D:P(A;ID;FA;;;" + user + ")", 0x1004, true, false},
		{"inheritable ACE", user, user, "D:P(A;OI;FA;;;" + user + ")", 0x1004, true, false},
		{"partial access", user, user, "D:P(A;;FR;;;" + user + ")", 0x1004, true, false},
		{"deny", user, user, "D:P(D;;FA;;;" + user + ")", 0x1004, true, false},
		{"projection failure", user, user, "", 0x1004, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := privateConfigOwnerAndDACLMatches(tc.control, tc.nonNull, tc.owner, tc.user, tc.projected, dacl); got != tc.want {
				t.Fatalf("private owner and DACL = %t, want %t", got, tc.want)
			}
		})
	}
}
