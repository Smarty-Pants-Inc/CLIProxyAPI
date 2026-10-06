package config

import "testing"

func TestPrivateConfigDACLMatches(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1008"
	const expected = "D:P(A;;FA;;;" + user + ")"
	for _, tc := range []struct {
		name      string
		control   uint16
		nonNull   bool
		projected string
		expected  string
		want      bool
	}{
		{"private", 0x1004, true, expected, expected, true},
		{"auto inherited metadata", 0x1404, true, expected, expected, true},
		{"self relative metadata", 0x9404, true, expected, expected, true},
		{"unprotected", 0x0004, true, expected, expected, false},
		{"absent", 0x1000, true, expected, expected, false},
		{"null", 0x1004, false, expected, expected, false},
		{"empty", 0x1004, true, "D:P", expected, false},
		{"other user", 0x1004, true, "D:P(A;;FA;;;S-1-5-21-1-2-3-1009)", expected, false},
		{"extra trustee", 0x1004, true, expected + "(A;;FA;;;WD)", expected, false},
		{"system grant", 0x1004, true, expected + "(A;;FA;;;SY)", expected, false},
		{"inherited ACE", 0x1004, true, "D:P(A;ID;FA;;;" + user + ")", expected, false},
		{"inheritable ACE", 0x1004, true, "D:P(A;OI;FA;;;" + user + ")", expected, false},
		{"partial access", 0x1004, true, "D:P(A;;FR;;;" + user + ")", expected, false},
		{"deny ACE", 0x1004, true, "D:P(D;;FA;;;" + user + ")", expected, false},
		{"serialization failure", 0x1004, true, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := privateConfigDACLMatches(tc.control, tc.nonNull, tc.projected, tc.expected); got != tc.want {
				t.Fatalf("private DACL match = %t, want %t", got, tc.want)
			}
		})
	}
}
