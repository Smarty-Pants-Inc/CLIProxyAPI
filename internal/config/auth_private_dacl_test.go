package config

import "testing"

// Auth directories inherit owner access; files remain explicit and
// non-inheritable. Keep the exact policy regression runnable on Linux too.
func TestPrivateAuthOwnerAndDACLMatches(t *testing.T) {
	const user = "S-1-5-21-1-2-3-1008"
	for _, directory := range []bool{false, true} {
		name, flags := "file", ""
		if directory {
			name, flags = "directory", "OICI"
		}
		t.Run(name, func(t *testing.T) {
			exact := "D:P(A;" + flags + ";FA;;;" + user + ")"
			if got := privateConfigDACLTemplate(user, directory); got != exact {
				t.Fatalf("DACL template = %s, want %s", got, exact)
			}
			for _, tc := range []struct {
				name, owner, dacl string
				control           uint16
				nonNull, want     bool
			}{
				{"current user only", user, exact, 0x1004, true, true},
				{"auto inherited metadata", user, exact, 0x1404, true, true},
				{"SYSTEM grant", user, exact + "(A;;FA;;;SY)", 0x1004, true, false},
				{"Everyone grant", user, exact + "(A;;FA;;;WD)", 0x1004, true, false},
				{"extra owner ACE", user, exact + "(A;;FR;;;" + user + ")", 0x1004, true, false},
				{"foreign owner", "S-1-5-21-1-2-3-1009", exact, 0x1004, true, false},
				{"wrong trustee", user, "D:P(A;" + flags + ";FA;;;S-1-5-21-1-2-3-1009)", 0x1004, true, false},
				{"unprotected", user, exact, 0x0004, true, false},
				{"absent", user, exact, 0x1000, true, false},
				{"null", user, exact, 0x1004, false, false},
				{"empty", user, "D:P", 0x1004, true, false},
				{"inherited user grant", user, "D:P(A;" + flags + "ID;FA;;;" + user + ")", 0x1004, true, false},
				{"inherited Everyone grant", user, exact + "(A;ID;FA;;;WD)", 0x1004, true, false},
				{"only object inheritance", user, "D:P(A;OI;FA;;;" + user + ")", 0x1004, true, false},
				{"only container inheritance", user, "D:P(A;CI;FA;;;" + user + ")", 0x1004, true, false},
				{"inherit only", user, "D:P(A;" + flags + "IO;FA;;;" + user + ")", 0x1004, true, false},
				{"no propagate", user, "D:P(A;" + flags + "NP;FA;;;" + user + ")", 0x1004, true, false},
				{"partial access", user, "D:P(A;" + flags + ";FR;;;" + user + ")", 0x1004, true, false},
				{"deny", user, "D:P(D;" + flags + ";FA;;;" + user + ")", 0x1004, true, false},
				{"wrong entry type", user, privateConfigDACLTemplate(user, !directory), 0x1004, true, false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					if got := privateConfigOwnerAndDACLMatches(tc.control, tc.nonNull, tc.owner, user, tc.dacl, exact); got != tc.want {
						t.Fatalf("auth private owner/DACL policy = %t, want %t", got, tc.want)
					}
				})
			}
		})
	}
}
