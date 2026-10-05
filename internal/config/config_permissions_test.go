package config

import (
	"os"
	"testing"
	"time"
)

type permissionDecisionInfo struct{ mode os.FileMode }

func (i permissionDecisionInfo) Name() string       { return "config.yaml" }
func (i permissionDecisionInfo) Size() int64        { return 0 }
func (i permissionDecisionInfo) Mode() os.FileMode  { return i.mode }
func (i permissionDecisionInfo) ModTime() time.Time { return time.Time{} }
func (i permissionDecisionInfo) IsDir() bool        { return false }
func (i permissionDecisionInfo) Sys() any           { return nil }

func TestReplacementPermissionDecision(t *testing.T) {
	cases := []struct {
		name     string
		original os.FileInfo
		named    bool
		want     os.FileMode
	}{
		{"new private", nil, false, 0600},
		{"new named ACL private", nil, true, 0600},
		{"restricted group reader", permissionDecisionInfo{0640}, false, 0640},
		{"read only", permissionDecisionInfo{0440}, false, 0440},
		{"owner only", permissionDecisionInfo{0600}, false, 0600},
		{"no permissions", permissionDecisionInfo{0}, false, 0},
		{"strip unsafe grants", permissionDecisionInfo{0777}, false, 0640},
		{"named ACL stays masked", permissionDecisionInfo{0640}, true, 0600},
		{"named ACL read only", permissionDecisionInfo{0440}, true, 0400},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := replacementConfigMode(tc.original, tc.named)
			if got != tc.want {
				t.Fatalf("mode=%04o want %04o", got, tc.want)
			}
			if tc.original != nil && got & ^tc.original.Mode().Perm() != 0 {
				t.Fatal("mode widens original access")
			}
		})
	}
}
