package config

import "os"

// replacementConfigMode retains existing owner permissions and restricted group
// read, never group write/execute or any other-user access. Named ACL entries on
// staging require a zero mask: enabling group read would also enable those entries.
func replacementConfigMode(original os.FileInfo, namedACL bool) os.FileMode {
	if original == nil {
		return 0600
	}
	allowed := os.FileMode(0640)
	if namedACL {
		allowed = 0600
	}
	return original.Mode().Perm() & allowed
}
