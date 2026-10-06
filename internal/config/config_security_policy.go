package config

import (
	"fmt"
	"os"
	"strings"
)

// verifyOriginalConfigSecurity is also a platform-probe seam: a policy we cannot
// reproduce exactly must refuse before credentials are staged. A failed probe
// is never evidence that the source is unprotected.
func verifyOriginalConfigSecurity(source *os.File, original os.FileInfo, platform string, probe func(*os.File) error) error {
	info, err := source.Stat()
	if err != nil {
		return fmt.Errorf("inspect original config identity: %w", err)
	}
	if !os.SameFile(original, info) {
		return fmt.Errorf("original config identity changed before %s security inspection", platform)
	}
	if err = probe(source); err != nil {
		return fmt.Errorf("publication refused: cannot preserve original %s security exactly: %w", platform, err)
	}
	return nil
}

// SELinux is the only Linux mandatory label supported by the copy-and-verify
// implementation. Refuse any other security namespace attribute (including
// Smack), not just a currently known list of label names.
func refuseUnsupportedConfigAttributes(names []string, supported string) error {
	for _, name := range names {
		if strings.HasPrefix(name, "security.") && name != supported {
			return fmt.Errorf("unsupported config security attribute %s", name)
		}
	}
	return nil
}
