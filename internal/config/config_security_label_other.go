//go:build !linux && !windows && !darwin

package config

import "os"

// Native security preservation is enforced by secureConfigReplacement.
func secureConfigMAC(*os.File, string, os.FileInfo) error { return nil }
