//go:build !linux && !windows

package config

import (
	"fmt"
	"os"
)

func secureConfigReplacement(file *os.File, original os.FileInfo) error {
	return fmt.Errorf("secure config publication requires native platform ACL preservation; publication refused")
}
