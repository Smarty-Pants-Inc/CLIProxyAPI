//go:build windows

package config

import (
	"fmt"
	"os"
)

func secureConfigReplacement(file *os.File, original os.FileInfo) error {
	// Numeric modes cannot establish or preserve a Windows DACL. Fail closed
	// until native security-descriptor preservation is supported.
	return fmt.Errorf("secure config publication requires native Windows DACL support; publication refused")
}
