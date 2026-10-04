//go:build windows

package config

import (
	"fmt"
	"os"
)

// Fail closed until durable native Windows publication has hosted validation.
func lockConfigPublication(*os.File) error {
	return fmt.Errorf("atomic config publication is not supported on Windows")
}
func unlockConfigPublication(*os.File) error { return nil }
func syncConfigPublicationDir(string) error {
	return fmt.Errorf("config directory sync is not supported on Windows")
}
