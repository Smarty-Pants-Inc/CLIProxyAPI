//go:build !windows

package config

import (
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func lockConfigPublication(file *os.File) error   { return unix.Flock(int(file.Fd()), unix.LOCK_EX) }
func unlockConfigPublication(file *os.File) error { return unix.Flock(int(file.Fd()), unix.LOCK_UN) }
func syncConfigPublicationDir(dir string) error {
	file, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			log.WithError(errClose).Error("close config directory")
		}
	}()
	return file.Sync()
}
