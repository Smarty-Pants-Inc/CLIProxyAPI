//go:build !windows

package config

import (
	"os"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

func openConfigPublicationLock(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
}

func createConfigPublicationStage(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".config-*.tmp")
}

func replaceConfigPublication(source, destination string) error {
	return os.Rename(source, destination)
}

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
