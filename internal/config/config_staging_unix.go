//go:build !windows

package config

import "os"

func createConfigStaging(dir string) (*os.File, error) {
	return os.CreateTemp(dir, ".config-*.tmp")
}

func replaceConfigFile(source, target string) error { return os.Rename(source, target) }
