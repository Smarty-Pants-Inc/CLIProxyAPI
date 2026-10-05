//go:build !linux && !darwin

package config

import "os"

func preserveConfigReadAccess(*os.File, os.FileInfo) error { return nil }
