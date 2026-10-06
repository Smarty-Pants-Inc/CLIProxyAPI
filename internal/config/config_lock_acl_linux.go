//go:build linux

package config

import "os"

func restrictConfigLockACL(*os.File) error { return nil }
