//go:build !windows

package config

// CheckAuthFilesOwnerOnly is a no-op on platforms without Windows DACLs.
func CheckAuthFilesOwnerOnly(string, bool) error { return nil }
