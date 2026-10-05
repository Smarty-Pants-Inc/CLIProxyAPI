//go:build linux

package config

import (
	"errors"
	"testing"
)

func TestSELinuxLabelPreservedBeforePublication(t *testing.T) {
	label := []byte("confined_config_t\x00")
	stage := []byte("default_config_t\x00")
	reads := 0
	err := preserveSELinuxLabel(func() ([]byte, error) { return label, nil }, func() ([]byte, error) { reads++; return stage, nil }, func(b []byte) error { stage = append([]byte(nil), b...); return nil })
	if err != nil || string(stage) != string(label) || reads != 2 {
		t.Fatalf("label not copied and verified: %q reads=%d err=%v", stage, reads, err)
	}
}

func TestSELinuxLabelRefusesUnverifiableProtection(t *testing.T) {
	for _, name := range []string{"read", "write", "verify", "unlabeled"} {
		t.Run(name, func(t *testing.T) {
			original := []byte("confined_config_t\x00")
			if name == "unlabeled" {
				original = nil
			}
			err := preserveSELinuxLabel(func() ([]byte, error) {
				if name == "read" {
					return nil, errors.New("denied")
				}
				return original, nil
			}, func() ([]byte, error) { return []byte("default_config_t\x00"), nil }, func([]byte) error {
				if name == "write" {
					return errors.New("denied")
				}
				return nil
			})
			if err == nil {
				t.Fatal("unverified MAC boundary accepted")
			}
		})
	}
}
