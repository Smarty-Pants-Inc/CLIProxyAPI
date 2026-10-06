//go:build linux

package config

import (
	"errors"
	"testing"
)

// The same core is bound to Darwin by config_lock_identity_unix.go. Linux can
// inject privileged/user ownership without changing host identities or unlinking.
func TestRound4InjectedDarwinLockWriterOrders(t *testing.T) {
	for _, privilegedFirst := range []bool{true, false} {
		const ownerUID, ownerGID uint32 = 1001, 1002
		uid, gid := ownerUID, ownerGID
		if privilegedFirst {
			uid, gid = 0, 0
		}
		repairs := 0
		if err := preserveConfigLockOwner(ownerUID, ownerGID, uid, gid, func(newUID, newGID int) error { repairs++; uid, gid = uint32(newUID), uint32(newGID); return nil }); err != nil {
			t.Fatal(err)
		}
		if uid != ownerUID || gid != ownerGID {
			t.Fatal("first writer retained privileged lock ownership")
		}
		if err := preserveConfigLockOwner(ownerUID, ownerGID, uid, gid, func(int, int) error { t.Fatal("second writer recreated/reassigned lock"); return nil }); err != nil {
			t.Fatal(err)
		}
		if privilegedFirst && repairs != 1 || !privilegedFirst && repairs != 0 {
			t.Fatal("unexpected repair count")
		}
	}
	if err := preserveConfigLockOwner(1001, 1002, 0, 0, func(int, int) error { return errors.New("injected chown refusal") }); err == nil {
		t.Fatal("unrepairable lock accepted")
	}
}
