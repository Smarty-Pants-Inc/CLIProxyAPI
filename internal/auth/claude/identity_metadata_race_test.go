package claude

import (
	"sync"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestClaudeHelpersShareAuthMetadataLock(t *testing.T) {
	shared := &coreauth.Auth{}
	const workers, iterations = 8, 128
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Go(func() {
		<-start
		for range iterations {
			shared.SetMetadata("other-provider-state", true)
			StoreMetadataString(shared, "email", "reader@example.com")
			StoreMetadataValue(shared, "skip_account_profile", true)
			if _, _, errEnsure := EnsureDeviceIDPoolFor(shared); errEnsure != nil {
				t.Errorf("ensure pool: %v", errEnsure)
			}
		}
	})
	for range workers {
		group.Go(func() {
			<-start
			for range iterations {
				_ = ReadMetadataString(shared, "email")
				_ = ReadMetadataBool(shared, "skip_account_profile")
				_ = ReadDeviceIDPool(shared)
				_ = shared.CloneMetadata()
			}
		})
	}
	close(start)
	group.Wait()
	if !HasCanonicalDeviceIDPool(ReadDeviceIDPool(shared)) {
		t.Fatal("concurrent helpers did not establish a canonical device pool")
	}
}
