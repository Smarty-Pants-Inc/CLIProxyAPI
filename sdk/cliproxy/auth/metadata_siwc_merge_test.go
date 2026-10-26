package auth

import (
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

func TestAuthSIWCMergeSnapshotsAndLock(t *testing.T) {
	shared := &Auth{Provider: "codex"}
	metadata := map[string]any{"use_siwc": true, "siwc": map[string]any{"access_token": "first", "refresh_token": "refresh", "client_id": "client"}}
	shared.ReplaceMetadata(metadata)
	metadata["siwc"].(map[string]any)["access_token"] = "external"
	patch := codex.NewCredentialRefreshPatch(nil, metadata, false, true)
	shared.CodexRefreshPatch = patch
	clone := shared.Clone()
	clone.Metadata["siwc"].(map[string]any)["access_token"] = "clone"
	if authSIWCTokenField(shared, "access_token") != "first" || clone.CodexRefreshPatch != patch {
		t.Fatal("clone dropped refresh patch or shared a mutable SIWC section")
	}

	var group sync.WaitGroup
	group.Go(func() {
		for range 128 {
			shared.ReplaceMetadata(map[string]any{"use_siwc": true, "siwc": map[string]any{"access_token": "next", "refresh_token": "refresh", "client_id": "client"}})
		}
	})
	group.Go(func() {
		for range 128 {
			_ = IsCodexAuthRecord(shared)
			_ = IsCodexUseSIWC(shared)
			_ = authSIWCTokenField(shared, "access_token")
			_, _ = shared.SIWCExpirationTime()
			_, _, _ = CodexSIWCNeedsRefresh(shared, time.Unix(100, 0))
			_ = shared.Clone()
		}
	})
	group.Wait()
}
