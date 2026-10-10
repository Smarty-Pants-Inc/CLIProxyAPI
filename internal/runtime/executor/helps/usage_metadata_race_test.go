package helps

import (
	"fmt"
	"sync"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func exerciseSharedUsageMetadata(t *testing.T, shared *cliproxyauth.Auth, want string) {
	t.Helper()
	const readers, iterations = 8, 256
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Go(func() {
		<-start
		for i := range iterations {
			cliproxyauth.MergeExistingAuthMetadata(shared, map[string]any{fmt.Sprintf("profile_%d", i): "value"})
		}
	})
	for range readers {
		group.Go(func() {
			<-start
			for range iterations {
				if got := resolveUsageSource(shared, "fallback"); got != want {
					t.Errorf("usage source = %q, want %q", got, want)
					return
				}
			}
		})
	}
	close(start)
	group.Wait()
}

func TestSharedAuthMetadataUsageEmail(t *testing.T) {
	// Explicit immutable classification avoids testing only AuthKind's map reads:
	// AccountInfo cannot supply an API key, so the usage email fallback is reached.
	shared := &cliproxyauth.Auth{
		Attributes: map[string]string{cliproxyauth.AttributeAuthKind: cliproxyauth.AuthKindAPIKey},
		Metadata:   map[string]any{"email": " reader@example.com "},
	}
	exerciseSharedUsageMetadata(t, shared, "reader@example.com")
}

func TestSharedAuthMetadataUsageProject(t *testing.T) {
	for _, key := range []string{"project_id", "project"} {
		t.Run(key, func(t *testing.T) {
			shared := &cliproxyauth.Auth{Provider: "vertex", Metadata: map[string]any{key: " project "}}
			exerciseSharedUsageMetadata(t, shared, "project")
		})
	}
}
