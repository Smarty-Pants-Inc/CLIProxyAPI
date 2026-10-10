package auth

import (
	"fmt"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// This driver uses only APIs present before the metadata-lock fix, so the exact
// regressions can also be run on its parent commit. The real merge writer adds
// profile keys while N readers use ONE credential, just like profile discovery.
func exerciseSharedMetadata(t *testing.T, shared *Auth, read func() bool) {
	t.Helper()
	const readers, iterations = 8, 256
	start := make(chan struct{})
	var group sync.WaitGroup
	group.Go(func() {
		<-start
		for i := range iterations {
			MergeExistingAuthMetadata(shared, map[string]any{fmt.Sprintf("profile_%d", i): "value"})
		}
	})
	for range readers {
		group.Go(func() {
			<-start
			for range iterations {
				if !read() {
					t.Error("shared metadata reader returned an unexpected value")
					return
				}
			}
		})
	}
	close(start)
	group.Wait()
}

func TestSharedAuthMetadataSelectorWeight(t *testing.T) {
	shared := &Auth{Metadata: map[string]any{AttributeWeight: 7}}
	exerciseSharedMetadata(t, shared, func() bool { return authWeight(shared) == 7 })
}

func TestSharedAuthMetadataSelectorWebsockets(t *testing.T) {
	shared := &Auth{Metadata: map[string]any{"websockets": true}}
	exerciseSharedMetadata(t, shared, func() bool { return authWebsocketsEnabled(shared) })
}

func TestSharedAuthMetadataClassificationString(t *testing.T) {
	shared := &Auth{Metadata: map[string]any{AttributeAuthKind: AuthKindOAuth}}
	exerciseSharedMetadata(t, shared, func() bool { return shared.AuthKind() == AuthKindOAuth })
}

func TestSharedAuthMetadataClassificationToken(t *testing.T) {
	shared := &Auth{Metadata: map[string]any{"token": map[string]any{"access_token": "token"}}}
	exerciseSharedMetadata(t, shared, func() bool { return shared.AuthKind() == AuthKindOAuth })
}

func TestSharedAuthMetadataConductorRules(t *testing.T) {
	for _, key := range []string{"request_scoped_errors", "request-scoped-errors"} {
		t.Run(key, func(t *testing.T) {
			shared := &Auth{Metadata: map[string]any{key: []internalconfig.RequestScopedErrorRule{{Status: 429, Action: RequestScopedActionContinue}}}}
			exerciseSharedMetadata(t, shared, func() bool {
				rules := extractRequestScopedErrorRules(shared, nil)
				return len(rules) == 1 && rules[0].Status == 429
			})
		})
	}
}

func TestSharedAuthMetadataTypesClone(t *testing.T) {
	shared := &Auth{ID: "shared", Metadata: map[string]any{"email": "reader@example.com"}}
	exerciseSharedMetadata(t, shared, func() bool {
		cloned := shared.Clone()
		return cloned.ID == "shared" && cloned.Metadata["email"] == "reader@example.com"
	})
}
