package redisqueue

import (
	"context"
	"testing"

	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

func TestUsageQueuePreservesRestrictedDigestWithAccessMetadata(t *testing.T) {
	withEnabledQueue(t, func() {
		ctx := coreusage.WithAccessProvider(context.Background(), "config-inline")
		(&usageQueuePlugin{}).HandleUsage(ctx, coreusage.Record{
			Provider:     "codex",
			Model:        "sync-model",
			APIKey:       "[REDACTED]",
			APIKeySHA256: coreusage.APIKeyDigest("sync-client-key"),
		})
		payload := popSinglePayload(t)
		requireStringField(t, payload, "api_key", "[REDACTED]")
		requireStringField(t, payload, "api_key_hash", coreusage.APIKeyDigest("sync-client-key"))
		requireStringField(t, payload, "access_provider", "config-inline")
		requireBoolField(t, payload, "is_native_key", true)
	})
}
