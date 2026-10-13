package helps

import (
	"context"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

func TestUsageReporterTypedAuthContextPreservesPolicyDigest(t *testing.T) {
	ctx := usage.WithAPIKey(context.Background(), "sync-client-key")
	ctx = usage.WithAccessProvider(ctx, "config-inline")
	ctx = cliproxyauth.WithKeyPolicy(ctx, &cliproxyauth.KeyPolicyOperation{})
	reporter := NewUsageReporter(ctx, "codex", "sync-model", nil)
	record := reporter.buildRecord(usage.Detail{TotalTokens: 1}, false)
	if record.APIKey != "[REDACTED]" || record.APIKeySHA256 != usage.APIKeyDigest("sync-client-key") {
		t.Fatalf("policy identity = (%q, %q)", record.APIKey, record.APIKeySHA256)
	}
	if !record.IsNativeKey || record.AccessProvider != "config-inline" {
		t.Fatalf("lost access metadata: native=%t provider=%q", record.IsNativeKey, record.AccessProvider)
	}
}
