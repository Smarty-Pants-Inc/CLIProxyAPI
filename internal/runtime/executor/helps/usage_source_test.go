package helps

import (
	"strings"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Usage records reach external sinks: an upstream API key is labelled, never copied.
func TestResolveUsageSourceNeverReturnsUpstreamAPIKey(t *testing.T) {
	const secret = "sk-raw-upstream-SECRET-7f3a9c"
	for _, provider := range []string{"claude", "codex", "openai-compatibility"} {
		a := &cliproxyauth.Auth{ID: "K", Provider: provider, Attributes: map[string]string{"api_key": secret}}
		got := resolveUsageSource(a, "")
		if strings.Contains(got, secret) || !strings.HasPrefix(got, "api-key:") || len(got) != len("api-key:")+8 {
			t.Fatalf("%s: source=%q", provider, got)
		}
		if again := resolveUsageSource(a, ""); again != got {
			t.Fatalf("%s: unstable label %q vs %q", provider, got, again)
		}
	}
	oauth := &cliproxyauth.Auth{ID: "O", Provider: "claude", Metadata: map[string]any{"email": "user@example.com", "access_token": secret}}
	if got := resolveUsageSource(oauth, ""); got != "user@example.com" {
		t.Fatalf("oauth source=%q", got)
	}
}
