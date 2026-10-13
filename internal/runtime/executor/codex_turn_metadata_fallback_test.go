package executor

import (
	"testing"

	"github.com/tidwall/gjson"
)

// CLIProxyAPI#116 P3: without a top-level prompt_cache_key, only top-level fields that equal the
// client's key are remapped; free text, nested fields and malformed metadata are left alone.
func TestCodexTurnMetadataFallbackRemapsOnlyExactTopLevelFields(t *testing.T) {
	state := &codexIdentityConfuseState{enabled: true, originalPromptCacheKey: "client-key", promptCacheKey: "confused-key"}
	raw := `{"session_id":"client-key","note":"see client-key here","nested":{"session_id":"client-key"},"other":"client-key-suffix"}`
	got := applyCodexTurnMetadataIdentityConfuse(raw, state)
	if v := gjson.Get(got, "session_id").String(); v != "confused-key" {
		t.Fatalf("session_id = %q, want confused-key; got %s", v, got)
	}
	for path, want := range map[string]string{"note": "see client-key here", "nested.session_id": "client-key", "other": "client-key-suffix"} {
		if v := gjson.Get(got, path).String(); v != want {
			t.Fatalf("%s = %q, want unchanged %q; got %s", path, v, want, got)
		}
	}
	malformed := `{"session_id":"client-key", "broken": }client-key`
	if out := applyCodexTurnMetadataIdentityConfuse(malformed, state); out != malformed {
		t.Fatalf("malformed metadata rewritten: %q", out)
	}
}
