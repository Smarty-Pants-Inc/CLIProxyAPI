package thinking_test

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
)

// smarty-dev#1579: Pi pins top-level output_config.effort to "high" and sends the
// real per-turn effort as a trailing {role:"system", output_config:{effort}} message.
func TestExtractTranslatedReasoningEffortClaudePerTurn(t *testing.T) {
	const head = `{"model":"claude-opus-5-5","thinking":{"type":"adaptive"},"output_config":{"effort":"high"},"messages":[`
	tests := []struct {
		name     string
		messages string
		want     string
	}{
		{"top-level only", `{"role":"user","content":"hi"}`, "high"},
		{"last system message wins", `{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":"medium"}}`, "medium"},
		{"effort persists across user messages", `{"role":"system","content":[],"output_config":{"effort":"low"}},{"role":"user","content":"hi"}`, "low"},
		{"appended cloaking system block does not reset effort", `{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":"low"}},{"role":"system","content":[{"type":"text","text":"You are a helpful assistant.","cache_control":{"type":"ephemeral","ttl":"1h"}}]}`, "low"},
		{"last directive wins before appended guidance", `{"role":"system","content":[],"output_config":{"effort":"medium"}},{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":"low"}},{"role":"system","content":[{"type":"text","text":"Caller guidance"}]}`, "low"},
		{"non-system effort does not reset directive", `{"role":"system","content":[],"output_config":{"effort":"low"}},{"role":"user","content":"hi","output_config":{"effort":"max"}}`, "low"},
		{"content-bearing system directive", `{"role":"system","content":[{"type":"text","text":"Caller guidance"}],"output_config":{"effort":"low"}}`, "low"},
		{"none before guidance", `{"role":"system","content":[],"output_config":{"effort":"none"}},{"role":"system","content":"guidance"}`, "none"},
		{"auto before guidance", `{"role":"system","content":[],"output_config":{"effort":"auto"}},{"role":"system","content":"guidance"}`, "auto"},
		{"invalid latest directive falls back", `{"role":"system","content":[],"output_config":{"effort":"low"}},{"role":"system","content":[],"output_config":{"effort":"turbo"}},{"role":"system","content":"guidance"}`, "high"},
		{"last of several system messages wins", `{"role":"system","content":[],"output_config":{"effort":"low"}},{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":"max"}}`, "max"},
		{"numeric effort ignored", `{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":3}}`, "high"},
		{"empty effort ignored", `{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":" "}}`, "high"},
		{"unknown effort ignored", `{"role":"user","content":"hi"},{"role":"system","content":[],"output_config":{"effort":"turbo"}}`, "high"},
		{"last user message with output_config ignored", `{"role":"user","content":"hi","output_config":{"effort":"low"}}`, "high"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := []byte(head + tt.messages + `]}`)
			if got := thinking.ExtractTranslatedReasoningEffort(body, "claude"); got != tt.want {
				t.Fatalf("ExtractTranslatedReasoningEffort() = %q, want %q", got, tt.want)
			}
		})
	}
}
