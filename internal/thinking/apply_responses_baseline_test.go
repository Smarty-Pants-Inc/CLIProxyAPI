package thinking_test

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/thinking"
	_ "github.com/router-for-me/CLIProxyAPI/v8/internal/thinking/provider/codex"
	"github.com/tidwall/gjson"
)

func TestApplyThinkingWithModelInfoPreservesNormalizedResponsesBaseline(t *testing.T) {
	modelInfo := &registry.ModelInfo{
		ID:       "private-codex",
		Type:     "codex",
		Thinking: &registry.ThinkingSupport{Levels: []string{"low", "high", "xhigh"}},
	}
	for _, effort := range []string{"max", "xhigh"} {
		for _, tc := range []struct {
			name string
			body string
			want string
		}{
			{name: "lower", body: `{"reasoning":{"effort":"low"}}`, want: "low"},
			{name: "delete", body: `{}`},
			{name: "normalized high cap", body: `{"reasoning":{"effort":"high"}}`, want: "high"},
		} {
			t.Run(effort+"/"+tc.name, func(t *testing.T) {
				source := []byte(`{"reasoning":{"effort":"` + effort + `"}}`)
				out, err := thinking.ApplyThinkingWithModelInfo([]byte(tc.body), source, modelInfo.ID, "openai-response", "codex", "codex", modelInfo)
				if err != nil {
					t.Fatalf("ApplyThinkingWithModelInfo() error = %v", err)
				}
				if got := gjson.GetBytes(out, "reasoning.effort"); got.String() != tc.want || got.Exists() != (tc.want != "") {
					t.Fatalf("normalized effort = %s, want %q; body=%s", got.Raw, tc.want, out)
				}
			})
		}
	}
}
