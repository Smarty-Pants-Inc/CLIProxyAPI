package executor

import (
	"slices"
	"strings"
	"testing"
)

// Haiku 5.5 advertises effort levels, so its requests keep the effort beta;
// Haiku 4.5 still drops it.
func TestClaudeRequestSupportsEffort_Haiku55(t *testing.T) {
	cases := []struct {
		model string
		want  bool
	}{
		{"claude-haiku-5-5", true},
		{"claude-haiku-5-5-20260928", true},
		{"claude-haiku-4-5-20251001", false},
		{"claude-haiku-5-4", false},
		{"claude-haiku-5-6", false},
		{"custom-haiku-5-proxy", false},
		{"claude-3-5-haiku-20241022", false},
		{"claude-sonnet-5-5", true},
	}
	for _, tc := range cases {
		body := []byte(`{"model":"` + tc.model + `","messages":[{"role":"user","content":"hi"}],"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}`)
		if got := claudeRequestSupportsEffort(body, nil); got != tc.want {
			t.Errorf("%s: claudeRequestSupportsEffort = %v, want %v", tc.model, got, tc.want)
		}
		betas := strings.Split(claudeCodeCLIBetas(body, nil, true, true), ",")
		if got := slices.Contains(betas, claudeEffortBeta); got != tc.want {
			t.Errorf("%s: effort beta present = %v, want %v; betas=%v", tc.model, got, tc.want, betas)
		}
	}
}
