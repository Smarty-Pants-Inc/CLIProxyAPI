package registry

import (
	"testing"
)

func TestDetectChangedProviders_KimiAliases(t *testing.T) {
	oldData := &staticModelsJSON{
		Kimi: []*ModelInfo{{ID: "kimi-k2"}},
	}
	newData := &staticModelsJSON{
		Kimi: []*ModelInfo{{ID: "kimi-k2"}, {ID: "kimi-k3"}},
	}

	changed := detectChangedProviders(oldData, newData)
	expected := map[string]bool{
		"kimi":     false,
		"kimi-ai":  false,
		"kimi.ai":  false,
		"kimi.com": false,
	}

	for _, p := range changed {
		if _, ok := expected[p]; ok {
			expected[p] = true
		}
	}

	for p, found := range expected {
		if !found {
			t.Errorf("expected changed provider %q to be reported, got %v", p, changed)
		}
	}
}

func TestKeepEmbeddedClaudeModels_RemoteWithoutSonnet55(t *testing.T) {
	remote := []*ModelInfo{{ID: "claude-opus-5-5", DisplayName: "remote"}}
	got := keepEmbeddedClaudeModels(remote)
	ids := map[string]string{}
	for _, m := range got {
		ids[m.ID] = m.DisplayName
	}
	if _, ok := ids["claude-sonnet-5-5"]; !ok {
		t.Fatal("remote refresh dropped embedded claude-sonnet-5-5")
	}
	if ids["claude-opus-5-5"] != "remote" {
		t.Fatalf("remote entry must win for shared IDs, got %q", ids["claude-opus-5-5"])
	}
}
