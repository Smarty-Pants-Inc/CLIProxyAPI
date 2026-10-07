package thinking

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
)

// TestValidateConfig_ClaudeHaiku55AcceptsOrdinaryRequests pins that the
// provisional claude-haiku-5-5 thinking metadata does not reject ordinary
// Claude requests at the gateway (levels, adaptive, disabled, budgets).
func TestValidateConfig_ClaudeHaiku55AcceptsOrdinaryRequests(t *testing.T) {
	modelInfo := registry.LookupStaticModelInfoByChannel("claude-haiku-5-5", "claude")
	if modelInfo == nil {
		t.Fatal("claude-haiku-5-5 missing from static claude catalog")
	}
	cases := []ThinkingConfig{
		{Mode: ModeLevel, Level: LevelLow},
		{Mode: ModeLevel, Level: LevelMedium},
		{Mode: ModeLevel, Level: LevelHigh},
		{Mode: ModeLevel, Level: LevelXHigh},
		{Mode: ModeLevel, Level: LevelMax},
		{Mode: ModeAuto, Budget: -1},
		{Mode: ModeNone},
		{Mode: ModeBudget, Budget: 31999},
		{Mode: ModeBudget, Budget: 1024},
	}
	for _, cfg := range cases {
		for _, from := range []string{"claude", "openai"} {
			if _, err := ValidateConfig(cfg, modelInfo, from, "claude", false); err != nil {
				t.Errorf("ValidateConfig(%+v, from=%s) error = %v", cfg, from, err)
			}
		}
	}
}
