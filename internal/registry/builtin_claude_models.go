package registry

// builtinClaudeModels supplies models missing from the CI-pinned upstream catalog.
// Keep these in Go: refresh-model-catalogs.sh replaces models.json before builds.
// A loaded catalog's entry takes precedence as upstream metadata evolves.
// Haiku 5.5 uses the pinned catalog's Sonnet 5.5 token and thinking limits.
func builtinClaudeModels() []*ModelInfo {
	return []*ModelInfo{{
		ID:                  "claude-haiku-5-5",
		Object:              "model",
		Created:             1790553600,
		OwnedBy:             "anthropic",
		Type:                "claude",
		DisplayName:         "Claude Haiku 5.5",
		ContextLength:       1000000,
		MaxCompletionTokens: 128000,
		Thinking: &ThinkingSupport{
			ZeroAllowed:    true,
			DynamicAllowed: true,
			Levels:         []string{"low", "medium", "high", "xhigh", "max"},
		},
		SupportedInputModalities:  []string{"text", "image"},
		SupportedOutputModalities: []string{"text"},
	}}
}
