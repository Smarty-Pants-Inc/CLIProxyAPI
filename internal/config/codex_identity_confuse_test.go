package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The fork keeps codex identity-confuse after the v8 layout change; migration
// must carry it to upstream.codex instead of archiving it as an unknown field.
func TestCodexIdentityConfuseSurvivesV8Layouts(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"legacy", "routing: {session-affinity: true}\ncodex: {identity-confuse: true}\n"},
		{"historical OAuth", "routing: {session-affinity: true}\noauth: {providers: {codex: {identity-confuse: true}}}\n"},
		{"upstream", "routing: {session-affinity: true}\nupstream: {codex: {identity-confuse: true}}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, errParse := ParseConfigBytes([]byte(tc.raw))
			if errParse != nil {
				t.Fatal(errParse)
			}
			if !cfg.Codex.IdentityConfuse {
				t.Fatal("IdentityConfuse = false, want true")
			}
			migrated, _, errMigrate := NormalizeConfigLayout([]byte(tc.raw), true)
			if errMigrate != nil {
				t.Fatal(errMigrate)
			}
			if errValidate := ValidateV8Config(migrated); errValidate != nil {
				t.Fatalf("migrated config is invalid: %v\n%s", errValidate, migrated)
			}
			var doc yaml.Node
			if errDecode := yaml.Unmarshal(migrated, &doc); errDecode != nil {
				t.Fatal(errDecode)
			}
			node := yamlPath(doc.Content[0], "upstream.codex.identity-confuse")
			if node == nil || node.Value != "true" {
				t.Fatalf("identity-confuse was not migrated to upstream.codex:\n%s", migrated)
			}
			if strings.Contains(string(migrated), "# codex.identity-confuse") || strings.Contains(string(migrated), "# oauth.providers.codex.identity-confuse") {
				t.Fatalf("identity-confuse was archived as an unknown field:\n%s", migrated)
			}
			reparsed, errReparse := ParseConfigBytes(migrated)
			if errReparse != nil || !reparsed.Codex.IdentityConfuse {
				t.Fatalf("migrated config lost identity-confuse: cfg=%+v error=%v", reparsed, errReparse)
			}
		})
	}
}
