package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// stream-bootstrap-buffering defaults ON: only an explicit false opts out, in either layout,
// and a YAML snapshot of a default config keeps the default.
func TestCodexStreamBootstrapBufferingDefaultsOnAndExplicitFalseOptsOut(t *testing.T) {
	for _, tc := range []struct {
		name string
		yaml string
		want bool
	}{
		{"absent", "codex:\n  model-level-cooling: true\n", true},
		{"no_codex_block", "port: 8317\n", true},
		{"legacy_true", "codex:\n  stream-bootstrap-buffering: true\n", true},
		{"legacy_false", "codex:\n  stream-bootstrap-buffering: false\n", false},
		{"v8_false", "upstream:\n  codex:\n    stream-bootstrap-buffering: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := ParseConfigBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Codex.StreamBootstrapBufferingEnabled(); got != tc.want {
				t.Fatalf("StreamBootstrapBufferingEnabled() = %t, want %t", got, tc.want)
			}
			snapshot, err := yaml.Marshal(cfg)
			if err != nil {
				t.Fatal(err)
			}
			var decoded Config
			if err = yaml.Unmarshal(snapshot, &decoded); err != nil {
				t.Fatal(err)
			}
			if got := decoded.Codex.StreamBootstrapBufferingEnabled(); got != tc.want {
				t.Fatalf("after YAML snapshot: StreamBootstrapBufferingEnabled() = %t, want %t\n%s", got, tc.want, snapshot)
			}
		})
	}
	if !(&Config{}).Codex.StreamBootstrapBufferingEnabled() {
		t.Fatal("zero config must keep the default hold")
	}
}
