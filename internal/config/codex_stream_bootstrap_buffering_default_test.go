package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// Ported from CLIProxyAPI#54 (cf34267a), adapted to the presence flag: stream-bootstrap-buffering
// defaults ON, only an explicit false opts out, and that survives save/reload, clone and YAML/JSON
// round trips.

func codexBuffering(value, set bool) CodexConfig {
	return CodexConfig{StreamBootstrapBuffering: value, StreamBootstrapBufferingSet: set}
}

func TestCodexStreamBootstrapBufferingSaveReload(t *testing.T) {
	for _, initial := range []string{"{}", "codex: {}", "codex:\n  stream-bootstrap-buffering: true", "codex:\n  stream-bootstrap-buffering: false"} {
		t.Run(initial, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if errWrite := os.WriteFile(path, []byte(initial), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			for _, option := range []CodexConfig{codexBuffering(false, true), codexBuffering(false, false), codexBuffering(true, true)} {
				loadedBefore, errLoad := LoadConfig(path)
				if errLoad != nil {
					t.Fatal(errLoad)
				}
				before := loadedBefore.Codex.StreamBootstrapBufferingEnabled()
				loadedBefore.Codex = option
				if errSave := SaveConfigPreserveComments(path, loadedBefore); errSave != nil {
					t.Fatal(errSave)
				}
				loaded, errLoad := LoadConfig(path)
				if errLoad != nil {
					t.Fatal(errLoad)
				}
				// An unset option keeps whatever the file already said; the others must win.
				want := option.StreamBootstrapBufferingEnabled()
				if !option.StreamBootstrapBufferingSet {
					want = before
				}
				if got := loaded.Codex.StreamBootstrapBufferingEnabled(); got != want {
					data, _ := os.ReadFile(path)
					t.Fatalf("option=%+v: loaded enabled=%t, want %t\n%s", option, got, want, data)
				}
			}
		})
	}
}

func TestCodexStreamBootstrapBufferingDefaultAndDecoding(t *testing.T) {
	var nilCodex *CodexConfig
	if !nilCodex.StreamBootstrapBufferingEnabled() {
		t.Fatal("nil Codex config must preserve buffering")
	}
	if !(&Config{}).Codex.StreamBootstrapBufferingEnabled() {
		t.Fatal("zero config must preserve buffering")
	}
	for _, tc := range []struct {
		name, yaml, json string
		want, explicit   bool
	}{
		{"absent", "{}", `{}`, true, false},
		{"empty-codex", "codex: {}", `{"codex":{}}`, true, false},
		{"null", "codex:\n  stream-bootstrap-buffering: null", `{"codex":{"stream-bootstrap-buffering":null}}`, true, false},
		{"true", "codex:\n  stream-bootstrap-buffering: true", `{"codex":{"stream-bootstrap-buffering":true}}`, true, true},
		{"false", "codex:\n  stream-bootstrap-buffering: false", `{"codex":{"stream-bootstrap-buffering":false}}`, false, true},
		{"v8-false", "upstream:\n  codex:\n    stream-bootstrap-buffering: false", `{"codex":{"stream-bootstrap-buffering":false}}`, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := func(t *testing.T, cfg *Config) {
				t.Helper()
				if got := cfg.Codex.StreamBootstrapBufferingEnabled(); got != tc.want {
					t.Fatalf("buffering = %t, want %t", got, tc.want)
				}
				if got := cfg.Codex.StreamBootstrapBufferingSet; got != tc.explicit {
					t.Fatalf("explicit option = %t, want %t", got, tc.explicit)
				}
			}
			for _, codec := range []struct {
				name, raw string
				unmarshal func([]byte, any) error
				marshal   func(any) ([]byte, error)
			}{
				{"yaml", tc.yaml, yaml.Unmarshal, yaml.Marshal},
				{"json", tc.json, json.Unmarshal, json.Marshal},
			} {
				t.Run(codec.name, func(t *testing.T) {
					var cfg Config
					if err := codec.unmarshal([]byte(codec.raw), &cfg); err != nil {
						t.Fatal(err)
					}
					check(t, &cfg)
					check(t, cfg.CloneForRuntime())
					raw, err := codec.marshal(&cfg)
					if err != nil {
						t.Fatal(err)
					}
					var roundTrip Config
					if err := codec.unmarshal(raw, &roundTrip); err != nil {
						t.Fatal(err)
					}
					check(t, &roundTrip)
				})
			}
			parsed, errParse := ParseConfigBytes([]byte(tc.yaml))
			if errParse != nil {
				t.Fatal(errParse)
			}
			check(t, parsed)
			path := filepath.Join(t.TempDir(), "config.yaml")
			if errWrite := os.WriteFile(path, []byte(tc.yaml), 0600); errWrite != nil {
				t.Fatal(errWrite)
			}
			loaded, errLoad := LoadConfig(path)
			if errLoad != nil {
				t.Fatal(errLoad)
			}
			check(t, loaded)
		})
	}
}
