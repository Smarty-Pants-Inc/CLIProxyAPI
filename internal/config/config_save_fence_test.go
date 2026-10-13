package config

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const fenceBaseline = "# synthetic fixture\nport: 8080\ndebug: false\nremote-management:\n  secret-key: ''\n"

func fenceFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(fenceBaseline), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fenceLoad(t *testing.T, path string) *Config {
	t.Helper()
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func fenceRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fenceRefuse(t *testing.T, path string, cfg *Config) {
	t.Helper()
	before := fenceRead(t, path)
	if err := SaveConfigPreserveComments(path, cfg); !errors.Is(err, ErrStaleConfig) {
		t.Errorf("full save error = %v, want ErrStaleConfig", err)
	}
	if !bytes.Equal(before, fenceRead(t, path)) {
		t.Error("refused save changed disk")
	}
}

// Run the real scalar writer (or a raw external rewrite) in another process.
// CombinedOutput is the completion barrier: no late-publication race is claimed here.
func TestConfigSaveFenceExternalWriter(t *testing.T) {
	if mode := os.Getenv("CONFIG_FENCE_CHILD"); mode != "" {
		path := os.Getenv("CONFIG_FENCE_PATH")
		var err error
		switch mode {
		case "raw":
			err = os.WriteFile(path, []byte("# external revision\nport: 9090\ndebug: true\n"), 0600)
		case "scalar":
			err = SaveConfigPreserveCommentsUpdateNestedScalar(path, []string{"remote-management", "secret-key"}, "synthetic-rotated-secret")
		default:
			t.Fatal("unknown fixture writer")
		}
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, mode := range []string{"raw", "scalar"} {
		for _, beforeLoad := range []bool{false, true} {
			name := mode + "/stale"
			if beforeLoad {
				name = mode + "/before-load"
			}
			t.Run(name, func(t *testing.T) {
				path := fenceFile(t)
				var cfg *Config
				if !beforeLoad {
					cfg = fenceLoad(t, path)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConfigSaveFenceExternalWriter$")
				cmd.Env = append(os.Environ(), "CONFIG_FENCE_CHILD="+mode, "CONFIG_FENCE_PATH="+path)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("external writer: %v\n%s", err, out)
				}
				if !beforeLoad {
					fenceRefuse(t, path, cfg)
					return
				}
				cfg = fenceLoad(t, path)
				cfg.Debug = false
				if err := SaveConfigPreserveComments(path, cfg); err != nil {
					t.Fatalf("before-load update prevented ordinary save: %v", err)
				}
				if mode == "raw" && fenceLoad(t, path).Port != 9090 {
					t.Error("ordinary save reverted prior update")
				}
			})
		}
	}
}

func TestConfigSaveFenceCopiesAndReloads(t *testing.T) {
	path := fenceFile(t)
	cfg := fenceLoad(t, path)
	copied := *cfg
	cloned := cfg.CloneForRuntime()
	delayed := fenceLoad(t, path)
	cfg.Port = 8081
	if err := SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	for _, stale := range []*Config{&copied, cloned, delayed} {
		fenceRefuse(t, path, stale)
	}
	// Saving the same supplied snapshot again is valid, but its old copies stay stale.
	cfg.Port = 8082
	if err := SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	reloaded := fenceLoad(t, path)
	cfg.Port = 8083
	if err := SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	fenceRefuse(t, path, reloaded)
	latest := fenceLoad(t, path)
	latest.Port = 8084
	if err := SaveConfigPreserveComments(path, latest); err != nil {
		t.Fatal(err)
	}
	fenceRefuse(t, path, cfg)
	if got := fenceLoad(t, path).Port; got != 8084 {
		t.Errorf("port = %d", got)
	}
}

func TestConfigSaveFenceParseAndOptional(t *testing.T) {
	path := fenceFile(t)
	cfg, err := ParseConfigBytes(fenceRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Port = 8081
	if err = SaveConfigPreserveComments(path, cfg); err != nil {
		t.Fatal(err)
	}
	optional, err := LoadConfigOptional(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveCommentsUpdateNestedScalar(path, []string{"port"}, "9090"); err != nil {
		t.Fatal(err)
	}
	fenceRefuse(t, path, cfg)
	fenceRefuse(t, path, optional)
	fenceRefuse(t, path, &Config{Port: 8080})
	missing := filepath.Join(t.TempDir(), "missing.yaml")
	standby, err := LoadConfigOptional(missing, true)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(missing, []byte(fenceBaseline), 0600); err != nil {
		t.Fatal(err)
	}
	fenceRefuse(t, missing, standby)
}

func TestConfigSaveFenceMetadataNotSerialized(t *testing.T) {
	cfg := fenceLoad(t, fenceFile(t))
	// Reconstruct exported fields only, without private provenance. Both encoders
	// must produce exactly the same output for tracked and untracked values.
	var decoded Config
	out, in := reflect.ValueOf(&decoded).Elem(), reflect.ValueOf(cfg).Elem()
	for i := 0; i < in.NumField(); i++ {
		if out.Field(i).CanSet() {
			out.Field(i).Set(in.Field(i))
		}
	}
	loadedYAML, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	roundtripYAML, err := yaml.Marshal(&decoded)
	if err != nil || !bytes.Equal(loadedYAML, roundtripYAML) {
		t.Fatal("source metadata leaked into YAML")
	}
	loadedJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	decodedJSON, err := json.Marshal(&decoded)
	if err != nil || !bytes.Equal(loadedJSON, decodedJSON) {
		t.Fatal("source metadata leaked into JSON")
	}
	fenceRefuse(t, fenceFile(t), &decoded)
}

func TestConfigSaveFenceLoadedCloneIsolation(t *testing.T) {
	path := fenceFile(t)
	original := fenceLoad(t, path)
	original.APIKeys = []string{"synthetic-client-key"}
	original.OAuthExcludedModels = map[string][]string{"codex": {"synthetic-model"}}
	original.Plugins.Configs = map[string]PluginInstanceConfig{
		"sample": parseTestPluginConfig(t, "name: original\n"),
	}
	clone := original.CloneForRuntime()
	if clone.sourceRevision != original.sourceRevision || !clone.sourceRevision.matches(fenceRead(t, path)) {
		t.Fatal("clone lost exact source revision")
	}
	clone.APIKeys[0] = "synthetic-clone-key"
	clone.OAuthExcludedModels["codex"][0] = "clone-model"
	clonedPlugin := clone.Plugins.Configs["sample"]
	clonedPlugin.Raw.Content[1].Value = "clone"
	if original.APIKeys[0] != "synthetic-client-key" || original.OAuthExcludedModels["codex"][0] != "synthetic-model" || original.Plugins.Configs["sample"].Raw.Content[1].Value != "original" {
		t.Fatal("loaded tracked config clone shares reference fields")
	}
	original.Port = 8081
	if err := SaveConfigPreserveComments(path, original); err != nil {
		t.Fatal(err)
	}
	fenceRefuse(t, path, clone)
}

func TestConfigSaveFencePlaintextHashProvenance(t *testing.T) {
	for _, parseOnly := range []bool{false, true} {
		name := "load"
		if parseOnly {
			name = "parse"
		}
		t.Run(name, func(t *testing.T) {
			path := fenceFile(t)
			input := []byte("port: 8080\nremote-management:\n  secret-key: synthetic-plaintext-secret\n")
			if err := os.WriteFile(path, input, 0600); err != nil {
				t.Fatal(err)
			}
			var cfg *Config
			var err error
			if parseOnly {
				cfg, err = ParseConfigBytes(input)
			} else {
				cfg, err = LoadConfig(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			if !cfg.sourceRevision.matches(fenceRead(t, path)) || !looksLikeBcrypt(cfg.RemoteManagement.SecretKey) {
				t.Fatal("hash snapshot is not bound to its exact source")
			}
			if parseOnly && !bytes.Equal(input, fenceRead(t, path)) {
				t.Fatal("ParseConfigBytes persisted a hash")
			}
			if err = SaveConfigPreserveComments(path, cfg); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(fenceRead(t, path), []byte("synthetic-plaintext-secret")) {
				t.Fatal("full save did not persist hashed management key")
			}
		})
	}
}

func TestConfigSaveFenceSecretFreeErrorsAndRemoval(t *testing.T) {
	path := fenceFile(t)
	cfg := fenceLoad(t, path)
	if err := os.WriteFile(path, []byte("remote-management: {secret-key: synthetic-secret-error-test}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	err := SaveConfigPreserveComments(path, cfg)
	if !errors.Is(err, ErrStaleConfig) || strings.Contains(err.Error(), "synthetic-secret") || strings.Contains(err.Error(), path) {
		t.Fatalf("expected secret-free stale sentinel, got %v", err)
	}
	fenceRefuse(t, path, nil)
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = SaveConfigPreserveComments(path, cfg); !errors.Is(err, ErrStaleConfig) {
		t.Fatalf("removed source error = %v", err)
	}
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("removed source was recreated")
	}
}
