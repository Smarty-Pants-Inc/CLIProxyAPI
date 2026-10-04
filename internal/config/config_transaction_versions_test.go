package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// saveConfigFixture gives synthetic test configs an explicit source version.
func saveConfigFixture(path string, cfg *Config) error {
	if cfg.ConfigFileVersion == "" {
		version, err := ConfigFileVersion(path)
		if err != nil {
			return err
		}
		cfg.ConfigFileVersion = version
	}
	return SaveConfigPreserveComments(path, cfg)
}

func TestConfigSaveRequiresVersionAndRejectsStale(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	const original = "debug: false\nrequest-retry: 1\n"
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfigPreserveComments(path, &Config{Debug: true}); !errors.Is(err, ErrConfigVersionRequired) {
		t.Fatalf("unversioned save error = %v", err)
	}
	if _, err := AtomicWriteConfigCAS(path, []byte("debug: true\n"), ""); !errors.Is(err, ErrConfigVersionRequired) {
		t.Fatalf("unversioned raw save error = %v", err)
	}
	if err := AtomicWriteConfig(path, []byte("debug: true\n")); !errors.Is(err, ErrConfigVersionRequired) {
		t.Fatalf("unversioned replacement error = %v", err)
	}
	first, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	stale, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	first.Debug = true
	if err = SaveConfigPreserveComments(path, first); err != nil {
		t.Fatal(err)
	}
	stale.RequestRetry = 8
	if err = SaveConfigPreserveComments(path, stale); !errors.Is(err, ErrConfigConflict) {
		t.Fatalf("stale save error = %v", err)
	}
	disk, err := LoadConfig(path)
	if err != nil || !disk.Debug || disk.RequestRetry != 1 {
		t.Fatalf("stale save overwrote file: cfg=%+v err=%v", disk, err)
	}
}

func TestAtomicConfigPublicationPreservesModeAndSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias.yaml")
	if err := os.Symlink("config.yaml", alias); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	version, err := ConfigFileVersion(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = AtomicWriteConfigCAS(alias, []byte("debug: true\n"), version); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(alias)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: info=%v err=%v", info, err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "debug: true\n" {
		t.Fatalf("target not published: data=%q err=%v", data, err)
	}
	if runtime.GOOS != "windows" {
		info, err = os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("mode changed: info=%v err=%v", info, err)
		}
	}
	if _, err = os.Stat(path + ".lock"); err != nil {
		t.Fatalf("canonical lock missing: %v", err)
	}
	if _, err = os.Stat(alias + ".lock"); !os.IsNotExist(err) {
		t.Fatalf("alias created a separate lock: %v", err)
	}
}

func TestLoadConfigHashRewritePreservesConcurrentScalars(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("remote-management:\n  secret-key: unit-test-only-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const writers = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if err := SaveConfigPreserveCommentsUpdateNestedScalar(path, []string{"writer-markers", strconv.Itoa(i)}, "present"); err != nil {
				t.Error(err)
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		if _, err := LoadConfig(path); err != nil {
			t.Error(err)
		}
	}()
	close(start)
	wg.Wait()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Management RemoteManagement  `yaml:"remote-management"`
		Markers    map[string]string `yaml:"writer-markers"`
	}
	if err = yaml.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Markers) != writers {
		t.Fatalf("lost scalar writes: %v", raw.Markers)
	}
	if err = bcrypt.CompareHashAndPassword([]byte(raw.Management.SecretKey), []byte("unit-test-only-password")); err != nil {
		t.Fatalf("management key rewrite failed: %v", err)
	}
}

func TestLoadConfigOptionalMissingParentRemainsReadOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "config.yaml")
	if _, err := LoadConfigOptional(path, true); err != nil {
		t.Fatalf("optional missing parent no longer supported: %v", err)
	}
}
