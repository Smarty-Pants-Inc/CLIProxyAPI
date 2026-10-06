package config

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRound4PostCommitEffectRetainsAuthorityAndVersion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Debug = true
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sentinel := errors.New("local effect needs recovery")
	version, effectErr, saveErr := SaveConfigPreserveCommentsCASContextWithCommit(ctx, path, cfg, cfg.ConfigFileVersion, func() error {
		cancel() // A confirmed commit is no longer governed by request cancellation.
		disk, err := LoadConfig(path)
		if err != nil || !disk.Debug {
			t.Fatal("effect ran before publication")
		}
		cancelledCtx, cancelLock := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancelLock()
		if err := withConfigFileLockContext(cancelledCtx, path, func(string) error { t.Fatal("canceled queued publisher entered boundary"); return nil }); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		return sentinel
	})
	if saveErr != nil || !errors.Is(effectErr, sentinel) || version == "" || version != cfg.ConfigFileVersion {
		t.Fatalf("commit and local failure conflated: %s %v %v", version, effectErr, saveErr)
	}
	diskVersion, _ := ConfigFileVersion(path)
	if diskVersion != version {
		t.Fatal("committed version lost after local failure")
	}
}

func TestRound4PostCommitEffectNeverRunsOnRefusal(t *testing.T) {
	for _, reason := range []string{"stale", "cancelled"} {
		t.Run(reason, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(path, []byte("debug: false\n"), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if reason == "stale" {
				if _, err := AtomicWriteConfigCAS(path, []byte("debug: true\n"), cfg.ConfigFileVersion); err != nil {
					t.Fatal(err)
				}
			} else {
				cancel()
			}
			version, effectErr, saveErr := SaveConfigPreserveCommentsCASContextWithCommit(ctx, path, cfg, cfg.ConfigFileVersion, func() error { t.Fatal("local effect ran on refused publication"); return nil })
			if version != "" || effectErr != nil || saveErr == nil {
				t.Fatal("refusal confused with committed effect failure")
			}
		})
	}
}
