package cliproxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestServiceAffinityTTLNormalization(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	if got := normalizedRoutingRuntimeState(nil).sessionAffinityTTL; got != 6*time.Hour || got <= 2*time.Hour {
		t.Fatalf("nil config TTL = %v, want 6h and more than 2h", got)
	}
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{
		{"", 6 * time.Hour},
		{"invalid", 6 * time.Hour},
		{"0s", 6 * time.Hour},
		{"-1h", 6 * time.Hour},
		{" 2h30m ", 150 * time.Minute},
		{"500ms", time.Second},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg := &internalconfig.Config{Routing: internalconfig.RoutingConfig{SessionAffinity: true, SessionAffinityTTL: tc.raw}}
			if got := normalizedRoutingRuntimeState(cfg).sessionAffinityTTL; got != tc.want {
				t.Fatalf("TTL = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestServiceAffinityStatePathAliasesShareOwner(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	root := t.TempDir()
	dir := filepath.Join(root, "auths")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, dir)
	if err != nil {
		t.Fatal(err)
	}
	stateFor := func(path string) routingRuntimeState {
		return normalizedRoutingRuntimeState(&internalconfig.Config{AuthDir: filepath.Join(root, "auth-dir"), Routing: internalconfig.RoutingConfig{SessionAffinity: true, SessionAffinityStateDir: path}})
	}
	absolute := stateFor(dir)
	if got := stateFor(relative); got != absolute {
		t.Fatalf("relative and absolute state paths differ: %#v vs %#v", got, absolute)
	}
	link := filepath.Join(root, "auth-link")
	if err := os.Symlink(dir, link); err != nil {
		t.Logf("symlink probe unavailable: %v", err)
		return
	}
	if got := stateFor(link); got != absolute {
		t.Fatalf("symlink and real state paths differ: %#v vs %#v", got, absolute)
	}
}

func TestServiceAffinityMissingSymlinkLeavesShareOwner(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	for _, suffix := range []string{"new", filepath.Join("new", "nested", "auths")} {
		t.Run(suffix, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			realDir := filepath.Join(root, "auth-real")
			if err := os.Mkdir(realDir, 0o700); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(root, "auth-link")
			if err := os.Symlink(realDir, link); err != nil {
				t.Skipf("symlink probe unavailable: %v", err)
			}
			realDir, err := filepath.EvalSymlinks(realDir)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &internalconfig.Config{AuthDir: filepath.Join(root, "auth-dir"), Routing: internalconfig.RoutingConfig{SessionAffinity: true, SessionAffinityStateDir: filepath.Join(link, suffix)}}
			state := normalizedRoutingRuntimeState(cfg)
			wantPath := filepath.Join(realDir, suffix, "session-affinity.state")
			if state.statePathUnavailable || state.statePath != wantPath {
				t.Fatalf("missing-directory state = %#v, want %q", state, wantPath)
			}
			if _, errStat := os.Stat(cfg.Routing.SessionAffinityStateDir); !os.IsNotExist(errStat) {
				t.Fatalf("normalization created the directory or stat failed: %v", errStat)
			}
			// The builder creates its selector before the Service adopts the cache.
			old := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
			service := &Service{coreManager: coreauth.NewManager(nil, old, nil), appliedRoutingState: &state}
			t.Cleanup(func() {
				service.coreManager.Selector().(*coreauth.SessionAffinitySelector).Stop()
				old.Stop()
			})
			record := func(selector *coreauth.SessionAffinitySelector, block, authID string) {
				t.Helper()
				payload := []byte(fmt.Sprintf(`{"output":[{"type":"compaction","encrypted_content":%q}]}`, block))
				if errRecord := selector.RecordCompactionOutput(authID, cliproxyexecutor.Options{}, payload); errRecord != nil {
					t.Fatalf("acknowledge %s: %v", block, errRecord)
				}
			}
			// A real persistence write, not a test mkdir, creates all missing leaves.
			record(old, "before-mkdir-reload", "z-bound")
			if _, errStat := os.Stat(wantPath); errStat != nil {
				t.Fatalf("first write did not create the state file: %v", errStat)
			}
			if after := normalizedRoutingRuntimeState(cfg); after != state {
				t.Fatalf("mkdir changed canonical key: %#v vs %#v", after, state)
			}
			apply := func(cfg *internalconfig.Config) {
				t.Helper()
				if !service.applyManagerConfig(ctx, configCommit{cfg: cfg, sequence: 1}) {
					t.Fatal("applyManagerConfig failed")
				}
			}
			apply(cfg)
			current := service.coreManager.Selector().(*coreauth.SessionAffinitySelector)
			if current.Cache() != old.Cache() {
				t.Fatal("same-config reload created another cache owner")
			}
			// Also force replacement, then acknowledge a held old-origin output
			// between new-origin writes to expose either stale-overwrite direction.
			updated := *cfg
			updated.Routing.Strategy = "fill-first"
			apply(&updated)
			current = service.coreManager.Selector().(*coreauth.SessionAffinitySelector)
			if current == old || current.Cache() != old.Cache() {
				t.Fatal("replacement did not retain the canonical cache owner")
			}
			record(current, "new-after-reload", "a-other")
			record(old, "held-old-output", "z-bound")
			record(current, "new-final-output", "a-other")
			current.Stop()
			// Restart from disk before the first replay of any signed block.
			restarted := newRoutingSelector(normalizedRoutingRuntimeState(&updated)).(*coreauth.SessionAffinitySelector)
			defer restarted.Stop()
			auths := []*coreauth.Auth{{ID: "a-other", Provider: "test", Status: coreauth.StatusActive}, {ID: "z-bound", Provider: "test", Status: coreauth.StatusActive}}
			for _, ack := range []struct {
				block  string
				authID string
			}{
				{"before-mkdir-reload", "z-bound"},
				{"new-after-reload", "a-other"},
				{"held-old-output", "z-bound"},
				{"new-final-output", "a-other"},
			} {
				opts := cliproxyexecutor.Options{OriginalRequest: []byte(fmt.Sprintf(`{"input":[{"type":"compaction","encrypted_content":%q}]}`, ack.block))}
				got, errPick := restarted.Pick(ctx, "test", "model", opts, auths)
				if errPick != nil || got == nil || got.ID != ack.authID {
					t.Fatalf("replay %s = %v, %v; want %s", ack.block, got, errPick, ack.authID)
				}
			}
		})
	}
}

func TestServiceAffinityStatePath(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := t.TempDir()
	for _, tc := range []struct {
		name    string
		authDir string
		enabled bool
		home    bool
	}{
		{"standalone", dir, true, false},
		{"tilde", "~/affinity-test", true, false},
		{"empty SDK directory", "", true, false},
		{"blank SDK directory", "  ", true, false},
		{"disabled", dir, false, false},
		{"Home", dir, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &internalconfig.Config{AuthDir: tc.authDir, Routing: internalconfig.RoutingConfig{SessionAffinity: tc.enabled}}
			cfg.Home.Enabled = tc.home
			want := ""
			if tc.enabled && !tc.home && tc.authDir != "" && tc.authDir != "  " {
				resolved, errResolve := cfg.ResolveSessionAffinityStateDir()
				if errResolve != nil {
					t.Fatal(errResolve)
				}
				want = filepath.Join(resolved, "session-affinity.state")
			}
			if got := normalizedRoutingRuntimeState(cfg).statePath; got != want {
				t.Fatalf("state path = %q, want %q", got, want)
			}
		})
	}
}

func TestServiceAffinityUnresolvedDirectoryFailsClosed(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	// Resolving the default state directory fails when the platform home is unavailable.
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	if _, errResolve := os.UserHomeDir(); errResolve == nil {
		t.Skip("platform can resolve the home directory without HOME or USERPROFILE")
	}
	cfg := &internalconfig.Config{AuthDir: "~/affinity-test", Routing: internalconfig.RoutingConfig{SessionAffinity: true}}
	state := normalizedRoutingRuntimeState(cfg)
	if state.statePath != "" || !state.statePathUnavailable {
		t.Fatalf("unresolved directory did not fail closed: %#v", state)
	}
	selector := newRoutingSelector(state)
	defer selector.(*coreauth.SessionAffinitySelector).Stop()
	if auth, errPick := selector.Pick(context.Background(), "test", "model", cliproxyexecutor.Options{}, []*coreauth.Auth{{ID: "one"}}); auth != nil || errPick == nil {
		t.Fatalf("unresolved state directory routed request: %v, %v", auth, errPick)
	}
}

func TestServiceAffinityStateDirectoryPermissionFailsClosed(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	dir := filepath.Join(t.TempDir(), "denied")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if err := os.Chmod(dir, 0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "missing", "nested")
	if _, err := filepath.EvalSymlinks(path); !os.IsPermission(err) {
		t.Skipf("platform or user does not enforce directory permissions: %v", err)
	}
	cfg := &internalconfig.Config{AuthDir: filepath.Join(t.TempDir(), "auth-dir"), Routing: internalconfig.RoutingConfig{SessionAffinity: true, SessionAffinityStateDir: path}}
	state := normalizedRoutingRuntimeState(cfg)
	if state.statePath != "" || !state.statePathUnavailable {
		t.Fatalf("permission error did not fail closed: %#v", state)
	}
	selector := newRoutingSelector(state).(*coreauth.SessionAffinitySelector)
	defer selector.Stop()
	if auth, errPick := selector.Pick(context.Background(), "test", "model", cliproxyexecutor.Options{}, []*coreauth.Auth{{ID: "one"}}); auth != nil || errPick == nil {
		t.Fatalf("permission-denied directory routed request: %v, %v", auth, errPick)
	}
}

func TestServiceAffinityConfigReloadPreservesBinding(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	dir := t.TempDir()
	cfg := &internalconfig.Config{AuthDir: dir, Routing: internalconfig.RoutingConfig{SessionAffinity: true}}
	service := &Service{coreManager: coreauth.NewManager(nil, nil, nil)}
	t.Cleanup(func() {
		if stoppable, ok := service.coreManager.Selector().(interface{ Stop() }); ok {
			stoppable.Stop()
		}
	})
	apply := func(cfg *internalconfig.Config) {
		t.Helper()
		if !service.applyManagerConfig(ctx, configCommit{cfg: cfg, sequence: 1}) {
			t.Fatal("applyManagerConfig failed")
		}
	}
	apply(cfg)
	original := service.coreManager.Selector()
	bound := &coreauth.Auth{ID: "z-bound", Provider: "test", Status: coreauth.StatusActive}
	other := &coreauth.Auth{ID: "a-other", Provider: "test", Status: coreauth.StatusActive}
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Claude-Code-Session-Id": []string{"persisted-session"}}}
	pick := func(auths []*coreauth.Auth, want string) {
		t.Helper()
		got, errPick := service.coreManager.Selector().Pick(ctx, "test", "model", opts, auths)
		if errPick != nil {
			t.Fatalf("Pick: %v", errPick)
		}
		if got == nil || got.ID != want {
			t.Fatalf("Pick = %v, want auth %q", got, want)
		}
	}
	beforePick := time.Now()
	pick([]*coreauth.Auth{bound}, bound.ID)
	afterPick := time.Now()
	statePath := normalizedRoutingRuntimeState(cfg).statePath
	data, errRead := os.ReadFile(statePath)
	if errRead != nil {
		t.Fatalf("affinity state not initialized: %v", errRead)
	}
	var persisted struct {
		Groups []struct {
			ExpiresAt time.Time `json:"expires_at"`
		} `json:"groups"`
	}
	if errDecode := json.Unmarshal(data, &persisted); errDecode != nil {
		t.Fatalf("decode affinity state: %v", errDecode)
	}
	if len(persisted.Groups) != 1 {
		t.Fatalf("persisted groups = %d, want 1", len(persisted.Groups))
	}
	expiresAt := persisted.Groups[0].ExpiresAt
	if expiresAt.Before(beforePick.Add(6*time.Hour)) || expiresAt.After(afterPick.Add(6*time.Hour)) {
		t.Fatalf("persisted expiry = %v, want a six-hour binding", expiresAt)
	}
	if !expiresAt.After(afterPick.Add(2 * time.Hour)) {
		t.Fatal("default binding cannot survive a two-hour idle interval")
	}
	apply(cfg)
	if service.coreManager.Selector() != original {
		t.Fatal("unchanged config recreated selector")
	}
	updated := *cfg
	updated.Routing.Strategy = "fill-first"
	updated.Routing.SessionAffinityTTL = "8h"
	apply(&updated)
	if service.coreManager.Selector() == original {
		t.Fatal("changed routing config did not recreate selector")
	}
	// Fill-first would choose a-other if the persisted z-bound binding was lost.
	pick([]*coreauth.Auth{other, bound}, bound.ID)
	previous := service.coreManager.Selector()
	updated.AuthDir = t.TempDir()
	apply(&updated)
	if service.coreManager.Selector() != previous {
		t.Fatal("changed auth-dir recreated the external state owner")
	}
	pick([]*coreauth.Auth{other, bound}, bound.ID)
	updated.Routing.SessionAffinityStateDir = t.TempDir()
	apply(&updated)
	if service.coreManager.Selector() == previous {
		t.Fatal("changed state directory did not recreate selector")
	}
	pick([]*coreauth.Auth{other, bound}, other.ID)
}

// affinityBarrierSelector holds a real affinity Pick in its fallback, before
// that Pick publishes its binding. No timer or cache-internal hook is needed.
type affinityBarrierSelector struct {
	entered chan struct{}
	release chan struct{}
}

func (s *affinityBarrierSelector) Pick(ctx context.Context, _ string, _ string, _ cliproxyexecutor.Options, auths []*coreauth.Auth) (*coreauth.Auth, error) {
	close(s.entered)
	select {
	case <-s.release:
		return auths[0], nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestServiceAffinityConfigReloadSharesInflightCache(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	cfg := &internalconfig.Config{AuthDir: t.TempDir(), Routing: internalconfig.RoutingConfig{SessionAffinity: true}}
	state := normalizedRoutingRuntimeState(cfg)
	barrier := &affinityBarrierSelector{entered: make(chan struct{}), release: make(chan struct{})}
	old := coreauth.NewSessionAffinitySelectorWithConfig(coreauth.SessionAffinityConfig{
		Fallback: barrier, TTL: state.sessionAffinityTTL, StatePath: state.statePath,
	})
	// Model the builder path: the initial cache exists before the Service map.
	service := &Service{coreManager: coreauth.NewManager(nil, old, nil), appliedRoutingState: &state}
	t.Cleanup(func() {
		service.coreManager.Selector().(*coreauth.SessionAffinitySelector).Stop()
		old.Stop()
	})
	bound := &coreauth.Auth{ID: "z-bound", Provider: "test", Status: coreauth.StatusActive}
	other := &coreauth.Auth{ID: "a-other", Provider: "test", Status: coreauth.StatusActive}
	opts := func(id string) cliproxyexecutor.Options {
		return cliproxyexecutor.Options{Headers: http.Header{"X-Claude-Code-Session-Id": []string{id}}}
	}
	ctxPick, cancelPick := context.WithCancel(ctx)
	defer cancelPick()
	oldDone := make(chan error, 1)
	go func() {
		got, errPick := old.Pick(ctxPick, "test", "model", opts("old-inflight"), []*coreauth.Auth{bound})
		if errPick == nil && (got == nil || got.ID != bound.ID) {
			errPick = fmt.Errorf("old Pick = %v, want %s", got, bound.ID)
		}
		oldDone <- errPick
	}()
	<-barrier.entered
	updated := *cfg
	updated.Routing.Strategy = "fill-first"
	updated.Routing.SessionAffinityTTL = "8h"
	subagents := false
	updated.Routing.SessionAffinitySubagents = &subagents
	if !service.applyManagerConfig(ctx, configCommit{cfg: &updated, sequence: 1}) {
		t.Fatal("applyManagerConfig failed")
	}
	current := service.coreManager.Selector().(*coreauth.SessionAffinitySelector)
	if current == old || current.Cache() != old.Cache() {
		t.Fatal("replacement did not share the old cache")
	}
	pick := func(selector coreauth.Selector, id string, auths []*coreauth.Auth, want string) {
		t.Helper()
		got, errPick := selector.Pick(ctx, "test", "model", opts(id), auths)
		if errPick != nil || got == nil || got.ID != want {
			t.Fatalf("Pick(%s) = %v, %v; want %s", id, got, errPick, want)
		}
	}
	// A new acknowledged write precedes the old in-flight write. Then another
	// new write follows it, exercising both stale-snapshot overwrite directions.
	pick(current, "new-after-swap", []*coreauth.Auth{bound}, bound.ID)
	close(barrier.release)
	if errPick := <-oldDone; errPick != nil {
		t.Fatal(errPick)
	}
	pick(current, "new-final", []*coreauth.Auth{bound}, bound.ID)
	current.Stop()
	restarted := newRoutingSelector(normalizedRoutingRuntimeState(&updated)).(*coreauth.SessionAffinitySelector)
	defer restarted.Stop()
	for _, id := range []string{"old-inflight", "new-after-swap", "new-final"} {
		// A cold fill-first binding would select a-other, not z-bound.
		pick(restarted, id, []*coreauth.Auth{other, bound}, bound.ID)
	}
}

func TestServiceAffinityCacheSurvivesPathAndModeChanges(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	ctx := context.Background()
	cfg := &internalconfig.Config{AuthDir: t.TempDir(), Routing: internalconfig.RoutingConfig{SessionAffinity: true, Strategy: "fill-first"}}
	service := &Service{coreManager: coreauth.NewManager(nil, nil, nil)}
	t.Cleanup(func() {
		if stoppable, ok := service.coreManager.Selector().(interface{ Stop() }); ok {
			stoppable.Stop()
		}
	})
	apply := func(t *testing.T, cfg *internalconfig.Config) {
		t.Helper()
		if !service.applyManagerConfig(ctx, configCommit{cfg: cfg, sequence: 1}) {
			t.Fatal("applyManagerConfig failed")
		}
	}
	apply(t, cfg)
	old := service.coreManager.Selector().(*coreauth.SessionAffinitySelector)
	bound := &coreauth.Auth{ID: "z-bound", Provider: "test", Status: coreauth.StatusActive}
	other := &coreauth.Auth{ID: "a-other", Provider: "test", Status: coreauth.StatusActive}
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Claude-Code-Session-Id": []string{"round-trip"}}}
	pick := func(t *testing.T, selector coreauth.Selector, auths []*coreauth.Auth, want string) {
		t.Helper()
		got, errPick := selector.Pick(ctx, "test", "model", opts, auths)
		if errPick != nil || got == nil || got.ID != want {
			t.Fatalf("Pick = %v, %v; want %s", got, errPick, want)
		}
	}
	pick(t, old, []*coreauth.Auth{bound}, bound.ID)
	for _, mode := range []string{"disabled", "Home", "new directory"} {
		t.Run(mode, func(t *testing.T) {
			updated := *cfg
			switch mode {
			case "disabled":
				updated.Routing.SessionAffinity = false
			case "Home":
				updated.Home.Enabled = true
			case "new directory":
				updated.Routing.SessionAffinityStateDir = t.TempDir()
			}
			apply(t, &updated)
			if selector, ok := service.coreManager.Selector().(*coreauth.SessionAffinitySelector); ok {
				if selector.Cache() == old.Cache() {
					t.Fatal("local cache leaked into a different directory or Home")
				}
				pick(t, selector, []*coreauth.Auth{other, bound}, other.ID)
			}
			// An old request can still refresh the old-path store while inactive.
			pick(t, old, []*coreauth.Auth{bound}, bound.ID)
			if mode == "new directory" {
				data, errRead := os.ReadFile(normalizedRoutingRuntimeState(&updated).statePath)
				if errRead != nil {
					t.Fatal(errRead)
				}
				var snapshot struct {
					Groups []struct {
						AuthID string `json:"auth_id"`
					} `json:"groups"`
				}
				if errDecode := json.Unmarshal(data, &snapshot); errDecode != nil {
					t.Fatal(errDecode)
				}
				if len(snapshot.Groups) != 1 || snapshot.Groups[0].AuthID != other.ID {
					t.Fatalf("old request overwrote new-directory state: %+v", snapshot)
				}
			}
			apply(t, cfg)
			restored := service.coreManager.Selector().(*coreauth.SessionAffinitySelector)
			if restored.Cache() != old.Cache() {
				t.Fatal("return to original path loaded a second cache")
			}
			pick(t, restored, []*coreauth.Auth{other, bound}, bound.ID)
		})
	}
}

func TestServiceHomeAffinityDoesNotPersist(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := &internalconfig.Config{AuthDir: t.TempDir(), Routing: internalconfig.RoutingConfig{SessionAffinity: true}}
	cfg.Home.Enabled = true
	selector := newRoutingSelector(normalizedRoutingRuntimeState(cfg))
	if stoppable, ok := selector.(interface{ Stop() }); ok {
		defer stoppable.Stop()
	}
	auth := &coreauth.Auth{ID: "home", Provider: "test", Status: coreauth.StatusActive}
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Claude-Code-Session-Id": []string{"home-session"}}}
	if _, errPick := selector.Pick(context.Background(), "test", "model", opts, []*coreauth.Auth{auth}); errPick != nil {
		t.Fatal(errPick)
	}
	if _, errStat := os.Stat(filepath.Join(cfg.AuthDir, "session-affinity.state")); !os.IsNotExist(errStat) {
		t.Fatalf("Home created local affinity state or stat failed: %v", errStat)
	}
}
