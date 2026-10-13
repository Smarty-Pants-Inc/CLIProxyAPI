package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// simulateCaseInsensitiveVolume makes paths below root behave like macOS APFS
// defaults when the test volume is case-sensitive: lookups ignore case and
// EvalSymlinks keeps the caller's spelling.
func simulateCaseInsensitiveVolume(t *testing.T, root string) {
	t.Helper()
	probe := filepath.Join(root, "probe")
	if err := os.Mkdir(probe, 0o700); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Remove(probe) }()
	if _, err := os.Stat(filepath.Join(root, "PROBE")); err == nil {
		return // already case-insensitive: exercise the real filesystem
	}
	fold := func(path string) string {
		if rest, ok := strings.CutPrefix(path, root); ok {
			return root + strings.ToLower(rest)
		}
		return path
	}
	evalSymlinks, stat := affinityEvalSymlinks, affinityStat
	t.Cleanup(func() { affinityEvalSymlinks, affinityStat = evalSymlinks, stat })
	affinityEvalSymlinks = func(path string) (string, error) {
		if _, err := filepath.EvalSymlinks(fold(path)); err != nil {
			return "", err
		}
		return path, nil
	}
	affinityStat = func(path string) (os.FileInfo, error) { return os.Stat(fold(path)) }
}

func TestAffinityStateDirectoryRefusesCaseVariantAuthDir(t *testing.T) {
	for _, authExists := range []bool{true, false} {
		t.Run(fmt.Sprintf("auth-exists=%t", authExists), func(t *testing.T) {
			root := t.TempDir()
			simulateCaseInsensitiveVolume(t, root)
			authDir := filepath.Join(root, "auth")
			if authExists {
				if err := os.Mkdir(authDir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, state := range []string{filepath.Join(root, "AUTH"), filepath.Join(root, "Auth", "state")} {
				cfg := &Config{AuthDir: authDir, Routing: RoutingConfig{SessionAffinityStateDir: state}}
				if got, err := cfg.ResolveSessionAffinityStateDir(); err == nil {
					t.Fatalf("case variant %q of auth-dir accepted as %q", state, got)
				}
			}
			cfg := &Config{AuthDir: authDir, Routing: RoutingConfig{SessionAffinityStateDir: filepath.Join(root, "auth-state")}}
			if _, err := cfg.ResolveSessionAffinityStateDir(); err != nil {
				t.Fatalf("sibling refused: %v", err)
			}
		})
	}
}

func TestAffinityStateDirectoryUnresolvedDefaultWhileUnused(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("XDG_STATE_HOME", "")
	authDir := filepath.Join(root, "auth")
	for _, tc := range []struct {
		name       string
		affinity   bool
		home       bool
		state      string
		wantReject bool
	}{
		{"affinity off", false, false, "", false},
		{"home on", true, true, "", false},
		{"affinity on", true, false, "", true},
		{"explicit unresolvable", false, false, "~/state", true},
		{"explicit inside auth-dir", false, false, filepath.Join(authDir, "state"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Home is runtime-only (-home-jwt), so it is set on the struct.
			cfg := &Config{AuthDir: authDir, Home: HomeConfig{Enabled: tc.home}, Routing: RoutingConfig{SessionAffinity: tc.affinity, SessionAffinityStateDir: tc.state}}
			errs := []error{cfg.ValidateSessionAffinityStateDir()}
			if !tc.home {
				data := []byte(fmt.Sprintf("auth-dir: %q\nrouting:\n  session-affinity: %t\n  session-affinity-state-dir: %q\n", authDir, tc.affinity, tc.state))
				_, errLoad := LoadConfigBytes(data, "", false)
				_, errParse := ParseConfigBytes(data)
				errs = append(errs, errLoad, errParse)
			}
			for _, err := range errs {
				if (err != nil) != tc.wantReject || (err != nil && !strings.Contains(err.Error(), "routing.session-affinity-state-dir")) {
					t.Fatalf("error = %v, want reject %t", err, tc.wantReject)
				}
			}
		})
	}
}
