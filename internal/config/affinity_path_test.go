package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAffinityStateDirectoryDefaultsAndExplicit(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, tc := range []struct{ name, xdg, explicit, want string }{
		{"XDG", filepath.Join(root, "xdg"), "", filepath.Join(root, "xdg", "cliproxyapi")},
		{"home fallback", "", "", filepath.Join(home, ".local", "state", "cliproxyapi")},
		{"explicit", filepath.Join(root, "xdg"), filepath.Join(root, "custom"), filepath.Join(root, "custom")},
		{"tilde", "", "~/custom", filepath.Join(home, "custom")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", tc.xdg)
			data := []byte(fmt.Sprintf("auth-dir: %q\nrouting:\n  session-affinity-state-dir: %q\n", filepath.Join(root, "auth"), tc.explicit))
			cfg, err := LoadConfigBytes(data, "", false)
			if err != nil {
				t.Fatal(err)
			}
			got, err := cfg.ResolveSessionAffinityStateDir()
			want, errWant := canonicalAffinityDirectory(tc.want)
			if err != nil || errWant != nil || got != want {
				t.Fatalf("directory = %q, %v; want %q, %v", got, err, want, errWant)
			}
			if _, err := os.Stat(got); !os.IsNotExist(err) {
				t.Fatalf("config load created state dir or stat failed: %v", err)
			}
		})
	}
}

func TestAffinityStateDirectoryRefusesAuthDescendants(t *testing.T) {
	root := t.TempDir()
	authDir := filepath.Join(root, "auth")
	if err := os.Mkdir(authDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "auth-link")
	if err := os.Symlink(authDir, link); err != nil {
		t.Fatal(err)
	}
	dangling := filepath.Join(root, "dangling")
	if err := os.Symlink(filepath.Join(authDir, "missing"), dangling); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, auth, state, xdg string }{
		{"same", authDir, authDir, ""},
		{"nested missing", authDir, filepath.Join(authDir, "new", "nested"), ""},
		{"state symlink exact", authDir, link, ""},
		{"state symlink", authDir, filepath.Join(link, "new", "nested"), ""},
		{"auth symlink", link, filepath.Join(authDir, "new"), ""},
		{"dangling symlink", authDir, filepath.Join(dangling, "new"), ""},
		{"XDG default", authDir, "", authDir},
		{"XDG symlink default", authDir, "", link},
		{"empty auth default", "", "", filepath.Join(root, ".cli-proxy-api")},
		{"home default", root, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("HOME", root)
			t.Setenv("USERPROFILE", root)
			t.Setenv("XDG_STATE_HOME", tc.xdg)
			// Validate irrespective of affinity enablement, Home, or optional loading.
			for _, enabled := range []bool{false, true} {
				for _, optional := range []bool{false, true} {
					data := []byte(fmt.Sprintf("auth-dir: %q\nhome:\n  enabled: true\nrouting:\n  session-affinity: %t\n  session-affinity-state-dir: %q\n", tc.auth, enabled, tc.state))
					if _, err := LoadConfigBytes(data, "", optional); err == nil || !strings.Contains(err.Error(), "routing.session-affinity-state-dir") {
						t.Fatalf("unsafe config not clearly rejected: %v", err)
					}
					if _, err := ParseConfigBytes(data); err == nil || !strings.Contains(err.Error(), "routing.session-affinity-state-dir") {
						t.Fatalf("unsafe in-memory config not clearly rejected: %v", err)
					}
				}
			}
		})
	}
}

func TestAffinityStateDirectoryAllowsAuthSiblingAndJSON(t *testing.T) {
	root := t.TempDir()
	data := []byte(fmt.Sprintf(`{"auth-dir":%q,"routing":{"session-affinity-state-dir":%q}}`, filepath.Join(root, "auth"), filepath.Join(root, "auth-state")))
	cfg, err := LoadConfigBytes(data, "", false)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(cfg.Routing)
	if err != nil || !strings.Contains(string(encoded), `"session-affinity-state-dir"`) {
		t.Fatalf("missing JSON configuration entry: %s, %v", encoded, err)
	}
	var routing RoutingConfig
	if err := json.Unmarshal(encoded, &routing); err != nil || routing.SessionAffinityStateDir != cfg.Routing.SessionAffinityStateDir {
		t.Fatalf("JSON round trip = %+v, %v", routing, err)
	}
}
