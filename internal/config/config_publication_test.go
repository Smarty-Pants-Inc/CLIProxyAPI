package config

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

func TestPrepareConfigPublication(t *testing.T) {
	for _, tc := range []struct {
		name, source, token, secret string
	}{
		{"plain", "remote-management:\n  secret-key: test-password # comment\nunknown: [x, y]\n", "test-password", "test-password"},
		{"single-quote", "remote-management: {secret-key: 'test''password', allow-remote: true}\n", "'test''password'", "test'password"},
		{"double-quote", "remote-management: {secret-key: \"test\\\"password\"}\n", "\"test\\\"password\"", "test\"password"},
		{"commas", "remote-management:\n  secret-key: test,password}\n", "test,password}", "test,password}"},
		{"crlf", "# comment\r\nremote-management:\r\n  secret-key: test-password  # comment\r\nrequest-retry: 2\r\n", "test-password", "test-password"},
		{"unicode-column", "{unknown: é, remote-management: {secret-key: 'test-password'}}\n", "'test-password'", "test-password"},
		{"bom-flow-two-spaces", "\xef\xbb\xbf{remote-management: {secret-key:  'bom-only-secret'}, unknown: [1, 2]}\n", "'bom-only-secret'", "bom-only-secret"},
		{"bom-quoted-flow", "\xef\xbb\xbf{\"remote-management\": {\"secret-key\":  \"bom-only-secret\"}, \"unknown\": 7}\n", "\"bom-only-secret\"", "bom-only-secret"},
		{"bom-flow-plain", "\xef\xbb\xbf{remote-management: {secret-key:  bom-only-secret}, unknown: [1, 2]}\n", "bom-only-secret", "bom-only-secret"},
		{"bom-next-line", "\xef\xbb\xbfremote-management:\n  secret-key:  'bom-only-secret'\n", "'bom-only-secret'", "bom-only-secret"},
		{"quoted-multiline", "remote-management:\n  secret-key: 'test\n    password'\nrequest-retry: 2\n", "'test\n    password'", "test password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := PrepareConfigPublication([]byte(tc.source))
			if err != nil {
				t.Fatal(err)
			}
			var cfg Config
			if err = yaml.Unmarshal(got, &cfg); err != nil {
				t.Fatal(err)
			}
			if err = bcrypt.CompareHashAndPassword([]byte(cfg.RemoteManagement.SecretKey), []byte(tc.secret)); err != nil {
				t.Fatal(err)
			}
			want := strings.Replace(tc.source, tc.token, cfg.RemoteManagement.SecretKey, 1)
			if string(got) != want {
				t.Fatalf("non-secret bytes changed: %q != %q", got, want)
			}
			stable, err := PrepareConfigPublication(got)
			if err != nil || !bytes.Equal(stable, got) {
				t.Fatalf("hashed source changed: %v", err)
			}
		})
	}
}

func TestPrepareConfigPublicationBlock(t *testing.T) {
	for _, indicator := range []string{"|-", ">-", "|2-"} {
		source := "# retained\nremote-management:\n  secret-key: " + indicator + " # header\n    test-password\nrequest-retry: 2\n# tail\n"
		got, err := PrepareConfigPublication([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		var cfg Config
		if err = yaml.Unmarshal(got, &cfg); err != nil {
			t.Fatal(err)
		}
		if err = bcrypt.CompareHashAndPassword([]byte(cfg.RemoteManagement.SecretKey), []byte("test-password")); err != nil {
			t.Fatal(err)
		}
		want := "# retained\nremote-management:\n  secret-key: " + cfg.RemoteManagement.SecretKey + " # header\nrequest-retry: 2\n# tail\n"
		if string(got) != want {
			t.Fatalf("non-secret block bytes changed: %q", got)
		}
	}
}

func TestPrepareConfigPublicationUnchangedAndRefused(t *testing.T) {
	for _, source := range []string{"request-retry: 2\n", "remote-management: {secret-key: ''}\n", "remote-management: {secret-key: null}\n", "remote-management: {secret-key: '$2a$10$already-hashed'}\n"} {
		got, err := PrepareConfigPublication([]byte(source))
		if err != nil || string(got) != source {
			t.Fatalf("non-plaintext source changed: %v %q", err, got)
		}
	}
	for _, source := range []string{
		"remote-management: {secret-key: &key test-password}\n",
		"other: &key test-password\nremote-management: {secret-key: *key}\n",
		"other: &management {secret-key: test-password}\nremote-management: {<<: *management}\n",
		"remote-management:\n  secret-key: test\n    password\n",
		"remote-management: {secret-key: !!str test-password}\n",
		"codex: {live-media-relay: {enabled: true, max-sessions: -1}}\n",
	} {
		if got, err := PrepareConfigPublication([]byte(source)); err == nil || got != nil {
			t.Fatalf("unsafe or invalid source was not refused: %q", source)
		}
	}
}

// Publication preserves source bytes, whereas the server saver serializes YAML.
// Compare the SAME bcrypt hash through both paths, not randomized hash outputs.
func TestPrepareConfigPublicationServerCredentialEquivalence(t *testing.T) {
	for _, tc := range []struct{ name, source, token string }{
		{"plain", "remote-management:\n  secret-key: save-only-secret\nrequest-retry: 2\n", "save-only-secret"},
		{"single-quoted", "remote-management:\n  secret-key: 'save-only-secret' # kept\nrequest-retry: 2\n", "'save-only-secret'"},
		{"double-quoted", "remote-management:\n  secret-key: \"save-only-secret\"\nrequest-retry: 2\n", "\"save-only-secret\""},
		{"flow", "remote-management: {secret-key: 'save-only-secret', allow-remote: false}\nrequest-retry: 2\n", "'save-only-secret'"},
		{"crlf", "remote-management:\r\n  secret-key: save-only-secret\r\nrequest-retry: 2\r\n", "save-only-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			published, err := PrepareConfigPublication([]byte(tc.source))
			if err != nil {
				t.Fatal(err)
			}
			var prepared Config
			if err = yaml.Unmarshal(published, &prepared); err != nil {
				t.Fatal(err)
			}
			hash := prepared.RemoteManagement.SecretKey
			if err = bcrypt.CompareHashAndPassword([]byte(hash), []byte("save-only-secret")); err != nil {
				t.Fatal(err)
			}
			want := strings.Replace(tc.source, tc.token, hash, 1)
			if string(published) != want {
				t.Fatalf("non-secret bytes changed: %q != %q", published, want)
			}
			server := filepath.Join(t.TempDir(), "server.yaml")
			if err = os.WriteFile(server, []byte(tc.source), 0600); err != nil {
				t.Fatal(err)
			}
			if err = SaveConfigPreserveCommentsUpdateNestedScalar(server, []string{"remote-management", "secret-key"}, hash); err != nil {
				t.Fatal(err)
			}
			saved, err := os.ReadFile(server)
			if err != nil {
				t.Fatal(err)
			}
			var serialized Config
			if err = yaml.Unmarshal(saved, &serialized); err != nil {
				t.Fatal(err)
			}
			if serialized.RemoteManagement.SecretKey != hash {
				t.Fatal("server saver changed credential representation")
			}
			live := filepath.Join(t.TempDir(), "published.yaml")
			if err = os.WriteFile(live, published, 0600); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(live)
			if err != nil || loaded.RemoteManagement.SecretKey != hash {
				t.Fatalf("server load credential mismatch: %v", err)
			}
			after, err := os.ReadFile(live)
			if err != nil || !bytes.Equal(after, published) {
				t.Fatalf("server startup rewrote publication: %v", err)
			}
		})
	}
}
