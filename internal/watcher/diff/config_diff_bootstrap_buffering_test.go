package diff

import (
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Ported from CLIProxyAPI#54: the diff reports the effective (default-on) value.
func TestCodexBootstrapBufferingChangeDetails(t *testing.T) {
	unset := config.CodexConfig{}
	explicitTrue := config.CodexConfig{StreamBootstrapBuffering: true, StreamBootstrapBufferingSet: true}
	explicitFalse := config.CodexConfig{StreamBootstrapBufferingSet: true}
	for _, tc := range []struct {
		name      string
		old, next config.CodexConfig
		want      string
	}{
		{"unset-to-true", unset, explicitTrue, ""},
		{"false-to-false", explicitFalse, explicitFalse, ""},
		{"unset-to-false", unset, explicitFalse, "codex.stream-bootstrap-buffering: true -> false"},
		{"false-to-unset", explicitFalse, unset, "codex.stream-bootstrap-buffering: false -> true"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			for _, detail := range BuildConfigChangeDetails(&config.Config{Codex: tc.old}, &config.Config{Codex: tc.next}) {
				if strings.HasPrefix(detail, "codex.stream-bootstrap-buffering:") {
					got = detail
				}
			}
			if got != tc.want {
				t.Fatalf("buffering change = %q, want %q", got, tc.want)
			}
		})
	}
}
