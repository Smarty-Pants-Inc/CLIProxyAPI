package management

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"gopkg.in/yaml.v3"
)

// loadHandlerConfigBaseline replaces literal-only persistence fixtures with a
// real file baseline loaded through the same path as a running handler. Keep the
// config pointer so existing tests can continue to inspect the mutated fixture.
func loadHandlerConfigBaseline(t *testing.T, h *Handler) {
	t.Helper()
	if h.cfg.CredentialInFlight == (config.CredentialInFlightConfig{}) {
		h.cfg.CredentialInFlight = config.DefaultCredentialInFlightConfig()
	}
	data, err := yaml.Marshal(h.cfg)
	if err != nil {
		t.Fatal(err)
	}
	writeConfigFixtureBytes(t, h.configFilePath, data)
	*h.cfg = *loadConfigFixture(t, h.configFilePath)
}
