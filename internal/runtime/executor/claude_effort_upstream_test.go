package executor

import (
	"bytes"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Effort is an Anthropic-only beta even when a compatible gateway uses an
// effort-capable Claude model or the caller explicitly requests the beta.
func TestApplyClaudeHeaders_EffortBetaRequiresAnthropicUpstream(t *testing.T) {
	for _, upstream := range []struct {
		name, baseURL string
		wantEffort    bool
	}{
		{name: "default", wantEffort: true},
		{name: "anthropic", baseURL: "https://api.anthropic.com", wantEffort: true},
		{name: "third-party", baseURL: "https://api.kimi.example/anthropic"},
		{name: "lookalike", baseURL: "https://api.anthropic.com.evil.example"},
	} {
		for _, caller := range []struct {
			name, apiKey string
			headerBeta   bool
			bodyBeta     bool
			confirmed    bool
		}{
			{name: "automatic-cli", apiKey: claudeRaceProbeOAuthKey},
			{name: "header-cli", apiKey: claudeRaceProbeOAuthKey, headerBeta: true},
			{name: "native-header", apiKey: claudeRaceProbeOAuthKey, headerBeta: true, confirmed: true},
			{name: "body-cli", apiKey: claudeRaceProbeOAuthKey, bodyBeta: true},
			{name: "body-caller-owned", apiKey: "key-effort-upstream", bodyBeta: true},
		} {
			for _, stream := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/stream=%t", upstream.name, caller.name, stream), func(t *testing.T) {
					auth := &cliproxyauth.Auth{Attributes: map[string]string{"api_key": caller.apiKey, "base_url": upstream.baseURL}}
					apiKey, baseURL := claudeCreds(auth)
					if baseURL == "" {
						baseURL = "https://api.anthropic.com"
					}
					req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/messages?beta=true", nil)
					if err != nil {
						t.Fatal(err)
					}
					incoming := http.Header{"Anthropic-Beta": {"unrelated-test-2099-01-01"}}
					if caller.headerBeta {
						incoming.Set("Anthropic-Beta", incoming.Get("Anthropic-Beta")+","+claudeEffortBeta)
					}
					var extraBetas []string
					if caller.bodyBeta {
						extraBetas = []string{claudeEffortBeta}
					}
					body := []byte(`{"model":"claude-opus-5-5","messages":[{"role":"user","content":"hi"}],"thinking":{"type":"adaptive"},"output_config":{"effort":"high"}}`)
					originalBody := bytes.Clone(body)
					if errHeaders := applyClaudeHeaders(req, auth, apiKey, stream, extraBetas, body, nil, incoming, caller.confirmed); errHeaders != nil {
						t.Fatal(errHeaders)
					}
					betas := strings.Split(req.Header.Get("Anthropic-Beta"), ",")
					if got := slices.Contains(betas, claudeEffortBeta); got != upstream.wantEffort {
						t.Errorf("effort beta present = %v, want %v; betas=%v", got, upstream.wantEffort, betas)
					}
					if !slices.Contains(betas, "unrelated-test-2099-01-01") {
						t.Errorf("unrelated caller beta lost: %v", betas)
					}
					if !bytes.Equal(body, originalBody) {
						t.Errorf("header assembly changed the effort body: %s", body)
					}
				})
			}
		}
	}
}
