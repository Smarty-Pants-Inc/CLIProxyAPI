package live

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestRound2RetainedCallImmutableIdentity(t *testing.T) {
	for _, change := range []string{"email", "credential-lifetime", "same-account-refresh"} {
		t.Run(change, func(t *testing.T) {
			h, m, cfg, _, original := round2Policy(t, true)
			defer h.Close()
			cfg.APIKeyPolicies[0].AllowedAuths = []string{"*@example.com"}
			admitted := m.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), "synthetic-round2-key", cfg.APIKeyPolicies), "gpt-realtime")
			admitted = context.WithValue(admitted, liveModelInspectionContextKey{}, true)
			original.RegistrationEpoch = 1
			session := liveSession{authID: original.ID, admittedAuth: original.Clone(), policyContext: livePolicyContext(admitted)}
			m.SetConfig(&config.Config{})
			attach := context.WithValue(m.WithClientRequest(auth.WithClientAPIKeyPolicies(context.Background(), "synthetic-round2-key", nil), "gpt-realtime"), liveModelInspectionContextKey{}, true)
			replacement := original.Clone()
			switch change {
			case "email":
				replacement.Metadata["email"] = "replacement@example.com"
			case "credential-lifetime":
				replacement.RegistrationEpoch++
			case "same-account-refresh":
				replacement.Metadata["access_token"] = "synthetic-refreshed-same-account"
			}
			err := h.validateRetainedLiveAuth(attach, replacement, session)
			if change == "same-account-refresh" {
				if err != nil {
					t.Fatalf("same identity refresh denied: %v", err)
				}
			} else if err == nil {
				t.Fatal("different immutable credential identity accepted within broad allowlist")
			}
		})
	}
}
