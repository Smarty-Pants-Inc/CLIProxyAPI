package auth

import (
	"context"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"testing"
	"time"
)

func TestAPIKeyPolicyRetainedRequestReceiptRolloverAndTightening(t *testing.T) {
	m := NewManager(nil, nil, nil)
	cfg := policyTestConfig("allowed.json")
	cap := int64(2)
	cfg.APIKeyPolicies[0].DailyRequestCap = &cap
	m.SetConfig(cfg)
	now := time.Date(2026, 10, 1, 23, 59, 59, 0, time.UTC)
	m.apiKeyUsage.now = func() time.Time { return now }
	ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
	if _, err := m.AdmitClientRequest(ctx, "model"); err != nil {
		t.Fatal(err)
	}
	initial, err := m.AdmitClientRequest(ctx, "model")
	if err != nil {
		t.Fatal(err)
	} // ordinal2
	selected := &Auth{ID: "rollover-socket", Provider: "codex", FileName: "allowed.json"}
	handlerBound := coreexecutor.WithWebsocketContextAuthCheck(initial, func(admitted context.Context, id string) bool { return m.ValidateClientAuth(admitted, selected) == nil })
	bound := m.contextWithClientAuthCheck(handlerBound, selected)
	now = now.Add(time.Second)
	cap = 1
	m.SetConfig(cfg)
	turn, err := coreexecutor.AdmitWebsocketRequest(bound, "")
	if err != nil {
		t.Fatal("day-two first turn", err)
	}
	if err = m.ValidateClientRequest(coreexecutor.WebsocketAdmittedContext(turn), "model"); err != nil {
		t.Fatal("fresh receipt not propagated", err)
	}
	if err = coreexecutor.ValidateWebsocketRequest(turn, ""); err != nil {
		t.Fatal("turn callback reused old ordinal", err)
	}
	if !coreexecutor.WebsocketAuthEnabled(turn, selected.ID) {
		t.Fatal("manager/handler auth checks reused old ordinal")
	}
	_, err = coreexecutor.AdmitWebsocketRequest(bound, "")
	requireControlStatus(t, err, 429)
	cfg.APIKeyPolicies[0].AllowedAuths = nil
	m.SetConfig(cfg)
	if coreexecutor.WebsocketAuthEnabled(turn, selected.ID) {
		t.Fatal("new receipt suppressed credential revocation")
	}
}
