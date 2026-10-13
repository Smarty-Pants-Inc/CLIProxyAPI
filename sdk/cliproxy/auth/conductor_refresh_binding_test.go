package auth

import (
	"context"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type bindingRefreshExecutor struct {
	schedulerProviderTestExecutor
	started chan struct{}
	release chan struct{}
	err     error
}

func (e *bindingRefreshExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	close(e.started)
	select {
	case <-e.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if e.err != nil {
		return nil, e.err
	}
	auth.Metadata["access_token"] = "late-refreshed-token"
	auth.Metadata["refresh_token"] = "late-refresh-token"
	auth.Metadata["account_id"] = "old-account"
	auth.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	return auth, nil
}

func startBindingRefresh(t *testing.T, m *Manager, e *bindingRefreshExecutor, id string) func() {
	t.Helper()
	done := make(chan struct{})
	go func() {
		m.refreshAuth(context.Background(), id)
		close(done)
	}()
	var once sync.Once
	finish := func() {
		once.Do(func() { close(e.release) })
		<-done
	}
	t.Cleanup(finish)
	<-e.started
	return finish
}

func TestManager_RefreshAuth_RejectsConcurrentMaterialReplacement(t *testing.T) {
	for _, outcome := range []string{"success", "unauthorized", "transient"} {
		for _, change := range []string{"token-account", "access-token", "refresh-token", "id-token", "account", "api-key", "dca-token", "attribute-dca-token", "provider", "endpoint"} {
			t.Run(outcome+"/"+change, func(t *testing.T) {
				ctx := context.Background()
				store := newMemoryAuthTestStore()
				m := NewManager(store, nil, nil)
				e := &bindingRefreshExecutor{
					schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "codex"},
					started:                       make(chan struct{}), release: make(chan struct{}),
				}
				if outcome == "unauthorized" {
					e.err = &Error{Code: "unauthorized", Message: "old refresh rejected", HTTPStatus: 401}
				} else if outcome == "transient" {
					e.err = &Error{Message: "old refresh failed", HTTPStatus: 503}
				}
				m.RegisterExecutor(e)
				base, errRegister := m.Register(ctx, &Auth{
					ID: "binding-replacement", Provider: "codex", Status: StatusActive,
					Attributes: map[string]string{"base_url": "https://fixed.example"},
					Metadata: map[string]any{
						"access_token": "old-token", "refresh_token": "old-refresh", "id_token": "old-id-token",
						"account_id": "old-account", "expired": time.Now().Add(time.Hour).Format(time.RFC3339),
					},
				})
				if errRegister != nil {
					t.Fatal(errRegister)
				}
				finish := startBindingRefresh(t, m, e, base.ID)
				replacement, _ := m.GetByID(base.ID)
				switch change {
				case "token-account":
					replacement.Metadata["access_token"] = "replacement-token"
					replacement.Metadata["account_id"] = "replacement-account"
				case "access-token":
					replacement.Metadata["access_token"] = "replacement-token"
				case "refresh-token":
					replacement.Metadata["refresh_token"] = "replacement-refresh"
				case "id-token":
					replacement.Metadata["id_token"] = "replacement-id-token"
				case "account":
					replacement.Metadata["account_id"] = "replacement-account"
				case "api-key":
					replacement.Attributes["api_key"] = "replacement-api-key"
				case "dca-token":
					replacement.Metadata["dca_token"] = "replacement-device-token"
				case "attribute-dca-token":
					replacement.Attributes["dca_token"] = "replacement-device-token"
				case "provider":
					replacement.Provider = "antigravity"
				case "endpoint":
					replacement.Attributes["base_url"] = "https://replacement.example"
				}
				saved, errUpdate := m.Update(ctx, replacement)
				if errUpdate != nil {
					t.Fatal(errUpdate)
				}
				if saved.RegistrationEpoch != base.RegistrationEpoch || saved.Generation <= base.Generation {
					t.Fatal("test must exercise ordinary same-epoch Update, not re-registration")
				}
				finish()
				current, _ := m.GetByID(base.ID)
				if !reflect.DeepEqual(current, saved) {
					t.Errorf("late %s refresh mutated completed %s replacement: generation %d -> %d, token=%v account=%v", outcome, change, saved.Generation, current.Generation, current.Metadata["access_token"], current.Metadata["account_id"])
				}
				store.mu.Lock()
				persisted := store.auths[base.ID].Clone()
				store.mu.Unlock()
				if !reflect.DeepEqual(persisted, saved) {
					t.Error("late refresh changed persisted replacement")
				}
				if change == "token-account" && outcome == "success" {
					assertReplacementPolicySend(t, m, base.ID)
				}
			})
		}
	}
}

// Exercise the consumers after publication, not a Register replacement after selection.
func assertReplacementPolicySend(t *testing.T, m *Manager, id string) {
	t.Helper()
	const model = "refresh-binding-model"
	policy := config.APIKeyPolicy{KeySHA256: keyDigest("refresh-client"), AllowedAuths: []string{id}}
	m.SetConfig(&config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{policy}}})
	registry.GetGlobalRegistry().RegisterClient(id, "codex", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	ctx, release, errBegin := m.BeginKeyPolicy(context.Background(), []config.APIKeyPolicy{policy}, model)
	if errBegin != nil {
		t.Fatal(errBegin)
	}
	defer release()
	selected, _, errSelect := KeyPolicyFromContext(ctx).selectExecutor(ex.Request{Model: model}, ex.Options{})
	if errSelect != nil {
		t.Fatal(errSelect)
	}
	if selected.Metadata["access_token"] != "replacement-token" || selected.Metadata["account_id"] != "replacement-account" {
		t.Error("restricted selection consumed obsolete/mixed refresh material")
	}
	req := httptest.NewRequest("POST", "https://fixed.example/responses", strings.NewReader(`{"model":"refresh-binding-model"}`)).WithContext(ctx)
	req.Header.Set("Authorization", "Bearer replacement-token")
	req.Header.Set("Chatgpt-Account-Id", "replacement-account")
	if errSend := CheckKeyPolicySend(req); errSend != nil {
		t.Errorf("replacement final send rejected: %v", errSend)
	}
}

func TestManager_RefreshAuth_BindingFenceAllowsNoteAndProxyMerge(t *testing.T) {
	ctx := context.Background()
	store := newMemoryAuthTestStore()
	m := NewManager(store, nil, nil)
	e := &bindingRefreshExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "codex"}, started: make(chan struct{}), release: make(chan struct{})}
	m.RegisterExecutor(e)
	base, errRegister := m.Register(ctx, &Auth{ID: "benign-binding-update", Provider: "codex", Status: StatusActive, Metadata: map[string]any{"access_token": "old-token", "account_id": "old-account", "note": "old-note"}})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	finish := startBindingRefresh(t, m, e, base.ID)
	current, _ := m.GetByID(base.ID)
	current.Metadata["note"] = "new-note"
	current.ProxyURL = "http://new-proxy.example:8080"
	current.Metadata["proxy_url"] = current.ProxyURL
	if _, errUpdate := m.Update(ctx, current); errUpdate != nil {
		t.Fatal(errUpdate)
	}
	finish()
	current, _ = m.GetByID(base.ID)
	if current.Metadata["access_token"] != "late-refreshed-token" || current.Metadata["refresh_token"] != "late-refresh-token" || current.LastRefreshedAt.IsZero() {
		t.Fatal("benign edit incorrectly fenced successful refresh")
	}
	if current.Metadata["note"] != "new-note" || current.ProxyURL != "http://new-proxy.example:8080" || current.Metadata["proxy_url"] != current.ProxyURL {
		t.Fatal("refresh lost concurrent note/proxy update")
	}
	store.mu.Lock()
	persisted := store.auths[base.ID].Clone()
	store.mu.Unlock()
	if !reflect.DeepEqual(persisted, current) {
		t.Fatal("merged refresh was not persisted")
	}
}
