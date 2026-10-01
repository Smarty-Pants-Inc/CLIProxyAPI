package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executionregistry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type filenamePolicyHomeDispatcher struct{ raw []byte }

func (filenamePolicyHomeDispatcher) HeartbeatOK() bool       { return true }
func (filenamePolicyHomeDispatcher) AbortAmbiguousDispatch() {}
func (d filenamePolicyHomeDispatcher) RPopAuth(context.Context, string, string, http.Header, int) ([]byte, error) {
	return d.raw, nil
}

func TestHomeDispatchFilenameOnlyPolicyJSON(t *testing.T) {
	for _, tc := range []struct {
		name     string
		basename string
		legacy   bool
		wantCode string
	}{
		{name: "trusted basename", basename: "verified.json"},
		{name: "legacy direct auth with explicit basename", basename: "verified.json", legacy: true},
		{name: "missing basename cannot grant by ID or label", wantCode: "api_key_policy_unavailable"},
		{name: "denied basename cannot grant by ID or label", basename: "denied.json", wantCode: "api_key_policy_unavailable"},
		{name: "unix path", basename: "/auth/verified.json", wantCode: "invalid_auth"},
		{name: "windows path", basename: `C:\auth\verified.json`, wantCode: "invalid_auth"},
		{name: "parent traversal", basename: "../verified.json", wantCode: "invalid_auth"},
		{name: "dot", basename: ".", wantCode: "invalid_auth"},
		{name: "dot dot", basename: "..", wantCode: "invalid_auth"},
		{name: "padded name", basename: " verified.json ", wantCode: "invalid_auth"},
		{name: "nul", basename: "verified.json\x00", wantCode: "invalid_auth"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			cfg := policyTestConfig("verified.json")
			cfg.Home.Enabled = true
			manager.SetConfig(cfg)
			manager.RegisterExecutor(&homeExecutionExecutor{})
			// FileName is intentionally json:"-". Only the explicit Home dispatch
			// field carries identity; IDs and labels are never credential filenames.
			auth := Auth{ID: "verified.json", Label: "verified.json", Provider: "home-execution", FileName: "verified.json"}
			payload := map[string]any{"auth": auth}
			if tc.legacy {
				payload = map[string]any{"id": auth.ID, "label": auth.Label, "provider": auth.Provider}
			}
			if tc.basename != "" {
				payload["auth_file_name"] = tc.basename
			}
			raw, errMarshal := json.Marshal(payload)
			if errMarshal != nil {
				t.Fatal(errMarshal)
			}
			manager.PublishHomeDispatch(filenamePolicyHomeDispatcher{raw: raw}, executionregistry.New(), 1)
			ctx := WithClientAPIKey(context.Background(), policyTestClientKey)
			selected, errSelection := manager.pickHomeDispatchSelection(ctx, "key-policy-model", cliproxyexecutor.Options{})
			if tc.wantCode == "" {
				if errSelection != nil || selected == nil {
					t.Fatalf("filename-only JSON dispatch denied: %v", errSelection)
				}
				defer selected.End("test_complete")
				if selected.CloneAuth().FileName != "verified.json" {
					t.Fatalf("trusted basename not restored: %q", selected.CloneAuth().FileName)
				}
				return
			}
			if selected != nil {
				selected.End("unexpected_selection")
				t.Fatal("invalid or denied filename granted selection through ID/label")
			}
			var authErr *Error
			// Selection deliberately sanitizes errors for a restricted caller.
			wantCode := tc.wantCode
			if wantCode == "invalid_auth" {
				wantCode = "api_key_policy_unavailable"
			}
			if !errors.As(errSelection, &authErr) || authErr.Code != wantCode {
				t.Fatalf("error = %v, want %s", errSelection, tc.wantCode)
			}
		})
	}
}
