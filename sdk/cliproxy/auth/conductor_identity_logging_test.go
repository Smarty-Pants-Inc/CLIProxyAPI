package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	internallogging "github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	log "github.com/sirupsen/logrus"
)

type identityLoggingStore struct{ persistFailureStore }

func (s *identityLoggingStore) Save(_ context.Context, auth *Auth) (string, error) {
	return "", fmt.Errorf("persist %s: permission denied; Bearer persist-secret-42 access_token=persist-token-42", auth.ID)
}

type identityLoggingRefreshExecutor struct {
	schedulerProviderTestExecutor
	err error
}

func (e *identityLoggingRefreshExecutor) Refresh(_ context.Context, auth *Auth) (*Auth, error) {
	if e.err != nil {
		return nil, e.err
	}
	updated := auth.Clone()
	updated.Metadata["access_token"] = "refreshed-access-token"
	return updated, nil
}

// Upstream's new persistence warnings must remain visible without undoing #5423.
// Exercise refresh/lifecycle paths, including debug logs and the active-token warning.
func TestConductorLifecycleRefreshLogsUseKeyedRedactedIdentity(t *testing.T) {
	for _, path := range []string{"register", "update", "refresh", "meta-refresh", "before-fallback", "active-refresh", "canceled-refresh"} {
		t.Run(path, func(t *testing.T) {
			hook := setupTestLoggerHook(t)
			log.SetLevel(log.DebugLevel)
			const authID = "claude-96a7ecf3-dev07@smartypants.ai.json"
			provider := "claude"
			if path == "meta-refresh" {
				provider = "meta"
			}
			auth := &Auth{
				ID: authID, FileName: "/auths/" + authID, Provider: provider, Status: StatusActive,
				Metadata: map[string]any{
					"access_token": "old-access-token", "refresh_token": "old-refresh-token",
					"expired": time.Now().Add(time.Hour).Format(time.RFC3339),
				},
			}
			manager := NewManager(&identityLoggingStore{}, nil, nil)
			if path == "register" {
				if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
					t.Fatal(errRegister)
				}
			} else {
				if _, errRegister := manager.Register(WithSkipPersist(context.Background()), auth); errRegister != nil {
					t.Fatal(errRegister)
				}
				hook.Reset()
				executor := &identityLoggingRefreshExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: provider}}
				if path == "before-fallback" || path == "active-refresh" {
					executor.err = fmt.Errorf("refresh %s: unavailable; Bearer refresh-secret-42 refresh_token=refresh-token-42", authID)
				} else if path == "canceled-refresh" {
					executor.err = context.Canceled
				}
				manager.RegisterExecutor(executor)
				switch path {
				case "update":
					if _, errUpdate := manager.Update(context.Background(), auth); errUpdate != nil {
						t.Fatal(errUpdate)
					}
				case "before-fallback":
					if _, refreshed := manager.tryRefreshAfterUnauthorized(context.Background(), auth, &Error{HTTPStatus: http.StatusUnauthorized}, false); refreshed {
						t.Fatal("failed refresh unexpectedly succeeded")
					}
				default:
					_, errRefresh := manager.ForceRefreshAuth(context.Background(), auth.ID)
					wantError := executor.err != nil || path == "meta-refresh"
					if (errRefresh != nil) != wantError {
						t.Fatalf("refresh error=%v, want error=%v", errRefresh, wantError)
					}
					if path == "canceled-refresh" && !errors.Is(errRefresh, context.Canceled) {
						t.Fatalf("lost refresh cancellation: %v", errRefresh)
					}
				}
			}
			formatter := &internallogging.LogFormatter{}
			sawKeyedDiagnostic := false
			for _, entry := range hook.AllEntries() {
				formatted, errFormat := formatter.Format(entry)
				if errFormat != nil {
					t.Fatal(errFormat)
				}
				line := string(formatted)
				for _, leak := range []string{authID, "dev07@smartypants.ai", "smartypants.ai", "96a7ecf3", "persist-secret-42", "persist-token-42", "refresh-secret-42", "refresh-token-42"} {
					if strings.Contains(line, leak) {
						t.Fatalf("log leaks %q: %s", leak, line)
					}
				}
				if _, exists := entry.Data["auth_id"]; exists {
					t.Fatal("raw auth_id field is present")
				}
				if _, exists := entry.Data["credential"]; exists {
					t.Fatal("raw credential field is present")
				}
				if strings.Contains(line, "auth_ref="+authLogRef(auth)) {
					sawKeyedDiagnostic = true
				}
			}
			if !sawKeyedDiagnostic {
				t.Fatal("lifecycle/refresh diagnostic lost its keyed reference")
			}
		})
	}
}
