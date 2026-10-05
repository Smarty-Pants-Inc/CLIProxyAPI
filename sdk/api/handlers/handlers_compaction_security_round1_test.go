package handlers

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func TestHandlerCompactionSecurityRound1PublicRoots(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		for _, kind := range []string{"duplicates", "bytes", "blocks", "canceled"} {
			t.Run(path+"/"+kind, func(t *testing.T) {
				executor := &bootstrapStreamExecutor{stream: func(context.Context, int) (*coreexecutor.StreamResult, error) {
					t.Fatal("rejected input reached upstream stream")
					return nil, nil
				}}
				handler, manager := registerBootstrapExecutor(t, executor)
				origin := coreauth.NewSessionAffinitySelector(nil)
				defer origin.Stop()
				manager.SetSelector(origin)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				body := []byte(`{"model":"bootstrap-model","input":[{"role":"user","content":"ordinary"}]}`)
				switch kind {
				case "duplicates":
					body = []byte(`{"model":"bootstrap-model","input":[],"input":[]}`)
				case "bytes":
					body = []byte(`{"model":"bootstrap-model","input":[{"role":"user","content":"` + strings.Repeat("x", 16<<20) + `"}]}`)
				case "blocks":
					body = []byte(`{"model":"bootstrap-model","input":[` + strings.TrimSuffix(strings.Repeat(`{"type":"compaction","encrypted_content":"x"},`, 257), ",") + `]}`)
				case "canceled":
					cancel()
				}
				var msg *interfaces.ErrorMessage
				var payload []byte
				switch path {
				case "execute":
					payload, _, msg = handler.ExecuteWithAuthManager(ctx, "openai-response", "bootstrap-model", body, "")
				case "count":
					payload, _, msg = handler.ExecuteCountWithAuthManager(ctx, "openai-response", "bootstrap-model", body, "")
				case "stream":
					data, _, errs := handler.ExecuteStreamWithAuthManager(ctx, "openai-response", "bootstrap-model", body, "")
					if data != nil {
						for unit := range data {
							payload = append(payload, unit...)
						}
					}
					for terminal := range errs {
						msg = terminal
					}
				}
				var local *coreauth.Error
				if msg == nil || msg.StatusCode != http.StatusBadRequest || !coreauth.IsLocalCompactionAffinityStop(msg.Error) || !errors.As(msg.Error, &local) || local.Code != "compaction_json_rejected" {
					t.Fatalf("HTTP root lost JSON stop: %+v", msg)
				}
				if len(payload) != 0 || executor.Calls() != 0 {
					t.Fatal("rejected input was delivered/executed")
				}
				if kind == "canceled" && !errors.Is(msg.Error, context.Canceled) {
					t.Fatal("HTTP root lost cancellation cause")
				}
				for _, a := range manager.List() {
					if a.Unavailable || a.LastError != nil || !a.NextRetryAfter.IsZero() || len(a.ModelStates) != 0 {
						t.Fatal("HTTP local rejection cooled an account")
					}
				}
			})
		}
	}
}

func TestHandlerCompactionSecurityRound1OrdinaryAndMissingManager(t *testing.T) {
	for _, path := range []string{"execute", "count"} {
		t.Run(path, func(t *testing.T) {
			handler, manager := registerBootstrapExecutor(t, &bootstrapStreamExecutor{})
			origin := coreauth.NewSessionAffinitySelector(nil)
			defer origin.Stop()
			manager.SetSelector(origin)
			body := []byte(`{"model":"bootstrap-model","input":[{"role":"user","content":"ordinary"}]}`)
			var msg *interfaces.ErrorMessage
			if path == "execute" {
				_, _, msg = handler.ExecuteWithAuthManager(context.Background(), "openai-response", "bootstrap-model", body, "")
			} else {
				_, _, msg = handler.ExecuteCountWithAuthManager(context.Background(), "openai-response", "bootstrap-model", body, "")
			}
			var upstream *coreauth.Error
			if msg == nil || !errors.As(msg.Error, &upstream) || upstream.Code != "not_implemented" || coreauth.IsLocalCompactionAffinityStop(msg.Error) {
				t.Fatalf("ordinary input did not reach existing executor: %+v", msg)
			}
			handler.AuthManager = nil
			if path == "execute" {
				_, _, msg = handler.ExecuteWithAuthManager(context.Background(), "openai-response", "bootstrap-model", body, "")
			} else {
				_, _, msg = handler.ExecuteCountWithAuthManager(context.Background(), "openai-response", "bootstrap-model", body, "")
			}
			if msg == nil || coreauth.IsLocalCompactionAffinityStop(msg.Error) {
				t.Fatalf("missing manager became a compaction stop: %+v", msg)
			}
		})
	}
}
