package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

// A cutoff plugin (like quota-router) picks the lowest-ID unblocked account. A bound
// session must stay on its account while that account is under the cutoff, and move
// only when the plugin refuses it.
func TestPluginSchedulerPickKeepsBoundSessionUnlessPluginRefusesIt(t *testing.T) {
	manager := NewManager(nil, NewSessionAffinitySelector(&FillFirstSelector{}), nil)
	manager.executors["claude"] = schedulerTestExecutor{}
	for _, id := range []string{"claude-a", "claude-b"} {
		if _, errRegister := manager.Register(context.Background(), &Auth{ID: id, Provider: "claude"}); errRegister != nil {
			t.Fatalf("Register(%s) error = %v", id, errRegister)
		}
	}
	blocked := map[string]bool{}
	scheduler := &fakePluginScheduler{pick: func(_ context.Context, req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
		best := ""
		for _, c := range req.Candidates {
			if !blocked[c.ID] && (best == "" || c.ID < best) {
				best = c.ID
			}
		}
		if best == "" {
			return pluginapi.SchedulerPickResponse{}, true, errors.New("quota_router_exhausted")
		}
		return pluginapi.SchedulerPickResponse{Handled: true, AuthID: best}, true, nil
	}}
	manager.SetPluginScheduler(scheduler)
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Affinity": []string{"01a0e5a2-0000-7000-8000-000000000001"}}}
	pick := func() string {
		t.Helper()
		got, _, errPick := manager.pickNext(context.Background(), "claude", "", opts, nil)
		if errPick != nil || got == nil {
			t.Fatalf("pickNext() = %v, %v", got, errPick)
		}
		return got.ID
	}

	blocked["claude-a"] = true
	if got := pick(); got != "claude-b" {
		t.Fatalf("first pick = %s, want claude-b", got)
	}
	blocked["claude-a"] = false // claude-a recovers; the plugin alone would move the session back
	if got := pick(); got != "claude-b" {
		t.Fatalf("bound session moved to %s, want it kept on claude-b", got)
	}
	blocked["claude-b"] = true // bound account past its cutoff: the plugin decides
	if got := pick(); got != "claude-a" {
		t.Fatalf("pick with bound account past cutoff = %s, want claude-a", got)
	}
	blocked["claude-b"] = false
	if got := pick(); got != "claude-a" {
		t.Fatalf("session did not stay on its new binding: got %s, want claude-a", got)
	}
}

// A cutoff plugin without the across-priorities opt-in is offered only the highest
// available tier. A session bound to a lower-priority account while the higher one
// cooled must stay there after the higher account recovers, unless the plugin refuses
// the bound account. Covered for single-provider and mixed-provider selection.
func TestPluginSchedulerPickKeepsLowerPriorityBindingAfterHigherPriorityRecovers(t *testing.T) {
	for _, tc := range []struct {
		name      string
		providers map[string]string // auth ID -> provider
		pick      func(*Manager, cliproxyexecutor.Options) (*Auth, error)
	}{
		{
			name:      "single-provider",
			providers: map[string]string{"acct-a": "claude", "acct-b": "claude"},
			pick: func(m *Manager, opts cliproxyexecutor.Options) (*Auth, error) {
				got, _, err := m.pickNext(context.Background(), "claude", "", opts, nil)
				return got, err
			},
		},
		{
			name:      "mixed-provider",
			providers: map[string]string{"acct-a": "codex", "acct-b": "claude"},
			pick: func(m *Manager, opts cliproxyexecutor.Options) (*Auth, error) {
				got, _, _, err := m.pickNextMixed(context.Background(), []string{"codex", "claude"}, "", opts, nil)
				return got, err
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manager := NewManager(nil, NewSessionAffinitySelector(&FillFirstSelector{}), nil)
			manager.executors["claude"] = schedulerTestExecutor{provider: "claude"}
			manager.executors["codex"] = schedulerTestExecutor{provider: "codex"}
			// acct-a has the higher priority and starts cooling.
			priorities := map[string]string{"acct-a": "1", "acct-b": "0"}
			for id, provider := range tc.providers {
				auth := &Auth{ID: id, Provider: provider, Attributes: map[string]string{"priority": priorities[id]}}
				if id == "acct-a" {
					auth.Unavailable = true
					auth.Status = StatusError
					auth.NextRetryAfter = time.Now().Add(time.Hour)
				}
				if _, errRegister := manager.Register(context.Background(), auth); errRegister != nil {
					t.Fatalf("Register(%s) error = %v", id, errRegister)
				}
			}
			blocked := map[string]bool{}
			var offered [][]string
			manager.SetPluginScheduler(&fakePluginScheduler{pick: func(_ context.Context, req pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
				ids := []string{}
				best := ""
				for _, c := range req.Candidates {
					ids = append(ids, c.ID)
					if !blocked[c.ID] && (best == "" || c.ID < best) {
						best = c.ID
					}
				}
				offered = append(offered, ids)
				if best == "" {
					return pluginapi.SchedulerPickResponse{}, true, errors.New("quota_router_exhausted")
				}
				return pluginapi.SchedulerPickResponse{Handled: true, AuthID: best}, true, nil
			}})
			opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Affinity": []string{"01a0e5a2-0000-7000-8000-0000000000" + map[string]string{"single-provider": "02", "mixed-provider": "03"}[tc.name]}}}
			pick := func() string {
				t.Helper()
				got, errPick := tc.pick(manager, opts)
				if errPick != nil || got == nil {
					t.Fatalf("pick = %v, %v", got, errPick)
				}
				return got.ID
			}

			if got := pick(); got != "acct-b" {
				t.Fatalf("first pick = %s, want acct-b while acct-a cools", got)
			}
			manager.mu.Lock()
			a := manager.auths["acct-a"]
			a.Unavailable, a.Status, a.NextRetryAfter = false, StatusActive, time.Time{}
			manager.mu.Unlock()
			offered = nil
			if got := pick(); got != "acct-b" {
				t.Fatalf("after higher-priority recovery the session moved to %s, want acct-b (offered %v)", got, offered)
			}
			if len(offered) != 2 || len(offered[1]) != 1 || offered[1][0] != "acct-b" {
				t.Fatalf("plugin must be asked about the bound account alone; offered %v", offered)
			}
			blocked["acct-b"] = true // plugin refuses the bound account: failover allowed
			if got := pick(); got != "acct-a" {
				t.Fatalf("pick with bound account refused = %s, want acct-a", got)
			}
		})
	}
}
