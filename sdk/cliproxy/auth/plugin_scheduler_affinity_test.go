package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"

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
