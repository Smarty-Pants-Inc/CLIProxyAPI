package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executionregistry"
)

// Keep reason: data safety, PR #174 N-9. Retirement may close the socket, but
// must not cancel the terminal-error consumer. Supervisor drains must still win.
func TestHomeStreamTerminalDeliveryR10(t *testing.T) {
	for _, end := range []string{"upstream_error", "upstream_disconnected", "consumer_rejected", "registry_close"} {
		t.Run(end, func(t *testing.T) {
			registry := executionregistry.New()
			pending, err := registry.BeginDispatch()
			if err != nil {
				t.Fatal(err)
			}
			scope, err := registry.Install(pending, executionregistry.ScopeSpec{})
			if err != nil {
				t.Fatal(err)
			}
			selection, err := newHomeDispatchSelection(&Auth{ID: "terminal-home"}, nil, "codex", scope)
			if err != nil {
				t.Fatal(err)
			}
			ctx, release, err := selection.AttemptContext(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer release()
			finish := selection.holdStreamTerminalDelivery()
			defer finish()
			if end == "registry_close" {
				if err := registry.Close(); err != nil {
					t.Fatal(err)
				}
			} else {
				selection.End(end)
			}
			held := end == "upstream_error" || end == "upstream_disconnected"
			if held && (ctx.Err() != nil || !selection.Active()) {
				t.Fatal("socket retirement canceled terminal delivery")
			}
			if !held && ctx.Err() == nil {
				t.Fatal("explicit stop or drain failed to cancel attempt")
			}
			finish()
			finish()
			if ctx.Err() == nil || selection.Active() && held {
				t.Fatal("finished terminal delivery did not end selection")
			}
		})
	}
}
