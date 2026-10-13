package auth

import (
	"context"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// CPA#22 Astra round 4 P1: a restricted key's allow-list is not signer
// authority. A-signed compaction input runs only on A, even when the policy
// orders B first, and policy-produced signed output is published before delivery.
func TestKeyPolicyHonoursCompactionSignerAndPublishesOutput(t *testing.T) {
	for _, producer := range []string{"unrestricted", "policy"} {
		for _, path := range []string{"execute", "stream"} {
			t.Run(producer+"/"+path, func(t *testing.T) {
				model := "key-policy-compaction-model"
				a, b := t.Name()+"-a", t.Name()+"-b"
				selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: &compactionAffinityFallback{preferredID: a}})
				defer selector.Stop()
				executor := &compactionAffinityExecutor{
					provider: "codex", firstID: a,
					output: []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`),
					streamOutput: [][]byte{
						[]byte(`data: {"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"signed-`),
						[]byte("block\"}}\n\n"),
					},
				}
				m := newCompactionAffinityManager(t, selector, executor, model, b)
				m.SetConfig(&config.Config{})

				// run mirrors the Responses handler: it prepares compaction
				// authority, then dispatches through the Manager.
				run := func(allowed []string, compacted bool) error {
					t.Helper()
					ctx := context.Background()
					if allowed != nil {
						var done func()
						var err error
						ctx, done, err = m.BeginKeyPolicy(ctx, []config.APIKeyPolicy{{KeySHA256: keyDigest("key"), AllowedAuths: allowed}}, model)
						if err != nil {
							t.Fatalf("BeginKeyPolicy: %v", err)
						}
						defer done()
					}
					req, opts := compactionAffinityRequest(model, "none", compacted, false)
					opts, err := m.PrepareCompactionRequest(req.Model, opts, ctx)
					if err != nil {
						return err
					}
					if path == "execute" {
						_, err = m.Execute(ctx, []string{"codex"}, req, opts)
						return err
					}
					opts.Stream = true
					stream, err := m.ExecuteStream(ctx, []string{"codex"}, req, opts)
					if err != nil {
						return err
					}
					var terminal error
					for chunk := range stream.Chunks {
						if chunk.Err != nil {
							terminal = chunk.Err
						}
					}
					return terminal
				}
				onlyA := func(step, pinned string) {
					t.Helper()
					if len(executor.attempts) != 1 || executor.attempts[0].authID != a || executor.attempts[0].pinned != pinned {
						t.Fatalf("%s: attempts=%#v, want exactly one on A", step, executor.attempts)
					}
					executor.attempts = nil
				}

				// A produces signed output (no seeded evidence).
				var allowed []string
				if producer == "policy" {
					allowed = []string{a, b}
				}
				if err := run(allowed, false); err != nil {
					t.Fatalf("produce on A: %v", err)
				}
				onlyA("produce", "")

				// A healthy and allowed, policy orders B first: execute on A only.
				executor.output, executor.streamOutput = nil, nil
				if err := run([]string{b, a}, true); err != nil {
					t.Fatalf("replay [B,A]: %v", err)
				}
				onlyA("replay [B,A]", a)

				// A excluded by policy: local refusal, zero B writes.
				if err := run([]string{b}, true); err == nil || len(executor.attempts) != 0 {
					t.Fatalf("replay [B]: err=%v attempts=%#v, want refusal and zero attempts", err, executor.attempts)
				}

				// A unavailable: local refusal, zero B writes.
				if _, err := m.Update(context.Background(), &Auth{ID: a, Provider: "codex", Status: StatusDisabled, Disabled: true}); err != nil {
					t.Fatalf("disable A: %v", err)
				}
				if err := run([]string{b, a}, true); err == nil || len(executor.attempts) != 0 {
					t.Fatalf("replay with A unavailable: err=%v attempts=%#v, want refusal and zero attempts", err, executor.attempts)
				}
			})
		}
	}
}
