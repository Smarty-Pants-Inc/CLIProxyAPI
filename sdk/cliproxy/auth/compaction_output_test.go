package auth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

const producedCompaction = `{"type":"compaction","encrypted_content":"signed-block"}`

func TestCompactionOutputKeysMatchInputPerBlock(t *testing.T) {
	want := compactionBlockKeys(gjson.Parse("[" + producedCompaction + "]"))
	for name, payload := range map[string]string{
		"compact":   `{"output":[` + producedCompaction + `]}`,
		"wrapped":   `{"response":{"output":[` + producedCompaction + `]}}`,
		"added":     `{"type":"response.output_item.added","item":` + producedCompaction + `}`,
		"done":      `{"type":"response.output_item.done","item":` + producedCompaction + `}`,
		"completed": `{"type":"response.completed","response":{"output":[` + producedCompaction + `]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			keys := compactionOutputKeys([]byte(payload))
			if len(keys) != 1 || keys[0] != want[0] {
				t.Fatalf("output keys = %v, want input per-block keys %v", keys, want)
			}
		})
	}
	for _, payload := range []string{
		`{"type":"response.output_item.added","item":{"type":"compaction"}}`,
		`{"output":[{"type":"message","encrypted_content":"not-compaction"}]}`,
		`{"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"unfinished`,
	} {
		if keys := compactionOutputKeys([]byte(payload)); len(keys) != 0 {
			t.Fatalf("incomplete/unsigned output attributed: %v", keys)
		}
	}
}

func TestRecordCompactionOutputKeepsIndependentProtectedGroups(t *testing.T) {
	statePath := filepath.Join(t.TempDir(), "affinity.state")
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: statePath})
	defer selector.Stop()
	_, opts := compactionAffinityRequest("model", "Session-Id", false, true)
	opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] = "mixed"
	opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] = "model"
	var blocks []string
	for i := 0; i < 80; i++ {
		blocks = append(blocks, fmt.Sprintf(`{"type":"compaction","encrypted_content":"signed-%d"}`, i))
	}
	payload := []byte(`{"output":[` + strings.Join(blocks, ",") + `]}`)
	if errSave := selector.RecordCompactionOutput("A", opts, payload); errSave != nil {
		t.Fatal(errSave)
	}
	keys := compactionOutputKeys(payload)
	if len(keys) != 80 {
		t.Fatalf("keys = %d, want all 80 blocks (not a 64-alias group)", len(keys))
	}
	for _, key := range keys {
		if authID, ok := selector.cache.Get(key); !ok || authID != "A" || !selector.cache.IsProtected(key) {
			t.Fatalf("signer not protected: %s = %s, %v", key, authID, ok)
		}
		selector.cache.mu.RLock()
		aliases := append([]string(nil), selector.cache.entries[key].aliases...)
		selector.cache.mu.RUnlock()
		if len(aliases) != 1 || aliases[0] != key {
			t.Fatalf("signer merged into mutable/other signer aliases: %v", aliases)
		}
	}
	primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	primaryKey := "mixed::" + cliproxysession.BoundSessionIdentity(primaryID) + "::model"
	if !selector.cache.IsProtected(primaryKey) {
		t.Fatal("output production did not independently protect explicit primary")
	}
	if errConflict := selector.RecordCompactionOutput("B", opts, payload); errConflict == nil {
		t.Fatal("same signed blocks were reassigned to B")
	}
	selector.Stop()
	state, errRead := os.ReadFile(statePath)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if bytes.Contains(state, []byte("signed-")) {
		t.Fatal("persisted raw encrypted output")
	}
	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: statePath})
	defer restarted.Stop()
	for _, key := range keys {
		if authID, ok := restarted.cache.Get(key); !ok || authID != "A" || !restarted.cache.IsProtected(key) {
			t.Fatalf("output signer lost on restart: %s = %s, %v", key, authID, ok)
		}
	}
}

func TestCompactionOutputStreamRegistersBeforeForwardingAcrossEverySplit(t *testing.T) {
	for _, event := range []string{
		`{"type":"response.output_item.added","item":` + producedCompaction + `}`,
		`{"type":"response.output_item.done","item":` + producedCompaction + `}`,
		`{"type":"response.completed","response":{"output":[` + producedCompaction + `]}}`,
	} {
		for _, wire := range []string{
			"data: " + event + "\n\n",
			"event: response\r\ndata: " + event + "\r\n\r\n",
			": keepalive\r\nid: response-id\nretry: 1000\nevent: response\ndata: " + event + "\n\n",
			"data: " + event, // executor's delimiter-free SSE event
			event,            // native websocket event
		} {
			for split := 1; split < len(wire); split++ {
				registered := false
				observer := &compactionOutputStream{record: func(payload []byte) error {
					if len(compactionOutputKeys(payload)) > 0 {
						registered = true
					}
					return nil
				}}
				var delivered []byte
				for _, part := range []string{wire[:split], wire[split:]} {
					ready, errSave := observer.push([]byte(part))
					if errSave != nil {
						t.Fatal(errSave)
					}
					delivered = append(delivered, ready...)
					if bytes.Contains(delivered, []byte(event)) && !registered {
						t.Fatalf("split %d exposed complete event before registration", split)
					}
				}
				delivered = append(delivered, observer.pending...)
				if !registered || string(delivered) != wire {
					t.Fatalf("split %d: registered=%v wire altered: %q", split, registered, delivered)
				}
			}
		}
	}
}

func TestCompactionOutputStreamPassesLeadingHeartbeatsImmediately(t *testing.T) {
	for _, heartbeat := range []string{": ping", ": ping\n", ": ping\r\n: pong\n", "event: response.created", "id: response-id", "retry: 1000"} {
		records := 0
		observer := &compactionOutputStream{record: func([]byte) error {
			records++
			return nil
		}}
		ready, errSave := observer.push([]byte(heartbeat))
		if errSave != nil || string(ready) != heartbeat || records != 0 || len(observer.pending) != 0 {
			t.Fatalf("heartbeat held/parsed: ready=%q err=%v records=%d pending=%q", ready, errSave, records, observer.pending)
		}
	}
	observer := &compactionOutputStream{record: func([]byte) error { return nil }}
	ready, errSave := observer.push([]byte(": ping\n" + `data: {"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"signed-`))
	if errSave != nil || string(ready) != ": ping\n" || len(observer.pending) == 0 {
		t.Fatalf("heartbeat did not pass ahead of partial data: %q, %v", ready, errSave)
	}
}

func TestCompactionOutputStreamSaveFailureWithholdsCompleteBlock(t *testing.T) {
	failure := errors.New("disk save failed")
	observer := &compactionOutputStream{record: func(payload []byte) error {
		if len(compactionOutputKeys(payload)) > 0 {
			return failure
		}
		return nil
	}}
	first := []byte(`data: {"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"signed-`)
	if ready, errSave := observer.push(first); len(ready) != 0 || errSave != nil {
		t.Fatalf("partial event released: %q, %v", ready, errSave)
	}
	if ready, errSave := observer.push([]byte("block\"}}\n\n")); len(ready) != 0 || !errors.Is(errSave, failure) {
		t.Fatalf("save failure released block: %q, %v", ready, errSave)
	}
}

func TestManagerPluginCompactionProductionSurvivesRestartBeforeReplay(t *testing.T) {
	for _, path := range []string{"execute", "stream-start", "stream-bootstrap"} {
		for _, identity := range []string{"none", "Session-Id"} {
			t.Run(path+"/"+identity, func(t *testing.T) {
				firstID, secondID := t.Name()+"-A", t.Name()+"-B"
				model := "plugin-compaction-output-model"
				statePath := filepath.Join(t.TempDir(), "affinity.state")
				selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
					Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath,
				})
				defer selector.Stop()
				executor := &compactionAffinityExecutor{
					provider: "codex", firstID: firstID, bootstrapChunk: path == "stream-bootstrap",
					output: []byte(`{"output":[` + producedCompaction + `]}`),
					streamOutput: [][]byte{
						[]byte(`data: {"type":"response.completed","response":{"output":[`),
						[]byte(producedCompaction + "]}}\n\n"),
					},
				}
				manager := newCompactionAffinityManager(t, selector, executor, model, secondID)
				plugin := &fakePluginScheduler{handled: true, resp: pluginapi.SchedulerPickResponse{Handled: true, AuthID: firstID}}
				manager.SetPluginScheduler(plugin)
				req, opts := compactionAffinityRequest(model, identity, false, true)
				if path == "execute" {
					opts.Alt = "responses/compact"
				}
				if errProduce := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errProduce != nil {
					t.Fatal(errProduce)
				}
				if plugin.calls == 0 || len(executor.attempts) != 1 || executor.attempts[0].authID != firstID {
					t.Fatalf("plugin did not actually produce on A: calls=%d attempts=%v", plugin.calls, executor.attempts)
				}
				selector.Stop()
				restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
					Fallback: &compactionAffinityFallback{preferredID: secondID}, StatePath: statePath,
				})
				defer restarted.Stop()
				manager = newCompactionAffinityManager(t, restarted, executor, model, secondID)
				manager.SetPluginScheduler(&fakePluginScheduler{
					handled: true,
					pick: func(_ context.Context, request pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
						if len(request.Candidates) != 1 || request.Candidates[0].ID != firstID {
							t.Fatalf("signed replay exposed other accounts to plugin: %+v", request.Candidates)
						}
						return pluginapi.SchedulerPickResponse{Handled: true, AuthID: firstID}, true, nil
					},
				})
				executor.output, executor.streamOutput = nil, nil
				executor.attempts = nil
				executor.failure = compactTestStatusError{code: http.StatusServiceUnavailable, msg: "A unavailable"}
				// Fresh options: no explicit ID or selector-produced metadata.
				req, opts = compactionAffinityRequest(model, identity, true, false)
				errReplay := runCompactionAffinityRequest(t, manager, executor, path, req, opts)
				var statusErr cliproxyexecutor.StatusError
				if !errors.As(errReplay, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
					t.Fatalf("first replay = %v, want A's upstream failure", errReplay)
				}
				assertCompactionAffinityOnlyA(t, executor, true)
				if len(executor.attempts) != 1 {
					t.Fatalf("first replay attempts = %v, want exactly A", executor.attempts)
				}
				if identity != "none" {
					executor.attempts = nil
					req, opts = compactionAffinityRequest(model, identity, false, true)
					if errOmitted := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errOmitted == nil {
						t.Fatal("block-omitting request moved the compacted explicit conversation")
					}
					assertCompactionAffinityOnlyA(t, executor, true)
				}
			})
		}
	}
}

func TestManagerCompactionOutputSaveFailureDoesNotCoolCredential(t *testing.T) {
	for _, path := range []string{"execute", "stream-start"} {
		t.Run(path, func(t *testing.T) {
			firstID, secondID := t.Name()+"-A", t.Name()+"-B"
			selector := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: firstID})
			defer selector.Stop()
			executor := &compactionAffinityExecutor{
				provider: "codex", firstID: firstID,
				output:       []byte(`{"output":[` + producedCompaction + `]}`),
				streamOutput: [][]byte{[]byte("data: {\"type\":\"response.output_item.done\",\"item\":" + producedCompaction + "}\n\n")},
				onExecute: func() {
					// Deterministically fail only after selection/upstream success.
					selector.cache.mu.Lock()
					selector.cache.persistenceErr = errors.New("save failed")
					selector.cache.mu.Unlock()
				},
			}
			manager := newCompactionAffinityManager(t, selector, executor, "save-failure-model", secondID)
			hook := &recordingHook{}
			manager.hook = hook
			req, opts := compactionAffinityRequest("save-failure-model", "none", false, false)
			errSave := runCompactionAffinityRequest(t, manager, executor, path, req, opts)
			var statusErr cliproxyexecutor.StatusError
			if !errors.As(errSave, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
				t.Fatalf("local save failure = %v, want 503", errSave)
			}
			if path == "stream-start" && (!isRequestStopError(errSave) || !IsLocalCompactionAffinityStop(errSave)) {
				t.Fatal("local streamed save failure lost request-stop marker")
			}
			if hook.lastResult.Load() != nil {
				t.Fatal("local save failure was published as an upstream result")
			}
			if len(executor.attempts) != 1 || executor.attempts[0].authID != firstID {
				t.Fatalf("save failure retried on another credential: %v", executor.attempts)
			}
			auth, ok := manager.GetByID(firstID)
			if !ok || auth.Unavailable || !auth.NextRetryAfter.IsZero() {
				t.Fatalf("local error poisoned credential availability: %+v", auth)
			}
		})
	}
}

func TestManagerHomeSkipsLocalCompactionOutputStore(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
	payload := []byte(`{"output":[` + producedCompaction + `]}`)
	if errSave := manager.RecordCompactionOutput("home-A", cliproxyexecutor.Options{}, payload); errSave != nil {
		t.Fatal(errSave)
	}
	for _, key := range compactionOutputKeys(payload) {
		if _, known := selector.cache.Get(key); known {
			t.Fatal("Home output leaked into local affinity store")
		}
	}
}

func TestManagerStreamCompactionRegisteredBeforeConsumerSeesEvent(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	_, opts := compactionAffinityRequest("model", "none", false, false)
	wire := "data: {\"type\":\"response.output_item.done\",\"item\":" + producedCompaction + "}\n\n"
	chunks := make(chan cliproxyexecutor.StreamChunk, 2)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(wire[:len(wire)/2])}
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(wire[len(wire)/2:])}
	close(chunks)
	stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "A"}, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, opts)
	var delivered []byte
	for chunk := range stream.Chunks {
		if chunk.Err != nil {
			t.Fatal(chunk.Err)
		}
		delivered = append(delivered, chunk.Payload...)
		if bytes.Contains(delivered, []byte(producedCompaction)) {
			for _, key := range compactionBlockKeys(gjson.Parse("[" + producedCompaction + "]")) {
				if authID, known := selector.cache.Get(key); !known || authID != "A" || !selector.cache.IsProtected(key) {
					t.Fatal("consumer observed signed block before protected registration")
				}
			}
		}
	}
	if string(delivered) != wire {
		t.Fatalf("wire bytes changed: %q", delivered)
	}
}

func TestManagerCompactionOutputUsesOriginStoreAndActualInFlightAuth(t *testing.T) {
	for _, transition := range []string{"replacement", "disabled", "home"} {
		for _, path := range []string{"execute", "stream-start"} {
			t.Run(transition+"/"+path, func(t *testing.T) {
				firstID, secondID := t.Name()+"-A", t.Name()+"-B"
				origin := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: firstID})
				defer origin.Stop()
				current := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: secondID})
				defer current.Stop()
				wire := "data: {\"type\":\"response.output_item.done\",\"item\":" + producedCompaction + "}\n\n"
				executor := &compactionAffinityExecutor{
					provider: "codex", firstID: firstID,
					output:       []byte(`{"output":[` + producedCompaction + `]}`),
					streamOutput: [][]byte{[]byte(wire[:len(wire)/2]), []byte(wire[len(wire)/2:])},
				}
				manager := newCompactionAffinityManager(t, origin, executor, "in-flight-output-model", secondID)
				executor.onExecute = func() {
					if transition == "replacement" {
						manager.SetSelector(current)
					} else {
						manager.SetSelector(&RoundRobinSelector{})
						if transition == "home" {
							manager.SetConfig(&internalconfig.Config{Home: internalconfig.HomeConfig{Enabled: true}})
						}
					}
				}
				req, opts := compactionAffinityRequest("in-flight-output-model", "none", false, false)
				if errProduce := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errProduce != nil {
					t.Fatal(errProduce)
				}
				for _, key := range compactionOutputKeys(executor.output) {
					if authID, known := origin.cache.Get(key); !known || authID != firstID || !origin.cache.IsProtected(key) {
						t.Fatalf("origin did not record actual in-flight A: %s, %v", authID, known)
					}
					if _, misrouted := current.cache.Get(key); misrouted {
						t.Fatal("output was written to replacement store instead of origin")
					}
				}
			})
		}
	}
}

func TestManagerNoAffinityStreamPassesChunksUnchanged(t *testing.T) {
	for _, format := range []sdktranslator.Format{sdktranslator.FormatOpenAIResponse, sdktranslator.FormatCodex} {
		manager := NewManager(nil, &RoundRobinSelector{}, nil)
		payloads := [][]byte{[]byte(": ping\n"), []byte("data: {\"type\":\"response.created\","), []byte("\"response\":{}}\n\n")}
		chunks := make(chan cliproxyexecutor.StreamChunk, len(payloads))
		for _, payload := range payloads {
			chunks <- cliproxyexecutor.StreamChunk{Payload: payload}
		}
		close(chunks)
		stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "A"}, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, cliproxyexecutor.Options{SourceFormat: format})
		index := 0
		for chunk := range stream.Chunks {
			if chunk.Err != nil || index >= len(payloads) || !bytes.Equal(chunk.Payload, payloads[index]) {
				t.Fatalf("no-affinity chunk %d was buffered/changed: %q, %v", index, chunk.Payload, chunk.Err)
			}
			index++
		}
		if index != len(payloads) {
			t.Fatalf("no-affinity chunks = %d, want %d", index, len(payloads))
		}
	}
}

// Exercise signer loss and list-shape attacks through the public Manager, not
// through direct selector seeding. Every signed item first comes from an actual
// successful executor response on its claimed account.
func TestManagerCompactionSignerEvidenceCannotBeGuessed(t *testing.T) {
	for _, path := range []string{"execute", "stream-start", "stream-bootstrap"} {
		for _, scenario := range []string{"expired", "evicted", "duplicate", "conflicting"} {
			t.Run(path+"/"+scenario, func(t *testing.T) {
				firstID, secondID := t.Name()+"-A", t.Name()+"-B"
				model := "public-signer-evidence-model"
				fallback := &compactionAffinityFallback{preferredID: firstID}
				selector := NewSessionAffinitySelector(fallback)
				defer selector.Stop()
				executor := &compactionAffinityExecutor{
					provider: "codex", firstID: firstID, bootstrapChunk: path == "stream-bootstrap",
				}
				manager := newCompactionAffinityManager(t, selector, executor, model, secondID)

				produce := func(block, authID, identity string) string {
					t.Helper()
					executor.output = []byte(`{"output":[` + block + `]}`)
					wire := "data: {\"type\":\"response.output_item.done\",\"item\":" + block + "}\n\n"
					executor.streamOutput = [][]byte{[]byte(wire[:len(wire)/2]), []byte(wire[len(wire)/2:])}
					req, opts := compactionAffinityRequest(model, "Session-Id", false, true)
					opts.Headers.Set("Session-Id", identity)
					opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = authID
					executor.attempts = nil
					if errProduce := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errProduce != nil {
						t.Fatalf("producing block on %s: %v", authID, errProduce)
					}
					if len(executor.attempts) != 1 || executor.attempts[0].authID != authID {
						t.Fatalf("block was not actually produced on %s: %v", authID, executor.attempts)
					}
					keys := compactionOutputKeys(executor.output)
					if len(keys) != 1 {
						t.Fatalf("produced output signer keys = %v", keys)
					}
					if signer, known := selector.cache.Get(keys[0]); !known || signer != authID || !selector.cache.IsProtected(keys[0]) {
						t.Fatalf("producing response did not register %s: %s, %v", authID, signer, known)
					}
					executor.output, executor.streamOutput = nil, nil
					return keys[0]
				}
				ordinaryOnB := func(identity string) {
					t.Helper()
					req, opts := compactionAffinityRequest(model, "Session-Id", false, true)
					opts.Headers.Set("Session-Id", identity)
					opts.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = secondID
					executor.attempts = nil
					if errOrdinary := runCompactionAffinityRequest(t, manager, executor, path, req, opts); errOrdinary != nil {
						t.Fatalf("establishing ordinary identity on B: %v", errOrdinary)
					}
					if len(executor.attempts) != 1 || executor.attempts[0].authID != secondID {
						t.Fatalf("ordinary identity was not established on B: %v", executor.attempts)
					}
				}

				productionIdentity := "stable-conversation"
				if scenario == "duplicate" || scenario == "conflicting" {
					// C stays live while an unrelated mutable explicit identity is B.
					productionIdentity = "producing-conversation-A"
				}
				keyC := produce(producedCompaction, firstID, productionIdentity)
				blockD := `{"type":"compaction","encrypted_content":"signed-block-D"}`
				switch scenario {
				case "expired":
					// Age only already-produced groups. No sleep and no fabricated
					// signer binding: normal public selection performs expiration.
					selector.cache.mu.Lock()
					for primary, entry := range selector.cache.groups {
						entry.expiresAt = time.Now().Add(-time.Hour)
						selector.cache.groups[primary] = entry
						for _, alias := range entry.aliases {
							selector.cache.entries[alias] = entry
						}
					}
					selector.cache.persistenceDirty = true
					selector.cache.persistLocked()
					selector.cache.mu.Unlock()
				case "evicted":
					// Actual public traffic exceeds capacity and evicts the signer
					// and its independently protected explicit primary.
					selector.cache.mu.Lock()
					capacity := selector.cache.maxEntries
					selector.cache.maxEntries = 1
					selector.cache.mu.Unlock()
					ordinaryOnB("eviction-pressure-conversation")
					selector.cache.mu.Lock()
					selector.cache.maxEntries = capacity
					selector.cache.mu.Unlock()
				case "conflicting":
					produce(blockD, secondID, "producing-conversation-B")
				}
				if scenario == "expired" || scenario == "evicted" {
					if signer, known := selector.cache.Get(keyC); known {
						t.Fatalf("cold signer was not lost: %s", signer)
					}
				}
				fallback.preferredID = secondID
				ordinaryOnB("stable-conversation")
				// Confirm the tempting mutable binding really is B, not merely
				// a fallback preference that was never used.
				_, identityOpts := compactionAffinityRequest(model, "Session-Id", false, true)
				identity, _ := extractExplicitSessionIDs(identityOpts.Headers, identityOpts.OriginalRequest, identityOpts.Metadata)
				primaryKey := "mixed::" + cliproxysession.BoundSessionIdentity(identity) + "::" + model
				if bound, known := selector.cache.Get(primaryKey); !known || bound != secondID || selector.cache.IsProtected(primaryKey) {
					t.Fatalf("ordinary explicit binding = %s, %v; want mutable B", bound, known)
				}

				req, opts := compactionAffinityRequest(model, "Session-Id", true, true)
				input := producedCompaction
				if scenario == "duplicate" {
					input += "," + producedCompaction
					// Exercise A's direct/stream-start/first-error-chunk failure.
					// B is healthy and must not be reached by failover.
					executor.failure = compactTestStatusError{code: http.StatusServiceUnavailable, msg: "signed account A unavailable"}
				} else if scenario == "conflicting" {
					input += "," + blockD
				}
				body := []byte(`{"input":[` + input + `,{"type":"message","role":"user","content":[{"type":"input_text","text":"continue"}]}]}`)
				req.Payload, opts.OriginalRequest = body, body
				executor.attempts = nil
				errReplay := runCompactionAffinityRequest(t, manager, executor, path, req, opts)
				if scenario == "duplicate" {
					var statusErr cliproxyexecutor.StatusError
					if !errors.As(errReplay, &statusErr) || statusErr.StatusCode() != http.StatusServiceUnavailable {
						t.Fatalf("duplicate-list replay = %v, want original A upstream 503", errReplay)
					}
					assertCompactionAffinityOnlyA(t, executor, true)
					if len(executor.attempts) != 1 {
						t.Fatalf("duplicate-list attempts = %v, want one pinned A", executor.attempts)
					}
				} else {
					var affinityErr *Error
					code := "compaction_affinity_missing"
					if scenario == "conflicting" {
						code = "compaction_affinity_conflict"
					}
					if !errors.As(errReplay, &affinityErr) || affinityErr.HTTPStatus != http.StatusConflict || affinityErr.Code != code {
						t.Fatalf("replay = %v, want %s / 409", errReplay, code)
					}
					if len(executor.attempts) != 0 {
						t.Fatalf("rejected signer invoked an executor (including B): %v", executor.attempts)
					}
				}
			})
		}
	}
}

func TestManagerCompactionStreamPreservesWireAndUpstreamError(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	_, opts := compactionAffinityRequest("model", "none", false, false)
	ordinary := "data: {\"type\":\"response.created\"}\n\n"
	signed := "data: {\"type\":\"response.output_item.done\",\"item\":" + producedCompaction + "}\n\n"
	upstreamErr := errors.New("upstream stream interrupted")
	chunks := make(chan cliproxyexecutor.StreamChunk, 4)
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(ordinary)}
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(signed[:len(signed)/2])}
	chunks <- cliproxyexecutor.StreamChunk{Payload: []byte(signed[len(signed)/2:])}
	chunks <- cliproxyexecutor.StreamChunk{Err: upstreamErr}
	close(chunks)
	stream := manager.wrapStreamResult(context.Background(), &Auth{ID: "A"}, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, opts)
	var delivered []byte
	var terminal error
	for chunk := range stream.Chunks {
		delivered = append(delivered, chunk.Payload...)
		if chunk.Err != nil {
			terminal = chunk.Err
		}
	}
	if string(delivered) != ordinary+signed || !errors.Is(terminal, upstreamErr) {
		t.Fatalf("wire/error changed: %q, %v", delivered, terminal)
	}
	for _, key := range compactionOutputKeys([]byte(`{"output":[` + producedCompaction + `]}`)) {
		if authID, known := selector.cache.Get(key); !known || authID != "A" || !selector.cache.IsProtected(key) {
			t.Fatal("upstream stream failure deleted the already-delivered signer")
		}
	}
}
