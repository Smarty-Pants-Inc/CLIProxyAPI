package auth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	coresession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/tidwall/gjson"
)

// These public Manager/callback regressions intentionally use only pre-fix
// symbols, so the identical tests can be run on the reviewed parent.
func compactionJSONSecurityCases() []struct{ name, payload string } {
	block := `{"type":"compaction","encrypted_content":"security-known"}`
	return []struct{ name, payload string }{
		{"root-input", `{"input":[],"input":[{"type":"compaction","encrypted_content":"unknown"}]}`},
		{"root-escaped-input", `{"input":[],"\u0069nput":[{"type":"compaction","encrypted_content":"unknown"}]}`},
		{"block-type", `{"input":[{"type":"message","type":"compaction","encrypted_content":"unknown"}]}`},
		{"block-encrypted-content", `{"input":[{"type":"compaction","encrypted_content":"security-known","encrypted_content":"unknown"}]}`},
		{"native-content", `{"messages":[{"content":[],"content":[{"type":"compaction","content":"unknown"}]}]}`},
		{"block-content", `{"messages":[{"content":[{"type":"compaction","encrypted_content":"security-known","content":"a","content":"b"}]}]}`},
		{"blocks", `{"input":[` + strings.Repeat(block+",", 256) + block + `]}`},
		{"shared-input-messages-bound", `{"input":[` + strings.TrimSuffix(strings.Repeat(block+",", 128), ",") + `],"messages":[{"content":[` + strings.TrimSuffix(strings.Repeat(block+",", 129), ",") + `]}]}`},
		{"bytes", `{"input":[],"padding":"` + strings.Repeat("x", 16<<20) + `"}`},
		{"depth", `{"input":[],"padding":` + strings.Repeat("[", 129) + `0` + strings.Repeat("]", 129) + `}`},
	}
}

func requireCompactionJSONLocalStop(t *testing.T, err error) {
	t.Helper()
	var local *Error
	if !errors.As(err, &local) || local.Code != "compaction_json_rejected" || local.StatusCode() != http.StatusBadRequest || !IsLocalCompactionAffinityStop(err) {
		t.Fatalf("error = %v, want typed local JSON stop (400)", err)
	}
}

func TestManagerCompactionJSONSecurityBeforeHTTPExecution(t *testing.T) {
	for _, path := range []string{"execute", "stream-start"} {
		for _, tc := range compactionJSONSecurityCases() {
			t.Run(path+"/"+tc.name, func(t *testing.T) {
				origin := NewSessionAffinitySelector(nil)
				defer origin.Stop()
				executor := &compactionAffinityExecutor{provider: "codex", firstID: t.Name() + "-A"}
				manager := newCompactionAffinityManager(t, origin, executor, "security-model", t.Name()+"-B")
				if err := origin.RecordCompactionOutput(executor.firstID, core.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"security-known"}]}`)); err != nil {
					t.Fatal(err)
				}
				req, opts := compactionAffinityRequest("security-model", "none", false, false)
				req.Payload, opts.OriginalRequest = []byte(tc.payload), []byte(tc.payload)
				err := runCompactionAffinityRequest(t, manager, executor, path, req, opts)
				requireCompactionJSONLocalStop(t, err)
				if len(executor.attempts) != 0 {
					t.Fatalf("upstream attempts = %d, want zero", len(executor.attempts))
				}
				for _, id := range []string{executor.firstID, t.Name() + "-B"} {
					a, _ := manager.GetByID(id)
					if a.Unavailable || !a.NextRetryAfter.IsZero() || a.LastError != nil || len(a.ModelStates) != 0 {
						t.Fatalf("local rejection cooled credential: %+v", a)
					}
				}
			})
		}
	}
}

func TestCompactionDuplexJSONSecurityCallback(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	if err := origin.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"security-known"}]}`)); err != nil {
		t.Fatal(err)
	}
	opts, err := manager.PrepareCompactionRequest("model", core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	for _, tc := range compactionJSONSecurityCases() {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(tc.payload)
			before := bytes.Clone(payload)
			requireCompactionJSONLocalStop(t, validate("A", payload))
			if !bytes.Equal(payload, before) {
				t.Fatal("callback rewrote raw frame")
			}
		})
	}
	// Ordinary, whitespace-bearing raw steering is neither normalized nor denied.
	payload := []byte(" { \"type\":\"response.steer\", \"input\":[{\"type\":\"compaction\",\"encrypted_content\":\"security-known\"},{\"type\":\"message\",\"content\":\"ok\"}] }\n")
	before := bytes.Clone(payload)
	if err := validate("A", payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, before) {
		t.Fatal("valid raw steering changed")
	}
}

func TestManagerCompactionJSONSecurityCancellation(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		t.Run(path, func(t *testing.T) {
			origin := NewSessionAffinitySelector(nil)
			defer origin.Stop()
			executor := &compactionAffinityExecutor{provider: "codex", firstID: t.Name() + "-A"}
			manager := newCompactionAffinityManager(t, origin, executor, "cancel-model", t.Name()+"-B")
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			req, opts := compactionAffinityRequest("cancel-model", "none", false, false)
			var err error
			switch path {
			case "execute":
				_, err = manager.Execute(ctx, []string{"codex"}, req, opts)
			case "count":
				_, err = manager.ExecuteCount(ctx, []string{"codex"}, req, opts)
			case "stream":
				_, err = manager.ExecuteStream(ctx, []string{"codex"}, req, opts)
			}
			requireCompactionJSONLocalStop(t, err)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("lost cancellation cause: %v", err)
			}
			if len(executor.attempts) != 0 {
				t.Fatal("canceled request executed upstream")
			}
		})
	}
}

func TestCompactionDuplexJSONSecurityCapturedCancellation(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	ctx, cancel := context.WithCancel(context.Background())
	opts := core.Options{Metadata: map[string]any{"compaction_request_context": ctx}}
	opts, err := manager.PrepareCompactionRequest("model", opts)
	if err != nil {
		t.Fatal(err)
	}
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	// Later metadata changes must not detach the installed callback's context.
	opts.Metadata["compaction_request_context"] = context.Background()
	cancel()
	err = validate("A", []byte(`{"input":[]}`))
	requireCompactionJSONLocalStop(t, err)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("lost captured cancellation: %v", err)
	}
}

// Use a real cancellable context, with a deterministic trigger on its Nth
// inspection. No timers or timing thresholds decide scan/cancellation results.
type compactionCancelAfterChecks struct {
	context.Context
	cancel context.CancelFunc
	checks int
	limit  int
}

func (c *compactionCancelAfterChecks) Err() error {
	c.checks++
	if c.checks == c.limit {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCompactionJSONSecurityBoundedReaderAndCancellationDuringScan(t *testing.T) {
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &compactionCancelAfterChecks{Context: base, cancel: cancel, limit: 8}
	reader := &compactionJSONReader{ctx: ctx, text: `"` + strings.Repeat("x", 2<<20) + `"`}
	_, err := json.NewDecoder(reader).Token()
	if !errors.Is(err, context.Canceled) || reader.offset > 7*4096 || ctx.checks != 8 {
		t.Fatalf("unbounded reader: offset=%d checks=%d err=%v", reader.offset, ctx.checks, err)
	}

	base, cancel = context.WithCancel(context.Background())
	defer cancel()
	ctx = &compactionCancelAfterChecks{Context: base, cancel: cancel, limit: 24}
	err = ValidateCompactionJSON(ctx, []byte(`{"input":[],"padding":"`+strings.Repeat("x", 2<<20)+`"}`))
	if !errors.Is(err, context.Canceled) || ctx.checks > 26 {
		t.Fatalf("validator did not stop during long token: checks=%d err=%v", ctx.checks, err)
	}
	var local *Error
	if !errors.As(err, &local) || local.Code != "compaction_json_rejected" {
		t.Fatalf("untyped cancellation: %v", err)
	}
}

func TestCompactionDuplexJSONSecurityCancellationDuringLongScan(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &compactionCancelAfterChecks{Context: base, cancel: cancel}
	opts, err := manager.PrepareCompactionRequest("model", core.Options{}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	ctx.limit = ctx.checks + 24
	err = validate("A", []byte(`{"input":[],"padding":"`+strings.Repeat("x", 2<<20)+`"}`))
	requireCompactionJSONLocalStop(t, err)
	if !errors.Is(err, context.Canceled) || ctx.checks > ctx.limit+2 {
		t.Fatalf("duplex did not stop during scan: checks=%d limit=%d err=%v", ctx.checks, ctx.limit, err)
	}
}

func TestCompactionJSONSecurityReceiverSkipsMatchingAccountCooldown(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	hook := &recordingHook{}
	manager := NewManager(nil, origin, hook)
	a := &Auth{ID: "security-receiver-A", Provider: "codex", Status: StatusActive, Metadata: map[string]any{
		"request_scoped_errors": []internalconfig.RequestScopedErrorRule{{Status: 400, Match: []string{"compaction JSON"}, Action: "stop-and-cooldown"}},
	}}
	if _, err := manager.Register(WithSkipPersist(context.Background()), a); err != nil {
		t.Fatal(err)
	}
	opts, err := manager.PrepareCompactionRequest("model", core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	local := &receiverDuplexAffinityError{cause: validate(a.ID, []byte(`{"input":[],"input":[]}`))}
	requireCompactionJSONLocalStop(t, local)
	if _, ok := matchRequestScopedErrorAction(a, local, manager.runtimeConfigSnapshot()); !ok {
		t.Fatal("fixture does not match account policy")
	}
	chunks := make(chan core.StreamChunk, 1)
	chunks <- core.StreamChunk{Err: local}
	close(chunks)
	stream := manager.wrapStreamResult(context.Background(), a, "codex", "model", "model", nil, nil, chunks, OAuthModelAliasResult{}, false, opts)
	for chunk := range stream.Chunks {
		if len(chunk.Payload) != 0 {
			t.Fatal("local rejection delivered payload")
		}
		if chunk.Err != nil {
			requireCompactionJSONLocalStop(t, chunk.Err)
		}
	}
	if hook.lastResult.Load() != nil {
		t.Fatal("local rejection reached credential accounting")
	}
	current, _ := manager.GetByID(a.ID)
	if current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil || len(current.ModelStates) != 0 {
		t.Fatal("local rejection cooled credential")
	}
}

func TestCompactionJSONSecuritySingleSeenSetCountersAndIdentity(t *testing.T) {
	collector := newCompactionKeyCollector(context.Background())
	for i := 0; i < 256; i++ {
		item := gjson.Parse(fmt.Sprintf(`{"type":"compaction","encrypted_content":"block-%d"}`, i))
		if err := collector.add(item); err != nil {
			t.Fatal(err)
		}
	}
	if collector.blocks != 256 || len(collector.keys) != 256 || len(collector.seen) != 256 {
		t.Fatalf("linear collector counters: blocks=%d keys=%d seen=%d", collector.blocks, len(collector.keys), len(collector.seen))
	}
	if err := collector.add(gjson.Parse(`{"type":"compaction","encrypted_content":"block-0"}`)); err == nil || len(collector.keys) != 256 || collector.blocks != 257 {
		t.Fatalf("duplicate capsule did not consume finite budget: blocks=%d keys=%d err=%v", collector.blocks, len(collector.keys), err)
	}

	variants := [][]string{
		{`{"type":"compaction","encrypted_content":"signed","id":"a"}`, ` { "encrypted_content":"signed", "type":"compaction", "id":"b" }`},
		{`{"type":"compaction","content":"native capsule"}`, ` { "content":"native\u0020capsule", "type":"compaction" }`},
		{`{"type":"compaction","content":{"a":1,"b":[2,3]}}`, ` { "content": { "b":[2,3], "a":1 }, "type":"compaction" }`},
	}
	for _, pair := range variants {
		c := newCompactionKeyCollector(context.Background())
		for _, raw := range pair {
			if err := c.add(gjson.Parse(raw)); err != nil {
				t.Fatal(err)
			}
		}
		if c.blocks != 2 || len(c.keys) != 1 {
			t.Fatalf("reserialized block identity changed: %+v", c.keys)
		}
	}
	c := newCompactionKeyCollector(context.Background())
	if err := c.add(gjson.Parse(variants[0][0])); err != nil {
		t.Fatal(err)
	}
	if want := fmt.Sprintf("compaction::%x", sha256.Sum256([]byte("signed"))); c.keys[0] != want {
		t.Fatalf("encrypted identity changed: got %s want %s", c.keys[0], want)
	}
}

func TestCompactionJSONSecurityBoundRejectsWholeBeforeCollection(t *testing.T) {
	for _, tc := range compactionJSONSecurityCases() {
		keys, err := compactionAffinityKeysChecked(context.Background(), core.Options{OriginalRequest: []byte(tc.payload)})
		if err == nil || keys != nil {
			t.Fatalf("%s quietly truncated: keys=%v err=%v", tc.name, keys, err)
		}
	}
	// A schema's array-valued type is valid JSON, not an ambiguous block type.
	ordinary := []byte(`{"input":[{"type":"message","content":"ok"}],"tools":[{"parameters":{"type":["object","null"]}}]}`)
	if err := ValidateCompactionJSON(context.Background(), ordinary); err != nil {
		t.Fatal(err)
	}
}

func TestCompactionJSONSecurityContextSurvivesEnrichAndNegativeOrigins(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, opts := compactionAffinityRequest("execution-model", "none", false, false)
	opts.Metadata[core.AuthSelectionModelMetadataKey] = "selection-model"
	opts, err := manager.PrepareCompactionRequest(req.Model, opts, ctx)
	if err != nil {
		t.Fatal(err)
	}
	req, opts = coresession.Enrich(req, opts)
	if compactionContext(opts) != ctx || opts.Metadata[compactionAffinityStoreMetadataKey] != origin || opts.Metadata[core.SessionAffinityModelMetadataKey] != "selection-model" {
		t.Fatal("preparation authority/context/selection model lost in Enrich clone")
	}
	if id, _ := opts.Metadata[core.DerivedSessionIDMetadataKey].(string); id == "" {
		t.Fatal("ordinary input no longer derives session identity")
	}
	_ = req

	for _, home := range []bool{false, true} {
		none := NewManager(nil, nil, nil)
		cfg := &internalconfig.Config{}
		cfg.Home.Enabled = home
		none.runtimeConfig.Store(cfg)
		negative, err := none.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[],"input":[]}`)}, ctx)
		if err != nil {
			t.Fatalf("negative origin unexpectedly enabled local JSON policy: %v", err)
		}
		none.runtimeConfig.Store(&internalconfig.Config{})
		none.SetSelector(origin)
		if _, err := none.PrepareCompactionRequest("model", negative, ctx); err != nil {
			t.Fatalf("negative origin changed on enable: %v", err)
		}
	}
}

func TestManagerCompactionJSONSecurityPayloadOnlyBeforeDerivation(t *testing.T) {
	for _, path := range []string{"execute", "count", "stream"} {
		t.Run(path, func(t *testing.T) {
			origin := NewSessionAffinitySelector(nil)
			defer origin.Stop()
			manager := NewManager(nil, origin, nil)
			// No explicit identity, OriginalRequest or credentials: preflight must
			// reject req.Payload before Enrich/selection can obscure this error.
			req := core.Request{Model: "model", Payload: []byte(`{"input":[{"role":"user","content":"` + strings.Repeat("x", 16<<20) + `"}]}`)}
			var err error
			switch path {
			case "execute":
				_, err = manager.Execute(context.Background(), []string{"codex"}, req, core.Options{})
			case "count":
				_, err = manager.ExecuteCount(context.Background(), []string{"codex"}, req, core.Options{})
			case "stream":
				_, err = manager.ExecuteStream(context.Background(), []string{"codex"}, req, core.Options{})
			}
			requireCompactionJSONLocalStop(t, err)
		})
	}
}
