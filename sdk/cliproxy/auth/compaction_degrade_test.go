package auth

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// smarty-dev#8742 acceptance: a session compacted on build N, a cold restart
// whose NEW state file is empty but whose legacy auth-dir file holds the
// signer, keeps its block on the signing account (state migrated once,
// legacy file untouched); with neither file the request is still served,
// without the block.
func TestCompactionColdRestartMigratesLegacyStateOrDegrades(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "auth", "session-affinity.state")
	statePath := filepath.Join(dir, "state", "cliproxyapi", "session-affinity.state")
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}

	// Build N kept its state in auth-dir.
	buildN := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: legacy, Fallback: lastAuthSelector{}})
	first, err := buildN.Pick(context.Background(), "openai", "model", affinityConversationOptions(false), auths)
	if err != nil || first == nil || first.ID != "auth-b" {
		t.Fatalf("build N Pick = %v, %v", first, err)
	}
	recordAffinityTestOutput(t, buildN, first.ID, affinityConversationOptions(false))
	buildN.Stop()
	before, err := os.ReadFile(legacy)
	if err != nil {
		t.Fatal(err)
	}

	// Cold restart: new state file missing, legacy present.
	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: statePath, LegacyStatePath: legacy, Fallback: &RoundRobinSelector{}})
	defer restarted.Stop()
	if errState := restarted.cache.PersistenceError(); errState != nil {
		t.Fatalf("migration failed closed: %v", errState)
	}
	manager := NewManager(nil, restarted, nil)
	req, opts := degradeTestRequest(affinityConversationOptions(true))
	req, opts, err = manager.PrepareCompactionPayload(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("migrated signer refused: %v", err)
	}
	if !legacyMigrationSupported {
		// Windows cannot prove the legacy file's owner: it is never imported,
		// so the block is removed and nothing is pinned (degrade).
		if strings.Contains(string(req.Payload), "compaction") || pinnedAuthIDFromMetadata(opts.Metadata) != "" {
			t.Fatalf("windows imported an unproven legacy file: pinned %q", pinnedAuthIDFromMetadata(opts.Metadata))
		}
	} else if !strings.Contains(string(req.Payload), "signed-account-a") || pinnedAuthIDFromMetadata(opts.Metadata) != "auth-b" {
		t.Fatalf("migrated block not kept on its signer: pinned %q payload %s", pinnedAuthIDFromMetadata(opts.Metadata), req.Payload)
	}
	if _, errStat := os.Stat(statePath); legacyMigrationSupported && errStat != nil {
		t.Fatalf("migrated state not written to the new path: %v", errStat)
	}
	if after, _ := os.ReadFile(legacy); !bytes.Equal(before, after) {
		t.Fatal("legacy state file was modified")
	}

	// Neither file: the unknown block is removed and the request served.
	empty := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: filepath.Join(dir, "none", "session-affinity.state"), LegacyStatePath: filepath.Join(dir, "missing.state"), Fallback: &RoundRobinSelector{}})
	defer empty.Stop()
	req, opts = degradeTestRequest(affinityConversationOptions(true))
	req, opts, err = NewManager(nil, empty, nil).PrepareCompactionPayload(context.Background(), req, opts)
	if err != nil {
		t.Fatalf("unknown signer refused: %v", err)
	}
	for _, sent := range [][]byte{req.Payload, opts.OriginalRequest} {
		if strings.Contains(string(sent), "compaction") || !strings.Contains(string(sent), "continue") {
			t.Fatalf("unknown block not removed: %s", sent)
		}
	}
	if pinned := pinnedAuthIDFromMetadata(opts.Metadata); pinned != "" {
		t.Fatalf("degraded request pinned to %q", pinned)
	}
}

// When both files exist the new one wins: a stale legacy signer never
// overrides a newer binding, and neither file is rewritten from the other.
func TestCompactionNewStateWinsOverLegacy(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "auth", "session-affinity.state")
	statePath := filepath.Join(dir, "state", "session-affinity.state")
	for _, file := range []struct{ path, signer string }{{legacy, "auth-b"}, {statePath, "auth-a"}} {
		build := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: file.path})
		recordAffinityTestOutput(t, build, file.signer, affinityConversationOptions(false))
		build.Stop()
	}
	legacyBefore, _ := os.ReadFile(legacy)
	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: statePath, LegacyStatePath: legacy})
	defer restarted.Stop()
	req, opts := degradeTestRequest(affinityConversationOptions(true))
	req, opts, err := NewManager(nil, restarted, nil).PrepareCompactionPayload(context.Background(), req, opts)
	if err != nil || pinnedAuthIDFromMetadata(opts.Metadata) != "auth-a" || !strings.Contains(string(req.Payload), "signed-account-a") {
		t.Fatalf("pinned %q err %v: the stale legacy signer overrode the new binding", pinnedAuthIDFromMetadata(opts.Metadata), err)
	}
	if legacyAfter, _ := os.ReadFile(legacy); !bytes.Equal(legacyBefore, legacyAfter) {
		t.Fatal("legacy state file was modified")
	}
}

// smarty-dev#8742 r1: imported aliases decide routing, so a legacy file another
// principal could write is never imported; the request then degrades.
func TestCompactionUntrustedLegacyStateIsIgnored(t *testing.T) {
	for _, tc := range []struct {
		name    string
		prepare func(t *testing.T, legacy string)
		trusted bool
	}{
		{"own-0600-migrates", func(*testing.T, string) {}, legacyMigrationSupported},
		{"group-writable-file", func(t *testing.T, legacy string) { chmod(t, legacy, 0o620) }, false},
		{"other-writable-file", func(t *testing.T, legacy string) { chmod(t, legacy, 0o602) }, false},
		{"group-writable-directory", func(t *testing.T, legacy string) { chmod(t, filepath.Dir(legacy), 0o770) }, false},
		{"other-owner", func(t *testing.T, _ string) {
			saved := legacyStateUID
			legacyStateUID = func() int { return saved() + 1 }
			t.Cleanup(func() { legacyStateUID = saved })
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			legacy := filepath.Join(dir, "auth", "session-affinity.state")
			buildN := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: legacy})
			recordAffinityTestOutput(t, buildN, "auth-b", affinityConversationOptions(false))
			buildN.Stop()
			tc.prepare(t, legacy)
			selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: filepath.Join(dir, "state", "session-affinity.state"), LegacyStatePath: legacy})
			defer selector.Stop()
			if err := selector.cache.PersistenceError(); err != nil {
				t.Fatalf("routing failed closed: %v", err)
			}
			req, opts := degradeTestRequest(affinityConversationOptions(true))
			req, opts, err := NewManager(nil, selector, nil).PrepareCompactionPayload(context.Background(), req, opts)
			if err != nil {
				t.Fatal(err)
			}
			pinned := pinnedAuthIDFromMetadata(opts.Metadata)
			if tc.trusted && (pinned != "auth-b" || !strings.Contains(string(req.Payload), "signed-account-a")) {
				t.Fatalf("trusted legacy file not migrated: pinned %q", pinned)
			}
			if !tc.trusted && (pinned != "" || strings.Contains(string(req.Payload), "compaction")) {
				t.Fatalf("untrusted legacy file imported: pinned %q payload %s", pinned, req.Payload)
			}
		})
	}
}

// legacyMigrationSupported: a POSIX owner can be proven (not on Windows,
// where session_cache_owner_windows.go never trusts a legacy file).
var legacyMigrationSupported = runtime.GOOS != "windows"

func chmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func TestCompactionInvalidLegacyStateIsIgnoredNotFailClosed(t *testing.T) {
	dir := t.TempDir()
	legacy := filepath.Join(dir, "legacy.state")
	if err := os.WriteFile(legacy, []byte(`{"version":7}`), 0o600); err != nil {
		t.Fatal(err)
	}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: filepath.Join(dir, "new", "session-affinity.state"), LegacyStatePath: legacy})
	defer selector.Stop()
	if err := selector.cache.PersistenceError(); err != nil {
		t.Fatalf("invalid legacy file made routing fail closed: %v", err)
	}
}

func TestCompactionDegradeSummaryAndOverCap(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	cases := map[string]struct{ body, want, absent string }{
		"native-summary-kept-as-text": {
			`{"messages":[{"role":"user","content":[{"type":"compaction","content":"plain summary of earlier turns"},{"type":"text","text":"continue"}]}]}`,
			`{"type":"text","text":"plain summary of earlier turns"}`, `"compaction"`},
		"encrypted-only-message-gets-placeholder": {
			`{"messages":[{"role":"assistant","content":[{"type":"compaction","encrypted_content":"opaque"}]},{"role":"user","content":[{"type":"text","text":"continue"}]}]}`,
			compactionOmittedText, `"compaction"`},
		"over-16MiB": {
			`{"input":[{"type":"compaction","encrypted_content":"` + strings.Repeat("A", maxCompactionJSONBytes) + `"},{"role":"user","content":"continue"}]}`,
			`"continue"`, `"compaction"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			req, opts := degradeTestRequest(cliproxyexecutor.Options{OriginalRequest: []byte(tc.body), SourceFormat: sdktranslator.FormatOpenAIResponse, Metadata: map[string]any{}})
			req, opts, err := manager.PrepareCompactionPayload(context.Background(), req, opts)
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !gjson.ValidBytes(req.Payload) || !strings.Contains(string(req.Payload), tc.want) || strings.Contains(string(req.Payload), tc.absent) {
				t.Fatalf("payload %.300s", req.Payload)
			}
		})
	}
}

// smarty-dev#8742 security r1: the scan stops at the limit, and a body over
// the hard input bound is refused before any compaction parse.
func TestCompactionDegradeIsBoundedForManyBlocksAndRefusesOverTheInputBound(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)

	block := `{"type":"compaction","encrypted_content":"x"},`
	many := []byte(`{"input":[` + strings.Repeat(block, 10000) + `{"role":"user","content":"continue"}]}`)
	items, over := compactionItems(gjson.ParseBytes(many))
	if !over || len(items) != maxCompactionBlocks+1 || cap(items) > 2*(maxCompactionBlocks+1) {
		t.Fatalf("scan held %d entries (cap %d, over %v); want it to stop at %d", len(items), cap(items), over, maxCompactionBlocks+1)
	}
	req, opts := degradeTestRequest(cliproxyexecutor.Options{OriginalRequest: many, SourceFormat: sdktranslator.FormatOpenAIResponse})
	req, _, err := manager.PrepareCompactionPayload(context.Background(), req, opts)
	if err != nil || strings.Contains(string(req.Payload), `"compaction"`) || !strings.Contains(string(req.Payload), "continue") {
		t.Fatalf("10,000 blocks: err %v payload %.200s", err, req.Payload)
	}

	huge := []byte(`{"input":[` + block + `{"role":"user","content":"` + strings.Repeat("A", MaxCompactionInputBytes) + `"}]}`)
	if out, dropped, _, _ := degradeCompactionPayload(context.Background(), selector, huge, ""); dropped != 0 || &out[0] != &huge[0] {
		t.Fatal("a body over the hard input bound was scanned")
	}
	req, opts = degradeTestRequest(cliproxyexecutor.Options{OriginalRequest: huge, SourceFormat: sdktranslator.FormatOpenAIResponse})
	_, _, err = manager.PrepareCompactionPayload(context.Background(), req, opts)
	var local *Error
	if !errors.As(err, &local) || local.HTTPStatus != http.StatusRequestEntityTooLarge || local.Code != "request_too_large" {
		t.Fatalf("over the input bound = %v, want 413 request_too_large", err)
	}
}

// smarty-dev#8742 security r2: one compaction item among 2,000,000 tiny input
// entries. The rewrite allocates about one output buffer, never per entry.
func TestCompactionRewriteAllocationIsNotPerEntry(t *testing.T) {
	const entries = 2_000_000
	var body bytes.Buffer
	body.WriteString(`{"input":[{"type":"compaction","encrypted_content":"unknown"}`)
	for i := 0; i < entries; i++ {
		body.WriteString(`,{}`)
	}
	body.WriteString(`]}`)
	payload := body.Bytes()
	root := gjson.ParseBytes(payload)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	out, ok := rewriteCompactionItems(payload, root, func(gjson.Result) bool { return true })
	if !ok {
		t.Fatal("a 6 MB rewrite stopped at the output limit")
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc
	// One output buffer (about len(payload)) plus small constants. The
	// per-entry version kept a 16-byte slice header per entry (32 MB here)
	// and then joined them: several times the request.
	if limit := uint64(len(payload))*2 + 1<<20; allocated > limit {
		t.Fatalf("rewrite allocated %d bytes for a %d-byte request (limit %d)", allocated, len(payload), limit)
	}
	if bytes.Contains(out, []byte("compaction")) || len(out) != len(payload)-len(`{"type":"compaction","encrypted_content":"unknown"},`) {
		t.Fatalf("rewrite output wrong: %d bytes, starts %.80s", len(out), out)
	}
	if !gjson.ValidBytes(out) {
		t.Fatal("rewrite output is not valid JSON")
	}
}

// smarty-dev#8742 (dev-lead, round 2): a body close to the 64 MiB bound with
// one compaction item among ordinary entries. It is still over 16 MiB without
// its block, so it is refused with 413. The streamed rewrite stops at the
// 16 MiB output limit: allocation stays far below the body size.
func TestCompactionNearInputBoundIsRefusedWithoutBodySizedAllocation(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	head := `{"input":[{"type":"compaction","encrypted_content":"unknown"}`
	var body bytes.Buffer
	body.Grow(MaxCompactionInputBytes)
	body.WriteString(head)
	for body.Len() < MaxCompactionInputBytes-(1<<20) {
		body.WriteString(`,{"role":"user","content":"ordinary entry"}`)
	}
	body.WriteString(`]}`)
	req, opts := degradeTestRequest(cliproxyexecutor.Options{OriginalRequest: body.Bytes(), SourceFormat: sdktranslator.FormatOpenAIResponse})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := manager.PrepareCompactionPayload(context.Background(), req, opts)
	runtime.ReadMemStats(&after)
	var local *Error
	if !errors.As(err, &local) || local.HTTPStatus != http.StatusRequestEntityTooLarge {
		t.Fatalf("near-64 MiB body = %v, want 413", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(maxCompactionJSONBytes) + 4<<20; allocated > limit {
		t.Fatalf("degrade allocated %d bytes for a %d-byte body (limit %d)", allocated, body.Len(), limit)
	}
	t.Logf("%d-byte body: 413 after %d bytes allocated", body.Len(), allocated)
}

// smarty-dev#8742 security r3: a dropped native compaction block whose plain
// summary is about 20 MB of escape-heavy text (each NUL is 6 bytes escaped).
// The summary must not be unescaped, marshalled or concatenated: the request is
// refused with 413 at the 16 MiB output cap, with allocation under the cap
// plus 1 MiB. A small summary is still kept as text.
func TestCompactionLargeSummaryIsBudgetedBeforeAnyCopy(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	manager := NewManager(nil, selector, nil)
	summary := strings.Repeat(`\u0000`, 20<<20/6)
	body := []byte(`{"messages":[{"role":"assistant","content":[{"type":"compaction","content":"` + summary + `"}]},{"role":"user","content":[{"type":"text","text":"continue"}]}]}`)
	req, opts := degradeTestRequest(cliproxyexecutor.Options{OriginalRequest: body, SourceFormat: sdktranslator.FormatOpenAIResponse})
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, _, err := manager.PrepareCompactionPayload(context.Background(), req, opts)
	runtime.ReadMemStats(&after)
	var local *Error
	if !errors.As(err, &local) || local.HTTPStatus != http.StatusRequestEntityTooLarge {
		t.Fatalf("20 MB summary = %v, want 413", err)
	}
	allocated := after.TotalAlloc - before.TotalAlloc
	if limit := uint64(maxCompactionJSONBytes) + 1<<20; allocated > limit {
		t.Fatalf("degrade allocated %d bytes for a %d-byte body (limit %d)", allocated, len(body), limit)
	}
	t.Logf("%d-byte body with a %d-byte escaped summary: 413 after %d bytes allocated", len(body), len(summary), allocated)
}

func TestCompactionDuplexSanitizerKeepsOnlyTheSocketAccountsBlocks(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	for _, signer := range []struct{ id, block string }{{"A", "known-a"}, {"B", "known-b"}} {
		if err := origin.RecordCompactionOutput(signer.id, cliproxyexecutor.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"`+signer.block+`"}]}`)); err != nil {
			t.Fatal(err)
		}
	}
	manager := NewManager(nil, origin, nil)
	opts := cliproxyexecutor.Options{Metadata: map[string]any{compactionAffinityStoreMetadataKey: origin}}
	manager.prepareCompactionDuplexValidation(opts)
	sanitize := opts.Metadata[cliproxyexecutor.CompactionAffinitySanitizerMetadataKey].(func(string, []byte) []byte)
	validate := opts.Metadata[cliproxyexecutor.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	frame := []byte(`{"type":"response.steer","input":[{"type":"compaction","encrypted_content":"known-a"},{"type":"compaction","encrypted_content":"known-b"},{"type":"compaction","encrypted_content":"unknown"}]}`)
	sent := sanitize("A", frame)
	if !strings.Contains(string(sent), "known-a") || strings.Contains(string(sent), "known-b") || strings.Contains(string(sent), "unknown") {
		t.Fatalf("socket A frame = %s", sent)
	}
	if err := validate("A", sent); err != nil {
		t.Fatalf("sanitized frame still refused: %v", err)
	}
	if err := validate("A", frame); err == nil {
		t.Fatal("the validator no longer refuses an unsanitized foreign block")
	}
}

func degradeTestRequest(opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	if opts.Metadata == nil {
		opts.Metadata = map[string]any{}
	}
	return cliproxyexecutor.Request{Model: "model", Payload: bytes.Clone(opts.OriginalRequest)}, opts
}
