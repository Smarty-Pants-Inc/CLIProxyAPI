package auth

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
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
	if !strings.Contains(string(req.Payload), "signed-account-a") || pinnedAuthIDFromMetadata(opts.Metadata) != "auth-b" {
		t.Fatalf("migrated block not kept on its signer: pinned %q payload %s", pinnedAuthIDFromMetadata(opts.Metadata), req.Payload)
	}
	if _, errStat := os.Stat(statePath); errStat != nil {
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
