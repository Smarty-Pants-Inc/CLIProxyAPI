package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// Each atomic snapshot creates a uniquely named temporary file. Watch actual
// filesystem publications, not a production counter or a mocked persistence API.
// The sentinel event is a barrier after synchronous mutation has returned.
func watchCompactionPublications(t *testing.T, dir string) func() int {
	t.Helper()
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	if err = watcher.Add(dir); err != nil {
		_ = watcher.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = watcher.Close() })
	type observation struct {
		count int
		err   error
	}
	result := make(chan observation, 1)
	sentinel := filepath.Join(dir, "publication-observation-complete")
	go func() {
		seen := make(map[string]bool)
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					result <- observation{err: fmt.Errorf("watch closed before barrier")}
					return
				}
				if event.Op&fsnotify.Create == 0 {
					continue
				}
				if event.Name == sentinel {
					result <- observation{count: len(seen)}
					return
				}
				if strings.HasPrefix(filepath.Base(event.Name), ".session-cache-") {
					seen[event.Name] = true
				}
			case errWatch, ok := <-watcher.Errors:
				if !ok {
					errWatch = fmt.Errorf("watch errors closed before barrier")
				}
				result <- observation{err: errWatch}
				return
			case <-timer.C:
				result <- observation{err: fmt.Errorf("publication barrier timed out")}
				return
			}
		}
	}()
	return func() int {
		t.Helper()
		if errWrite := os.WriteFile(sentinel, []byte("barrier"), 0o600); errWrite != nil {
			t.Fatal(errWrite)
		}
		observed := <-result
		if observed.err != nil {
			t.Fatal(observed.err)
		}
		return observed.count
	}
}

func populatedCompactionPublicationSelector(t *testing.T) (*SessionAffinitySelector, string) {
	t.Helper()
	dir := t.TempDir()
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		StatePath: filepath.Join(dir, "affinity.state"),
		Fallback: &FillFirstSelector{},
	})
	t.Cleanup(selector.Stop)
	for i := 0; i < 128; i++ {
		selector.Cache().Set(fmt.Sprintf("ordinary-%d", i), "A")
	}
	return selector, dir
}

func publicationCompactionBlocks(count int) string {
	blocks := make([]string, 0, count)
	for i := 0; i < count; i++ {
		blocks = append(blocks, fmt.Sprintf(`{"type":"compaction","encrypted_content":"publication-signed-%d"}`, i))
	}
	return strings.Join(blocks, ",")
}

func TestCompactionReplayPublicationBatch(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	blocks := publicationCompactionBlocks(256)
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(`{"output":[`+blocks+`]}`)); err != nil {
		t.Fatal(err)
	}
	count := watchCompactionPublications(t, dir)
	picked, err := selector.Pick(context.Background(), "codex", "model", cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		OriginalRequest: []byte(`{"input":[`+blocks+`]}`),
		Metadata: make(map[string]any),
	}, []*Auth{{ID: "A"}, {ID: "B"}})
	if err != nil || picked == nil || picked.ID != "A" {
		t.Fatalf("known replay = %v, %v", picked, err)
	}
	if publications := count(); publications != 1 {
		t.Fatalf("known replay made %d whole-store publications; want one signer batch", publications)
	}
}

func TestCompactionOutputPublicationBatch(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	count := watchCompactionPublications(t, dir)
	opts := cliproxyexecutor.Options{
		OriginalRequest: []byte(`{"prompt_cache_key":"publication-primary"}`),
		Metadata: map[string]any{
			cliproxyexecutor.SessionAffinityProviderMetadataKey: "codex",
			cliproxyexecutor.SessionAffinityModelMetadataKey: "model",
		},
	}
	if err := selector.RecordCompactionOutput("A", opts, []byte(`{"output":[`+publicationCompactionBlocks(32)+`]}`)); err != nil {
		t.Fatal(err)
	}
	if publications := count(); publications != 1 {
		t.Fatalf("output plus primary made %d whole-store publications; want one complete batch", publications)
	}
	state, errRead := os.ReadFile(filepath.Join(dir, "affinity.state"))
	if errRead != nil {
		t.Fatal(errRead)
	}
	var snapshot struct {
		Groups []struct {
			AuthID    string   `json:"auth_id"`
			Aliases   []string `json:"aliases"`
			Protected bool     `json:"protected"`
		} `json:"groups"`
	}
	if errDecode := json.Unmarshal(state, &snapshot); errDecode != nil {
		t.Fatal(errDecode)
	}
	protected := 0
	for _, group := range snapshot.Groups {
		if group.Protected {
			protected++
			if group.AuthID != "A" || len(group.Aliases) != 1 {
				t.Fatalf("batch merged independent signer/primary groups: %+v", group)
			}
		}
	}
	if protected != 33 || len(snapshot.Groups) != 161 {
		t.Fatalf("snapshot retained %d protected / %d total groups; want 33 / 161", protected, len(snapshot.Groups))
	}
	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: filepath.Join(dir, "affinity.state")})
	defer restarted.Stop()
	if restarted.Cache().Len() != 161 || restarted.Cache().PersistenceError() != nil {
		t.Fatal("complete independent batch did not survive restart")
	}
}

type cancelCompactionPublicationSelector struct {
	cancel context.CancelFunc
}

func (s cancelCompactionPublicationSelector) Pick(_ context.Context, _, _ string, _ cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	s.cancel()
	return auths[0], nil
}

func TestCompactionCanceledReplayHasZeroPublications(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	blocks := publicationCompactionBlocks(32)
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(`{"output":[`+blocks+`]}`)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	replaySelector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{
		Cache: selector.Cache(), Fallback: cancelCompactionPublicationSelector{cancel: cancel},
	})
	defer replaySelector.Stop()
	count := watchCompactionPublications(t, dir)
	picked, err := replaySelector.Pick(ctx, "codex", "model", cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatOpenAIResponse,
		OriginalRequest: []byte(`{"input":[`+blocks+`]}`),
		Metadata: make(map[string]any),
	}, []*Auth{{ID: "A"}})
	publications := count()
	if publications != 0 || picked != nil || err == nil {
		t.Fatalf("canceled-before-batch replay = %v, %v; publications=%d, want local stop and zero writes", picked, err, publications)
	}
}

func TestCompactionOutputBatchPrechecksLateConflict(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	known := publicationCompactionBlocks(1)
	if err := selector.RecordCompactionOutput("B", cliproxyexecutor.Options{}, []byte(`{"output":[`+known+`]}`)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "affinity.state")
	before, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	beforeLen := selector.Cache().Len()
	count := watchCompactionPublications(t, dir)
	payload := []byte(`{"output":[{"type":"compaction","encrypted_content":"new-before-conflict"},`+known+`]}`)
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, payload); err == nil {
		t.Fatal("late signer conflict accepted")
	}
	if publications := count(); publications != 0 || selector.Cache().Len() != beforeLen {
		t.Fatalf("late conflict partially mutated store: publications=%d len=%d, want 0 / %d", publications, selector.Cache().Len(), beforeLen)
	}
	after, errRead := os.ReadFile(path)
	if errRead != nil || !bytes.Equal(before, after) {
		t.Fatal("late conflict changed published state")
	}
}

func TestCompactionOutputBatchPrechecksRetention(t *testing.T) {
	dir := t.TempDir()
	cache := NewSessionCacheWithCapacity(time.Hour, 2)
	defer cache.Stop()
	if err := cache.EnablePersistence(filepath.Join(dir, "affinity.state")); err != nil {
		t.Fatal(err)
	}
	cache.Set("ordinary", "A")
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Cache: cache})
	defer selector.Stop()
	count := watchCompactionPublications(t, dir)
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(`{"output":[`+publicationCompactionBlocks(3)+`]}`)); err == nil {
		t.Fatal("output larger than retention capacity acknowledged")
	}
	if publications := count(); publications != 0 || cache.Len() != 1 {
		t.Fatalf("capacity refusal partially mutated store: publications=%d len=%d, want 0 / 1", publications, cache.Len())
	}
	if id, ok := cache.Get("ordinary"); !ok || id != "A" {
		t.Fatal("capacity refusal evicted an unrelated binding")
	}
}

func TestCompactionOutputBatchPreservesExistingAliasGroups(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	primary := "codex::pck:publication-primary::model"
	selector.Cache().SetAliases("A", primary, "conversation-alias")
	count := watchCompactionPublications(t, dir)
	opts := cliproxyexecutor.Options{
		OriginalRequest: []byte(`{"prompt_cache_key":"publication-primary"}`),
		Metadata: map[string]any{
			cliproxyexecutor.SessionAffinityProviderMetadataKey: "codex",
			cliproxyexecutor.SessionAffinityModelMetadataKey: "model",
		},
	}
	if err := selector.RecordCompactionOutput("A", opts, []byte(`{"output":[`+publicationCompactionBlocks(32)+`]}`)); err != nil {
		t.Fatal(err)
	}
	if publications := count(); publications != 1 {
		t.Fatalf("existing primary aliases made %d publications; want one", publications)
	}
	if id, ok := selector.Cache().Get("conversation-alias"); !ok || id != "A" || !selector.Cache().IsProtected("conversation-alias") {
		t.Fatal("batch dropped or detached the existing primary alias group")
	}
	selector.Cache().Invalidate(primary)
	if id, ok := selector.Cache().Get("conversation-alias"); !ok || id != "A" || !selector.Cache().IsProtected("conversation-alias") {
		t.Fatal("primary alias invalidation lost the remaining protected group")
	}
}

func TestCompactionOutputBatchStickyFailure(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	path := filepath.Join(dir, "affinity.state")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(`{"output":[`+publicationCompactionBlocks(32)+`]}`)); err == nil {
		t.Fatal("failed atomic replacement acknowledged output")
	}
	sticky := selector.Cache().PersistenceError()
	if sticky == nil {
		t.Fatal("save failure not sticky")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	beforeLen := selector.Cache().Len()
	count := watchCompactionPublications(t, dir)
	if err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"after-save-failure"}]}`)); err == nil {
		t.Fatal("restored filesystem bypassed sticky fail-closed state")
	}
	if publications := count(); publications != 0 || selector.Cache().Len() != beforeLen || selector.Cache().PersistenceError() != sticky {
		t.Fatal("sticky refusal published or mutated signer state")
	}
}

func TestCompactionOutputBatchRejectsExpiredPublication(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	// Stop unrelated cleanup publications. The existing nanosecond TTL expires
	// during planning/serialization/fsync; no sleep or elapsed-time assertion.
	selector.Cache().Stop()
	selector.Cache().SetTTL(time.Nanosecond)
	count := watchCompactionPublications(t, dir)
	err := selector.RecordCompactionOutput("A", cliproxyexecutor.Options{}, []byte(`{"output":[`+publicationCompactionBlocks(32)+`]}`))
	local, ok := err.(*Error)
	if !ok || local.Code != "affinity_state_unavailable" {
		t.Fatalf("expired publication acknowledged signed output: %v", err)
	}
	if publications := count(); publications != 1 {
		t.Fatalf("expiry refusal made %d publications; want one attempted snapshot and no follow-up save", publications)
	}
	state, errRead := os.ReadFile(filepath.Join(dir, "affinity.state"))
	if errRead != nil {
		t.Fatal(errRead)
	}
	// Verify the real publication, not just the passage of a short TTL: all
	// expired signer groups were omitted, and the old ordinary store survived.
	var snapshot struct {
		Groups []struct {
			Aliases   []string `json:"aliases"`
			Protected bool     `json:"protected"`
		} `json:"groups"`
	}
	if errDecode := json.Unmarshal(state, &snapshot); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(snapshot.Groups) != 128 {
		t.Fatalf("expiry snapshot retained %d groups; want only 128 ordinary groups", len(snapshot.Groups))
	}
	for _, group := range snapshot.Groups {
		if group.Protected || len(group.Aliases) != 1 || !strings.HasPrefix(group.Aliases[0], "ordinary-") {
			t.Fatal("expiry snapshot published a signer despite its refusal")
		}
	}
	if selector.Cache().PersistenceError() != nil {
		t.Fatal("expiry refusal was confused with a sticky filesystem failure")
	}
}

func TestCompactionCanceledOutputHasZeroPublications(t *testing.T) {
	selector, dir := populatedCompactionPublicationSelector(t)
	manager := NewManager(nil, selector, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opts, err := manager.PrepareCompactionRequest("model", cliproxyexecutor.Options{OriginalRequest: []byte(`{}`)}, ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	count := watchCompactionPublications(t, dir)
	err = manager.RecordCompactionOutput("A", opts, []byte(`{"output":[`+publicationCompactionBlocks(32)+`]}`))
	if publications := count(); publications != 0 || err == nil {
		t.Fatalf("canceled output = %v; publications=%d, want rejection and zero writes", err, publications)
	}
}
