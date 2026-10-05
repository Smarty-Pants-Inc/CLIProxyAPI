package auth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func affinityConversationOptions(compacted bool) cliproxyexecutor.Options {
	payload := `{"prompt_cache_key":"conversation-a","input":[{"role":"user","content":"hello"}]}`
	if compacted {
		payload = `{"prompt_cache_key":"conversation-a","input":[{"type":"compaction","encrypted_content":"signed-account-a"},{"role":"user","content":"continue"}]}`
	}
	return cliproxyexecutor.Options{
		OriginalRequest: []byte(payload),
		SourceFormat:    sdktranslator.FormatOpenAIResponse,
		Metadata:        make(map[string]any),
	}
}

func recordAffinityTestOutput(t *testing.T, selector *SessionAffinitySelector, authID string, opts cliproxyexecutor.Options) {
	t.Helper()
	if err := selector.RecordCompactionOutput(authID, opts, []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-account-a"}]}`)); err != nil {
		t.Fatal(err)
	}
}

func TestCompactionAffinityRestartAndTwoHourIdle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-affinity.state")
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: path, Fallback: lastAuthSelector{}})
	defer selector.Stop()
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	initial := affinityConversationOptions(false)
	first, err := selector.Pick(context.Background(), "openai", "model", initial, auths)
	if err != nil || first == nil || first.ID != "auth-b" {
		t.Fatalf("initial Pick = %v, %v; want auth-b", first, err)
	}
	// Persist actual production evidence, then restart BEFORE the first replay.
	recordAffinityTestOutput(t, selector, first.ID, initial)
	key := compactionAffinityKeys(affinityConversationOptions(true))[0]
	selector.cache.mu.Lock()
	group := selector.cache.entries[key]
	selector.cache.replaceAliasGroupsLocked(group.authID, time.Now().Add(4*time.Hour), group.aliases, group)
	selector.cache.mu.Unlock()
	selector.cache.cleanup()
	selector.Stop()

	restarted := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: path, Fallback: &RoundRobinSelector{}})
	defer restarted.Stop()
	// Without signer persistence the fresh round-robin selector would choose A.
	picked, err := restarted.Pick(context.Background(), "openai", "model", affinityConversationOptions(true), auths)
	if err != nil || picked == nil || picked.ID != first.ID {
		t.Fatalf("restart after two-hour idle Pick = %v, %v; want %s", picked, err, first.ID)
	}
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatal(errRead)
	}
	if strings.Contains(string(data), "signed-account-a") || strings.Contains(string(data), "continue") {
		t.Fatal("state contains plaintext request content or compaction block")
	}
}

func TestCompactionAffinityPreservesBindingOnErrorAndInvalidation(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: lastAuthSelector{}})
	defer selector.Stop()
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	initial := affinityConversationOptions(false)
	first, err := selector.Pick(context.Background(), "openai", "model", initial, auths)
	if err != nil {
		t.Fatal(err)
	}
	recordAffinityTestOutput(t, selector, first.ID, initial)
	compacted := affinityConversationOptions(true)
	if _, err = selector.Pick(context.Background(), "openai", "model", compacted, auths); err != nil {
		t.Fatal(err)
	}
	selector.OnResult(Result{AuthID: first.ID, Provider: "openai", Model: "model", Error: &Error{Code: "rate_limited", HTTPStatus: 429}, Options: compacted})
	selector.InvalidateAuth(first.ID)
	if _, err = selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(true), auths[:1]); err == nil {
		t.Fatal("compacted request silently failed over to auth-a")
	}
	if _, err = selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(false), auths[:1]); err == nil {
		t.Fatal("protected conversation silently failed over when block was omitted")
	}
	picked, err := selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(true), auths)
	if err != nil || picked == nil || picked.ID != first.ID {
		t.Fatalf("recovered original account Pick = %v, %v", picked, err)
	}
}

func TestCompactionAffinityColdBlockRequiresRecompaction(t *testing.T) {
	selector := NewSessionAffinitySelector(nil)
	defer selector.Stop()
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	// Even a valid mutable conversation binding is NOT signer evidence.
	if _, err := selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(false), auths); err != nil {
		t.Fatal(err)
	}
	picked, err := selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(true), auths)
	if picked != nil || err == nil {
		t.Fatalf("unknown signed block guessed an account: %v, %v", picked, err)
	}
	if authErr, ok := err.(*Error); !ok || authErr.Code != "compaction_affinity_missing" || authErr.HTTPStatus != http.StatusConflict {
		t.Fatalf("cold block error = %v, want recompaction-required conflict", err)
	}
	if selector.cache.Len() != 1 {
		t.Fatal("cold block created signer evidence")
	}
}

func TestCompactionAffinityDigestSurvivesIdentityAndModelChange(t *testing.T) {
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{Fallback: lastAuthSelector{}})
	defer selector.Stop()
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	initial := affinityConversationOptions(false)
	first, err := selector.Pick(context.Background(), "openai", "model", initial, auths)
	if err != nil {
		t.Fatal(err)
	}
	recordAffinityTestOutput(t, selector, first.ID, initial)
	changed := affinityConversationOptions(true)
	changed.OriginalRequest = []byte(strings.ReplaceAll(string(changed.OriginalRequest), "conversation-a", "conversation-new"))
	picked, err := selector.Pick(context.Background(), "openai", "other-model", changed, auths)
	if err != nil || picked == nil || picked.ID != "auth-b" {
		t.Fatalf("same block with changed identity/model Pick = %v, %v; want auth-b", picked, err)
	}
	changed.Metadata[cliproxyexecutor.PinnedAuthMetadataKey] = "auth-a"
	if _, err = selector.Pick(context.Background(), "openai", "other-model", changed, auths); err == nil {
		t.Fatal("conflicting caller pin overrode signed-block account")
	}
}

func TestCompactionAffinityLostSignerCannotUseNewSessionBinding(t *testing.T) {
	for _, loss := range []string{"expiration", "eviction"} {
		t.Run(loss, func(t *testing.T) {
			selector := NewSessionAffinitySelector(&RoundRobinSelector{})
			defer selector.Stop()
			auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
			initial := affinityConversationOptions(false)
			first, err := selector.Pick(context.Background(), "openai", "model", initial, auths)
			if err != nil || first.ID != "auth-a" {
				t.Fatalf("first Pick = %v, %v", first, err)
			}
			recordAffinityTestOutput(t, selector, first.ID, initial)
			if loss == "expiration" {
				selector.cache.mu.Lock()
				groups := make([]sessionEntry, 0, len(selector.cache.groups))
				for _, group := range selector.cache.groups {
					groups = append(groups, group)
				}
				for _, group := range groups {
					selector.cache.replaceAliasGroupsLocked(group.authID, time.Now().Add(-time.Hour), group.aliases, group)
				}
				selector.cache.mu.Unlock()
				selector.cache.cleanup()
			} else {
				selector.cache.mu.Lock()
				selector.cache.maxEntries = 2
				selector.cache.mu.Unlock()
				selector.cache.Set("new-1", "other")
				selector.cache.Set("new-2", "other")
			}
			second, err := selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(false), auths)
			if err != nil || second == nil || second.ID != "auth-b" {
				t.Fatalf("ordinary cold conversation should rebind B: %v, %v", second, err)
			}
			if picked, errReplay := selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(true), auths); picked != nil || errReplay == nil {
				t.Fatalf("lost signer was guessed from newer B binding: %v, %v", picked, errReplay)
			}
		})
	}
}

func TestCompactionAffinityEveryBlockConstrainsSigner(t *testing.T) {
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	defer selector.Stop()
	auths := []*Auth{{ID: "auth-a"}, {ID: "auth-b"}}
	initial := affinityConversationOptions(false)
	first, err := selector.Pick(context.Background(), "openai", "model", initial, auths)
	if err != nil {
		t.Fatal(err)
	}
	recordAffinityTestOutput(t, selector, first.ID, initial)
	unrelated := affinityConversationOptions(false)
	unrelated.OriginalRequest = []byte(`{"prompt_cache_key":"unrelated","input":[{"role":"user","content":"hello"}]}`)
	second, err := selector.Pick(context.Background(), "openai", "model", unrelated, auths)
	if err != nil || second.ID != "auth-b" {
		t.Fatalf("unrelated ordinary binding = %v, %v", second, err)
	}
	composite := affinityConversationOptions(true)
	composite.OriginalRequest = []byte(`{"prompt_cache_key":"unrelated","input":[{"type":"compaction","encrypted_content":"signed-account-a"},{"type":"compaction","encrypted_content":"signed-account-a"}]}`)
	picked, err := selector.Pick(context.Background(), "openai", "model", composite, auths)
	if err != nil || picked == nil || picked.ID != first.ID {
		t.Fatalf("duplicate/list shape bypassed signer A: %v, %v", picked, err)
	}
	if err := selector.RecordCompactionOutput(second.ID, cliproxyexecutor.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-account-b"}]}`)); err != nil {
		t.Fatal(err)
	}
	composite = affinityConversationOptions(true)
	composite.OriginalRequest = []byte(`{"input":[{"type":"compaction","encrypted_content":"signed-account-a"},{"type":"compaction","encrypted_content":"signed-account-b"}]}`)
	if picked, err := selector.Pick(context.Background(), "openai", "model", composite, auths); picked != nil || err == nil {
		t.Fatalf("conflicting signers were dispatched: %v, %v", picked, err)
	}
}

func TestCompactionAffinityPersistenceFailureFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session-affinity.state")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	selector := NewSessionAffinitySelectorWithConfig(SessionAffinityConfig{StatePath: path})
	defer selector.Stop()
	if picked, err := selector.Pick(context.Background(), "openai", "model", affinityConversationOptions(false), []*Auth{{ID: "auth-a"}}); picked != nil || err == nil {
		t.Fatalf("corrupt affinity state routed request: %v, %v", picked, err)
	}
}
