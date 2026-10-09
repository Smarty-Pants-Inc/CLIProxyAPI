package auth

import (
	"errors"
	"net/http"
	"testing"
	"time"

	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestCompactionDuplexCapturedOriginStrictSigner(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	other := NewSessionAffinitySelector(nil)
	defer other.Stop()
	manager := NewManager(nil, other, nil)
	for _, block := range []struct{ content, signer string }{{"known-a", "A"}, {"known-b", "B"}, {"expired", "A"}} {
		payload := []byte(`{"output":[{"type":"compaction","encrypted_content":"` + block.content + `"}]}`)
		if err := origin.RecordCompactionOutput(block.signer, core.Options{}, payload); err != nil {
			t.Fatal(err)
		}
	}
	expiredPayload := []byte(`{"input":[{"type":"compaction","encrypted_content":"expired"}]}`)
	expiredKey := compactionAffinityKeys(core.Options{OriginalRequest: expiredPayload})[0]
	origin.cache.mu.Lock()
	entry := origin.cache.entries[expiredKey]
	origin.cache.replaceAliasGroupsLocked(entry.authID, time.Now().Add(-time.Hour), entry.aliases, entry)
	origin.cache.mu.Unlock()
	// Conflicting mutable routing metadata is never a source of signer authority.
	opts := core.Options{Metadata: map[string]any{
		compactionAffinityStoreMetadataKey: origin,
		core.PinnedAuthMetadataKey:         "B", core.LCPAffinitySessionIDMetadataKey: "mutable-B",
	}}
	manager.prepareCompactionDuplexValidation(opts)
	validate, ok := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	if !ok || validate == nil {
		t.Fatal("captured origin did not install callback")
	}
	// Changing request metadata after installation cannot replace its captured store.
	opts.Metadata[compactionAffinityStoreMetadataKey] = other
	cases := []struct{ name, input, code string }{
		{"known-a", `[{"type":"compaction","encrypted_content":"known-a"}]`, ""},
		{"duplicate-a", `[{"type":"compaction","encrypted_content":"known-a"},{"type":"compaction","encrypted_content":"known-a"}]`, ""},
		{"ordinary-tool", `[{"type":"function_call_output","call_id":"call-1","output":"ok"}]`, ""},
		{"known-b", `[{"type":"compaction","encrypted_content":"known-b"}]`, "compaction_affinity_conflict"},
		{"unknown", `[{"type":"compaction","encrypted_content":"unknown"}]`, "compaction_affinity_missing"},
		{"expired", `[{"type":"compaction","encrypted_content":"expired"}]`, "compaction_affinity_missing"},
		{"composite", `[{"type":"compaction","encrypted_content":"known-a"},{"type":"compaction","encrypted_content":"known-b"}]`, "compaction_affinity_conflict"},
		{"known-and-unknown", `[{"type":"compaction","encrypted_content":"known-a"},{"type":"compaction","encrypted_content":"unknown"}]`, "compaction_affinity_missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validate("A", []byte(`{"input":`+tc.input+`}`))
			if tc.code == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			var local *Error
			if !errors.As(err, &local) || local.Code != tc.code || local.StatusCode() != http.StatusConflict || !IsLocalCompactionAffinityStop(err) {
				t.Fatalf("callback error = %v, want typed local %s", err, tc.code)
			}
		})
	}
	// Claude-shaped signed content is subject to the same per-block rule.
	if err := validate("A", []byte(`{"messages":[{"content":[{"type":"compaction","encrypted_content":"known-b"}]}]}`)); !IsLocalCompactionAffinityStop(err) {
		t.Fatalf("message content bypassed signer guard: %v", err)
	}
	origin.cache.mu.Lock()
	origin.cache.persistenceErr = errors.New("disk unavailable")
	origin.cache.mu.Unlock()
	if err := validate("A", []byte(`{"input":[{"type":"compaction","encrypted_content":"known-a"}]}`)); !IsLocalCompactionAffinityStop(err) {
		t.Fatalf("unavailable store did not fail closed: %v", err)
	}
	if err := validate("A", []byte(`{"input":[]}`)); err != nil {
		t.Fatalf("ordinary follow-up requires no signer lookup: %v", err)
	}
}

func TestCompactionDuplexNegativeOriginHasNoCallback(t *testing.T) {
	current := NewSessionAffinitySelector(nil)
	defer current.Stop()
	manager := NewManager(nil, current, nil)
	for _, explicit := range []bool{false, true} {
		opts := core.Options{Metadata: map[string]any{core.CompactionAffinityValidatorMetadataKey: func(string, []byte) error { return errors.New("stale") }}}
		if explicit {
			opts.Metadata[compactionAffinityStoreMetadataKey] = (*SessionAffinitySelector)(nil)
		}
		manager.prepareCompactionDuplexValidation(opts)
		if _, exists := opts.Metadata[core.CompactionAffinityValidatorMetadataKey]; exists {
			t.Fatal("negative origin acquired callback from current selector")
		}
	}
}
