package auth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	core "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	pluginapi "github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

// Move the existing cache clock deterministically by changing expiration times,
// not by sleeping or inserting new signer evidence. Keep entries/groups coherent.
func round3ShiftSignerExpiry(t *testing.T, selector *SessionAffinitySelector, payload []byte, delta time.Duration) map[string]time.Time {
	t.Helper()
	keys := compactionAffinityKeys(core.Options{OriginalRequest: payload})
	cache := selector.Cache()
	cache.mu.Lock()
	defer cache.mu.Unlock()
	before := make(map[string]time.Time, len(keys))
	for _, key := range keys {
		entry, exists := cache.entries[key]
		if !exists {
			t.Fatalf("signer evidence absent: %s", key)
		}
		expires := entry.expiresAt.Add(delta)
		cache.replaceAliasGroupsLocked(entry.authID, expires, entry.aliases, entry)
		before[key] = expires
	}
	return before
}

func round3SignerExpiry(t *testing.T, selector *SessionAffinitySelector, key string) time.Time {
	t.Helper()
	selector.cache.mu.RLock()
	defer selector.cache.mu.RUnlock()
	entry, exists := selector.cache.entries[key]
	if !exists {
		t.Fatal("signer evidence removed")
	}
	return entry.expiresAt
}

func TestCompactionRetentionRound3ManagerHandledPlugin(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		for _, replacement := range []bool{false, true} {
			name := path + "/original-input"
			if replacement {
				name = path + "/after-auth-replacement"
			}
			t.Run(name, func(t *testing.T) {
				a, b, model := t.Name()+"-A", t.Name()+"-B", "retention-round3-model"
				origin := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: a})
				defer origin.Stop()
				origin.Cache().Stop()
				origin.Cache().SetTTL(6 * time.Hour)
				e := &compactionAffinityExecutor{provider: "codex", firstID: a,
					output:       []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`),
					streamOutput: [][]byte{[]byte("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"compaction\",\"encrypted_content\":\"signed-block\"}}\n\n")},
				}
				m := newCompactionAffinityManager(t, origin, e, model, b)
				m.SetPluginScheduler(&fakePluginScheduler{handled: true, resp: pluginapi.SchedulerPickResponse{Handled: true, AuthID: a}})
				req, opts := compactionAffinityRequest(model, "none", false, false)
				if err := runCompactionAffinityRequest(t, m, e, path, req, opts); err != nil {
					t.Fatal(err)
				}
				e.output, e.streamOutput = nil, nil // ordinary output cannot renew an input signer
				replayReq, replayOpts := compactionAffinityRequest(model, "none", true, false)
				original := round3ShiftSignerExpiry(t, origin, replayOpts.OriginalRequest, -5*time.Hour)
				if replacement {
					req, opts = compactionAffinityRequest(model, "none", false, false)
					opts.RequestAfterAuthInterceptor = func(context.Context, core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
						return core.RequestAfterAuthInterceptResponse{Body: replayReq.Payload}
					}
				} else {
					req, opts = replayReq, replayOpts
				}
				before := time.Now()
				if err := runCompactionAffinityRequest(t, m, e, path, req, opts); err != nil {
					t.Fatal(err)
				}
				for key, oldExpiry := range original {
					fresh := round3SignerExpiry(t, origin, key)
					if !fresh.After(oldExpiry) || fresh.Before(before.Add(6*time.Hour)) {
						t.Fatalf("admitted replay did not refresh signer: old=%v fresh=%v", oldExpiry, fresh)
					}
				}
				// Advance two hours: past t=0's original six-hour expiry, but
				// only two hours since the successful t=5h replay.
				round3ShiftSignerExpiry(t, origin, replayOpts.OriginalRequest, -2*time.Hour)
				if err := runCompactionAffinityRequest(t, m, e, path, replayReq, replayOpts); err != nil {
					t.Fatalf("active signer lost across original expiry with ordinary output: %v", err)
				}
				if len(e.attempts) != 3 {
					t.Fatalf("upstream calls=%d, want production plus two replays", len(e.attempts))
				}
				assertCompactionAffinityOnlyA(t, e, false)
			})
		}
	}
}

func TestCompactionRetentionRound3DuplexCallbacks(t *testing.T) {
	for _, action := range []string{"response.create", "response.append", "response.steer"} {
		t.Run(action, func(t *testing.T) {
			origin, dir := populatedCompactionPublicationSelector(t)
			origin.Cache().Stop()
			origin.Cache().SetTTL(6 * time.Hour)
			blocks := publicationCompactionBlocks(32)
			if err := origin.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[`+blocks+`]}`)); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"type":"` + action + `","input":[` + blocks + `]}`)
			original := round3ShiftSignerExpiry(t, origin, payload, -5*time.Hour)
			m := NewManager(nil, origin, nil)
			opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[]}`)}, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			// Current selector can change; the callback still owns the old origin.
			m.SetSelector(&FillFirstSelector{})
			validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
			count := watchCompactionPublications(t, dir)
			before := time.Now()
			if err := validate("A", payload); err != nil {
				t.Fatal(err)
			}
			if publications := count(); publications != 1 {
				t.Fatalf("admission publications=%d, want one complete signer batch", publications)
			}
			for key, oldExpiry := range original {
				fresh := round3SignerExpiry(t, origin, key)
				if !fresh.After(oldExpiry) || fresh.Before(before.Add(6*time.Hour)) {
					t.Fatal("actual-account callback did not renew signer TTL")
				}
			}
			round3ShiftSignerExpiry(t, origin, payload, -2*time.Hour)
			if err := validate("A", payload); err != nil {
				t.Fatalf("active follow-up expired at original deadline: %v", err)
			}
		})
	}
}

func TestCompactionRetentionRound3CanceledWrongAccountAndUnused(t *testing.T) {
	for _, control := range []string{"canceled", "wrong-account", "unused-expired", "negative-origin"} {
		t.Run(control, func(t *testing.T) {
			origin, dir := populatedCompactionPublicationSelector(t)
			origin.Cache().Stop()
			blocks := publicationCompactionBlocks(32)
			if err := origin.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[`+blocks+`]}`)); err != nil {
				t.Fatal(err)
			}
			payload := []byte(`{"input":[` + blocks + `]}`)
			before := round3ShiftSignerExpiry(t, origin, payload, -time.Hour)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m := NewManager(nil, origin, nil)
			opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[]}`)}, ctx)
			if err != nil {
				t.Fatal(err)
			}
			validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
			account := "A"
			if control == "canceled" {
				cancel()
			}
			if control == "wrong-account" {
				account = "B"
			}
			if control == "unused-expired" {
				round3ShiftSignerExpiry(t, origin, payload, -24*time.Hour)
				if err := validate(account, payload); !IsLocalCompactionAffinityStop(err) {
					t.Fatalf("unused expiry = %v, want local stop", err)
				}
				return // Get removes expired evidence; cleanup persistence is not a refresh
			}
			count := watchCompactionPublications(t, dir)
			if control == "negative-origin" {
				opts.Metadata[compactionAffinityStoreMetadataKey] = (*SessionAffinitySelector)(nil)
				m.prepareCompactionDuplexValidation(opts)
				if _, ok := opts.Metadata[core.CompactionAffinityValidatorMetadataKey]; ok {
					t.Fatal("negative origin installed signer callback")
				}
				err = validateCompactionSelectedAuth(ctx, account, core.Options{OriginalRequest: payload, Metadata: opts.Metadata})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				err = validate(account, payload)
				if err == nil {
					t.Fatal("rejected admission accepted")
				}
				if control == "canceled" && !errors.Is(err, context.Canceled) {
					t.Fatalf("cancel error=%v", err)
				}
				if control == "wrong-account" {
					var local *Error
					if !errors.As(err, &local) || local.StatusCode() != http.StatusConflict {
						t.Fatalf("wrong-account error=%v", err)
					}
				}
			}
			if publications := count(); publications != 0 {
				t.Fatalf("rejected/negative admission made %d publications", publications)
			}
			for key, expiry := range before {
				if !round3SignerExpiry(t, origin, key).Equal(expiry) {
					t.Fatal("rejected/negative admission refreshed signer")
				}
			}
		})
	}
}

func TestCompactionRetentionRound3SelectionDispatchOneBatch(t *testing.T) {
	for _, plugin := range []bool{false, true} {
		name := "selector"
		if plugin {
			name = "handled-plugin"
		}
		t.Run(name, func(t *testing.T) {
			origin, dir := populatedCompactionPublicationSelector(t)
			origin.Cache().Stop()
			blocks := publicationCompactionBlocks(256)
			if err := origin.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[`+blocks+`]}`)); err != nil {
				t.Fatal(err)
			}
			m := NewManager(nil, origin, nil)
			opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[` + blocks + `]}`)}, context.Background())
			if err != nil {
				t.Fatal(err)
			}
			opts.RequestAfterAuthInterceptor = func(context.Context, core.RequestAfterAuthInterceptRequest) core.RequestAfterAuthInterceptResponse {
				return core.RequestAfterAuthInterceptResponse{}
			}
			count := watchCompactionPublications(t, dir)
			if plugin {
				scheduler := &fakePluginScheduler{handled: true, resp: pluginapi.SchedulerPickResponse{Handled: true, AuthID: "A"}}
				_, handled, err := m.pickViaPluginScheduler(context.Background(), scheduler, "codex", []string{"codex"}, "model", opts, nil, []*Auth{{ID: "A"}})
				if err != nil || !handled {
					t.Fatalf("plugin selection=%v handled=%v", err, handled)
				}
			} else {
				if _, err := origin.Pick(context.Background(), "codex", "model", opts, []*Auth{{ID: "A"}}); err != nil {
					t.Fatal(err)
				}
			}
			if _, _, err := applyRequestAfterAuthInterceptor(context.Background(), nil, "codex", core.Request{Model: "model", Payload: opts.OriginalRequest}, opts, "model", "A"); err != nil {
				t.Fatal(err)
			}
			if publications := count(); publications != 1 {
				t.Fatalf("selection plus unchanged dispatch made %d publications, want one signer batch", publications)
			}
		})
	}
}
