package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	core "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCompactionRetentionRound3ManagerPluginCancellation(t *testing.T) {
	for _, path := range []string{"execute", "stream"} {
		t.Run(path, func(t *testing.T) {
			origin, dir := populatedCompactionPublicationSelector(t)
			origin.Cache().Stop()
			a, b, model := t.Name()+"-A", t.Name()+"-B", "retention-cancel-model"
			e := &compactionAffinityExecutor{provider: "codex", firstID: a, output: []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`)}
			m := newCompactionAffinityManager(t, origin, e, model, b)
			m.SetPluginScheduler(&fakePluginScheduler{handled: true, resp: pluginapi.SchedulerPickResponse{Handled: true, AuthID: a}})
			req, opts := compactionAffinityRequest(model, "none", false, false)
			if err := runCompactionAffinityRequest(t, m, e, "execute", req, opts); err != nil {
				t.Fatal(err)
			}
			e.attempts = nil
			e.output = nil
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			m.SetPluginScheduler(&fakePluginScheduler{pick: func(context.Context, pluginapi.SchedulerPickRequest) (pluginapi.SchedulerPickResponse, bool, error) {
				cancel()
				return pluginapi.SchedulerPickResponse{Handled: true, AuthID: a}, true, nil
			}})
			req, opts = compactionAffinityRequest(model, "none", true, false)
			before := round3ShiftSignerExpiry(t, origin, opts.OriginalRequest, 0)
			count := watchCompactionPublications(t, dir)
			var err error
			if path == "execute" {
				_, err = m.Execute(ctx, []string{"codex"}, req, opts)
			} else {
				_, err = m.ExecuteStream(ctx, []string{"codex"}, req, opts)
			}
			if !errors.Is(err, context.Canceled) || len(e.attempts) != 0 {
				t.Fatalf("canceled handled selection dispatched: err=%v calls=%d", err, len(e.attempts))
			}
			if publications := count(); publications != 0 {
				t.Fatalf("canceled handled selection made %d publications", publications)
			}
			for key, expiry := range before {
				if !round3SignerExpiry(t, origin, key).Equal(expiry) {
					t.Fatal("canceled plugin refreshed signer")
				}
			}
			current, _ := m.GetByID(a)
			if current.Unavailable || !current.NextRetryAfter.IsZero() || current.LastError != nil {
				t.Fatal("local cancellation changed credential availability")
			}
		})
	}
}

func TestCompactionRetentionRound3DuplexStickySaveFailure(t *testing.T) {
	origin, dir := populatedCompactionPublicationSelector(t)
	origin.Cache().Stop()
	blocks := publicationCompactionBlocks(32)
	if err := origin.RecordCompactionOutput("A", core.Options{}, []byte(`{"output":[`+blocks+`]}`)); err != nil {
		t.Fatal(err)
	}
	m := NewManager(nil, origin, nil)
	opts, err := m.PrepareCompactionRequest("model", core.Options{OriginalRequest: []byte(`{"input":[]}`)}, context.Background())
	if err != nil {
		t.Fatal(err)
	}
	validate := opts.Metadata[core.CompactionAffinityValidatorMetadataKey].(func(string, []byte) error)
	path := filepath.Join(dir, "affinity.state")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"input":[` + blocks + `]}`)
	if err := validate("A", payload); !IsLocalCompactionAffinityStop(err) {
		t.Fatalf("failed synchronous refresh=%v", err)
	}
	sticky := origin.Cache().PersistenceError()
	if sticky == nil {
		t.Fatal("refresh save failure was not sticky")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	count := watchCompactionPublications(t, dir)
	if err := validate("A", payload); !IsLocalCompactionAffinityStop(err) {
		t.Fatalf("sticky refresh refusal=%v", err)
	}
	if publications := count(); publications != 0 || origin.Cache().PersistenceError() != sticky {
		t.Fatal("restored filesystem bypassed sticky refresh refusal")
	}
}
