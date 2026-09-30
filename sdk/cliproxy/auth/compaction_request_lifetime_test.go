package auth

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// The barrier holds the first upstream attempt while a reload disables affinity.
// No timer or scheduler ordering is used to decide when the mode changes.
type compactionLifetimeExecutor struct {
	*compactionAffinityExecutor
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (e *compactionLifetimeExecutor) barrier() {
	e.once.Do(func() {
		close(e.entered)
		<-e.release
	})
}

func (e *compactionLifetimeExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.barrier()
	return e.compactionAffinityExecutor.Execute(ctx, auth, req, opts)
}

func (e *compactionLifetimeExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.barrier()
	return e.compactionAffinityExecutor.ExecuteStream(ctx, auth, req, opts)
}

func TestCompactionRequestLifetimePinSurvivesDisableAcrossRetryRounds(t *testing.T) {
	for _, path := range []string{"execute", "stream-start", "stream-bootstrap"} {
		t.Run(path, func(t *testing.T) {
			model := "compaction-lifetime-model"
			a, b := t.Name()+"-a", t.Name()+"-b"
			origin := NewSessionAffinitySelector(&compactionAffinityFallback{preferredID: a})
			defer origin.Stop()
			if errSave := origin.RecordCompactionOutput(a, cliproxyexecutor.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-block"}]}`)); errSave != nil {
				t.Fatal(errSave)
			}
			base := &compactionAffinityExecutor{
				provider: "codex", firstID: a, bootstrapChunk: path == "stream-bootstrap",
				failure: compactTestStatusError{code: http.StatusServiceUnavailable, msg: "upstream unavailable"},
			}
			manager := newCompactionAffinityManager(t, origin, base, model, b)
			manager.SetRetryConfig(1, 0, 1)
			executor := &compactionLifetimeExecutor{compactionAffinityExecutor: base, entered: make(chan struct{}), release: make(chan struct{})}
			manager.RegisterExecutor(executor)
			req, opts := compactionAffinityRequest(model, "none", true, false)
			finished := make(chan error, 1)
			go func() {
				if path == "execute" {
					_, errExecute := manager.Execute(context.Background(), []string{"codex"}, req, opts)
					finished <- errExecute
					return
				}
				stream, errStream := manager.ExecuteStream(context.Background(), []string{"codex"}, req, opts)
				if errStream == nil && stream != nil {
					for chunk := range stream.Chunks {
						if chunk.Err != nil {
							errStream = chunk.Err
						}
					}
				}
				finished <- errStream
			}()
			<-executor.entered
			// This selector prefers healthy B, so an unrooted retry dispatches B.
			manager.SetSelector(&compactionAffinityFallback{preferredID: b})
			close(executor.release)
			if errRequest := <-finished; errRequest == nil {
				t.Fatal("signed request succeeded after its signer failed")
			}
			if len(base.attempts) == 0 {
				t.Fatal("barrier did not exercise upstream A")
			}
			assertCompactionAffinityOnlyA(t, base, true)
		})
	}
}

func TestCompactionRequestLifetimeExplicitNegativeOrigin(t *testing.T) {
	for _, home := range []bool{false, true} {
		t.Run(fmt.Sprintf("home=%v", home), func(t *testing.T) {
			manager := NewManager(nil, nil, nil)
			cfg := &internalconfig.Config{}
			cfg.Home.Enabled = home
			manager.runtimeConfig.Store(cfg)
			opts, errPrepare := manager.PrepareCompactionRequest("model", cliproxyexecutor.Options{})
			if errPrepare != nil {
				t.Fatal(errPrepare)
			}
			origin, present := opts.Metadata[compactionAffinityStoreMetadataKey]
			store, typed := origin.(*SessionAffinitySelector)
			if !present || !typed || store != nil {
				t.Fatalf("negative origin = %#v (present=%v typed=%v)", origin, present, typed)
			}
			local := NewSessionAffinitySelector(nil)
			defer local.Stop()
			manager.runtimeConfig.Store(&internalconfig.Config{})
			manager.SetSelector(local)
			opts = withAttemptedAuthTracker(opts, make(map[string]struct{}))
			opts, errPrepare = manager.PrepareCompactionRequest("model", opts)
			if errPrepare != nil {
				t.Fatal(errPrepare)
			}
			if manager.compactionOutputStore(opts) != nil {
				t.Fatal("request acquired a local observer after enable")
			}
			if errSave := manager.RecordCompactionOutput("a", opts, []byte(`{"output":[{"type":"compaction","encrypted_content":"negative-origin"}]}`)); errSave != nil {
				t.Fatal(errSave)
			}
			if local.cache.Len() != 0 {
				t.Fatal("negative-origin output was registered in the newly enabled store")
			}
		})
	}
}

func TestCompactionRequestLifetimeUsesAuthSelectionModel(t *testing.T) {
	origin := NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager := NewManager(nil, origin, nil)
	opts, errPrepare := manager.PrepareCompactionRequest("execution-model", cliproxyexecutor.Options{Metadata: map[string]any{
		cliproxyexecutor.AuthSelectionModelMetadataKey: "route-model",
	}})
	if errPrepare != nil {
		t.Fatal(errPrepare)
	}
	if opts.Metadata[cliproxyexecutor.RequestedModelMetadataKey] != "route-model" || opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey] != "route-model" || opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey] != "mixed" {
		t.Fatalf("root routing metadata = %#v", opts.Metadata)
	}
}
