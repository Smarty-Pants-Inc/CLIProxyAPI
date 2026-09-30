package handlers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type compactionRetryExecutor struct {
	bootstrapStreamExecutor
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	ids     []string
	failure bool
}

func (e *compactionRetryExecutor) Execute(_ context.Context, auth *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{Payload: []byte(fmt.Sprintf(`{"output":[{"type":"compaction","encrypted_content":%q}]}`, auth.ID))}, nil
}

func (e *compactionRetryExecutor) ExecuteStream(ctx context.Context, auth *coreauth.Auth, _ coreexecutor.Request, _ coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	e.mu.Lock()
	e.calls++
	e.ids = append(e.ids, auth.ID)
	e.mu.Unlock()
	e.once.Do(func() {
		close(e.entered)
		<-e.release
	})
	coreexecutor.MarkUpstreamAttempt(ctx)
	chunks := make(chan coreexecutor.StreamChunk, 1)
	if e.failure {
		chunks <- coreexecutor.StreamChunk{Err: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "ordinary upstream failure"}}
	} else {
		chunks <- coreexecutor.StreamChunk{Payload: []byte(fmt.Sprintf("data: {\"type\":\"response.output_item.done\",\"item\":{\"type\":\"compaction\",\"encrypted_content\":%q}}\n\n", auth.ID))}
	}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}

type compactionHandlerResult struct {
	data <-chan []byte
	errs <-chan *interfaces.ErrorMessage
}

func TestHandlerCompactionRegistrationConflictDoesNotBootstrapRetry(t *testing.T) {
	executor := &compactionRetryExecutor{entered: make(chan struct{}), release: make(chan struct{})}
	handler, manager := registerBootstrapExecutor(t, &executor.bootstrapStreamExecutor)
	manager.RegisterExecutor(executor)
	origin := coreauth.NewSessionAffinitySelector(&coreauth.FillFirstSelector{})
	defer origin.Stop()
	manager.SetSelector(origin)
	body := []byte(`{"model":"bootstrap-model","prompt_cache_key":"registration-race","input":[]}`)
	result := make(chan compactionHandlerResult, 1)
	go func() {
		data, _, errs := handler.ExecuteStreamWithAuthManager(context.Background(), "openai-response", "bootstrap-model", body, "")
		result <- compactionHandlerResult{data: data, errs: errs}
	}()
	<-executor.entered
	if len(executor.ids) != 1 || executor.ids[0] != "bootstrap-auth" {
		close(executor.release)
		t.Fatalf("first producing account = %v, want A", executor.ids)
	}
	// A was selected before either output existed. B now completes production
	// on the same explicit identity; A's independent digest is valid, but its
	// primary registration conflicts. This is not a sticky disk failure.
	_, errProduce := manager.Execute(context.Background(), []string{executor.Identifier()}, coreexecutor.Request{Model: "bootstrap-model", Payload: body}, coreexecutor.Options{
		OriginalRequest: body, SourceFormat: sdktranslator.FormatOpenAIResponse,
		Metadata: map[string]any{coreexecutor.PinnedAuthMetadataKey: "bootstrap-auth-retry"},
	})
	close(executor.release)
	if errProduce != nil {
		t.Fatal(errProduce)
	}
	stream := <-result
	for payload := range stream.data {
		if len(payload) != 0 {
			t.Fatalf("local rejection leaked payload: %q", payload)
		}
	}
	var terminal *interfaces.ErrorMessage
	for msg := range stream.errs {
		terminal = msg
	}
	if terminal == nil || !coreauth.IsLocalCompactionAffinityStop(terminal.Error) {
		t.Fatalf("local stop marker lost through ErrorMessage: %+v", terminal)
	}
	var local *coreauth.Error
	if !errors.As(terminal.Error, &local) || local.Code != "affinity_state_unavailable" {
		t.Fatalf("typed local error lost: %v", terminal.Error)
	}
	if executor.Calls() != 1 {
		t.Fatalf("local conflict caused %d stream attempts, want 1", executor.Calls())
	}
	for _, auth := range manager.List() {
		if auth.ID == "bootstrap-auth" && (auth.Unavailable || auth.LastError != nil) {
			t.Fatalf("local registration failure cooled credential: %+v", auth)
		}
	}
}

func TestHandlerCompactionSignerSurvivesDisableAtBootstrap(t *testing.T) {
	executor := &compactionRetryExecutor{entered: make(chan struct{}), release: make(chan struct{}), failure: true}
	handler, manager := registerBootstrapExecutor(t, &executor.bootstrapStreamExecutor)
	manager.RegisterExecutor(executor)
	origin := coreauth.NewSessionAffinitySelector(nil)
	defer origin.Stop()
	manager.SetSelector(origin)
	manager.SetRetryConfig(1, 0, 1)
	if errSave := origin.RecordCompactionOutput("bootstrap-auth", coreexecutor.Options{}, []byte(`{"output":[{"type":"compaction","encrypted_content":"signed-a"}]}`)); errSave != nil {
		t.Fatal(errSave)
	}
	result := make(chan compactionHandlerResult, 1)
	go func() {
		data, _, errs := handler.ExecuteStreamWithAuthManager(context.Background(), "openai-response", "bootstrap-model", []byte(`{"model":"bootstrap-model","input":[{"type":"compaction","encrypted_content":"signed-a"}]}`), "")
		result <- compactionHandlerResult{data: data, errs: errs}
	}()
	<-executor.entered
	manager.SetSelector(&coreauth.RoundRobinSelector{})
	close(executor.release)
	stream := <-result
	for payload := range stream.data {
		if len(payload) != 0 {
			t.Fatalf("signed bootstrap failure leaked payload: %q", payload)
		}
	}
	var terminal *interfaces.ErrorMessage
	for msg := range stream.errs {
		terminal = msg
	}
	if terminal == nil {
		t.Fatal("expected terminal bootstrap failure")
	}
	for _, id := range executor.ids {
		if id != "bootstrap-auth" {
			t.Fatalf("signed HTTP retry executed on another account: %v", executor.ids)
		}
	}
}

func TestHandlerOrdinaryUpstream503StillBootstrapRetries(t *testing.T) {
	executor := &bootstrapStreamExecutor{stream: func(_ context.Context, call int) (*coreexecutor.StreamResult, error) {
		chunks := make(chan coreexecutor.StreamChunk, 1)
		if call == 1 {
			chunks <- coreexecutor.StreamChunk{Err: &coreauth.Error{HTTPStatus: http.StatusServiceUnavailable, Message: "ordinary upstream"}}
		} else {
			chunks <- coreexecutor.StreamChunk{Payload: []byte("ok")}
		}
		close(chunks)
		return &coreexecutor.StreamResult{Chunks: chunks}, nil
	}}
	handler, _ := registerBootstrapExecutor(t, executor)
	data, _, errs := handler.ExecuteStreamWithAuthManager(context.Background(), "openai", "bootstrap-model", []byte(`{"model":"bootstrap-model"}`), "")
	var got []byte
	for payload := range data {
		got = append(got, payload...)
	}
	for msg := range errs {
		if msg != nil {
			t.Fatalf("ordinary upstream retry failed: %+v", msg)
		}
	}
	if string(got) != "ok" || executor.Calls() != 2 {
		t.Fatalf("ordinary upstream retry: payload=%q attempts=%d", got, executor.Calls())
	}
}
