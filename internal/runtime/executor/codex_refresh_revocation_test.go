package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type codexRevocationTransport func(*http.Request) (*http.Response, error)

func (f codexRevocationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func blockedCodexRefresh(t *testing.T) (<-chan struct{}, func()) {
	t.Helper()
	started, resume := make(chan struct{}), make(chan struct{})
	original := http.DefaultTransport
	http.DefaultTransport = codexRevocationTransport(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-resume
		return &http.Response{
			StatusCode: http.StatusOK, Header: make(http.Header), Request: req,
			Body: io.NopCloser(strings.NewReader(`{"access_token":"refreshed-access","refresh_token":"refreshed-refresh","expires_in":3600}`)),
		}, nil
	})
	var once sync.Once
	release := func() { once.Do(func() { close(resume) }) }
	t.Cleanup(func() { release(); http.DefaultTransport = original })
	return started, release
}

func revocationAuth(t *testing.T) (*cliproxyauth.Auth, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "revoked.json")
	metadata := map[string]any{"type": "codex", "access_token": "old-access", "refresh_token": "old-refresh"}
	if err := codexauth.WriteJSONFileAtomic(path, metadata); err != nil {
		t.Fatal(err)
	}
	return &cliproxyauth.Auth{
		ID: "revoked.json", Provider: "codex", FileName: "revoked.json",
		Attributes: map[string]string{cliproxyauth.AttributePath: path}, Metadata: metadata,
	}, path
}

func TestCodexRefreshRemovedRegistrationDoesNotPersist(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "removed", true: "replaced"}[replace], func(t *testing.T) {
			auth, path := revocationAuth(t)
			manager := cliproxyauth.NewManager(nil, nil, nil)
			manager.RegisterExecutor(NewCodexExecutor(&config.Config{}))
			if _, err := manager.Register(context.Background(), auth); err != nil {
				t.Fatal(err)
			}
			started, resume := blockedCodexRefresh(t)
			done := make(chan error, 1)
			go func() { _, err := manager.ForceRefreshAuth(context.Background(), auth.ID); done <- err }()
			<-started // The executor has read disk and holds its file lock.
			manager.Remove(context.Background(), auth.ID)
			if replace {
				if _, err := manager.Register(context.Background(), auth.Clone()); err != nil {
					t.Fatal(err)
				}
			}
			resume()
			if err := <-done; !errors.Is(err, codexauth.ErrRefreshNotPersisted) {
				t.Fatalf("removed registration refresh error = %v, want not-persisted", err)
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), "refreshed-access") {
				t.Fatal("refresh persisted after its registration was removed/replaced")
			}
		})
	}
}

func TestCodexRefreshDeletedSourceIsNotPersisted(t *testing.T) {
	auth, path := revocationAuth(t)
	started, resume := blockedCodexRefresh(t)
	done := make(chan error, 1)
	go func() { _, err := NewCodexExecutor(&config.Config{}).Refresh(context.Background(), auth); done <- err }()
	<-started
	// Simulate an external actor not using the cooperative credential lock.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	resume()
	if err := <-done; !errors.Is(err, codexauth.ErrRefreshNotPersisted) {
		t.Fatalf("deleted source error = %v, want not-persisted", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("refresh recreated deleted source: %v", err)
	}
}

func TestCodexRefreshDeletionWaitsAndStaysDeletedAfterRestart(t *testing.T) {
	auth, path := revocationAuth(t)
	started, resume := blockedCodexRefresh(t)
	refreshDone := make(chan error, 1)
	go func() {
		_, err := NewCodexExecutor(&config.Config{}).Refresh(context.Background(), auth)
		refreshDone <- err
	}()
	<-started
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(filepath.Dir(path))
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- store.Delete(context.Background(), path) }()
	select {
	case err := <-deleteDone:
		resume()
		<-refreshDone
		t.Fatalf("deletion overtook the in-flight refresh lock: %v", err)
	case <-time.After(100 * time.Millisecond): // Bounded lock-wait observation, not a TTL assertion.
	}
	resume()
	if err := <-refreshDone; err != nil {
		t.Fatal(err)
	}
	if err := <-deleteDone; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("deleted credential exists: %v", err)
	}
	restarted := fileauth.NewFileTokenStore()
	restarted.SetBaseDir(filepath.Dir(path))
	loaded, err := restarted.List(context.Background())
	if err != nil || len(loaded) != 0 {
		t.Fatalf("restart recovered revoked credential: count=%d err=%v", len(loaded), err)
	}
}
