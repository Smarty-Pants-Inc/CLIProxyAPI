package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	config "github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	filestore "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	auth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	executor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type round2RefreshExecutor struct {
	refresh func(*auth.Auth) (*auth.Auth, error)
}

func (*round2RefreshExecutor) Identifier() string { return "codex" }
func (e *round2RefreshExecutor) Refresh(_ context.Context, a *auth.Auth) (*auth.Auth, error) {
	return e.refresh(a)
}
func (*round2RefreshExecutor) Execute(context.Context, *auth.Auth, executor.Request, executor.Options) (executor.Response, error) {
	return executor.Response{}, errors.New("unexpected execution")
}
func (*round2RefreshExecutor) CountTokens(context.Context, *auth.Auth, executor.Request, executor.Options) (executor.Response, error) {
	return executor.Response{}, errors.New("unexpected count")
}
func (*round2RefreshExecutor) ExecuteStream(context.Context, *auth.Auth, executor.Request, executor.Options) (*executor.StreamResult, error) {
	return nil, errors.New("unexpected stream")
}
func (*round2RefreshExecutor) HttpRequest(context.Context, *auth.Auth, *http.Request) (*http.Response, error) {
	return nil, errors.New("unexpected HTTP")
}

func round2File(t *testing.T) (*filestore.FileTokenStore, string) {
	t.Helper()
	dir := t.TempDir()
	name := filepath.Join(dir, "credential.json")
	if err := os.WriteFile(name, []byte(`{"type":"codex","email":"a@example.com","access_token":"synthetic-a","refresh_token":"synthetic-refresh-a"}`), 0600); err != nil {
		t.Fatal(err)
	}
	store := filestore.NewFileTokenStore()
	store.SetBaseDir(dir)
	return store, name
}
func round2Policy(email string) *config.Config {
	digest := sha256.Sum256([]byte("round2-client"))
	return &config.Config{SDKConfig: config.SDKConfig{APIKeyPolicies: []config.APIKeyPolicy{{KeySHA256: hex.EncodeToString(digest[:]), AllowedAuths: []string{email}}}}}
}
func round2Deny(t *testing.T, err error) {
	t.Helper()
	var e *auth.Error
	if !errors.As(err, &e) || e.Code != "api_key_policy_unavailable" {
		t.Fatalf("expected policy denial, got %v", err)
	}
}

func TestRound2Finding8FileLoadedRefreshIdentity(t *testing.T) {
	store, _ := round2File(t)
	manager := auth.NewManager(store, nil, nil)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	manager.SetConfig(round2Policy("a@example.com"))
	ctx := auth.WithClientAPIKey(context.Background(), "round2-client")
	loaded, ok := manager.GetByID("credential.json")
	if !ok || loaded.Attributes["email"] != "a@example.com" {
		t.Fatal("file email mirror absent")
	}
	// This is the snapshot returned by real OAuth executors: only Metadata changes.
	contradictory := loaded.Clone()
	contradictory.Metadata["email"] = "b@example.com"
	t.Run("contradictory-aliases", func(t *testing.T) { round2Deny(t, manager.ValidateClientAuth(ctx, contradictory)) })
	manager.RegisterExecutor(&round2RefreshExecutor{refresh: func(a *auth.Auth) (*auth.Auth, error) {
		a.Metadata["email"] = "b@example.com"
		a.Metadata["access_token"] = "synthetic-b"
		return a, nil
	}})
	refreshed, err := manager.ForceRefreshAuth(context.Background(), loaded.ID)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("coherent-refresh", func(t *testing.T) {
		if refreshed.Attributes["email"] != "b@example.com" || refreshed.Metadata["email"] != "b@example.com" {
			t.Fatalf("refresh left split email identity: attr=%q meta=%v", refreshed.Attributes["email"], refreshed.Metadata["email"])
		}
		round2Deny(t, manager.ValidateClientAuth(ctx, refreshed))
		manager.SetConfig(round2Policy("b@example.com"))
		if err := manager.ValidateClientAuth(ctx, refreshed); err != nil {
			t.Fatal(err)
		}
	})
	reloaded, err := store.List(context.Background())
	if err != nil || len(reloaded) != 1 || reloaded[0].Attributes["email"] != "b@example.com" || reloaded[0].Metadata["access_token"] != "synthetic-b" {
		t.Fatalf("persisted identity/tokens incoherent: %v, %v", reloaded, err)
	}
}

func TestRound2Finding9PendingRefreshFileReplacement(t *testing.T) {
	for _, outcome := range []string{"success", "failure"} {
		t.Run(outcome, func(t *testing.T) {
			store, name := round2File(t)
			manager := auth.NewManager(store, nil, nil)
			if err := manager.Load(context.Background()); err != nil {
				t.Fatal(err)
			}
			started, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
			manager.RegisterExecutor(&round2RefreshExecutor{refresh: func(a *auth.Auth) (*auth.Auth, error) {
				close(started)
				<-release
				if outcome == "failure" {
					return nil, errors.New("synthetic refresh failed")
				}
				a.Metadata["access_token"] = "late-synthetic-a"
				a.Metadata["email"] = "a-refreshed@example.com"
				return a, nil
			}})
			go func() { _, err := manager.ForceRefreshAuth(context.Background(), "credential.json"); done <- err }()
			<-started
			// Join the refresh even if an assertion fails while replacing the file.
			joined := false
			defer func() {
				if !joined {
					close(release)
					<-done
				}
			}()
			if err := os.WriteFile(name, []byte(`{"type":"codex","email":"b@example.com","access_token":"synthetic-b","refresh_token":"synthetic-refresh-b","notes":"replacement"}`), 0600); err != nil {
				t.Fatal(err)
			}
			replacements, err := store.List(context.Background())
			if err != nil || len(replacements) != 1 {
				t.Fatalf("replacement load: %v", err)
			}
			if _, err = manager.Update(context.Background(), replacements[0]); err != nil {
				t.Fatal(err)
			}
			close(release)
			err = <-done
			joined = true // The refresh goroutine has completed.
			if err == nil {
				t.Error("obsolete refresh was accepted")
			}
			current, _ := manager.GetByID("credential.json")
			if current.Metadata["access_token"] != "synthetic-b" || current.Metadata["email"] != "b@example.com" || current.Attributes["email"] != "b@example.com" || current.Metadata["notes"] != "replacement" || current.LastError != nil {
				t.Fatalf("late refresh corrupted replacement: %+v", current)
			}
			disk, err := store.List(context.Background())
			if err != nil || len(disk) != 1 || disk[0].Metadata["access_token"] != "synthetic-b" || disk[0].Metadata["email"] != "b@example.com" {
				t.Fatalf("obsolete refresh reached disk: %v, %v", disk, err)
			}
		})
	}
}

func TestRound2Finding9RefreshPreservesUnrelatedUpdates(t *testing.T) {
	store, _ := round2File(t)
	manager := auth.NewManager(store, nil, nil)
	if err := manager.Load(context.Background()); err != nil {
		t.Fatal(err)
	}
	base, _ := manager.GetByID("credential.json")
	edited := base.Clone()
	edited.ProxyURL = "http://proxy.invalid"
	edited.Metadata["notes"] = "concurrent notes"
	edited.Attributes[auth.AttributeWeight] = "2"
	if _, err := manager.Update(auth.WithSkipPersist(context.Background()), edited); err != nil {
		t.Fatal(err)
	}
	updated := base.Clone()
	updated.Metadata["access_token"] = "fresh-synthetic-a"
	updated.Metadata["email"] = "fresh-a@example.com"
	current, err := manager.UpdateRefreshedAuth(context.Background(), base, updated)
	if err != nil {
		t.Fatal(err)
	}
	if current.ProxyURL != edited.ProxyURL || current.Metadata["notes"] != "concurrent notes" || current.Attributes[auth.AttributeWeight] != "2" || current.Metadata["access_token"] != "fresh-synthetic-a" || current.Attributes["email"] != "fresh-a@example.com" {
		t.Fatalf("non-atomic refresh or lost unrelated update: %+v", current)
	}
}
