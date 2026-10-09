package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sdkAuth "github.com/router-for-me/CLIProxyAPI/v8/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type startupAuthStore struct {
	*sdkAuth.FileTokenStore
	beforeList func()
	calls      int
}

func (s *startupAuthStore) List(ctx context.Context) ([]*coreauth.Auth, error) {
	s.calls++
	s.beforeList()
	return s.FileTokenStore.List(ctx)
}

type startupTokenProvider struct {
	beforeLoad func()
	calls      int
}

func (p *startupTokenProvider) Load(context.Context, *config.Config) (*TokenClientResult, error) {
	p.calls++
	p.beforeLoad()
	return &TokenClientResult{}, nil
}

type startupAPIKeyProvider struct {
	beforeLoad func()
	calls      int
	stop       error
}

func (p *startupAPIKeyProvider) Load(context.Context, *config.Config) (*APIKeyClientResult, error) {
	p.calls++
	p.beforeLoad()
	return nil, p.stop
}

// Exercise the real Run -> Manager.Load -> FileTokenStore.List ordering on every
// platform, independently of the Windows-only native DACL migration fixtures.
func TestStartupAuthRestrictionPrecedesAllLoads(t *testing.T) {
	for _, fail := range []bool{false, true} {
		name := "secured_then_loaded"
		if fail {
			name = "restriction_failed_no_load"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "legacy.json")
			if err := os.WriteFile(path, []byte(`{"type":"startup-test","access_token":"synthetic-token"}`), 0o600); err != nil {
				t.Fatal(err)
			}
			var events []string
			original := restrictAuthDir
			t.Cleanup(func() { restrictAuthDir = original })
			denied := errors.New("simulated auth file DACL denial")
			restrictAuthDir = func(root string) error {
				if root != dir {
					t.Fatalf("restriction path = %q, want %q", root, dir)
				}
				events = append(events, "restrict")
				if fail {
					return fmt.Errorf("secure auth entry %q: %w", path, denied)
				}
				return nil
			}
			store := &startupAuthStore{FileTokenStore: sdkAuth.NewFileTokenStore(), beforeList: func() { events = append(events, "file store") }}
			store.SetBaseDir(dir)
			tokenProvider := &startupTokenProvider{beforeLoad: func() { events = append(events, "tokens") }}
			stop := errors.New("stop before starting server or watcher")
			apiKeyProvider := &startupAPIKeyProvider{beforeLoad: func() { events = append(events, "API keys") }, stop: stop}
			service := &Service{
				cfg:            &config.Config{AuthDir: dir},
				coreManager:    coreauth.NewManager(store, nil, nil),
				tokenProvider:  tokenProvider,
				apiKeyProvider: apiKeyProvider,
			}
			err := service.Run(context.Background())
			wantEvents := []string{"restrict", "file store", "tokens", "API keys"}
			wantAuths := 1
			wantError := stop
			if fail {
				wantEvents = []string{"restrict"}
				wantAuths = 0
				wantError = denied
				if err == nil || !strings.Contains(err.Error(), path) {
					t.Fatalf("startup error must name the unsecured file: %v", err)
				}
			}
			if !errors.Is(err, wantError) || !reflect.DeepEqual(events, wantEvents) || len(service.coreManager.List()) != wantAuths {
				t.Fatalf("startup error=%v, events=%v, auths=%d; want %v, %v, %d", err, events, len(service.coreManager.List()), wantError, wantEvents, wantAuths)
			}
			if service.server != nil || service.watcher != nil {
				t.Fatal("test must stop before server or watcher startup")
			}
		})
	}
}
