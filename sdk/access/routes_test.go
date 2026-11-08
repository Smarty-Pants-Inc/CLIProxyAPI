package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type routeProvider struct {
	principal string
	started   chan struct{}
	release   chan struct{}
	once      sync.Once
}

func (*routeProvider) Identifier() string { return "synthetic-provider" }
func (p *routeProvider) Authenticate(context.Context, *http.Request) (*Result, *AuthError) {
	if p.started != nil {
		p.once.Do(func() { close(p.started); <-p.release })
	}
	return &Result{Provider: p.Identifier(), Principal: p.principal, RouteKeyDigests: []string{"untrusted-attribution"}}, nil
}

// Keep: the manager is the trust boundary shared by config, plugin and embedded callers.
func TestAPIKeyRoutesManagerSnapshotAndProviderRefresh(t *testing.T) {
	key := "synthetic-sdk-client"
	provider := &routeProvider{principal: key, started: make(chan struct{}), release: make(chan struct{})}
	m := NewManager()
	routes := []config.APIKeyRoute{{KeySHA256: internalconfig.APIKeyDigest(key), Allow: []string{"GET /allowed"}}}
	m.SetProvidersAndAPIKeyRoutes([]Provider{provider}, routes)
	// Mutating a caller's config must not change the published snapshot.
	routes[0].Allow[0] = "GET /denied"
	req := httptest.NewRequest("GET", "/allowed/?query=ignored", nil)
	req.Header.Set("Authorization", "Bearer "+key)
	type outcome struct {
		result *Result
		err    *AuthError
	}
	done := make(chan outcome, 1)
	go func() { result, err := m.Authenticate(context.Background(), req); done <- outcome{result, err} }()
	<-provider.started
	// A request uses one coherent snapshot even if a reload finishes during auth.
	m.SetProvidersAndAPIKeyRoutes([]Provider{provider}, []config.APIKeyRoute{{KeySHA256: internalconfig.APIKeyDigest(key), Allow: []string{"GET /elsewhere"}}})
	close(provider.release)
	got := <-done
	if got.err != nil || got.result == nil || !reflect.DeepEqual(got.result.RouteKeyDigests, []string{internalconfig.APIKeyDigest(key)}) {
		t.Fatalf("old request lost immutable snapshot/attribution: %+v %v", got.result, got.err)
	}
	// Plugin runtime refreshes use SetProviders and must not erase route rules.
	m.SetProviders([]Provider{provider})
	if result, err := m.Authenticate(context.Background(), req); result != nil || !IsAuthErrorCode(err, AuthErrorCodeAPIKeyRouteDenied) || err.HTTPStatusCode() != 403 {
		t.Fatalf("new snapshot not enforced after provider refresh: %+v %v", result, err)
	}
	m.SetProvidersAndAPIKeyRoutes([]Provider{provider}, nil)
	if _, err := m.Authenticate(context.Background(), req); err != nil {
		t.Fatalf("removed policy still enforced: %v", err)
	}
}

func TestAPIKeyRoutesMappedPrincipalWithoutCredential(t *testing.T) {
	key := "synthetic-restricted-account"
	m := NewManager()
	m.SetProvidersAndAPIKeyRoutes([]Provider{&routeProvider{principal: key}}, []config.APIKeyRoute{{KeySHA256: internalconfig.APIKeyDigest(key), Allow: []string{"GET /only"}}})
	req := httptest.NewRequest("GET", "/other", nil)
	req.Header.Set("X-Audit-Plugin", "synthetic-custom-credential")
	result, err := m.Authenticate(context.Background(), req)
	if err != nil || result == nil || result.Principal != key || result.Provider != "synthetic-provider" || len(result.RouteKeyDigests) != 0 {
		t.Fatalf("mapped principal became a credential: result=%+v err=%v", result, err)
	}
	// A real standard credential must still carry its restriction, regardless
	// of the plugin's mapped identity or its claimed attribution.
	req.Header.Set("X-Api-Key", key)
	if _, err := m.Authenticate(context.Background(), req); !IsAuthErrorCode(err, AuthErrorCodeAPIKeyRouteDenied) {
		t.Fatalf("supplied restricted credential bypassed policy: %v", err)
	}
}

func TestAPIKeyRoutesNilAndUnrestrictedBehavior(t *testing.T) {
	var nilManager *Manager
	if nilManager.RequestHasRouteKey(nil) || nilManager.AuthorizeAPIKeyRoutes("key", nil) != nil || nilManager.AuthorizeRouteKeyDigests([]string{"digest"}, nil) != nil {
		t.Fatal("nil manager changed optional-auth behavior")
	}
	m := NewManager()
	if result, err := m.Authenticate(context.Background(), httptest.NewRequest("GET", "/anonymous", nil)); result != nil || err != nil {
		t.Fatalf("empty manager no longer allows anonymous: %+v %v", result, err)
	}
	m.SetProvidersAndAPIKeyRoutes([]Provider{&routeProvider{principal: "synthetic-unrestricted"}}, []config.APIKeyRoute{{KeySHA256: internalconfig.APIKeyDigest("synthetic-restricted"), Allow: []string{"GET /only"}}})
	if _, err := m.Authenticate(context.Background(), httptest.NewRequest("GET", "/other", nil)); err != nil {
		t.Fatalf("unrestricted principal denied: %v", err)
	}
}
