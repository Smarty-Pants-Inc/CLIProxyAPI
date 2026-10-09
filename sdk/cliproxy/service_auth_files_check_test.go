package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type authFilesCheckStore struct{ events *[]string }

func (s *authFilesCheckStore) List(context.Context) ([]*coreauth.Auth, error) {
	*s.events = append(*s.events, "core load")
	return nil, nil
}
func (*authFilesCheckStore) Save(context.Context, *coreauth.Auth) (string, error) {
	return "", errors.New("unexpected auth save")
}
func (*authFilesCheckStore) Delete(context.Context, string) error {
	return errors.New("unexpected auth delete")
}

type authFilesTokenProbe struct{ events *[]string }

func (p authFilesTokenProbe) Load(context.Context, *config.Config) (*TokenClientResult, error) {
	*p.events = append(*p.events, "token load")
	return &TokenClientResult{}, nil
}

type authFilesAPIKeyProbe struct {
	events *[]string
	stop   error
}

func (p authFilesAPIKeyProbe) Load(context.Context, *config.Config) (*APIKeyClientResult, error) {
	*p.events = append(*p.events, "API key load")
	return nil, p.stop
}

// Stop immediately after all startup loaders, before binding a server or starting
// a watcher. The probes never read credentials and also work in Windows fixtures.
func newAuthFilesStartupProbe(dir string, events *[]string) (*Service, error) {
	stop := errors.New("startup reached all auth loaders")
	catalog := filepath.Join(dir, "startup-probe-missing-catalog.json")
	return &Service{
		cfg: &config.Config{
			AuthDir:   dir,
			Models:    registry.CatalogSources{Catalog: catalog, CodexCatalog: catalog, DevinCatalog: catalog},
			SDKConfig: config.SDKConfig{ProxyURL: "http://127.0.0.1:1"},
		},
		coreManager:    coreauth.NewManager(&authFilesCheckStore{events: events}, nil, nil),
		tokenProvider:  authFilesTokenProbe{events: events},
		apiKeyProvider: authFilesAPIKeyProbe{events: events, stop: stop},
	}, stop
}

func TestServiceAuthFilesCheckBeforeLoad(t *testing.T) {
	denied := errors.New("unsafe top-level auth file")
	for _, tc := range []struct {
		name     string
		checkErr error
	}{
		{"allowed", nil},
		{"refused", denied},
	} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", tc.name, existing), func(t *testing.T) {
				dir := t.TempDir()
				if !existing {
					dir = filepath.Join(dir, "new-auth-dir")
				}
				var events []string
				originalRestrict, originalCheck := restrictAuthDir, checkAuthFilesOwnerOnly
				t.Cleanup(func() {
					restrictAuthDir, checkAuthFilesOwnerOnly = originalRestrict, originalCheck
				})
				restrictAuthDir = func(path string) error {
					if path != dir || !reflect.DeepEqual(events, []string{"pre-check"}) {
						t.Fatalf("restriction must follow the pre-check: path=%q events=%v", path, events)
					}
					events = append(events, "restrict")
					return nil
				}
				checkAuthFilesOwnerOnly = func(path string, ignoreInherited bool) error {
					if path != dir {
						t.Fatalf("check path = %q, want %q", path, dir)
					}
					if ignoreInherited {
						if len(events) != 0 {
							t.Fatalf("pre-check must be first: events=%v", events)
						}
						events = append(events, "pre-check")
						return tc.checkErr
					}
					if !reflect.DeepEqual(events, []string{"pre-check", "restrict"}) {
						t.Fatalf("full check must follow restriction: events=%v", events)
					}
					events = append(events, "full check")
					return nil
				}
				s, stop := newAuthFilesStartupProbe(dir, &events)
				err := s.Run(context.Background())
				want := []string{"pre-check"}
				if tc.checkErr != nil {
					if !errors.Is(err, denied) || !strings.Contains(err.Error(), "before restricting") {
						t.Fatalf("startup must return pre-check refusal: %v", err)
					}
				} else {
					want = append(want, "restrict", "full check", "core load", "token load", "API key load")
					if !errors.Is(err, stop) {
						t.Fatalf("startup did not reach auth loaders: %v", err)
					}
				}
				if !reflect.DeepEqual(events, want) {
					t.Fatalf("startup events = %v, want %v", events, want)
				}
			})
		}
	}
}
