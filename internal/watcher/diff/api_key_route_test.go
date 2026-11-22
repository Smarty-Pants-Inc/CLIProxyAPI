package diff

import (
	"reflect"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

func TestAPIKeyRoutesChangeDetailsRedacted(t *testing.T) {
	routes := []config.APIKeyRoute{{KeySHA256: config.APIKeyDigest("synthetic-client"), Allow: []string{"GET /v1/models", "/sensitive-route"}}}
	for _, tc := range []struct {
		name      string
		old, next []config.APIKeyRoute
		changed   bool
	}{
		{"unchanged", routes, routes, false},
		{"add", nil, routes, true},
		{"remove", routes, nil, true},
		{"edit allow", routes, []config.APIKeyRoute{{KeySHA256: routes[0].KeySHA256, Allow: []string{"POST /other-sensitive-route"}}}, true},
		{"edit hash", routes, []config.APIKeyRoute{{KeySHA256: config.APIKeyDigest("other-synthetic-client"), Allow: routes[0].Allow}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oldCfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyRoutes: tc.old}}
			newCfg := &config.Config{SDKConfig: config.SDKConfig{APIKeyRoutes: tc.next}}
			got := BuildConfigChangeDetails(oldCfg, newCfg)
			if tc.changed {
				if !reflect.DeepEqual(got, []string{"api-key-routes changed"}) {
					t.Fatalf("expected exactly one redacted diff line, got %q", got)
				}
			} else if len(got) != 0 {
				t.Fatalf("unchanged routes reported: %q", got)
			}
		})
	}
}
