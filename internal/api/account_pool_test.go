package api

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type poolAccessFixture struct{ result *sdkaccess.Result }

func (poolAccessFixture) Identifier() string { return "fixture" }
func (p poolAccessFixture) Authenticate(context.Context, *http.Request) (*sdkaccess.Result, *sdkaccess.AuthError) {
	return p.result, nil
}
func apiPoolFixture(t *testing.T, capacity int64) *auth.Manager {
	t.Helper()
	raw := fmt.Sprintf(`ws-auth: true
codex:
  live-media-relay:
    enabled: true
access:
  api-keys: ["api-pool-key"]
  account-pools:
    - id: humans
      org: test
      class: human
      max-in-flight: %d
      accounts:
        - {provider: codex, account-id: api-user, entitlement-id: api-entitlement}
  api-key-policies:
    - {key-sha256: "%x", pool: humans}
`, capacity, sha256.Sum256([]byte("api-pool-key")))
	cfg, err := config.ParseConfigBytes([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	m := auth.NewManager(nil, nil, nil)
	m.SetConfig(cfg)
	if !m.PoolMode() {
		t.Fatal("pool mode lost")
	}
	return m
}

func TestPoolMiddlewareRequiresActualNativeAccessResult(t *testing.T) {
	for _, scenario := range []string{"nil-manager", "nil-result", "foreign-provider", "unconfigured-principal", "native"} {
		t.Run(scenario, func(t *testing.T) {
			m := apiPoolFixture(t, 1)
			access := sdkaccess.NewManager()
			result := &sdkaccess.Result{Provider: "config-inline", Principal: "api-pool-key"}
			switch scenario {
			case "nil-manager":
				access = nil
			case "nil-result":
				result = nil
			case "foreign-provider":
				result.Provider = "extension"
				result.Metadata = map[string]string{"provider": "config-inline", "pool": "humans"}
			case "unconfigured-principal":
				result.Principal = "arbitrary-policy-digest"
			}
			if access != nil {
				access.SetProviders([]sdkaccess.Provider{poolAccessFixture{result}})
			}
			router := gin.New()
			router.Use(func(c *gin.Context) {
				c.Set("userApiKey", "api-pool-key")
				c.Set("accessProvider", "config-inline")
				c.Next()
			})
			router.Use(AuthMiddleware(access, m))
			reached := false
			router.POST("/v1/responses", func(c *gin.Context) {
				reached = true
				op := auth.KeyPolicyFromContext(c.Request.Context())
				if !op.IsPoolOperation() || op.PoolID() != "humans" {
					t.Error("normal response route did not receive sole pool admission")
				}
				c.Status(204)
			})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(`{"model":"api-model"}`))
			req.Header.Set("Authorization", "Bearer api-pool-key")
			req.Header.Set("X-Pool-Id", "humans")
			router.ServeHTTP(rr, req)
			want := 403
			if scenario == "native" {
				want = 204
			}
			if rr.Code != want || reached != (want == 204) {
				t.Fatalf("status=%d reached=%v; want=%d body=%s", rr.Code, reached, want, rr.Body.String())
			}
		})
	}
}

func TestPoolMiddlewareLiveClassifiesWithoutAdmissionAndRejectsAliases(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         int
		live         bool
	}{
		{"POST", "/v1/live", 204, true}, {"GET", "/v1/live/call_test", 204, true},
		{"GET", "/v1/models", 204, false}, {"GET", "/v1/responses", 503, false},
		{"POST", "/v1/realtime/client_secrets", 503, false}, {"POST", "/v1/realtime/sessions", 503, false},
		{"GET", "/v1/realtime", 503, false}, {"POST", "/v1/live/client_secrets", 503, false},
		{"POST", "/v1/chat/completions", 503, false}, {"GET", "/v1/live/call_test/nested", 503, false},
		{"POST", "/v1/messages", 429, false},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			// A zero cap proves middleware cannot have acquired a live slot. The
			// actual live handler owns bounded parsing and its sole subsequent Begin.
			m := apiPoolFixture(t, 0)
			access := sdkaccess.NewManager()
			access.SetProviders([]sdkaccess.Provider{poolAccessFixture{&sdkaccess.Result{Provider: "config-inline", Principal: "api-pool-key"}}})
			router := gin.New()
			router.Use(AuthMiddleware(access, m))
			reached := false
			router.Any(tc.path, func(c *gin.Context) {
				reached = true
				if tc.live && auth.KeyPolicyFromContext(c.Request.Context()) != nil {
					t.Error("middleware double-admitted live request")
				}
				body, _ := io.ReadAll(c.Request.Body)
				if tc.method == "POST" && string(body) != `{"model":"api-model"}` {
					t.Error("classification consumed/replaced live body")
				}
				c.Status(204)
			})
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"model":"api-model"}`))
			router.ServeHTTP(rr, req)
			if rr.Code != tc.want || reached != (tc.want == 204) {
				t.Fatalf("status=%d reached=%v want=%d body=%s", rr.Code, reached, tc.want, rr.Body.String())
			}
		})
	}
}

func TestPoolMiddlewareBoundedCanonicalBodyBeforeCapacity(t *testing.T) {
	for _, body := range []string{`{"model":"first","model":"second"}`, `{"model":"api-model"} {}`, `{"input":"missing model"}`, `{"model":"api-model","tools":[{"type":"image_generation"}]}`} {
		m := apiPoolFixture(t, 0)
		access := sdkaccess.NewManager()
		access.SetProviders([]sdkaccess.Provider{poolAccessFixture{&sdkaccess.Result{Provider: "config-inline", Principal: "api-pool-key"}}})
		router := gin.New()
		router.Use(AuthMiddleware(access, m))
		router.POST("/v1/responses", func(c *gin.Context) { t.Error("invalid request reached execution"); c.Status(204) })
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, httptest.NewRequest("POST", "/v1/responses", strings.NewReader(body)))
		if rr.Code != 400 {
			t.Fatalf("canonical input rejected after capacity: status=%d body=%s", rr.Code, rr.Body.String())
		}
	}
}
