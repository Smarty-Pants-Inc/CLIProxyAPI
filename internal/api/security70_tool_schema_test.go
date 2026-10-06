package api

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
)

func TestSecurity70ToolSchemaHTTP400(t *testing.T) {
	server := newTestServerWithConfig(t, &config.Config{SDKConfig: config.SDKConfig{APIKeys: []string{"security70-client"}}})
	model := "security70-tool-model"
	registry.GetGlobalRegistry().RegisterClient("security70-schema-http", "openai", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient("security70-schema-http") })
	leaf := `{"name":"sleep","parameters":{"properties":{"duration_ms":{"type":"number"}}}}`
	deep := leaf
	for i := 0; i < 64; i++ {
		deep = `{"function_declarations":[` + deep + `]}`
	}
	for _, tc := range []struct{ name, fields string }{
		{"deep", `"tools":[` + deep + `]`},
		{"large", `"tools":[{"functionDeclarations":[` + strings.TrimSuffix(strings.Repeat(leaf+",", 4097), ",") + `]}]`},
		{"groups", `"input":[` + strings.TrimSuffix(strings.Repeat(`{"type":"additional_tools","tools":[`+leaf+`]},`, 257), ",") + `]`},
	} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%v", tc.name, stream), func(t *testing.T) {
				req := httptest.NewRequest("POST", "/v1/responses", strings.NewReader(fmt.Sprintf(`{"model":%q,"stream":%v,%s}`, model, stream, tc.fields)))
				req.Header.Set("Authorization", "Bearer security70-client")
				req.Header.Set("User-Agent", "codex/1.0")
				rr := httptest.NewRecorder()
				server.engine.ServeHTTP(rr, req)
				if rr.Code != 400 || !strings.Contains(rr.Body.String(), "tool schema") {
					t.Fatalf("HTTP rejection missing: status=%d body=%s", rr.Code, rr.Body.String())
				}
			})
		}
	}
}
