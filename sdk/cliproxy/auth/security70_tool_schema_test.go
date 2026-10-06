package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	ex "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestSecurity70ToolSchemaRejectedBeforeDispatch(t *testing.T) {
	leaf := `{"name":"sleep","parameters":{"properties":{"duration_ms":{"type":"number"}}}}`
	deep := leaf
	for i := 0; i < 64; i++ {
		deep = `{"functionDeclarations":[` + deep + `]}`
	}
	groups := strings.TrimSuffix(strings.Repeat(`{"type":"additional_tools","tools":[`+leaf+`]},`, 257), ",")
	for _, tc := range []struct{ name, body string }{
		{"deep", `{"tools":[` + deep + `]}`},
		{"large", `{"tools":[{"function_declarations":[` + strings.TrimSuffix(strings.Repeat(leaf+",", 4097), ",") + `]}]}`},
		{"groups", `{"input":[` + groups + `]}`},
	} {
		for _, original := range []bool{false, true} {
			for _, mode := range []string{"execute", "count", "stream"} {
				t.Run(tc.name+"/"+mode+map[bool]string{false: "/request", true: "/original"}[original], func(t *testing.T) {
					m := NewManager(nil, nil, nil)
					req := ex.Request{Model: "model", Payload: []byte(tc.body)}
					opts := ex.Options{Headers: http.Header{"User-Agent": []string{"codex"}}}
					if original {
						opts.OriginalRequest = req.Payload
						req.Payload = []byte(`{"input":"normal"}`)
					}
					err := security70Execute(m, context.Background(), mode, req, opts)
					status, ok := err.(interface{ StatusCode() int })
					if !ok || status.StatusCode() != 400 || !strings.Contains(err.Error(), "tool schema") {
						t.Fatalf("expected clear 400 before dispatch, got %v", err)
					}
				})
			}
		}
	}
}

func security70Execute(m *Manager, ctx context.Context, mode string, req ex.Request, opts ex.Options) error {
	var err error
	switch mode {
	case "execute":
		_, err = m.Execute(ctx, nil, req, opts)
	case "count":
		_, err = m.ExecuteCount(ctx, nil, req, opts)
	case "stream":
		_, err = m.ExecuteStream(ctx, nil, req, opts)
	}
	return err
}

func TestSecurity70DispatchCancellationAndOrdinaryClients(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m := NewManager(nil, nil, nil)
	req := ex.Request{Model: "model", Payload: []byte(`{"input":"normal"}`)}
	opts := ex.Options{Headers: http.Header{"User-Agent": []string{"codex"}}}
	for _, mode := range []string{"execute", "count", "stream"} {
		if err := security70Execute(m, ctx, mode, req, opts); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s cancellation lost: %v", mode, err)
		}
	}
	opts.Headers.Set("User-Agent", "ordinary-client")
	req.Payload = []byte(`{"tools":[` + strings.TrimSuffix(strings.Repeat(`{"name":"custom"},`, 4097), ",") + `]}`)
	err := security70Execute(m, context.Background(), "execute", req, opts)
	if !strings.Contains(err.Error(), "no provider supplied") {
		t.Fatalf("non-Codex behavior changed: %v", err)
	}
}
