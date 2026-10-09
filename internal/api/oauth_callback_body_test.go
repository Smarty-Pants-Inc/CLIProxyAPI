package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	managementHandlers "github.com/router-for-me/CLIProxyAPI/v8/internal/api/handlers/management"
)

// countingReader yields a 4 MiB JSON string body (never closed) and counts the bytes the handler pulls.
type countingReader struct{ read int64 }

const countingReaderLimit = 4 << 20

func (r *countingReader) Read(p []byte) (int, error) {
	if r.read >= countingReaderLimit {
		return 0, io.EOF
	}
	if rest := countingReaderLimit - r.read; int64(len(p)) > rest {
		p = p[:rest]
	}
	if r.read == 0 && len(p) > 0 {
		p[0] = '{'
		n := copy(p[1:], `"code":"`)
		for i := 1 + n; i < len(p); i++ {
			p[i] = 'a'
		}
		r.read += int64(len(p))
		return len(p), nil
	}
	for i := range p {
		p[i] = 'a'
	}
	r.read += int64(len(p))
	return len(p), nil
}

// smarty-dev#7643: the key-less OAuth callback (v0 and v8 routes) bounds its body before decoding.
func TestOAuthCallbackPostBodyIsBounded(t *testing.T) {
	t.Setenv("MANAGEMENT_PASSWORD", "test-management-key")
	server := newTestServer(t)

	for _, path := range []string{"/v0/management/oauth-callback", "/v8/management/oauth/callback"} {
		t.Run(path+"/sized", func(t *testing.T) {
			body := `{"code":"` + strings.Repeat("a", 1<<20) + `"}`
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413 body=%s", rr.Code, rr.Body.String())
			}
		})

		t.Run(path+"/chunked", func(t *testing.T) {
			src := &countingReader{}
			req := httptest.NewRequest(http.MethodPost, path, io.NopCloser(src))
			req.ContentLength = -1
			req.TransferEncoding = []string{"chunked"}
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusRequestEntityTooLarge {
				t.Fatalf("status = %d, want 413 body=%s", rr.Code, rr.Body.String())
			}
			if src.read > 1<<20 {
				t.Fatalf("handler read %d bytes of a 4 MiB body; want it stopped near the 64 KiB bound", src.read)
			}
		})

		t.Run(path+"/normal", func(t *testing.T) {
			state := "body-bound-state-" + strings.NewReplacer("/", "-").Replace(strings.Trim(path, "/"))
			if errRegister := managementHandlers.RegisterPluginOAuthSession(state, "gemini-cli", nil); errRegister != nil {
				t.Fatalf("register plugin oauth session: %v", errRegister)
			}
			defer managementHandlers.CompleteOAuthSession(state)
			body := []byte(`{"state":"` + state + `","code":"test-code"}`)
			req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			server.engine.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}
