package helps

import (
	"errors"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestCodexModelGuard(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantErr string
	}{
		{name: "same model", payload: `{"type":"response.created","response":{"model":"gpt-5.6-astra"}}`},
		{name: "luna mismatch", payload: `{"type":"response.created","response":{"model":"gpt-5.6-luna"}}`, wantErr: "model_mismatch"},
		{name: "absent at terminal", payload: `{"type":"response.completed","response":{"usage":{"total_tokens":1}}}`, wantErr: "model_mismatch"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			guard := NewCodexModelGuard("gpt-5.6-astra")
			err := guard.Observe([]byte(tt.payload))
			if tt.wantErr == "" {
				if err != nil || !guard.Authoritative() {
					t.Fatalf("same-model guard = %v, authoritative=%t", err, guard.Authoritative())
				}
				return
			}
			var authErr *cliproxyauth.Error
			if !errors.As(err, &authErr) || authErr.Code != tt.wantErr {
				t.Fatalf("guard error = %v, want %s", err, tt.wantErr)
			}
		})
	}
}

func TestCodexModelGuardDoesNotAliasMismatch(t *testing.T) {
	guard := NewCodexModelGuard("gpt-5.6-astra")
	if err := guard.Observe([]byte(`{"type":"response.created","response":{"model":"gpt-5.6-luna"}}`)); err == nil {
		t.Fatal("expected alias/model mismatch")
	}
}

func TestCodexModelGuardIgnoresNonCoveredEvents(t *testing.T) {
	guard := NewCodexModelGuard("gpt-5.6-astra")
	for _, payload := range []string{
		`{"type":"response.output_text.delta","delta":"hello"}`,
		`{"type":"response.completed","response":{"model":"gpt-5.6-astra"},"images":[]}`,
	} {
		_ = guard.Observe([]byte(payload))
	}
	if !guard.Authoritative() {
		t.Fatal("expected covered response event to establish authority")
	}
}
