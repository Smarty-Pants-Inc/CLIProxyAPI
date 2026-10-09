package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
	"golang.org/x/net/context"
)

// smarty-dev#6207: the three sender-name headers reach the request metadata, validated.
func TestGetContextWithCancelCapturesSenderHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ginCtx.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	ginCtx.Request.Header.Set("X-Smarty-Role", "task-agent")
	ginCtx.Request.Header.Set("X-Smarty-Agent", "l6207-gw/task:a.b_c-1")
	ginCtx.Request.Header.Set("X-Smarty-Spawner", "session:01a0ec99-ec1c-7467-89ea-f470939c722e")

	handler := &BaseAPIHandler{Cfg: &config.SDKConfig{}}
	ctx, cancel := handler.GetContextWithCancel(nil, ginCtx, context.Background())
	defer cancel()
	// Session enrichment later in the request must keep the sender snapshot.
	ctx = EnrichContextWithSessionHierarchy(ctx, nil, []byte(`{"session_id":"routing-session"}`), nil)

	meta := logging.GetClientRequestMetadata(ctx)
	if meta.SenderRole != "task-agent" || meta.SenderAgent != "l6207-gw/task:a.b_c-1" ||
		meta.SenderSpawner != "session:01a0ec99-ec1c-7467-89ea-f470939c722e" {
		t.Fatalf("sender metadata = (%q, %q, %q)", meta.SenderRole, meta.SenderAgent, meta.SenderSpawner)
	}
}

func TestSenderNameRejectsInvalidValues(t *testing.T) {
	for name, values := range map[string][]string{
		"absent":    nil,
		"empty":     {""},
		"too long":  {strings.Repeat("a", 65)},
		"space":     {"task agent"},
		"at sign":   {"task-agent@abc"},
		"newline":   {"task\n"},
		"non-ascii": {"agént"},
		"repeated":  {"a", "b"},
	} {
		headers := http.Header{}
		for _, value := range values {
			headers.Add("X-Smarty-Agent", value)
		}
		if got := senderName(headers, "X-Smarty-Agent"); got != "" {
			t.Errorf("%s: senderName = %q, want empty", name, got)
		}
	}
	headers := http.Header{}
	headers.Set("X-Smarty-Agent", strings.Repeat("a", 64))
	if got := senderName(headers, "X-Smarty-Agent"); got != strings.Repeat("a", 64) {
		t.Errorf("64-byte value rejected: %q", got)
	}
}
