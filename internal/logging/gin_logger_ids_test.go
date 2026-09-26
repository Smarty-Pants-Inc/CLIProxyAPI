package logging

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

// serveAndCaptureLogLine runs one request through GinLogrusLogger and returns its log line.
func serveAndCaptureLogLine(t *testing.T, req *http.Request, handler gin.HandlerFunc) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	hook := logtest.NewLocal(log.StandardLogger())
	t.Cleanup(hook.Reset)

	engine := gin.New()
	engine.Use(GinLogrusLogger())
	engine.POST("/*path", handler)
	engine.ServeHTTP(httptest.NewRecorder(), req)

	for _, entry := range hook.AllEntries() {
		if _, ok := entry.Data["request_id"]; ok {
			return entry.Message
		}
	}
	t.Fatalf("no request log line")
	return ""
}

func TestGinLoggerRecordsJoinKeys(t *testing.T) {
	cases := []struct {
		name    string
		path    string
		compact bool
		chunks  []string
		want    string
	}{
		{
			name:    "compaction streaming",
			path:    "/v1/messages",
			compact: true,
			// The ID is split across two writes, as an SSE stream can do.
			chunks: []string{
				"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_011CfRU",
				"PnHXBi1nkUgbCtJLd\",\"type\":\"message\",\"content\":[]}}\n\n",
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"id\":\"msg_not_this\"}}\n\n",
			},
			want: "| session=01a0cdab-6295-73b9 msg=msg_011CfRUPnHXBi1nkUgbCtJLd compact=yes",
		},
		{
			name:   "ordinary non-streaming",
			path:   "/v1/messages",
			chunks: []string{`{"id":"msg_01ordinary","type":"message","content":[{"type":"text","text":"hi"}]}`},
			want:   "| session=01a0cdab-6295-73b9 msg=msg_01ordinary compact=no",
		},
		{
			name:   "responses compact route",
			path:   "/v1/responses/compact",
			chunks: []string{`{"id":"resp_abc123","object":"response.compaction","output":[{"id":"msg_item"}]}`},
			want:   "| session=01a0cdab-6295-73b9 msg=resp_abc123 compact=yes",
		},
		{
			name: "responses root ID after output item ID",
			path: "/v1/responses",
			chunks: []string{
				`{"object":"response","output":[{"type":"message","id":"msg_output_item",`,
				`"role":"assistant","content":[]}],"id":"resp_real","status":"completed"}`,
			},
			want: "| session=01a0cdab-6295-73b9 msg=resp_real compact=no",
		},
		{
			name: "messages root ID after tool input ID",
			path: "/v1/messages",
			chunks: []string{
				`{"type":"message","content":[{"type":"tool_use","id":"toolu_1","input":{"id":"msg_customer_`,
				`record_123"}}],"id":"msg_real","role":"assistant"}`,
			},
			want: "| session=01a0cdab-6295-73b9 msg=msg_real compact=no",
		},
		{
			name: "root ID beyond the capture limit",
			path: "/v1/messages",
			chunks: []string{
				`{"type":"message","content":[{"type":"tool_use","input":{"id":"msg_customer_record_123","pad":"` + strings.Repeat("x", maxResponseIDSniff) + `"}}],`,
				`"id":"msg_real"}`,
			},
			want: "| session=01a0cdab-6295-73b9 msg=- compact=no",
		},
		{
			name: "responses streaming split",
			path: "/v1/responses",
			chunks: []string{
				"event: response.created\ndata: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"output\":[{\"id\":\"msg_item\"}],\"id\":\"resp_st",
				"ream1\",\"object\":\"response\"}}\n\n",
			},
			want: "| session=01a0cdab-6295-73b9 msg=resp_stream1 compact=no",
		},
		{
			name: "ping before message_start split",
			path: "/v1/messages",
			chunks: []string{
				"event: ping\ndata: {\"type\":\"pi",
				"ng\"}\n\nevent: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_re",
				"al\",\"model\":\"expected\"}}\n\n",
			},
			want: "| session=01a0cdab-6295-73b9 msg=msg_real compact=no",
		},
		{
			name: "first stream event without an envelope ID",
			path: "/v1/messages",
			chunks: []string{
				"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"content_block\":{\"type\":\"tool_use\",\"input\":{\"id\":\"msg_customer\"}}}\n\n",
				"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_late\"}}\n\n",
			},
			want: "| session=01a0cdab-6295-73b9 msg=- compact=no",
		},
		{
			name:   "no ID in response",
			path:   "/v1/messages",
			chunks: []string{`{"type":"error","error":{"message":"overloaded"}}`},
			want:   "| session=01a0cdab-6295-73b9 msg=- compact=no",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(`{}`))
			req.Header.Set("X-Session-Affinity", "01a0cdab-6295-73b9")
			line := serveAndCaptureLogLine(t, req, func(c *gin.Context) {
				if tc.compact {
					SetGinCompaction(c)
				}
				for _, chunk := range tc.chunks {
					_, _ = c.Writer.WriteString(chunk)
					c.Writer.Flush()
				}
			})
			if !strings.HasSuffix(line, tc.want) {
				t.Fatalf("log line %q does not end with %q", line, tc.want)
			}
		})
	}
}

func TestGinLoggerSanitizesSessionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{}`))
	// Set the raw map entry: net/http would reject these bytes on the wire,
	// but the logger must not trust that.
	req.Header["Session_id"] = []string{"abc\r\n[info] fake line\x1b[31m\x00" + strings.Repeat("z", 300)}
	line := serveAndCaptureLogLine(t, req, func(c *gin.Context) {
		c.String(http.StatusOK, `{"id":"msg_x"}`)
	})
	if strings.ContainsAny(line, "\r\n\x1b\x00") || strings.Contains(line, "fake line") {
		t.Fatalf("unsanitized session in log line %q", line)
	}
	want := "session=abcinfofakeline31m" + strings.Repeat("z", maxLogTokenLength-len("abcinfofakeline31m")) + " msg=msg_x compact=no"
	if !strings.HasSuffix(line, want) {
		t.Fatalf("log line %q does not end with %q", line, want)
	}
}

func TestGinLoggerNoSessionHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{}`))
	line := serveAndCaptureLogLine(t, req, func(c *gin.Context) {
		c.String(http.StatusOK, `{"id":"chatcmpl-9x","object":"chat.completion"}`)
	})
	if !strings.HasSuffix(line, "| session=- msg=chatcmpl-9x compact=no") {
		t.Fatalf("unexpected log line %q", line)
	}
}
