package logging

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
)

// Request log join keys (smarty-dev#933): the client session, the response
// message ID the client received, and whether the request asked for a
// compaction. Values keep only [A-Za-z0-9_-] and are bounded, so a header
// cannot inject text into the log line.

const (
	compactionKey       = "__request_is_compaction__"
	maxLogTokenLength   = 128
	maxResponseIDSniff  = 4096
	logTokenPlaceholder = "-"
)

// clientSessionHeaders lists the session headers that clients send, in the
// priority order of the session package (ExtractSessionInfo).
var clientSessionHeaders = []string{
	"X-Claude-Code-Session-Id",
	"Session-Id",
	"Session_id",
	"X-Http-Session-Id",
	"X-Session-Id",
	"X-Session-Affinity",
}

// responseIDPattern matches the first message or response ID in a response
// body: Anthropic message_start or message (msg_), OpenAI Responses (resp_)
// and Chat Completions (chatcmpl-).
var responseIDPattern = regexp.MustCompile(`"id"\s*:\s*"((?:msg_|resp_|chatcmpl-)[A-Za-z0-9_-]+)"`)

// SetGinCompaction marks the request as a compaction request for the request log line.
func SetGinCompaction(c *gin.Context) {
	if c != nil {
		c.Set(compactionKey, true)
	}
}

func isCompaction(c *gin.Context) bool {
	if c == nil {
		return false
	}
	if c.Request != nil && c.Request.URL != nil && strings.HasSuffix(c.Request.URL.Path, "/responses/compact") {
		return true
	}
	val, _ := c.Get(compactionKey)
	flag, _ := val.(bool)
	return flag
}

// clientSessionID returns the first session header value the client sent, sanitized.
func clientSessionID(headers http.Header) string {
	for _, name := range clientSessionHeaders {
		for _, value := range headers.Values(name) {
			if token := sanitizeLogToken(value); token != "" {
				return token
			}
		}
	}
	return ""
}

// sanitizeLogToken keeps only [A-Za-z0-9_-] and bounds the length.
func sanitizeLogToken(value string) string {
	var b strings.Builder
	for i := 0; i < len(value) && b.Len() < maxLogTokenLength; i++ {
		ch := value[i]
		if ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-' {
			b.WriteByte(ch)
		}
	}
	return b.String()
}

func logTokenOrPlaceholder(value string) string {
	if value == "" {
		return logTokenPlaceholder
	}
	return value
}

// responseIDWriter records the first message or response ID written to the
// client. It reads at most maxResponseIDSniff bytes and never changes the body.
type responseIDWriter struct {
	gin.ResponseWriter
	sniff []byte
	id    string
	done  bool
}

func (w *responseIDWriter) Write(data []byte) (int, error) {
	w.observe(data)
	return w.ResponseWriter.Write(data)
}

func (w *responseIDWriter) WriteString(data string) (int, error) {
	w.observe([]byte(data))
	return w.ResponseWriter.WriteString(data)
}

func (w *responseIDWriter) observe(data []byte) {
	if w.done || len(data) == 0 {
		return
	}
	room := maxResponseIDSniff - len(w.sniff)
	if len(data) > room {
		data = data[:room]
	}
	w.sniff = append(w.sniff, data...)
	if match := responseIDPattern.FindSubmatch(w.sniff); match != nil {
		w.id = sanitizeLogToken(string(match[1]))
		w.done = true
	} else if len(w.sniff) >= maxResponseIDSniff {
		w.done = true
	}
	if w.done {
		w.sniff = nil
	}
}
