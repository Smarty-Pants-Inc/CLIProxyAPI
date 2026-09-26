package logging

import (
	"bytes"
	"net/http"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
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

// responseIDPattern accepts only message and response IDs: Anthropic (msg_),
// OpenAI Responses (resp_) and Chat Completions (chatcmpl-).
var responseIDPattern = regexp.MustCompile(`^(?:msg_|resp_|chatcmpl-)[A-Za-z0-9_-]{1,120}$`)

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

// responseIDWriter keeps the first maxResponseIDSniff bytes written to the
// client, so the request log can read the response envelope ID. It never
// changes the body.
type responseIDWriter struct {
	gin.ResponseWriter
	prefix []byte
}

func (w *responseIDWriter) Write(data []byte) (int, error) {
	if room := maxResponseIDSniff - len(w.prefix); room > 0 {
		w.prefix = append(w.prefix, data[:min(room, len(data))]...)
	}
	return w.ResponseWriter.Write(data)
}

func (w *responseIDWriter) WriteString(data string) (int, error) {
	if room := maxResponseIDSniff - len(w.prefix); room > 0 {
		w.prefix = append(w.prefix, data[:min(room, len(data))]...)
	}
	return w.ResponseWriter.WriteString(data)
}

// responseID returns the envelope ID of the response, or "" when the captured
// prefix does not establish it. It never falls back to a nested ID: nested IDs
// belong to output items or tool input.
func (w *responseIDWriter) responseID() string {
	body := bytes.TrimLeft(w.prefix, " \t\r\n")
	if len(body) > 0 && body[0] == '{' {
		return envelopeID(body)
	}
	// Server-sent events: the envelope is in the first data event.
	for _, line := range bytes.Split(body, []byte("\n")) {
		if data, ok := bytes.CutPrefix(bytes.TrimSpace(line), []byte("data:")); ok {
			return envelopeID(bytes.TrimSpace(data))
		}
	}
	return ""
}

// envelopeID reads the protocol envelope ID of one JSON response or event:
// Claude message_start message.id, Responses lifecycle response.id, else the
// top-level id. A value cut off by the capture limit does not parse.
func envelopeID(event []byte) string {
	path := "id"
	switch eventType := gjson.GetBytes(event, "type").String(); {
	case eventType == "message_start":
		path = "message.id"
	case strings.HasPrefix(eventType, "response."):
		path = "response.id"
	}
	value := gjson.GetBytes(event, path)
	if value.Type != gjson.String || !responseIDPattern.MatchString(value.Str) {
		return ""
	}
	return value.Str
}
