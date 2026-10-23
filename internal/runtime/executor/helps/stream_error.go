package helps

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// StreamSSEData joins multiline JSON data before inspection. Codex also accepts
// delimiterless JSON records, so it emits as soon as the joined JSON is valid.
// Native SSE passthrough uses StreamSSEEvent to wait for the event boundary.
// Returned data and Lines remain valid only until the next Observe call.
type StreamSSEData struct {
	// PreserveLines retains owned Scanner units for native passthrough. Lines
	// is nonempty only for a multiline record, including intervening controls.
	PreserveLines bool
	Lines         [][]byte
	ready         bool
	wireBytes     int
	Event         string
	pending       []byte
	hasData       bool
	depth         int
	inString      bool
	escaped       bool
	compact       bytes.Buffer
}

func (s *StreamSSEData) Observe(line []byte) ([]byte, bool) {
	if s.ready {
		clear(s.Lines)
		s.Lines = s.Lines[:0]
		s.ready = false
		s.wireBytes = 0
	}
	originalLine := line
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		s.Event = ""
		s.pending = s.pending[:0]
		s.hasData = false
		s.depth = 0
		s.inString = false
		s.escaped = false
		clear(s.Lines)
		s.Lines = s.Lines[:0]
		s.wireBytes = 0
		return nil, false
	}
	if s.PreserveLines && s.hasData {
		// Bound retained wire bytes (including comments) and slice headers
		// before cloning. The unit limit still admits the 100k-line fixture.
		if len(originalLine) > 52_428_800-s.wireBytes || len(s.Lines) >= 1<<20 {
			return s.overflow()
		}
		s.Lines = append(s.Lines, bytes.Clone(originalLine))
		s.wireBytes += len(originalLine)
	}
	if bytes.HasPrefix(line, []byte("event:")) {
		s.Event = strings.TrimSpace(string(line[6:]))
		return nil, false
	}
	if !bytes.HasPrefix(line, []byte("data:")) {
		return nil, false
	}
	data := bytes.TrimSpace(line[5:])
	// Match the executor scanner's 50 MB ceiling across data lines as well.
	if len(s.pending)+len(data)+1 > 52_428_800 {
		return s.overflow()
	}
	multiline := s.hasData
	// Visit only the new bytes. Validating every accumulated prefix makes a
	// large event split into short Scanner units quadratic. This checkpoint
	// only detects a possible end; json.Valid still owns syntax validation.
	for _, b := range data {
		if s.inString {
			if s.escaped {
				s.escaped = false
			} else if b == '\\' {
				s.escaped = true
			} else if b == '"' {
				s.inString = false
			}
			continue
		}
		switch b {
		case '"':
			s.inString = true
		case '{', '[':
			s.depth++
		case '}', ']':
			s.depth--
		}
	}
	if multiline {
		s.pending = append(s.pending, '\n')
		s.pending = append(s.pending, data...)
		data = s.pending
	}
	if !s.inString && s.depth == 0 && (bytes.Equal(data, []byte("[DONE]")) || json.Valid(data)) {
		s.pending = s.pending[:0]
		s.hasData = false
		s.ready = true
		if multiline {
			// Reuse storage: translated SSE must not contain bare JSON newlines.
			s.compact.Reset()
			if errCompact := json.Compact(&s.compact, data); errCompact == nil {
				data = s.compact.Bytes()
			}
		}
		return data, true
	}
	s.hasData = true
	if !multiline {
		s.pending = append(s.pending[:0], data...)
		if s.PreserveLines {
			s.Lines = append(s.Lines, bytes.Clone(originalLine))
			s.wireBytes = len(originalLine)
		}
	}
	return nil, false
}

func (s *StreamSSEData) overflow() ([]byte, bool) {
	s.pending = s.pending[:0]
	s.hasData = false
	s.depth = 0
	s.inString = false
	s.escaped = false
	s.ready = true
	return []byte(`{"type":"error","error":{"code":"upstream_stream_invalid","type":"server_error","message":"upstream SSE event exceeds buffering limit"}}`), true
}

func IsStreamErrorFrame(data []byte, event string) bool {
	root := gjson.ParseBytes(data)
	for _, path := range []string{"error", "response.error"} {
		if v := root.Get(path); v.Exists() && v.Type != gjson.Null {
			return true
		}
	}
	for _, kind := range []string{event, root.Get("type").String()} {
		switch strings.ToLower(strings.TrimSpace(kind)) {
		case "error", "response.error", "response.failed":
			return true
		}
	}
	return false
}

// UpstreamError retains only the diagnostic contract, never arbitrary upstream
// fields (headers, credentials, request echoes, etc.). Sanitize fields separately:
// truncating the JSON envelope would lose its code/type and can produce invalid JSON.
func (p *StreamProgress) UpstreamError(ctx context.Context, provider, model, authLabel string, status int, data []byte, cause error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	// Retain the executor's existing cooling/status contract; classification
	// below derives the client retry hint without changing credential policy.
	failureStatus := status
	var upstreamStatus interface{ StatusCode() int }
	if errors.As(cause, &upstreamStatus) {
		failureStatus = upstreamStatus.StatusCode()
	}
	root := gjson.ParseBytes(data)
	node := root.Get("response.error")
	if !node.Exists() || node.Type == gjson.Null {
		node = root.Get("error")
	}
	if !node.Exists() || node.Type == gjson.Null {
		node = root
	}
	code := node.Get("code").String()
	errType := node.Get("type").String()
	if errType == "error" || errType == "response.failed" {
		errType = ""
	}
	if errType == "" {
		errType = node.Get("error_type").String()
	}
	message := node.Get("message").String()
	if message == "" && node.Get("detail").Type == gjson.String {
		message = node.Get("detail").String()
	}
	if message == "" && node.Type == gjson.String {
		message = node.String()
	}
	explicitStatus := 0
	for _, value := range []gjson.Result{node, root} {
		for _, path := range []string{"status_code", "status"} {
			if n := int(value.Get(path).Int()); n >= 400 && n <= 599 {
				explicitStatus = n
				break
			}
		}
		if explicitStatus != 0 {
			break
		}
	}
	class := strings.ToLower(code + " " + errType)
	switch {
	case explicitStatus != 0:
		status = explicitStatus
	case strings.Contains(class, "rate_limit") || code == "429" || strings.Contains(class, "usage_limit") || strings.Contains(class, "insufficient_quota"):
		status = http.StatusTooManyRequests
	case strings.Contains(class, "overloaded") || strings.Contains(class, "at_capacity"):
		status = http.StatusServiceUnavailable
	case strings.Contains(class, "server_error") || strings.Contains(class, "internal_error"):
		status = http.StatusInternalServerError
	case strings.Contains(class, "invalid_request") || strings.Contains(class, "invalid_value") || strings.Contains(class, "context_length") || code == "cyber_policy":
		status = http.StatusBadRequest
	case strings.Contains(class, "authentication") || code == "invalid_api_key":
		status = http.StatusUnauthorized
	case strings.Contains(class, "permission") || code == "forbidden":
		status = http.StatusForbidden
	}
	if status < 400 || status > 599 {
		status = http.StatusBadGateway
	}
	retryable := status == http.StatusTooManyRequests || status >= 500
	if errType == "" {
		switch {
		case status == 429:
			errType = "rate_limit_error"
		case status >= 500:
			errType = "server_error"
		default:
			errType = "invalid_request_error"
		}
	}
	if code == "" {
		code = errType
	}
	// Never forward upstream prose across the client trust boundary. Code/type
	// retain the upstream classification; only the message is gateway-authored.
	clientMessage := "upstream request rejected"
	switch {
	case status == http.StatusTooManyRequests:
		clientMessage = "upstream rate limited"
	case strings.Contains(class, "overloaded") || strings.Contains(class, "at_capacity"):
		clientMessage = "upstream overloaded"
	case status >= 500:
		clientMessage = "upstream server error"
	}
	safe := logging.SafeDiagnosticForLog
	detail := map[string]any{"code": code, "type": errType, "message": clientMessage + ": " + code, "retryable": retryable, "provider": safe(provider), "model": safe(model), "upstream_status": status, "partial_bytes": p.Bytes, "partial_chunks": p.Chunks}
	body := map[string]any{"error": detail}
	if seq := root.Get("sequence_number"); seq.Exists() {
		body["sequence_number"] = seq.Int()
	}
	encoded, _ := json.Marshal(body)
	LogWithRequestID(ctx).WithFields(logrus.Fields{"provider": safe(provider), "model": safe(model), "auth_label": safe(authLabel), "code": detail["code"], "type": detail["type"], "message": logging.SafeUpstreamDiagnosticForLog(message), "upstream_status": status, "partial_bytes": p.Bytes, "partial_chunks": p.Chunks}).Warn("upstream stream error")
	if failureStatus < 400 || failureStatus > 599 {
		failureStatus = status
	}
	return &UpstreamStreamError{body: string(encoded), status: failureStatus, cause: cause}
}

// Unwrap preserves upstream cooling/replay markers. The public error and response
// body are sanitized even when the original classified cause carries raw details.
type UpstreamStreamError struct {
	body   string
	status int
	cause  error
}

func (e *UpstreamStreamError) Error() string             { return e.body }
func (e *UpstreamStreamError) ResponseBody() []byte      { return []byte(e.body) }
func (e *UpstreamStreamError) StatusCode() int           { return e.status }
func (e *UpstreamStreamError) Unwrap() error             { return e.cause }
func (*UpstreamStreamError) IsUpstreamStreamError() bool { return true }
