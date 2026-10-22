package helps

import (
	"bytes"
	"strings"
)

// StreamSSEEvent assembles one native SSE event, including its name and all
// data fields. Observe emits only at a blank-line boundary; Flush handles a
// final event at EOF. Event remains available until the next event begins.
// Inspection is independent of the physical lines forwarded to the client.
type StreamSSEEvent struct {
	Event     string
	pending   []byte
	hasData   bool
	oversized bool
	flushed   bool
}

func (s *StreamSSEEvent) Observe(line []byte) ([]byte, bool) {
	if s.flushed {
		s.Event = ""
		s.pending = nil
		s.hasData = false
		s.oversized = false
		s.flushed = false
	}
	line = bytes.TrimSuffix(line, []byte("\r"))
	if len(line) == 0 {
		return s.Flush()
	}
	field, value, _ := bytes.Cut(line, []byte(":"))
	value = bytes.TrimPrefix(value, []byte(" "))
	switch string(field) {
	case "event":
		s.Event = strings.TrimSpace(string(value))
	case "data":
		if s.oversized {
			return nil, false
		}
		// Match the executor scanner's 50 MB ceiling across data lines as well.
		if len(s.pending)+len(value)+1 > 52_428_800 {
			s.pending = nil
			s.oversized = true
			s.hasData = true
			return nil, false
		}
		if s.hasData {
			s.pending = append(s.pending, '\n')
		}
		s.pending = append(s.pending, value...)
		s.hasData = true
	}
	return nil, false
}

func (s *StreamSSEEvent) Flush() ([]byte, bool) {
	if s.flushed {
		return nil, false
	}
	s.flushed = true
	if s.oversized {
		return []byte(`{"type":"error","error":{"code":"upstream_stream_invalid","type":"server_error","message":"upstream SSE event exceeds 50 MB"}}`), true
	}
	return s.pending, s.hasData
}
