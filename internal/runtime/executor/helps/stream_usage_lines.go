package helps

import "bytes"

// MaxStreamUsageLineBytes bounds one SSE line held for usage observation across transport reads. Forwarding never
// waits on it; a longer line (an image payload) is dropped from usage observation, never grown without bound.
const MaxStreamUsageLineBytes = 1 << 20

// StreamUsageLines observes complete CR/LF/CRLF-delimited SSE lines across transport reads, so a usage event split
// inside its JSON is still parsed once (CLIProxyAPI#115). It holds at most MaxStreamUsageLineBytes of one line.
type StreamUsageLines struct {
	partial  []byte
	dropping bool // the current line overflowed the bound; skip to its end
	lastCR   bool // the previous chunk ended in CR, so a leading LF closes nothing new
}

// Observe feeds one transport chunk and calls observe for each nonempty complete line.
func (s *StreamUsageLines) Observe(chunk []byte, observe func([]byte)) {
	for len(chunk) > 0 {
		if s.lastCR && chunk[0] == '\n' {
			chunk = chunk[1:]
			s.lastCR = false
			continue
		}
		s.lastCR = false
		i := bytes.IndexAny(chunk, "\r\n")
		if i < 0 {
			s.hold(chunk)
			return
		}
		s.hold(chunk[:i])
		s.flush(observe)
		s.lastCR = chunk[i] == '\r'
		chunk = chunk[i+1:]
	}
}

// Close observes a final line that had no terminator.
func (s *StreamUsageLines) Close(observe func([]byte)) { s.flush(observe) }

func (s *StreamUsageLines) hold(part []byte) {
	if s.dropping {
		return
	}
	if len(s.partial)+len(part) > MaxStreamUsageLineBytes {
		s.partial, s.dropping = s.partial[:0], true
		return
	}
	s.partial = append(s.partial, part...)
}

func (s *StreamUsageLines) flush(observe func([]byte)) {
	if !s.dropping {
		if line := bytes.TrimSpace(s.partial); len(line) > 0 {
			observe(line)
		}
	}
	s.partial, s.dropping = s.partial[:0], false
}

// ObserveStreamUsageChunkLines observes nonempty CR/LF-delimited fragments in a single chunk, without state across
// chunks. Kept for callers that observe whole bodies.
func ObserveStreamUsageChunkLines(chunk []byte, observe func([]byte)) {
	for _, line := range bytes.FieldsFunc(chunk, func(r rune) bool { return r == '\r' || r == '\n' }) {
		if line = bytes.TrimSpace(line); len(line) > 0 {
			observe(line)
		}
	}
}
