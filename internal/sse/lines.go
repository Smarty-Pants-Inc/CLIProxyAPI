// Package sse contains shared physical and Scanner SSE line-boundary rules.
package sse

import "bytes"

// Lines recognizes CRLF, CR and LF. A CR ends the line immediately; a following
// LF is consumed even if it arrives in another chunk (or after empty chunks).
// Keep this state across event boundaries, not just across data lines.
type Lines struct{ afterCR bool }

// Step reports a physical line break or the LF half of a previous CRLF.
func (l *Lines) Step(b byte) (lineBreak, skip bool) {
	if l.afterCR {
		l.afterCR = false
		if b == '\n' {
			return false, true
		}
	}
	if b == '\r' {
		l.afterCR = true
		return true, false
	}
	return b == '\n', false
}

// Normalize uses the same splitter but represents all line endings as LF.
func (l *Lines) Normalize(chunk []byte) []byte {
	// Most producers already send LF or delimiter-free Scanner units.
	if !l.afterCR && bytes.IndexByte(chunk, '\r') < 0 {
		return chunk
	}
	out := make([]byte, 0, len(chunk))
	for _, b := range chunk {
		br, skip := l.Step(b)
		if skip {
			continue
		}
		if br {
			b = '\n'
		}
		out = append(out, b)
	}
	return out
}

// LexicalBoundary is the JSON and transport evidence at an open line's end.
// A Scanner may omit line delimiters; byte streams may split anywhere instead.
type LexicalBoundary struct {
	InString, PartialField, RawJSON            bool
	DataLine, Open, AfterBreak, Colon, Scanner bool
}

// StartsLine recognizes a delimiter-free Scanner unit only when it cannot be
// a JSON string or partial field continuation. Any colon in an open data value
// is ambiguous until Scanner framing is proven; physical breaks are unambiguous.
func StartsLine(chunk []byte, b LexicalBoundary) bool {
	if len(chunk) == 0 || b.InString || b.PartialField || b.RawJSON {
		return false
	}
	if bytes.HasPrefix(chunk, []byte("data:")) || bytes.HasPrefix(chunk, []byte("event:")) || bytes.HasPrefix(chunk, []byte("id:")) || bytes.HasPrefix(chunk, []byte("retry:")) {
		return true
	}
	if chunk[0] != ':' {
		return false
	}
	return !(b.DataLine && b.Open && (b.AfterBreak || !b.Scanner))
}
