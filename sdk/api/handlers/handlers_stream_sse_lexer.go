package handlers

import (
	"unicode"
	"unicode/utf8"
)

// sseDataLexer reads each pending byte once and tracks the joined data payload
// of the pending SSE event (data values joined by LF, as
// sseJSONValidationDataPayload builds it). It proves "not valid JSON yet"
// (open string or container, invalid token, content after the root) so that
// sseJSONValidationState runs the whole-event check at most once per root.
// Space follows bytes.TrimSpace (Unicode), so trimmed bytes never decide.
type sseDataLexer struct {
	pos     int
	line    byte // 0 line start or field name, 1 data value, 2 other field
	prefix  int  // bytes of "data:" matched
	afterLF bool // the open line began after a wire LF, not at a unit start
	content bool // pending has a non-space byte
	stopped bool // stopped before an incomplete UTF-8 rune

	root           byte // 0 none, 1 object or array, 2 string, 3 number or literal
	depth          int
	inStr, esc     bool
	done, bad      bool // root complete; payload can never become valid
	num            int8 // number state (sseNumberNext)
	lit            string
	litPos         int
	checked, valid bool // cached whole-event answer for a complete root

	colon, key bool // the last token is an object key, so ':' must follow
	prev       byte
	stack      []byte
}

func (s *sseJSONValidationState) lexPending() {
	l, p := &s.lex, s.pending
	l.stopped = false
	for l.pos < len(p) {
		i, b := l.pos, p[l.pos]
		if b == '\n' {
			if l.line == 1 {
				l.value('\n') // the payload's line separator
			}
			l.line, l.prefix = 0, 0
			l.afterLF = i+1 != s.insertedLF
			l.pos++
			continue
		}
		size := 1
		if b >= utf8.RuneSelf && l.line != 2 && !l.inStr {
			if !utf8.FullRune(p[i:]) {
				l.stopped = true
				return
			}
			var r rune
			r, size = utf8.DecodeRune(p[i:])
			if unicode.IsSpace(r) {
				b = ' '
			}
		}
		l.pos += size
		switch l.line {
		case 0:
			if l.prefix == 0 && sseSpace(b) {
				continue
			}
			l.content = true
			if b == "data:"[l.prefix] {
				if l.prefix++; l.prefix == len("data:") {
					l.line = 1
				}
			} else {
				l.line = 2
			}
		case 1:
			l.value(b)
		}
	}
}

func sseSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\v' || b == '\f'
}

// value takes one payload byte; a non-space non-ASCII rune arrives as its
// first byte (>= 0x80), which is never valid JSON outside a string.
func (l *sseDataLexer) value(b byte) {
	if l.inStr {
		switch {
		case l.esc:
			l.esc = false
		case b == '\\':
			l.esc = true
		case b == '"':
			l.inStr = false
			l.prev, l.colon = '"', l.key
			l.done = l.done || l.root == 2
		}
		return
	}
	if sseSpace(b) {
		if l.root == 3 {
			l.done = true
		}
		return
	}
	if l.done {
		l.bad = true
		return
	}
	switch l.root {
	case 0:
		switch b {
		case '{', '[':
			l.root = 1
		case '"':
			l.root = 2
		default:
			l.root = 3
			switch b {
			case 't':
				l.lit = "true"
			case 'f':
				l.lit = "false"
			case 'n':
				l.lit = "null"
			}
			l.token(b)
			return
		}
	case 3:
		l.token(b)
		return
	}
	inObject := len(l.stack) > 0 && l.stack[len(l.stack)-1] == '{'
	l.key = b == '"' && inObject && (l.prev == '{' || l.prev == ',')
	l.prev, l.colon = b, false
	switch b {
	case '"':
		l.inStr = true
	case '{', '[':
		l.depth++
		l.stack = append(l.stack, b)
	case '}', ']':
		l.depth--
		if n := len(l.stack); n > 0 {
			l.stack = l.stack[:n-1]
		}
		l.done = l.depth <= 0
	}
}

func (l *sseDataLexer) token(b byte) {
	if l.lit != "" {
		if l.litPos >= len(l.lit) || b != l.lit[l.litPos] {
			l.bad = true
		}
		l.litPos++
		return
	}
	if l.num = sseNumberNext(l.num, b); l.num < 0 {
		l.bad = true
	}
}

func (l *sseDataLexer) tokenValid() bool {
	if l.lit != "" {
		return l.litPos == len(l.lit)
	}
	return l.num == 2 || l.num == 3 || l.num == 5 || l.num == 8
}

// sseNumberNext is the JSON number grammar: 0 start, 1 '-', 2 leading 0,
// 3 integer, 4 '.', 5 fraction, 6 'e', 7 exponent sign, 8 exponent; -1 invalid.
func sseNumberNext(state int8, b byte) int8 {
	digit := b >= '0' && b <= '9'
	switch state {
	case 0:
		if b == '-' {
			return 1
		}
		fallthrough
	case 1:
		if b == '0' {
			return 2
		}
		if digit {
			return 3
		}
	case 2, 3:
		if state == 3 && digit {
			return 3
		}
		if b == '.' {
			return 4
		}
		if b == 'e' || b == 'E' {
			return 6
		}
	case 4, 5:
		if digit {
			return 5
		}
		if state == 5 && (b == 'e' || b == 'E') {
			return 6
		}
	case 6:
		if b == '+' || b == '-' {
			return 7
		}
		fallthrough
	case 7, 8:
		if digit {
			return 8
		}
	}
	return -1
}
