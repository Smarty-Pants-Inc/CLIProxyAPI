package helps

import (
	"bytes"
	"encoding/json"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ReplaceCodexIdentityResponse rewrites string values, not JSON field names or
// numbers. Unchanged bytes (including string escapes and SSE metadata) are kept.
func ReplaceCodexIdentityResponse(payload []byte, from, to string) []byte {
	from, to = strings.TrimSpace(from), strings.TrimSpace(to)
	if len(payload) == 0 || from == "" || to == "" || from == to {
		return payload
	}
	if json.Valid(payload) {
		return NewCodexIdentityResponseRewriter(from, to, false, true).Rewrite(payload, true)
	}
	sse := false
	for _, line := range bytes.FieldsFunc(payload, func(r rune) bool { return r == '\r' || r == '\n' }) {
		if bytes.HasPrefix(line, []byte("data:")) || bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte("id:")) || bytes.HasPrefix(line, []byte("retry:")) || bytes.HasPrefix(line, []byte(":")) {
			sse = true
			break
		}
	}
	if !sse {
		return NewCodexIdentityResponseRewriter(from, to, false, false).Rewrite(payload, true)
	}
	var out []byte
	for len(payload) > 0 {
		end := bytes.IndexAny(payload, "\r\n")
		if end < 0 {
			end = len(payload)
		}
		line := payload[:end]
		if bytes.HasPrefix(line, []byte("data:")) {
			out = append(out, line[:5]...)
			data := line[5:]
			out = append(out, NewCodexIdentityResponseRewriter(from, to, false, json.Valid(data)).Rewrite(data, true)...)
		} else {
			out = append(out, line...)
		}
		payload = payload[end:]
		if len(payload) > 0 {
			out = append(out, payload[0])
			payload = payload[1:]
		}
	}
	return out
}

type codexIdentityAtom struct {
	raw []byte
	r   rune
}

// CodexIdentityResponseRewriter carries only an undecided identity prefix and
// an incomplete escape/rune. JSON/SSE lexical state survives arbitrary reads;
// neither a complete string nor a complete SSE line is buffered.
// In streaming SSE data, JSON is recognized by its first non-space character.
// The caller must flush with final=true at EOF (also on a terminal read error).
type CodexIdentityResponseRewriter struct {
	from, to  string
	jsonTo    []byte
	sse       bool
	line      int // 0: SSE field prefix, 1: metadata, 2: data format, 3: data
	prefix    []byte
	jsonMode  bool
	stack     []byte // 'k': object expecting a key, 'v': object value, '[': array
	inString  bool
	value     bool
	keyEscape bool
	pending   []byte
	atoms     []codexIdentityAtom
	matched   int
	leftID    bool
}

func NewCodexIdentityResponseRewriter(from, to string, sse, jsonBody bool) *CodexIdentityResponseRewriter {
	encoded, _ := json.Marshal(to)
	return &CodexIdentityResponseRewriter{from: from, to: to, jsonTo: encoded[1 : len(encoded)-1], sse: sse, jsonMode: jsonBody}
}

func codexIdentityRune(r rune) bool {
	return r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r)
}

func (w *CodexIdentityResponseRewriter) flush(out *[]byte, replace bool) {
	if replace {
		if w.jsonMode {
			*out = append(*out, w.jsonTo...)
		} else {
			*out = append(*out, w.to...)
		}
	} else {
		for _, atom := range w.atoms {
			*out = append(*out, atom.raw...)
		}
	}
	w.atoms = w.atoms[:0]
	w.matched = 0
}

func (w *CodexIdentityResponseRewriter) atom(out *[]byte, atom codexIdentityAtom) {
	if w.matched == len(w.from) && w.matched > 0 {
		w.flush(out, !codexIdentityRune(atom.r))
	}
	if w.matched > 0 {
		next := string(atom.r)
		if strings.HasPrefix(w.from[w.matched:], next) {
			atom.raw = bytes.Clone(atom.raw)
			w.atoms = append(w.atoms, atom)
			w.matched += len(next)
			w.leftID = codexIdentityRune(atom.r)
			return
		}
		// Reconsider suffixes after a failed prefix, without keeping a growing
		// token. This also handles operator keys containing punctuation.
		saved := append([]codexIdentityAtom(nil), w.atoms...)
		w.atoms = w.atoms[:0]
		w.matched = 0
		*out = append(*out, saved[0].raw...)
		w.leftID = codexIdentityRune(saved[0].r)
		for _, old := range saved[1:] {
			w.atom(out, old)
		}
		w.atom(out, atom)
		return
	}
	if !w.leftID && w.from != "" && strings.HasPrefix(w.from, string(atom.r)) {
		atom.raw = bytes.Clone(atom.raw)
		w.atoms = append(w.atoms, atom)
		w.matched = len(string(atom.r))
	} else {
		*out = append(*out, atom.raw...)
	}
	w.leftID = codexIdentityRune(atom.r)
}

func (w *CodexIdentityResponseRewriter) finishToken(out *[]byte) {
	w.flush(out, w.matched == len(w.from) && w.matched > 0)
	w.leftID = false
}

// Rewrite returns owned bytes. final is a true input boundary, never merely a
// read/chunk boundary: a full match needs the following decoded character.
func (w *CodexIdentityResponseRewriter) Rewrite(chunk []byte, final bool) []byte {
	input := append(w.pending, chunk...)
	w.pending = nil
	out := make([]byte, 0, len(input))
	for i := 0; i < len(input); {
		b := input[i]
		if w.sse {
			if b == '\r' || b == '\n' {
				w.finishToken(&out)
				out = append(out, w.prefix...)
				w.prefix = w.prefix[:0]
				out = append(out, b)
				w.line, w.jsonMode, w.inString, w.keyEscape = 0, false, false, false
				w.stack = w.stack[:0]
				i++
				continue
			}
			if w.line == 0 {
				w.prefix = append(w.prefix, b)
				i++
				if !bytes.HasPrefix([]byte("data:"), w.prefix) {
					out = append(out, w.prefix...)
					w.prefix = w.prefix[:0]
					w.line = 1
				} else if len(w.prefix) == 5 {
					out = append(out, w.prefix...)
					w.prefix = w.prefix[:0]
					w.line = 2
				}
				continue
			}
			if w.line == 1 {
				out = append(out, b)
				i++
				continue
			}
			if w.line == 2 {
				if b == ' ' || b == '\t' {
					out = append(out, b)
					i++
					continue
				}
				w.jsonMode = b == '{' || b == '[' || b == '"' || b == '-' || b >= '0' && b <= '9' || b == 't' || b == 'f' || b == 'n'
				w.line = 3
			}
		}
		if w.jsonMode {
			if !w.inString {
				switch b {
				case '{':
					w.stack = append(w.stack, 'k')
				case '[':
					w.stack = append(w.stack, '[')
				case '}', ']':
					if len(w.stack) > 0 {
						w.stack = w.stack[:len(w.stack)-1]
					}
				case ':':
					if len(w.stack) > 0 && w.stack[len(w.stack)-1] == 'k' {
						w.stack[len(w.stack)-1] = 'v'
					}
				case ',':
					if len(w.stack) > 0 && w.stack[len(w.stack)-1] == 'v' {
						w.stack[len(w.stack)-1] = 'k'
					}
				case '"':
					w.inString = true
					w.value = len(w.stack) == 0 || w.stack[len(w.stack)-1] != 'k'
					w.leftID = false
				}
				out = append(out, b)
				i++
				continue
			}
			if !w.value {
				out = append(out, b)
				if w.keyEscape {
					w.keyEscape = false
				} else if b == '\\' {
					w.keyEscape = true
				} else if b == '"' {
					w.inString = false
				}
				i++
				continue
			}
			if b == '"' {
				w.finishToken(&out)
				w.inString = false
				out = append(out, b)
				i++
				continue
			}
		}
		size := 1
		var r rune
		if w.jsonMode && b == '\\' {
			if len(input)-i < 2 && !final {
				w.pending = bytes.Clone(input[i:])
				break
			}
			size = 2
			if len(input)-i >= 2 && input[i+1] == 'u' {
				size = 6
				if len(input)-i >= 6 && (input[i+2] == 'd' || input[i+2] == 'D') && (input[i+3] == '8' || input[i+3] == '9' || input[i+3] == 'a' || input[i+3] == 'b' || input[i+3] == 'A' || input[i+3] == 'B') {
					// A high surrogate may be followed by a low surrogate.
					if len(input)-i < 12 && !final {
						w.pending = bytes.Clone(input[i:])
						break
					}
					if len(input)-i >= 12 && input[i+6] == '\\' && input[i+7] == 'u' && (input[i+8] == 'd' || input[i+8] == 'D') && strings.ContainsRune("cdefCDEF", rune(input[i+9])) {
						size = 12
					}
				}
			}
			if len(input)-i < size {
				if !final {
					w.pending = bytes.Clone(input[i:])
					break
				}
				size = len(input) - i
			}
			quoted := append([]byte{'"'}, input[i:i+size]...)
			quoted = append(quoted, '"')
			var decoded string
			if json.Unmarshal(quoted, &decoded) == nil {
				r, _ = utf8.DecodeRuneInString(decoded)
			} else {
				w.finishToken(&out)
				out = append(out, input[i:i+size]...)
				i += size
				continue
			}
		} else {
			if !utf8.FullRune(input[i:]) && !final {
				w.pending = bytes.Clone(input[i:])
				break
			}
			r, size = utf8.DecodeRune(input[i:])
		}
		w.atom(&out, codexIdentityAtom{raw: input[i : i+size], r: r})
		i += size
	}
	if final {
		w.finishToken(&out)
		out = append(out, w.prefix...)
		w.prefix = w.prefix[:0]
	}
	return out
}
