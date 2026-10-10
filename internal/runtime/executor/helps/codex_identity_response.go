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
	if from == "" || to == "" || from == to {
		return payload
	}
	return ReplaceCodexIdentityResponseWithMappings(payload, [][2]string{{from, to}})
}

// ReplaceCodexIdentityResponseWithMappings applies one view's mapping table to
// the raw payload. Generated values are emitted directly, never matched again.
func ReplaceCodexIdentityResponseWithMappings(payload []byte, mappings [][2]string) []byte {
	if len(payload) == 0 || len(mappings) == 0 {
		return payload
	}
	if json.Valid(payload) {
		return NewCodexIdentityResponseRewriterWithMappings(mappings, false, true).Rewrite(payload, true)
	}
	sse := false
	for _, line := range bytes.FieldsFunc(payload, func(r rune) bool { return r == '\r' || r == '\n' }) {
		if bytes.HasPrefix(line, []byte("data:")) || bytes.HasPrefix(line, []byte("event:")) || bytes.HasPrefix(line, []byte("id:")) || bytes.HasPrefix(line, []byte("retry:")) || bytes.HasPrefix(line, []byte(":")) {
			sse = true
			break
		}
	}
	if !sse {
		return NewCodexIdentityResponseRewriterWithMappings(mappings, false, false).Rewrite(payload, true)
	}
	return NewCodexIdentityResponseRewriterWithMappings(mappings, true, false).Rewrite(payload, true)
}

type codexIdentityAtom struct {
	raw []byte
	r   rune
}

type codexIdentityResponseMapping struct {
	from, to string
	jsonTo   []byte
}

// CodexIdentityResponseRewriter carries only an undecided identity prefix and
// an incomplete escape/rune. JSON/SSE lexical state survives arbitrary reads;
// neither a complete string nor a complete SSE line is buffered.
// SSE data fields share JSON context until the blank event delimiter. Literal
// prefixes use bounded lookahead so plaintext starting with t/f/n is not JSON.
// The caller must flush with final=true at EOF (also on a terminal read error).
type CodexIdentityResponseRewriter struct {
	mappings  []codexIdentityResponseMapping
	sse       bool
	line      int // 0: SSE field prefix, 1: metadata, 2: data format, 3: data, 4: literal probe
	prefix    []byte
	skipLF    bool // CRLF is one line ending, even across reads
	formatSet bool
	literal   string
	format    []byte // at most len("false") bytes of undecided literal prefix
	jsonMode  bool
	scalar    int    // 0: structured/plaintext, 1: scalar tail, 2: number token
	stack     []byte // 'k': object expecting a key, 'v': object value, '[': array
	inString  bool
	value     bool
	keyEscape bool
	pending   []byte
	atoms     []codexIdentityAtom
	candidate string // decoded atoms; bounded by the longest source plus one rune
	leftID    bool   // lexical class of the last consumed raw rune, not generated text
}

func NewCodexIdentityResponseRewriter(from, to string, sse, jsonBody bool) *CodexIdentityResponseRewriter {
	return NewCodexIdentityResponseRewriterWithMappings([][2]string{{from, to}}, sse, jsonBody)
}

// NewCodexIdentityResponseRewriterWithMappings selects leftmost-longest whole
// identifiers in one pass. Equal sources keep the first registration; no-op
// mappings still participate in selection and preserve their original escapes.
func NewCodexIdentityResponseRewriterWithMappings(mappings [][2]string, sse, jsonBody bool) *CodexIdentityResponseRewriter {
	w := &CodexIdentityResponseRewriter{sse: sse, jsonMode: jsonBody}
	seen := make(map[string]bool)
	for _, pair := range mappings {
		if pair[0] == "" || seen[pair[0]] {
			continue
		}
		seen[pair[0]] = true
		encoded, _ := json.Marshal(pair[1])
		w.mappings = append(w.mappings, codexIdentityResponseMapping{from: pair[0], to: pair[1], jsonTo: encoded[1 : len(encoded)-1]})
	}
	return w
}

func codexIdentityRune(r rune) bool {
	return r == '_' || r == '-' || unicode.IsLetter(r) || unicode.IsNumber(r) || unicode.IsMark(r)
}

// drain consumes only decided raw atoms. A shorter whole match waits while a
// longer source is possible; a failed prefix is reconsidered at the next raw
// offset, with its original left boundary. Replacement bytes never enter atoms.
func (w *CodexIdentityResponseRewriter) drain(out *[]byte, final bool) {
	for len(w.atoms) > 0 {
		best, undecided := -1, false
		if !w.leftID {
			for i, mapping := range w.mappings {
				if !final && strings.HasPrefix(mapping.from, w.candidate) {
					undecided = true
				}
				if !strings.HasPrefix(w.candidate, mapping.from) {
					continue
				}
				right := w.candidate[len(mapping.from):]
				if right == "" {
					if !final {
						continue
					}
				} else if r, _ := utf8.DecodeRuneInString(right); codexIdentityRune(r) {
					continue
				}
				if best < 0 || len(mapping.from) > len(w.mappings[best].from) {
					best = i
				}
			}
		}
		if undecided {
			return
		}
		consumed, decodedBytes := 1, len(string(w.atoms[0].r))
		if best >= 0 {
			mapping := w.mappings[best]
			consumed, decodedBytes = 0, 0
			for decodedBytes < len(mapping.from) {
				decodedBytes += len(string(w.atoms[consumed].r))
				consumed++
			}
			if mapping.from == mapping.to {
				for _, atom := range w.atoms[:consumed] {
					*out = append(*out, atom.raw...)
				}
			} else if w.jsonMode {
				*out = append(*out, mapping.jsonTo...)
			} else {
				*out = append(*out, mapping.to...)
			}
		} else {
			*out = append(*out, w.atoms[0].raw...)
		}
		w.leftID = codexIdentityRune(w.atoms[consumed-1].r)
		w.atoms = w.atoms[consumed:]
		w.candidate = w.candidate[decodedBytes:]
	}
}

func (w *CodexIdentityResponseRewriter) atom(out *[]byte, atom codexIdentityAtom) {
	next := string(atom.r)
	if len(w.atoms) == 0 {
		starts := false
		if !w.leftID {
			for _, mapping := range w.mappings {
				if strings.HasPrefix(mapping.from, next) {
					starts = true
					break
				}
			}
		}
		if !starts {
			*out = append(*out, atom.raw...)
			w.leftID = codexIdentityRune(atom.r)
			return
		}
	}
	atom.raw = bytes.Clone(atom.raw)
	w.atoms = append(w.atoms, atom)
	w.candidate += next
	w.drain(out, false)
}

func (w *CodexIdentityResponseRewriter) finishToken(out *[]byte) {
	w.drain(out, true)
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
			if w.skipLF {
				w.skipLF = false
				if b == '\n' {
					out = append(out, b)
					i++
					continue
				}
			}
			if w.line == 4 {
				if len(w.format) < len(w.literal) && b == w.literal[len(w.format)] {
					w.format = append(w.format, b)
					i++
					continue
				}
				w.jsonMode = len(w.format) == len(w.literal) && (b == ' ' || b == '\t' || b == '\r' || b == '\n')
				w.line, w.formatSet = 3, true
				if w.jsonMode {
					// A complete literal is not a string identity. Only later
					// non-whitespace text can disqualify the scalar format.
					out = append(out, w.format...)
					w.scalar = 1
				} else {
					// Replay only the bounded probe through the plaintext path.
					input = append(bytes.Clone(w.format), input[i:]...)
					i = 0
				}
				w.format = w.format[:0]
				continue
			}
			if b == '\r' || b == '\n' {
				if w.line == 2 || w.line == 3 {
					// The logical LF joining data fields is a token boundary, not
					// a JSON-context or event boundary.
					w.finishToken(&out)
					if w.scalar == 2 {
						w.scalar = 1
					}
				}
				if w.line == 0 && len(w.prefix) == 0 {
					w.jsonMode, w.formatSet, w.inString, w.keyEscape = false, false, false, false
					w.scalar = 0
					w.stack = w.stack[:0]
				}
				out = append(out, w.prefix...)
				w.prefix = w.prefix[:0]
				out = append(out, b)
				w.line, w.skipLF = 0, b == '\r'
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
				w.line = 3
				if !w.formatSet {
					switch b {
					case 't':
						w.literal = "true"
					case 'f':
						w.literal = "false"
					case 'n':
						w.literal = "null"
					default:
						w.literal = ""
					}
					if w.literal != "" {
						w.format = append(w.format[:0], b)
						w.line = 4
						i++
						continue
					}
					w.jsonMode = b == '{' || b == '[' || b == '"' || b == '-' || b >= '0' && b <= '9'
					if b == '-' || b >= '0' && b <= '9' {
						w.scalar = 2
					}
					w.formatSet = true
				}
			}
			if w.jsonMode && w.scalar != 0 {
				if b == ' ' || b == '\t' {
					w.scalar = 1
					w.leftID = false
				} else if w.scalar == 1 || !(b >= '0' && b <= '9' || b == '-' || b == '+' || b == '.' || b == 'e' || b == 'E') {
					// Root scalars cannot have a second non-whitespace token.
					// Emit whitespace eagerly; subsequent text uses whole-token
					// fallback rather than buffering an entire scalar/event.
					w.jsonMode, w.scalar = false, 0
				} else {
					w.leftID = codexIdentityRune(rune(b))
				}
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
		if w.line == 4 {
			w.jsonMode = len(w.format) == len(w.literal)
			w.line, w.formatSet = 3, true
			if w.jsonMode {
				out = append(out, w.format...)
				w.scalar = 1
				w.format = w.format[:0]
			} else {
				probe := bytes.Clone(w.format)
				w.format = w.format[:0]
				out = append(out, w.Rewrite(probe, true)...)
			}
		}
		w.finishToken(&out)
		out = append(out, w.prefix...)
		w.prefix = w.prefix[:0]
	}
	return out
}
