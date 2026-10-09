package auth

import (
	"bytes"
	"context"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/sse"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/session"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// RecordCompactionOutput records signer evidence, not a guess from input affinity.
// Each block has its own protected group, independent of mutable session aliases.
// The caller must pass the auth that actually executed the producing request.
func (s *SessionAffinitySelector) RecordCompactionOutput(authID string, opts cliproxyexecutor.Options, payload []byte) error {
	collector := newCompactionKeyCollector(compactionContext(opts))
	if errCollect := collectCompactionOutput(compactionContext(opts), payload, collector); errCollect != nil {
		return errCollect
	}
	return s.recordCompactionOutputKeys(authID, opts, collector.keys)
}

func (s *SessionAffinitySelector) recordCompactionOutputKeys(authID string, opts cliproxyexecutor.Options, keys []string, contexts ...context.Context) error {
	ctx := compactionContext(opts)
	if len(contexts) > 0 && contexts[0] != nil {
		ctx = contexts[0]
	}
	if err := compactionCheckContext(ctx); err != nil {
		return err
	}
	if len(keys) == 0 {
		return nil
	}
	if s == nil || s.cache == nil || strings.TrimSpace(authID) == "" {
		return affinityStateError()
	}
	bindings := append([]string(nil), keys...)
	// Protect the explicit primary independently. Production on this account is
	// authoritative even when a handled scheduler bypassed selector.Pick.
	primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	namespace, _ := opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey].(string)
	model, _ := opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey].(string)
	if primaryID != "" && namespace != "" {
		primaryKey := namespace + "::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + canonicalModelKey(model)
		bindings = append(bindings, primaryKey)
	}
	// All signer groups and the independent primary are retained together and
	// published synchronously once, before the caller delivers signed bytes.
	if errSave := s.cache.SetProtectedBindings(ctx, authID, bindings...); errSave != nil {
		if err := compactionCheckContext(ctx); err != nil {
			return err
		}
		return affinityStateError()
	}
	return nil
}

// RecordCompactionOutput retains the request's origin store across reload,
// disable, auth-directory changes, or a transition to Home. Requests originating
// in Home do not have a local store. The actual executing auth remains the signer.
func (m *Manager) RecordCompactionOutput(authID string, opts cliproxyexecutor.Options, payload []byte) error {
	if affinity := m.compactionOutputStore(opts); affinity != nil {
		return affinity.RecordCompactionOutput(authID, opts, payload)
	}
	return nil
}

func (m *Manager) compactionOutputStore(opts cliproxyexecutor.Options) *SessionAffinitySelector {
	if value, captured := opts.Metadata[compactionAffinityStoreMetadataKey]; captured {
		origin, _ := value.(*SessionAffinitySelector)
		return origin
	}
	if m.HomeEnabled() {
		return nil
	}
	affinity, _ := m.Selector().(*SessionAffinitySelector)
	return affinity
}

// compactionOutputKeys is a compatibility helper for tests. Production must
// propagate collection errors before mutating signer state or delivering bytes.
func compactionOutputKeys(payload []byte) []string {
	collector := newCompactionKeyCollector(context.Background())
	if collectCompactionOutput(context.Background(), payload, collector) != nil {
		return nil
	}
	return collector.keys
}

func completeCompactionOutput(item gjson.Result) bool {
	if item.Get("type").String() != "compaction" {
		return false
	}
	if item.Get("encrypted_content").String() != "" {
		return true
	}
	content := item.Get("content")
	return content.Exists() && content.Type != gjson.Null && (content.Type != gjson.String || content.String() != "")
}

func collectCompactionOutput(ctx context.Context, payload []byte, collector *compactionKeyCollector, current ...*[]string) error {
	if err := compactionCheckContext(ctx); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(payload)
	// Ordinary SDK success payloads may be opaque or empty. Only JSON
	// containers can carry signer evidence; validate every such container,
	// not just those with recognizable compaction fields (which may be escaped).
	if bytes.Equal(trimmed, []byte("[DONE]")) || len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') {
		return compactionCheckContext(ctx)
	}
	if errValidate := ValidateCompactionJSON(ctx, payload); errValidate != nil {
		return errValidate
	}
	root := gjson.ParseBytes(payload)
	var errCollect error
	seen := make(map[string]struct{})
	add := func(item gjson.Result) error {
		if err := collector.add(item); err != nil {
			return err
		}
		// Global dedup bounds collection, but every signed acknowledgement
		// must refresh/recheck its own evidence even if an earlier event had it.
		if len(current) > 0 && current[0] != nil {
			key := collector.lastKey
			if _, duplicate := seen[key]; !duplicate {
				seen[key] = struct{}{}
				*current[0] = append(*current[0], key)
			}
		}
		return nil
	}
	collect := func(items gjson.Result, nativeComplete bool) {
		items.ForEach(func(_, item gjson.Result) bool {
			if errCollect = compactionCheckContext(ctx); errCollect != nil {
				return false
			}
			content := item.Get("content")
			// content[] is a completed native response (or an assembled stop),
			// unlike content_block_start where an empty string is a skeleton.
			if completeCompactionOutput(item) || (nativeComplete && item.Get("type").String() == "compaction" && content.Exists() && content.Type != gjson.Null) {
				errCollect = add(item)
			}
			return errCollect == nil
		})
	}
	for _, path := range []string{"output", "response.output", "content"} {
		collect(root.Get(path), path == "content")
		if errCollect != nil {
			return errCollect
		}
	}
	switch root.Get("type").String() {
	case "response.output_item.added", "response.output_item.done":
		item := root.Get("item")
		if completeCompactionOutput(item) {
			return add(item)
		}
	case "content_block_start":
		item := root.Get("content_block")
		if completeCompactionOutput(item) {
			return add(item)
		}
	}
	return compactionCheckContext(ctx)
}

// compactionOutputStream holds only a partial wire event, never durable raw
// blocks. It also accepts the executor's delimiter-free data: JSON chunks and
// native websocket JSON events. Complete event bytes are released only after
// their signer evidence is saved. Concatenation preserves the wire bytes.
type compactionOutputStream struct {
	pending     []byte
	record      func([]byte) error
	controlLine bool
	// Only new bytes enter the lexical checkpoint. Scanner line boundaries
	// affect data, never the retained original wire units.
	units          [][]byte
	released       [][]byte
	data           []byte
	linePrefix     []byte
	lineMode       byte // 0 prefix, 1 data, 2 control, 3 raw JSON
	lineBytes      int
	lines          sse.Lines
	dataSpace      bool
	jsonDepth      int
	jsonStarted    bool
	jsonString     bool
	jsonEscape     bool
	jsonDone       bool
	jsonBad        bool
	jsonScalar     byte // 1 quoted string, 2 number/literal
	jsonLiteral    string
	jsonScalarPos  int
	jsonNumberLast byte
	framed         bool // literal SSE data LF requires a blank-line boundary
	sse            bool
	// Line provenance for a unit that starts with ':' (F2). A line that began
	// after a wire LF can only be continued by the next unit; a Scanner never
	// sends LF, so a stream with complete events and no LF is Scanner-framed.
	lineAfterLF bool
	sawLF       bool
	events      int
	// jsonColon: the last JSON token is an object key, so only ':' may follow.
	jsonColon     bool
	jsonPrev      byte
	jsonKey       bool
	jsonContainer []byte

	// Native Claude sends a skeleton followed by content deltas. Only these
	// signed block bytes wait for completion; ordinary SSE remains immediate.
	native            bool
	ctx               context.Context
	nativeBlock       []byte
	nativeIndex       int64
	nativeHold        bool
	nativeWire        [][]byte
	nativeBytes       int
	nativeContent     strings.Builder
	nativeContentType gjson.Type
}

func (s *compactionOutputStream) push(payload []byte) ([]byte, error) {
	if s.ctx != nil {
		if err := compactionCheckContext(s.ctx); err != nil {
			return nil, err
		}
	}
	ready, err := s.pushEvent(payload)
	if err != nil {
		s.nativeWire, s.nativeBlock = nil, nil
		return nil, err
	}
	if !s.native || (!s.nativeHold && len(s.nativeWire) == 0) {
		return ready, nil
	}
	units := s.released
	s.released = nil
	if units == nil && len(ready) > 0 {
		units = [][]byte{ready}
	}
	for _, unit := range units {
		if len(unit) > maxCompactionJSONBytes-s.nativeBytes || len(s.nativeWire) >= maxCompactionWireUnits {
			s.nativeWire, s.nativeBlock = nil, nil
			return nil, affinityStateError()
		}
		s.nativeBytes += len(unit)
		s.nativeWire = append(s.nativeWire, bytes.Clone(unit))
	}
	if s.nativeHold {
		return nil, nil
	}
	s.released = s.nativeWire
	ready = bytes.Join(s.nativeWire, nil)
	s.nativeWire, s.nativeBytes = nil, 0
	return ready, nil
}

func (s *compactionOutputStream) recordEvent(data []byte) error {
	if !s.native || bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
		return s.record(data)
	}
	if errValidate := ValidateCompactionJSON(s.ctx, data); errValidate != nil {
		return errValidate
	}
	root := gjson.ParseBytes(data)
	switch root.Get("type").String() {
	case "content_block_start":
		block := root.Get("content_block")
		if block.Get("type").String() != "compaction" {
			break
		}
		if s.nativeBlock != nil || root.Get("index").Type != gjson.Number || root.Get("index").Int() < 0 {
			return affinityStateError()
		}
		s.nativeBlock = []byte(block.Raw)
		s.nativeIndex = root.Get("index").Int()
		s.nativeContentType = block.Get("content").Type
		s.nativeContent.Reset()
		if block.Get("content").Type == gjson.String {
			s.nativeContent.WriteString(block.Get("content").String())
		}
		s.nativeHold = !completeCompactionOutput(block)
	case "content_block_delta":
		if s.nativeBlock == nil {
			break
		}
		if root.Get("index").Type != gjson.Number || root.Get("index").Int() != s.nativeIndex {
			return affinityStateError()
		}
		content := root.Get("delta.content")
		if content.Type != gjson.String {
			return affinityStateError()
		}
		if s.nativeContentType != gjson.String && s.nativeContentType != gjson.Null {
			return affinityStateError()
		}
		if s.nativeContent.Len()+len(content.String()) > maxCompactionJSONBytes {
			return affinityStateError()
		}
		s.nativeContent.WriteString(content.String())
		s.nativeHold = true
	case "content_block_stop":
		if s.nativeBlock == nil {
			break
		}
		if root.Get("index").Type != gjson.Number || root.Get("index").Int() != s.nativeIndex {
			return affinityStateError()
		}
		// Assemble once, not once per delta (which would be quadratic).
		if s.nativeHold {
			var errSet error
			s.nativeBlock, errSet = sjson.SetBytes(s.nativeBlock, "content", s.nativeContent.String())
			if errSet != nil {
				return affinityStateError()
			}
		}
		// Reuse the output collector and replay identity, never hash SSE JSON.
		if errSave := s.record([]byte(`{"content":[` + string(s.nativeBlock) + `]}`)); errSave != nil {
			return errSave
		}
		s.nativeBlock, s.nativeHold = nil, false
		s.nativeContent.Reset()
	case "message_stop":
		if s.nativeHold {
			return affinityStateError()
		}
	}
	return s.record(data)
}

// The unit ceiling bounds slice headers even for one-byte SDK fragments. It
// admits the 100k-line (<1 MiB) Scanner event independently of the byte ceiling.
const maxCompactionWireUnits = 1 << 20

// Test-only observation uses a private context key, not a public SDK option.
// The receipt counts actual lexical visits and the single completed-data scan.
type compactionFramingWorkKey struct{}

func (s *compactionOutputStream) framingWork(n int) {
	if s.ctx != nil {
		if observe, ok := s.ctx.Value(compactionFramingWorkKey{}).(func(int)); ok {
			observe(n)
		}
	}
}

func (s *compactionOutputStream) dataByte(b byte) error {
	if len(s.data) >= maxCompactionJSONBytes {
		return affinityStateError()
	}
	s.framingWork(1)
	s.data = append(s.data, b)
	if s.jsonString {
		if s.jsonEscape {
			s.jsonEscape = false
		} else if b == '\\' {
			s.jsonEscape = true
		} else if b == '"' {
			s.jsonString = false
			s.jsonPrev, s.jsonColon = '"', s.jsonKey
			if s.jsonScalar == 1 {
				s.jsonDone = true
			}
		}
		return nil
	}
	if s.jsonScalar == 2 {
		if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
			return nil
		}
		if s.jsonLiteral != "" {
			if s.jsonScalarPos >= len(s.jsonLiteral) || b != s.jsonLiteral[s.jsonScalarPos] {
				s.jsonBad, s.jsonDone = true, true
			} else {
				s.jsonScalarPos++
				s.jsonDone = s.jsonScalarPos == len(s.jsonLiteral)
			}
		} else {
			s.jsonNumberLast = b
		}
		return nil
	}
	if b == ' ' || b == '\t' || b == '\r' || b == '\n' {
		return nil
	}
	if s.jsonDone {
		s.jsonBad = true
		return nil
	}
	if !s.jsonStarted {
		s.jsonStarted = true
		if b == '"' {
			s.jsonScalar = 1
		} else if b != '{' && b != '[' {
			// A scalar has no nesting checkpoint. Inspect it once at the
			// unit/blank-line boundary, never on each raw fragment byte.
			s.jsonScalar = 2
			s.jsonNumberLast = b
			switch b {
			case 't':
				s.jsonLiteral = "true"
			case 'f':
				s.jsonLiteral = "false"
			case 'n':
				s.jsonLiteral = "null"
			}
			s.jsonScalarPos = 1
			if s.jsonLiteral == "" && b != '-' && (b < '0' || b > '9') {
				s.jsonBad, s.jsonDone = true, true
			}
			return nil
		}
	}
	inObject := len(s.jsonContainer) > 0 && s.jsonContainer[len(s.jsonContainer)-1] == '{'
	s.jsonKey = b == '"' && inObject && (s.jsonPrev == '{' || s.jsonPrev == ',')
	s.jsonPrev, s.jsonColon = b, false
	switch b {
	case '"':
		s.jsonString = true
	case '{', '[':
		s.jsonDepth++
		if s.jsonDepth > maxCompactionJSONDepth {
			return affinityStateError()
		}
		s.jsonContainer = append(s.jsonContainer, b)
	case '}', ']':
		s.jsonDepth--
		if n := len(s.jsonContainer); n > 0 {
			s.jsonContainer = s.jsonContainer[:n-1]
		}
		if s.jsonDepth <= 0 {
			s.jsonDone = true
		}
	}
	return nil
}

func (s *compactionOutputStream) resetLine() {
	s.linePrefix = nil
	s.lineMode, s.lineBytes = 0, 0
	s.dataSpace, s.controlLine, s.lineAfterLF = false, false, false
}

func (s *compactionOutputStream) resetData() {
	s.data = nil
	s.jsonDepth = 0
	s.jsonScalar, s.jsonNumberLast, s.jsonScalarPos = 0, 0, 0
	s.jsonLiteral = ""
	s.framed, s.sse = false, false
	s.jsonStarted, s.jsonString, s.jsonEscape, s.jsonDone, s.jsonBad = false, false, false, false, false
	s.jsonColon, s.jsonPrev, s.jsonKey, s.jsonContainer = false, 0, false, s.jsonContainer[:0]
}

func (s *compactionOutputStream) releaseUnits() {
	s.released = append(s.released, s.units...)
	s.pending, s.units = nil, nil
}

func (s *compactionOutputStream) completeCandidate() bool {
	return s.jsonDone || (s.jsonScalar == 2 && s.jsonLiteral == "" && s.jsonNumberLast >= '0' && s.jsonNumberLast <= '9')
}

func (s *compactionOutputStream) completeEvent() error {
	data := bytes.TrimSpace(s.data)
	s.framingWork(len(data))
	// This is the only whole-data syntax scan. The recorder still owns
	// recursive duplicate rejection, collection and protected publication.
	if s.jsonBad || (!bytes.Equal(data, []byte("[DONE]")) && !gjson.ValidBytes(data)) {
		return affinityStateError()
	}
	if err := s.recordEvent(data); err != nil {
		return err
	}
	s.events++
	s.releaseUnits()
	s.resetData()
	return nil
}

func (s *compactionOutputStream) endLine() error {
	if s.lineMode == 1 || s.lineMode == 3 {
		if err := s.dataByte('\n'); err != nil {
			return err
		}
	}
	s.resetLine()
	return nil
}

// startsLine shares the handler's lexer-aware Scanner boundary rule. Physical
// CR, LF and CRLF boundaries are handled separately by s.lines, so a comment
// after an object key is unambiguous when the transport carries a terminator.
func (s *compactionOutputStream) startsLine(payload []byte) bool {
	return sse.StartsLine(payload, sse.LexicalBoundary{
		InString: s.jsonString, PartialField: s.lineMode == 0 && len(s.linePrefix) > 0,
		RawJSON: s.jsonStarted && !s.sse, DataLine: s.lineMode == 1,
		Open: s.jsonStarted && !s.jsonDone, AfterBreak: s.lineAfterLF,
		Colon: s.jsonColon, Scanner: s.events > 0 && !s.sawLF,
	})
}

func (s *compactionOutputStream) pushEvent(payload []byte) ([]byte, error) {
	s.released = nil
	recognized := s.startsLine(payload)
	if s.lineBytes > 0 && recognized && !(s.jsonStarted && !s.sse) {
		// Scanner strips delimiters; only the new unit's prefix is examined.
		if err := s.endLine(); err != nil {
			return nil, err
		}
	} else if s.controlLine {
		trimmed := bytes.TrimSpace(payload)
		if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
			s.resetLine()
		}
	}
	start := 0
	hold := func(end int) error {
		if end == start {
			return nil
		}
		if len(s.units) >= maxCompactionWireUnits {
			return affinityStateError()
		}
		s.units = append(s.units, bytes.Clone(payload[start:end]))
		start = end
		return nil
	}
	fail := func(err error) ([]byte, error) {
		s.pending, s.units, s.released = nil, nil, nil
		s.resetLine()
		s.resetData()
		return nil, err
	}
	for i, b := range payload {
		if i&1023 == 0 && s.ctx != nil {
			if err := compactionCheckContext(s.ctx); err != nil {
				return fail(err)
			}
		}
		// Bound both raw wire and unit headers BEFORE their append, including
		// complete events that could otherwise bypass the old partial limit.
		if len(s.pending) >= maxCompactionJSONBytes || len(s.units) >= maxCompactionWireUnits {
			return fail(affinityStateError())
		}
		s.pending = append(s.pending, b)
		s.framingWork(1)
		lineBreak, skip := s.lines.Step(b)
		if skip {
			continue
		}
		if lineBreak {
			blank := s.lineBytes == 0
			if s.lineMode == 1 {
				s.framed = true
			}
			completed := blank && s.completeCandidate()
			if completed {
				if err := hold(i + 1); err != nil {
					return fail(err)
				}
				if err := s.completeEvent(); err != nil {
					return fail(err)
				}
			} else if blank && len(s.data) > 0 && s.sse {
				return fail(affinityStateError())
			} else if len(s.data) == 0 && len(s.linePrefix) == 0 {
				if err := hold(i + 1); err != nil {
					return fail(err)
				}
				s.releaseUnits()
			}
			if completed {
				s.resetLine()
			} else if err := s.endLine(); err != nil {
				return fail(err)
			}
			s.sawLF, s.lineAfterLF = true, true
			continue
		}
		s.lineBytes++
		switch s.lineMode {
		case 1:
			if s.dataSpace {
				s.dataSpace = false
				if b == ' ' {
					continue
				}
			}
			if err := s.dataByte(b); err != nil {
				return fail(err)
			}
		case 2:
			// Control bytes never enter JSON, even inside a held SSE event.
		case 3:
			if err := s.dataByte(b); err != nil {
				return fail(err)
			}
		default:
			// Once raw JSON starts, later line prefixes are JSON bytes, not
			// SSE controls that could hide an invalid suffix from validation.
			if s.jsonStarted && !s.sse {
				s.lineMode = 3
				if err := s.dataByte(b); err != nil {
					return fail(err)
				}
				continue
			}
			if len(s.linePrefix) == 0 && (b == ' ' || b == '\t' || b == '\r') {
				continue
			}
			s.linePrefix = append(s.linePrefix, b)
			prefix := s.linePrefix
			if bytes.Equal(prefix, []byte("data:")) {
				s.sse = true
				s.lineMode, s.dataSpace = 1, true
				s.linePrefix = nil
				continue
			}
			if compactionControlLine(prefix) {
				s.lineMode, s.controlLine = 2, true
				s.linePrefix = nil
				continue
			}
			possible := false
			for _, name := range []string{"data:", "event:", "id:", "retry:"} {
				if bytes.HasPrefix([]byte(name), prefix) {
					possible = true
					break
				}
			}
			if possible {
				continue
			}
			s.lineMode, s.linePrefix = 3, nil
			for _, value := range prefix {
				if err := s.dataByte(value); err != nil {
					return fail(err)
				}
			}
		}
	}
	if err := hold(len(payload)); err != nil {
		return fail(err)
	}
	if s.completeCandidate() && !s.framed {
		if err := s.completeEvent(); err != nil {
			return fail(err)
		}
		s.resetLine()
	} else if len(s.data) == 0 && len(s.linePrefix) == 0 && s.lineMode != 1 {
		s.releaseUnits()
	}
	return bytes.Join(s.released, nil), nil
}

// pushChunks is the Manager boundary: synthesized parser separators are not
// wire bytes, and downstream must receive each original Scanner unit intact.
func (s *compactionOutputStream) pushChunks(payload []byte) ([][]byte, error) {
	ready, err := s.push(payload)
	if err != nil {
		return nil, err
	}
	if s.released != nil {
		units := s.released
		s.released = nil
		return units, nil
	}
	if len(ready) == 0 {
		return nil, nil
	}
	return [][]byte{ready}, nil
}

func (s *compactionOutputStream) finishChunks() ([][]byte, error) {
	ready, err := s.finish()
	if err != nil || len(ready) == 0 {
		return nil, err
	}
	return [][]byte{ready}, nil
}

func compactionControlLine(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte(":")) || bytes.HasPrefix(payload, []byte("event:")) ||
		bytes.HasPrefix(payload, []byte("id:")) || bytes.HasPrefix(payload, []byte("retry:"))
}

// finish never publishes an unexamined tail. A partial data event cannot be
// acknowledged safely; complete events have already been released by push.
func (s *compactionOutputStream) finish() ([]byte, error) {
	ready, errSave := s.push(nil)
	if errSave != nil {
		return nil, errSave
	}
	if len(s.pending) != 0 || s.nativeHold {
		s.pending, s.nativeWire, s.nativeBlock = nil, nil, nil
		return nil, affinityStateError()
	}
	return ready, nil
}

func compactionSSEFrameEnd(payload []byte) int {
	// Recognize LF and CRLF blank lines, including mixed line endings.
	lineStart := 0
	for i, b := range payload {
		if b != '\n' {
			continue
		}
		if len(bytes.TrimSuffix(payload[lineStart:i], []byte("\r"))) == 0 {
			return i + 1
		}
		lineStart = i + 1
	}
	return 0
}

func compactionSSEData(frame []byte) []byte {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		return trimmed
	}
	var data []byte
	for _, line := range bytes.Split(frame, []byte("\n")) {
		line = bytes.TrimSuffix(line, []byte("\r"))
		_, value, found := extractSSEDataLine(line)
		if !found {
			continue
		}
		if len(data) > 0 {
			data = append(data, '\n')
		}
		data = append(data, value...)
	}
	return bytes.TrimSpace(data)
}
