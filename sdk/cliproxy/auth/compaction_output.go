package auth

import (
	"bytes"
	"context"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
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
	// Parser-only line boundaries must never change exposed wire units.
	parsed   []byte
	units    [][]byte
	released [][]byte

	// Native Claude sends a skeleton followed by content deltas. Only these
	// signed block bytes wait for completion; ordinary SSE remains immediate.
	native        bool
	ctx           context.Context
	nativeBlock   []byte
	nativeIndex   int64
	nativeHold    bool
	nativeWire    [][]byte
	nativeBytes   int
	nativeContent strings.Builder
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
		s.nativeBytes += len(unit)
		if s.nativeBytes > maxCompactionJSONBytes {
			s.nativeWire, s.nativeBlock = nil, nil
			return nil, affinityStateError()
		}
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
		previous := gjson.GetBytes(s.nativeBlock, "content")
		if previous.Exists() && previous.Type != gjson.String && previous.Type != gjson.Null {
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

func (s *compactionOutputStream) pushEvent(payload []byte) ([]byte, error) {
	// Scanner removes line endings. A new recognized line unit ends the
	// previous control unit; otherwise a fragmented raw control line continues.
	_, _, scannerLine := extractSSEDataLine(payload)
	if s.controlLine && (compactionControlLine(payload) || scannerLine ||
		(gjson.ValidBytes(payload) && bytes.HasPrefix(bytes.TrimSpace(payload), []byte("{")))) {
		s.controlLine = false
	}
	// Match the HTTP validator's recognized-unit boundary rule, but retain
	// original chunks separately. Raw LF/CRLF fragments need no synthesis.
	if len(s.pending) > 0 && len(payload) > 0 &&
		!bytes.HasSuffix(s.pending, []byte("\n")) && !bytes.HasPrefix(payload, []byte("\n")) &&
		(scannerLine || bytes.HasPrefix(payload, []byte("event:"))) {
		if s.parsed == nil {
			s.parsed = bytes.Clone(s.pending)
			s.units = [][]byte{bytes.Clone(s.pending)}
		}
		s.parsed = append(s.parsed, '\n')
	}
	if s.parsed != nil {
		s.parsed = append(s.parsed, payload...)
		s.pending = append(s.pending, payload...)
		if len(payload) > 0 {
			s.units = append(s.units, bytes.Clone(payload))
		}
		data := compactionSSEData(s.parsed)
		if !gjson.ValidBytes(data) && !bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			if compactionSSEFrameEnd(s.parsed) != 0 || len(s.pending) > maxCompactionJSONBytes {
				s.pending, s.parsed, s.units = nil, nil, nil
				return nil, affinityStateError()
			}
			return nil, nil
		}
		if errSave := s.recordEvent(data); errSave != nil {
			s.pending, s.parsed, s.units = nil, nil, nil
			return nil, errSave
		}
		ready := s.pending
		s.released = s.units
		s.pending, s.parsed, s.units = nil, nil, nil
		return ready, nil
	}
	s.pending = append(s.pending, payload...)
	var ready []byte
	for len(s.pending) > 0 {
		// Control lines contain no signed data. Release even bare Scanner
		// comments/event:/id:/retry: units promptly, without adding delimiters.
		if s.controlLine || compactionControlLine(s.pending) {
			end := len(s.pending)
			s.controlLine = true
			if newline := bytes.IndexByte(s.pending, '\n'); newline >= 0 {
				end = newline + 1
				s.controlLine = false
			}
			ready = append(ready, s.pending[:end]...)
			s.pending = s.pending[end:]
			continue
		}
		if len(bytes.TrimSpace(s.pending)) == 0 {
			ready = append(ready, s.pending...)
			s.pending = nil
			break
		}
		end := compactionSSEFrameEnd(s.pending)
		if end == 0 {
			// Most executors emit a complete JSON event per chunk without SSE
			// separators; waiting for a separator would deadlock their consumers.
			data := compactionSSEData(s.pending)
			if !gjson.ValidBytes(data) && !bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
				break
			}
			end = len(s.pending)
		}
		frame := s.pending[:end]
		data := compactionSSEData(frame)
		if !gjson.ValidBytes(data) && !bytes.Equal(bytes.TrimSpace(data), []byte("[DONE]")) {
			s.pending = nil
			return nil, affinityStateError()
		}
		if errSave := s.recordEvent(data); errSave != nil {
			s.pending = nil
			return nil, errSave
		}
		ready = append(ready, frame...)
		s.pending = s.pending[end:]
	}
	if len(s.pending) == 0 {
		s.pending = nil
	}
	// Do not buffer an unbounded malformed event or emit an unregistered block.
	if len(s.pending) > maxCompactionJSONBytes {
		s.pending = nil
		return nil, affinityStateError()
	}
	return ready, nil
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
