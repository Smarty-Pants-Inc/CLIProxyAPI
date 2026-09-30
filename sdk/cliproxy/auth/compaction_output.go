package auth

import (
	"bytes"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	cliproxysession "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/session"
	"github.com/tidwall/gjson"
)

// RecordCompactionOutput records signer evidence, not a guess from input affinity.
// Each block has its own protected group, independent of mutable session aliases.
// The caller must pass the auth that actually executed the producing request.
func (s *SessionAffinitySelector) RecordCompactionOutput(authID string, opts cliproxyexecutor.Options, payload []byte) error {
	keys := compactionOutputKeys(payload)
	if len(keys) == 0 {
		return nil
	}
	if s == nil || s.cache == nil || strings.TrimSpace(authID) == "" {
		return affinityStateError()
	}
	for _, key := range keys {
		if errSave := s.cache.SetProtectedAliases(authID, key); errSave != nil {
			return affinityStateError()
		}
	}
	// Protect the explicit primary independently. Production on this account is
	// authoritative even when a handled scheduler bypassed selector.Pick.
	primaryID, _ := extractExplicitSessionIDs(opts.Headers, opts.OriginalRequest, opts.Metadata)
	namespace, _ := opts.Metadata[cliproxyexecutor.SessionAffinityProviderMetadataKey].(string)
	model, _ := opts.Metadata[cliproxyexecutor.SessionAffinityModelMetadataKey].(string)
	primaryKey := ""
	if primaryID != "" && namespace != "" {
		primaryKey = namespace + "::" + cliproxysession.BoundSessionIdentity(primaryID) + "::" + canonicalModelKey(model)
		if errSave := s.cache.SetProtectedAliases(authID, primaryKey); errSave != nil {
			return affinityStateError()
		}
	}
	// Capacity eviction must not allow acknowledged evidence to disappear during
	// this registration, including when a response contains multiple blocks.
	for _, key := range keys {
		if retainedID, ok := s.cache.Get(key); !ok || retainedID != authID || !s.cache.IsProtected(key) {
			return affinityStateError()
		}
	}
	if primaryKey != "" {
		if retainedID, ok := s.cache.Get(primaryKey); !ok || retainedID != authID || !s.cache.IsProtected(primaryKey) {
			return affinityStateError()
		}
	}
	if s.cache.PersistenceError() != nil {
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

func compactionOutputKeys(payload []byte) []string {
	if !gjson.ValidBytes(payload) {
		return nil
	}
	root := gjson.ParseBytes(payload)
	var keys []string
	collect := func(items gjson.Result) {
		// An added item may be only a skeleton. Do not attribute it until the
		// complete encrypted value is present in a complete JSON event.
		items.ForEach(func(_, item gjson.Result) bool {
			if item.Get("type").String() == "compaction" && item.Get("encrypted_content").String() != "" {
				keys = mergeSessionAliases(keys, compactionBlockKeys(gjson.Parse("["+item.Raw+"]"))...)
			}
			return true
		})
	}
	collect(root.Get("output"))
	collect(root.Get("response.output"))
	switch root.Get("type").String() {
	case "response.output_item.added", "response.output_item.done":
		item := root.Get("item")
		if item.Exists() {
			collect(gjson.Parse("[" + item.Raw + "]"))
		}
	}
	return keys
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
}

func (s *compactionOutputStream) push(payload []byte) ([]byte, error) {
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
			if compactionSSEFrameEnd(s.parsed) != 0 || len(s.pending) > 32<<20 {
				s.pending, s.parsed, s.units = nil, nil, nil
				return nil, affinityStateError()
			}
			return nil, nil
		}
		if errSave := s.record(data); errSave != nil {
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
		if errSave := s.record(data); errSave != nil {
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
	if len(s.pending) > 32<<20 {
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
	if len(s.pending) != 0 {
		s.pending = nil
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
