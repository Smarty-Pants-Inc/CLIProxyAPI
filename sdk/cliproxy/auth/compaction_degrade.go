package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"unsafe"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// Degrade instead of refuse (smarty-dev#8742). A signed compaction block whose
// signer this gateway does not know (state lost, moved, or never recorded), a
// block from a different account than the one the request is pinned to, and
// compaction input over the parsing caps used to end the request with a hard
// 409/400; with X-Should-Retry false that killed long-running sessions. Such
// blocks are now removed before signer preparation: a block that carries a
// plain summary ("content" string) is replaced by that summary as text, an
// encrypted-only block is dropped, and the request is served on the selected
// account. The selector's own refusals stay as the inner check, so a signed
// block is still never sent to an account that did not sign it.

const compactionOmittedText = "[earlier conversation context was compacted and is unavailable on this account]"

var compactionOmittedBlock = func() string {
	text, _ := json.Marshal(compactionOmittedText)
	return `{"type":"text","text":` + string(text) + `}`
}()

// MaxCompactionInputBytes is the documented maximum request (or websocket
// frame) size for compaction handling: bodies above it are refused with 413
// before any JSON parse. Between 16 MiB and this bound, compaction blocks are
// dropped instead of refused (smarty-dev#8742 security r1).
const MaxCompactionInputBytes = 64 << 20

func compactionInputTooLargeError() error {
	return wrapRequestStopError(&Error{Code: "request_too_large", Message: "request body exceeds the 64 MiB input limit", HTTPStatus: http.StatusRequestEntityTooLarge})
}

// compactionResultTooLargeError: the request is still over the 16 MiB
// compaction JSON limit without its compaction blocks. It is refused with 413
// as soon as the streamed rewrite passes that size, so no buffer larger than
// the limit is ever built for it.
func compactionResultTooLargeError() error {
	return wrapRequestStopError(&Error{Code: "request_too_large", Message: "request exceeds 16 MiB without its compaction blocks", HTTPStatus: http.StatusRequestEntityTooLarge})
}

// reasonTooLarge marks a degrade that stopped at the output limit.
const reasonTooLarge = "too large without compaction blocks"

// PrepareCompactionPayload degrades req.Payload and opts.OriginalRequest, then
// runs PrepareCompactionRequest. Callers use it wherever they hold both.
func (m *Manager) PrepareCompactionPayload(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options, error) {
	if len(opts.OriginalRequest) > MaxCompactionInputBytes || len(req.Payload) > MaxCompactionInputBytes {
		return req, opts, compactionInputTooLargeError()
	}
	req, opts, err := m.degradeCompactionInput(ctx, req, opts)
	if err != nil {
		return req, opts, err
	}
	opts, err = m.PrepareCompactionRequest(req.Model, opts, ctx)
	return req, opts, err
}

func (m *Manager) degradeCompactionInput(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options, error) {
	if m == nil || len(opts.OriginalRequest) == 0 {
		return req, opts, nil
	}
	// Pool membership and the original signer pin must both hold. Degrading
	// an unknown (including foreign-pool) signer would erase that pin before
	// PrepareCompactionRequest can enforce it. Legacy degradation stays intact.
	if KeyPolicyFromContext(ctx).IsPoolOperation() {
		return req, opts, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var origin *SessionAffinitySelector
	if raw, captured := opts.Metadata[compactionAffinityStoreMetadataKey]; captured {
		origin, _ = raw.(*SessionAffinitySelector)
	} else if !m.HomeEnabled() {
		origin, _ = m.Selector().(*SessionAffinitySelector)
	}
	degraded, dropped, reason, target := degradeCompactionPayload(ctx, origin, opts.OriginalRequest, "")
	if reason == reasonTooLarge {
		return req, opts, compactionResultTooLargeError()
	}
	if dropped == 0 {
		return req, opts, nil
	}
	if bytes.Equal(req.Payload, opts.OriginalRequest) {
		req.Payload = degraded
	} else if len(req.Payload) > 0 {
		// Same account rule for the executor's copy as for the checked original.
		var payloadReason string
		req.Payload, _, payloadReason, _ = degradeCompactionPayload(ctx, origin, req.Payload, target)
		if payloadReason == reasonTooLarge {
			return req, opts, compactionResultTooLargeError()
		}
	}
	opts.OriginalRequest = degraded
	session, _ := extractSessionIDs(opts.Headers, degraded, opts.Metadata)
	log.WithField("session", session).Warnf("compaction: removed %d compaction block(s) (%s); serving the request without them (smarty-dev#8742)", dropped, reason)
	return req, opts, nil
}

// degradeCompactionPayload returns payload without the compaction blocks it may
// not carry. authID "" (HTTP admission) keeps blocks of the newest known
// signer; a websocket passes its socket account, whose blocks alone stay.
// It never removes anything when affinity state is unusable or the JSON is
// ambiguous: those keep their existing fail-closed answers.
// The returned target is the account whose blocks were kept ("" if none).
func degradeCompactionPayload(ctx context.Context, origin *SessionAffinitySelector, payload []byte, authID string) ([]byte, int, string, string) {
	if origin == nil || origin.cache == nil || origin.cache.PersistenceError() != nil || len(payload) == 0 ||
		len(payload) > MaxCompactionInputBytes {
		// Above the hard bound nothing is parsed here; the caller refuses it.
		return payload, 0, "", authID
	}
	// ponytail: gjson.ParseBytes copies the whole body into a string; this
	// read-only view does not (payload is never written while root is used).
	root := gjson.Parse(unsafe.String(unsafe.SliceData(payload), len(payload)))
	if !root.IsObject() {
		return payload, 0, "", authID
	}
	items, over := compactionItems(root)
	if len(items) == 0 {
		return payload, 0, "", authID
	}
	if over || len(payload) > maxCompactionJSONBytes {
		dropped := 0
		out, ok := rewriteCompactionItems(payload, root, func(gjson.Result) bool { dropped++; return true })
		if !ok {
			return payload, 0, reasonTooLarge, authID
		}
		return out, dropped, "over the compaction limits", authID
	}
	if ValidateCompactionJSON(ctx, payload) != nil {
		return payload, 0, "", authID
	}
	keys := make([]string, len(items))
	for i, item := range items {
		collector := newCompactionKeyCollector(ctx)
		if collector.add(item) != nil {
			return payload, 0, "", authID
		}
		keys[i] = collector.lastKey
	}
	target := authID
	if target == "" {
		for i := len(keys) - 1; i >= 0; i-- {
			if signer, known := origin.cache.Get(keys[i]); known && signer != "" && origin.cache.IsProtected(keys[i]) {
				target = signer
				break
			}
		}
	}
	drop := make(map[string]bool)
	reason := "signer unknown"
	for _, key := range keys {
		signer, known := origin.cache.Get(key)
		switch {
		case !known || signer == "":
			drop[key] = true
		case !origin.cache.IsProtected(key):
			// Inconsistent state: keep the existing 503, never guess.
		case signer != target:
			drop[key] = true
			reason = "signed by another account"
		}
	}
	if len(drop) == 0 {
		return payload, 0, "", target
	}
	dropped := 0
	for _, key := range keys {
		if drop[key] {
			dropped++
		}
	}
	// Decide by each block's own byte offset in the payload, never by visit
	// order: compactionItems scans input[] before messages[], while the rewrite
	// writes spans in payload order, so with both fields present an order-based
	// decision could remove the wrong blocks (#135 Astra P2).
	dropAt := make(map[int]bool, len(items))
	for i, item := range items {
		if drop[keys[i]] {
			dropAt[item.Index] = true
		}
	}
	out, ok := rewriteCompactionItems(payload, root, func(item gjson.Result) bool {
		return dropAt[item.Index]
	})
	if !ok {
		return payload, 0, reasonTooLarge, authID
	}
	return out, dropped, reason, target
}

// rawStringMember returns the raw JSON string literal (quotes included) of
// object member KEY, or "" when it is absent or not a string. It only scans:
// it never unescapes or copies, so a large or escape-heavy value costs no
// allocation. Malformed input gives "".
func rawStringMember(object, key string) string {
	i := skipJSONSpace(object, 0)
	if i >= len(object) || object[i] != '{' {
		return ""
	}
	i++
	for {
		i = skipJSONSpace(object, i)
		if i >= len(object) || object[i] != '"' {
			return ""
		}
		nameEnd := skipJSONString(object, i)
		if nameEnd < 0 {
			return ""
		}
		name := object[i:nameEnd]
		i = skipJSONSpace(object, nameEnd)
		if i >= len(object) || object[i] != ':' {
			return ""
		}
		start := skipJSONSpace(object, i+1)
		end := skipJSONValue(object, start)
		if end < 0 {
			return ""
		}
		if name == `"`+key+`"` {
			if object[start] == '"' {
				return object[start:end]
			}
			return ""
		}
		i = skipJSONSpace(object, end)
		if i >= len(object) || object[i] != ',' {
			return ""
		}
		i++
	}
}

func skipJSONSpace(s string, i int) int {
	for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	return i
}

// skipJSONString returns the index just past the string starting at s[i] ('"'), or -1.
func skipJSONString(s string, i int) int {
	for i++; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}

// skipJSONValue returns the index just past the value starting at s[i], or -1.
func skipJSONValue(s string, i int) int {
	if i >= len(s) {
		return -1
	}
	switch s[i] {
	case '"':
		return skipJSONString(s, i)
	case '{', '[':
		depth := 0
		for ; i < len(s); i++ {
			switch s[i] {
			case '"':
				if i = skipJSONString(s, i); i < 0 {
					return -1
				}
				i--
			case '{', '[':
				depth++
			case '}', ']':
				if depth--; depth == 0 {
					return i + 1
				}
			}
		}
		return -1
	default:
		for ; i < len(s); i++ {
			switch s[i] {
			case ',', '}', ']', ' ', '\t', '\n', '\r':
				return i
			}
		}
		return i
	}
}

// compactionItems lists the compaction items in input[], then in
// messages[].content[]; each Result carries its byte offset (Index) in the
// payload, which is how rewrite decisions are matched to blocks. The
// scan stops as soon as the block or byte limit is passed (over = true): it
// never holds more than maxCompactionBlocks+1 entries, whatever the input.
func compactionItems(root gjson.Result) (items []gjson.Result, over bool) {
	size := 0
	collect := func(list gjson.Result) bool {
		list.ForEach(func(_, item gjson.Result) bool {
			if item.Get("type").String() != "compaction" {
				return true
			}
			items = append(items, item)
			size += len(item.Raw)
			over = len(items) > maxCompactionBlocks || size > maxCompactionJSONBytes
			return !over
		})
		return !over
	}
	if collect(root.Get("input")) {
		root.Get("messages").ForEach(func(_, message gjson.Result) bool {
			return collect(message.Get("content"))
		})
	}
	return items, over
}

// rewriteCompactionItems removes each compaction item for which drop returns
// true. In messages[].content[] a block with a plain "content" summary becomes
// a text block; a message left empty gets a short placeholder text.
// It writes the result in one pass into one buffer pre-sized to the payload:
// unchanged bytes are copied by range, kept items by their raw span, and no
// per-entry slice or per-list copy of the payload is ever built, so its
// allocation is bounded by the output limit, whatever the entry count or body
// size (smarty-dev#8742 security r2). It stops as soon as the output would
// pass maxCompactionJSONBytes and returns ok == false: such a request is still
// too large without its compaction blocks.
func rewriteCompactionItems(payload []byte, root gjson.Result, drop func(gjson.Result) bool) ([]byte, bool) {
	limit := maxCompactionJSONBytes
	var out bytes.Buffer
	out.Grow(min(len(payload), limit) + len(compactionOmittedText) + 64)
	cursor, full := 0, false
	put := func(chunk string) {
		if full || out.Len()+len(chunk) > limit {
			full = true
			return
		}
		out.WriteString(chunk)
	}
	emit := func(list gjson.Result, summaries bool) {
		start, end := list.Index, list.Index+len(list.Raw)
		if !list.IsArray() || start < cursor || end > len(payload) || payload[start] != '[' {
			return // span unknown: leave this list as it is
		}
		put(root.Raw[cursor:start])
		put("[")
		kept, changed := 0, false
		write := func(raws ...string) {
			if kept > 0 {
				put(",")
			}
			for _, raw := range raws {
				put(raw)
			}
			kept++
		}
		list.ForEach(func(_, item gjson.Result) bool {
			if full {
				return false
			}
			if item.Get("type").String() != "compaction" || !drop(item) {
				write(item.Raw)
				return true
			}
			changed = true
			// Only the summary that is actually emitted is budgeted (#135 r5): its
			// raw JSON string literal is located without unescaping and copied
			// as-is through the capped writer, so a large encrypted block with a
			// small or absent summary still degrades. A summary that does not fit
			// the remaining budget ends the rewrite (413) inside put(); no
			// marshal, unescape or concatenation happens for it (security r3).
			if summary := rawStringMember(item.Raw, "content"); summaries && len(summary) > len(`""`) {
				write(`{"type":"text","text":`, summary, `}`)
			}
			return true
		})
		if summaries && changed && kept == 0 {
			write(compactionOmittedBlock)
		}
		put("]")
		cursor = end
	}
	input, messages := root.Get("input"), root.Get("messages")
	contents := func() {
		messages.ForEach(func(_, message gjson.Result) bool {
			emit(message.Get("content"), true)
			return true
		})
	}
	// Spans must be written in payload order.
	if messages.Exists() && input.Exists() && messages.Index < input.Index {
		contents()
		emit(input, false)
	} else {
		emit(input, false)
		contents()
	}
	put(root.Raw[cursor:])
	if full {
		return nil, false
	}
	return out.Bytes(), true
}
