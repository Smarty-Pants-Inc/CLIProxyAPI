package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
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

// MaxCompactionInputBytes is the documented maximum request (or websocket
// frame) size for compaction handling: bodies above it are refused with 413
// before any JSON parse. Between 16 MiB and this bound, compaction blocks are
// dropped instead of refused (smarty-dev#8742 security r1).
const MaxCompactionInputBytes = 64 << 20

func compactionInputTooLargeError() error {
	return wrapRequestStopError(&Error{Code: "request_too_large", Message: "request body exceeds the 64 MiB input limit", HTTPStatus: http.StatusRequestEntityTooLarge})
}

// PrepareCompactionPayload degrades req.Payload and opts.OriginalRequest, then
// runs PrepareCompactionRequest. Callers use it wherever they hold both.
func (m *Manager) PrepareCompactionPayload(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options, error) {
	if len(opts.OriginalRequest) > MaxCompactionInputBytes || len(req.Payload) > MaxCompactionInputBytes {
		return req, opts, compactionInputTooLargeError()
	}
	req, opts = m.degradeCompactionInput(ctx, req, opts)
	opts, err := m.PrepareCompactionRequest(req.Model, opts, ctx)
	return req, opts, err
}

func (m *Manager) degradeCompactionInput(ctx context.Context, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options) {
	if m == nil || len(opts.OriginalRequest) == 0 {
		return req, opts
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
	if dropped == 0 {
		return req, opts
	}
	if bytes.Equal(req.Payload, opts.OriginalRequest) {
		req.Payload = degraded
	} else if len(req.Payload) > 0 {
		// Same account rule for the executor's copy as for the checked original.
		req.Payload, _, _, _ = degradeCompactionPayload(ctx, origin, req.Payload, target)
	}
	opts.OriginalRequest = degraded
	session, _ := extractSessionIDs(opts.Headers, degraded, opts.Metadata)
	log.WithField("session", session).Warnf("compaction: removed %d compaction block(s) (%s); serving the request without them (smarty-dev#8742)", dropped, reason)
	return req, opts
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
	root := gjson.ParseBytes(payload)
	if !root.IsObject() {
		return payload, 0, "", authID
	}
	items, over := compactionItems(root)
	if len(items) == 0 {
		return payload, 0, "", authID
	}
	if over || len(payload) > maxCompactionJSONBytes {
		dropped := 0
		out := rewriteCompactionItems(payload, root, func(gjson.Result) bool { dropped++; return true })
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
	index := 0
	out := rewriteCompactionItems(payload, root, func(gjson.Result) bool {
		removed := drop[keys[index]]
		index++
		return removed
	})
	return out, dropped, reason, target
}

// compactionItems lists the compaction items in input[] and
// messages[].content[], in the order rewriteCompactionItems visits them. The
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
func rewriteCompactionItems(payload []byte, root gjson.Result, drop func(gjson.Result) bool) []byte {
	filter := func(list gjson.Result, summaries bool) (string, bool) {
		var parts []string
		changed := false
		list.ForEach(func(_, item gjson.Result) bool {
			if item.Get("type").String() != "compaction" || !drop(item) {
				parts = append(parts, item.Raw)
				return true
			}
			changed = true
			if content := item.Get("content"); summaries && content.Type == gjson.String && content.String() != "" {
				text, _ := json.Marshal(content.String())
				parts = append(parts, `{"type":"text","text":`+string(text)+`}`)
			}
			return true
		})
		if summaries && changed && len(parts) == 0 {
			text, _ := json.Marshal(compactionOmittedText)
			parts = append(parts, `{"type":"text","text":`+string(text)+`}`)
		}
		return "[" + strings.Join(parts, ",") + "]", changed
	}
	out := payload
	if input := root.Get("input"); input.IsArray() {
		if raw, changed := filter(input, false); changed {
			out, _ = sjson.SetRawBytes(out, "input", []byte(raw))
		}
	}
	i := 0
	root.Get("messages").ForEach(func(_, message gjson.Result) bool {
		if content := message.Get("content"); content.IsArray() {
			if raw, changed := filter(content, true); changed {
				out, _ = sjson.SetRawBytes(out, "messages."+strconv.Itoa(i)+".content", []byte(raw))
			}
		}
		i++
		return true
	})
	return out
}
