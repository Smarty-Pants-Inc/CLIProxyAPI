package auth

import (
	"context"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

// newCompactionOutputRecorder captures signer authority once for this stream.
// The caller supplies decoded complete events and saves before releasing bytes.
// Ordinary streams retain one bound; duplex streams may carry many responses.
func (m *Manager) newCompactionOutputRecorder(ctx context.Context, authID string, opts cliproxyexecutor.Options) func([]byte) error {
	store := m.compactionOutputStore(opts)
	if store == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	format := cliproxyexecutor.ResponseFormatOrSource(opts)
	duplex := cliproxyexecutor.WebsocketInputFromContext(ctx) != nil &&
		(format == translator.FormatCodex || format == translator.FormatOpenAIResponse)
	collector := newCompactionKeyCollector(ctx)
	responseID := ""
	ended := false
	return func(payload []byte) error {
		root := gjson.ParseBytes(payload)
		event := root.Get("type").String()
		id := root.Get("response.id").String()
		if id == "" {
			id = root.Get("response_id").String()
		}
		if duplex && event == "response.created" {
			// Validate before a boundary can mutate the budget. In particular,
			// duplicate/escaped IDs must not reset an already consumed bound.
			if err := ValidateCompactionJSON(ctx, payload); err != nil {
				return err
			}
			if id != "" && id != responseID {
				if responseID != "" && !ended {
					return compactionJSONError("compaction response changed before its terminal boundary", nil)
				}
				if responseID != "" {
					collector = newCompactionKeyCollector(ctx)
				}
				responseID = id
			}
			// Same-ID created events never replenish a budget, even after a
			// terminal acknowledgement. They still need a new terminal boundary.
			ended = false
		}
		var current []string
		if err := collectCompactionOutput(ctx, payload, collector, &current); err != nil {
			return err
		}
		if duplex && len(current) > 0 && responseID != "" && id != "" && id != responseID {
			return compactionJSONError("compaction output does not match the active response", nil)
		}
		// Use current, not the deduplicated collector.keys: every repeated
		// acknowledgement must refresh and recheck evidence before delivery.
		if err := store.recordCompactionOutputKeys(authID, opts, current, ctx); err != nil {
			return err
		}
		if duplex && responseID != "" && id == responseID {
			switch event {
			case "response.completed", "response.failed", "response.cancelled", "response.incomplete":
				// Count and persist the terminal frame before granting a reset to
				// a later, distinct response.created. Repeated terminals still count.
				ended = true
			}
		}
		return nil
	}
}
