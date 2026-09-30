package auth

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const compactionRequestContextMetadataKey = "compaction_request_context"

// Generous conversation limits, not cache capacity: reject the whole request
// before signer lookups or writes. 256 capsules / 16 MiB allow large legitimate
// histories while bounding untrusted parsing, hashing and allocation. Depth 128
// leaves room for tool schemas without allowing adversarial recursive nesting.
const (
	maxCompactionBlocks    = 256
	maxCompactionJSONBytes = 16 << 20
	maxCompactionJSONDepth = 128
)

func compactionContext(opts cliproxyexecutor.Options) context.Context {
	if ctx, ok := opts.Metadata[compactionRequestContextMetadataKey].(context.Context); ok && ctx != nil {
		return ctx
	}
	return context.Background()
}

func compactionJSONError(message string, cause error) error {
	err := &Error{Code: "compaction_json_rejected", Message: message, HTTPStatus: http.StatusBadRequest}
	if cause != nil {
		return WithCause(err, cause)
	}
	return err
}

func compactionCheckContext(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return compactionJSONError("compaction JSON inspection canceled", err)
	}
	return nil
}

// Reads are deliberately small: Decoder.Token can otherwise scan one enormous
// string without returning control to the token-level cancellation checks.
type compactionJSONReader struct {
	ctx    context.Context
	text   string
	offset int
}

func (r *compactionJSONReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if r.offset == len(r.text) {
		return 0, io.EOF
	}
	if len(p) > 4096 {
		p = p[:4096]
	}
	n := copy(p, r.text[r.offset:])
	r.offset += n
	return n, nil
}

// ValidateCompactionJSON rejects parser ambiguity at every object level, before
// GJSON inspection or upstream writes. It never normalizes valid raw wire bytes.
func ValidateCompactionJSON(ctx context.Context, payload []byte) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := compactionCheckContext(ctx); err != nil {
		return err
	}
	if len(payload) > maxCompactionJSONBytes {
		return compactionJSONError("compaction JSON exceeds 16 MiB limit", nil)
	}
	decoder := json.NewDecoder(&compactionJSONReader{ctx: ctx, text: string(payload)})
	decoder.UseNumber()
	blocks := 0
	var consume func(int, json.Token) error
	consume = func(depth int, token json.Token) error {
		if err := compactionCheckContext(ctx); err != nil {
			return err
		}
		delim, container := token.(json.Delim)
		if !container {
			return nil
		}
		if depth >= maxCompactionJSONDepth {
			return compactionJSONError("compaction JSON exceeds depth 128 limit", nil)
		}
		switch delim {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				if err := compactionCheckContext(ctx); err != nil {
					return err
				}
				nameToken, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := nameToken.(string)
				if !ok {
					return compactionJSONError("invalid compaction JSON member", nil)
				}
				if _, duplicate := seen[name]; duplicate {
					return compactionJSONError("duplicate compaction JSON member", nil)
				}
				seen[name] = struct{}{}
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				// Count capsules before a large GJSON collection can run.
				// Repeated identical blocks still consume the budget.
				if name == "type" && value == "compaction" {
					blocks++
					if blocks > maxCompactionBlocks {
						return compactionJSONError("compaction JSON exceeds 256 block limit", nil)
					}
				}
				if err := consume(depth+1, value); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				value, err := decoder.Token()
				if err != nil {
					return err
				}
				if err := consume(depth+1, value); err != nil {
					return err
				}
			}
		default:
			return compactionJSONError("invalid compaction JSON delimiter", nil)
		}
		_, err := decoder.Token()
		return err
	}
	token, err := decoder.Token()
	if err == nil {
		err = consume(0, token)
	}
	if err != nil {
		if canceled := compactionCheckContext(ctx); canceled != nil {
			return canceled
		}
		if local, ok := err.(*Error); ok {
			return local
		}
		return compactionJSONError("invalid compaction JSON", nil)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if canceled := compactionCheckContext(ctx); canceled != nil {
			return canceled
		}
		return compactionJSONError("invalid trailing compaction JSON", nil)
	}
	return compactionCheckContext(ctx)
}

// One collector is shared across every input/output location in a payload.
// Never use mergeSessionAliases per block: that rescans all preceding keys.
type compactionKeyCollector struct {
	ctx     context.Context
	seen    map[string]struct{}
	keys    []string
	lastKey string
	blocks  int
	bytes   int
}

func newCompactionKeyCollector(ctx context.Context) *compactionKeyCollector {
	if ctx == nil {
		ctx = context.Background()
	}
	return &compactionKeyCollector{ctx: ctx, seen: make(map[string]struct{})}
}

// add accepts one block, not a list. Validation of the complete original JSON
// must precede all calls, and callers must propagate errors before cache writes.
func (c *compactionKeyCollector) add(item gjson.Result) error {
	if err := compactionCheckContext(c.ctx); err != nil {
		return err
	}
	if item.Get("type").String() != "compaction" {
		return nil
	}
	c.blocks++
	c.bytes += len(item.Raw)
	if c.blocks > maxCompactionBlocks || c.bytes > maxCompactionJSONBytes {
		return compactionJSONError("compaction collection exceeds block or byte limit", nil)
	}
	block := item.Get("encrypted_content").String()
	if block == "" {
		if content := item.Get("content"); content.Type == gjson.String {
			block = content.String()
		} else {
			// json.Marshal sorts map keys; replay survives whitespace and
			// member-order changes without storing raw native capsule text.
			var value any
			decoder := json.NewDecoder(&compactionJSONReader{ctx: c.ctx, text: item.Raw})
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				if canceled := compactionCheckContext(c.ctx); canceled != nil {
					return canceled
				}
				return compactionJSONError("invalid compaction block", nil)
			}
			canonical, err := json.Marshal(value)
			if err != nil {
				return compactionJSONError("invalid compaction block", nil)
			}
			block = string(canonical)
		}
	}
	digest := sha256.New()
	for len(block) > 0 {
		if err := compactionCheckContext(c.ctx); err != nil {
			return err
		}
		n := len(block)
		if n > 4096 {
			n = 4096
		}
		_, _ = io.WriteString(digest, block[:n])
		block = block[n:]
	}
	key := fmt.Sprintf("compaction::%x", digest.Sum(nil))
	if err := compactionCheckContext(c.ctx); err != nil {
		return err
	}
	// The stream owner needs every current frame's key, even when it is
	// already in the request-wide seen-set and may need evidence refreshed.
	c.lastKey = key
	if _, duplicate := c.seen[key]; !duplicate {
		c.seen[key] = struct{}{}
		c.keys = append(c.keys, key)
	}
	return compactionCheckContext(c.ctx)
}

func (c *compactionKeyCollector) addItems(items gjson.Result) error {
	var err error
	items.ForEach(func(_, item gjson.Result) bool {
		err = c.add(item)
		return err == nil
	})
	if err != nil {
		return err
	}
	return compactionCheckContext(c.ctx)
}

func compactionAffinityKeysChecked(ctx context.Context, opts cliproxyexecutor.Options) ([]string, error) {
	if err := compactionCheckContext(ctx); err != nil {
		return nil, err
	}
	if len(opts.OriginalRequest) == 0 {
		return nil, nil
	}
	if err := ValidateCompactionJSON(ctx, opts.OriginalRequest); err != nil {
		return nil, err
	}
	root := gjson.ParseBytes(opts.OriginalRequest)
	collector := newCompactionKeyCollector(ctx)
	if err := collector.addItems(root.Get("input")); err != nil {
		return nil, err
	}
	var err error
	root.Get("messages").ForEach(func(_, message gjson.Result) bool {
		if err = compactionCheckContext(ctx); err != nil {
			return false
		}
		err = collector.addItems(message.Get("content"))
		return err == nil
	})
	if err != nil {
		return nil, err
	}
	return collector.keys, compactionCheckContext(ctx)
}

// Compatibility helpers for existing fixtures only. Production uses the
// error-aware collector and must not confuse a rejected request with no blocks.
func compactionAffinityKeys(opts cliproxyexecutor.Options) []string {
	keys, _ := compactionAffinityKeysChecked(compactionContext(opts), opts)
	return keys
}

func compactionBlockKeys(items gjson.Result) []string {
	collector := newCompactionKeyCollector(context.Background())
	if raw := strings.TrimSpace(items.Raw); raw != "" {
		if ValidateCompactionJSON(collector.ctx, []byte(raw)) != nil {
			return nil
		}
	}
	if collector.addItems(items) != nil {
		return nil
	}
	return collector.keys
}
