package helps

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ClaudeCompactionBeta enables Anthropic on-demand compaction. Requests that ask
// for a summary and requests that carry the returned block both need it.
const ClaudeCompactionBeta = "compact-2026-09-04"

// claudeCompactionCapsulePrefix marks a Responses compaction item whose
// encrypted_content carries an Anthropic compaction block verbatim.
const claudeCompactionCapsulePrefix = "cpa-claude-compact-v1:"

// RecognizedClaudeCompactionCapsule identifies native signed blocks before
// upstream's foreign-capsule filtering. Decoding still validates the block.
func RecognizedClaudeCompactionCapsule(encrypted string) bool {
	return strings.HasPrefix(encrypted, claudeCompactionCapsulePrefix)
}

// ClaudeResponsesCompaction records Responses compaction items removed before
// Responses-to-Claude translation, which has no mapping for them.
type ClaudeResponsesCompaction struct {
	// Trigger is set when the request ends in compaction_trigger (Codex remote
	// compaction v2). The Claude request then asks for a summary only.
	Trigger bool
	// Block is the exact Anthropic compaction block from an earlier summary.
	Block []byte
}

// PrepareClaudeResponsesCompaction removes compaction_trigger and CPA Claude
// compaction items from a Responses payload. Other compaction items (for example
// OpenAI ciphertext from an earlier GPT turn) are left for existing handling.
func PrepareClaudeResponsesCompaction(payload []byte) ([]byte, ClaudeResponsesCompaction, error) {
	var state ClaudeResponsesCompaction
	input := gjson.GetBytes(payload, "input")
	if !input.IsArray() {
		return payload, state, nil
	}
	kept := make([]string, 0, len(input.Array()))
	changed := false
	for _, item := range input.Array() {
		switch item.Get("type").String() {
		case "compaction_trigger":
			state.Trigger = true
			changed = true
			continue
		case "compaction":
			encrypted := item.Get("encrypted_content").String()
			if strings.HasPrefix(encrypted, claudeCompactionCapsulePrefix) {
				if state.Block != nil {
					return nil, state, fmt.Errorf("request carries more than one Claude compaction item")
				}
				block, errDecode := decodeClaudeCompactionCapsule(encrypted)
				if errDecode != nil {
					return nil, state, errDecode
				}
				state.Block = block
				changed = true
				continue
			}
		}
		kept = append(kept, item.Raw)
	}
	if !changed {
		return payload, state, nil
	}
	out, errSet := sjson.SetRawBytes(payload, "input", []byte("["+strings.Join(kept, ",")+"]"))
	if errSet != nil {
		return nil, state, fmt.Errorf("rewrite compaction input: %w", errSet)
	}
	return out, state, nil
}

// ApplyClaudeResponsesCompaction applies prepared compaction state to the
// translated Claude body. The block goes first, as Anthropic requires; a
// trigger requests an on-demand summary and removes fields the API rejects on
// that call. Threshold auto-compaction is never enabled.
func ApplyClaudeResponsesCompaction(body []byte, state ClaudeResponsesCompaction) ([]byte, error) {
	out := body
	if state.Block != nil {
		message := []byte(`{"role":"assistant","content":[]}`)
		message, _ = sjson.SetRawBytes(message, "content.-1", state.Block)
		messages := []string{string(message)}
		for _, existing := range gjson.GetBytes(out, "messages").Array() {
			messages = append(messages, existing.Raw)
		}
		var errSet error
		out, errSet = sjson.SetRawBytes(out, "messages", []byte("["+strings.Join(messages, ",")+"]"))
		if errSet != nil {
			return nil, fmt.Errorf("insert compaction block: %w", errSet)
		}
	}
	if state.Trigger {
		out, _ = sjson.SetRawBytes(out, "compaction", []byte(`{"type":"summarize"}`))
		for _, path := range []string{"context_management", "stop_sequences", "output_config.format"} {
			out, _ = sjson.DeleteBytes(out, path)
		}
		switch gjson.GetBytes(out, "tool_choice.type").String() {
		case "any", "tool":
			out, _ = sjson.DeleteBytes(out, "tool_choice")
		}
	}
	return out, nil
}

// ClaudeBodyUsesCompaction reports whether a Claude body requests a summary or
// carries a compaction block.
func ClaudeBodyUsesCompaction(body []byte) bool {
	if gjson.GetBytes(body, "compaction").Exists() {
		return true
	}
	for _, message := range gjson.GetBytes(body, "messages").Array() {
		for _, block := range message.Get("content").Array() {
			if block.Get("type").String() == "compaction" {
				return true
			}
		}
	}
	return false
}

// ClaudeCompactionResult is the verified outcome of an on-demand summary.
type ClaudeCompactionResult struct {
	Capsule             string
	InputTokens         int64 // Responses input includes cache creation and read.
	OutputTokens        int64
	CachedTokens        int64
	CacheCreationTokens int64
}

// UsageDetail publishes iteration usage in the canonical Anthropic accounting
// representation; ordinary message_delta usage is zero on summary-only turns.
func (result ClaudeCompactionResult) UsageDetail() usage.Detail {
	payload := []byte(`{"usage":{}}`)
	payload, _ = sjson.SetBytes(payload, "usage.input_tokens", result.InputTokens-result.CachedTokens-result.CacheCreationTokens)
	payload, _ = sjson.SetBytes(payload, "usage.output_tokens", result.OutputTokens)
	payload, _ = sjson.SetBytes(payload, "usage.cache_read_input_tokens", result.CachedTokens)
	payload, _ = sjson.SetBytes(payload, "usage.cache_creation_input_tokens", result.CacheCreationTokens)
	return ParseClaudeUsage(payload)
}

// ParseClaudeCompactionStream extracts exactly one compaction block from an
// upstream Claude SSE response. Any other outcome is an error, so the client
// never receives zero or several compaction items.
func ParseClaudeCompactionStream(data []byte) (ClaudeCompactionResult, error) {
	var result ClaudeCompactionResult
	var block []byte
	blocks := 0
	stopReason := ""
	completed := false
	usagePayload := []byte(`{}`)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 52_428_800)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if !gjson.ValidBytes(payload) {
			return result, claudeCompactionError("claude compaction returned malformed stream data")
		}
		event := gjson.ParseBytes(payload)
		switch event.Get("type").String() {
		case "error":
			return result, claudeCompactionError("claude compaction returned an upstream error event")
		case "message_start":
			if initialUsage := event.Get("message.usage"); initialUsage.IsObject() {
				usagePayload = []byte(initialUsage.Raw)
			}
		case "content_block_start":
			if event.Get("content_block.type").String() == "compaction" {
				blocks++
				block = []byte(event.Get("content_block").Raw)
			}
		case "message_delta":
			stopReason = event.Get("delta.stop_reason").String()
			event.Get("usage").ForEach(func(key, value gjson.Result) bool {
				usagePayload, _ = sjson.SetRawBytes(usagePayload, key.String(), []byte(value.Raw))
				return true
			})
		case "message_stop":
			completed = true
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return result, errScan
	}
	if blocks != 1 || stopReason != "compaction" || !completed {
		return result, claudeCompactionError("claude compaction did not complete with exactly one compaction block")
	}
	if !gjson.GetBytes(block, "content").Exists() || gjson.GetBytes(block, "content").Type == gjson.Null {
		return result, claudeCompactionError("claude compaction returned no summary")
	}
	result.InputTokens, result.OutputTokens, result.CachedTokens, result.CacheCreationTokens = claudeCompactionUsage(gjson.ParseBytes(usagePayload))
	result.Capsule = claudeCompactionCapsulePrefix + base64.RawURLEncoding.EncodeToString(block)
	return result, nil
}

// claudeCompactionUsage sums the billed iterations; top-level usage is zero on
// a summary-only response.
func claudeCompactionUsage(usageNode gjson.Result) (input, output, cached, cacheCreation int64) {
	add := func(node gjson.Result) {
		input += node.Get("input_tokens").Int()
		output += node.Get("output_tokens").Int()
		cached += node.Get("cache_read_input_tokens").Int()
		cacheCreation += node.Get("cache_creation_input_tokens").Int()
	}
	iterations := usageNode.Get("iterations")
	if iterations.IsArray() && len(iterations.Array()) > 0 {
		for _, iteration := range iterations.Array() {
			add(iteration)
		}
	} else {
		add(usageNode)
	}
	return input + cached + cacheCreation, output, cached, cacheCreation
}

func decodeClaudeCompactionCapsule(encrypted string) ([]byte, error) {
	block, errDecode := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(encrypted, claudeCompactionCapsulePrefix))
	if errDecode != nil || !gjson.ValidBytes(block) || gjson.GetBytes(block, "type").String() != "compaction" {
		return nil, fmt.Errorf("invalid Claude compaction item")
	}
	return block, nil
}

type claudeCompactionStatusError struct{ msg string }

func (e claudeCompactionStatusError) Error() string   { return e.msg }
func (e claudeCompactionStatusError) StatusCode() int { return http.StatusBadGateway }

// IsRequestScoped keeps a refused or empty summary from cooling the account or
// silently retrying the summary on another one.
func (claudeCompactionStatusError) IsRequestScoped() bool { return true }

func claudeCompactionError(msg string) error { return claudeCompactionStatusError{msg: msg} }

// BuildClaudeCompactionStreamChunks returns the Responses stream for one
// compaction item.
func BuildClaudeCompactionStreamChunks(modelName string, result ClaudeCompactionResult) [][]byte {
	total := result.InputTokens + result.OutputTokens
	chunks := buildResponsesCompactionStreamChunks("claude", modelName, result.Capsule, int(result.InputTokens), int(result.OutputTokens), int(total))
	for i, chunk := range chunks {
		idx := bytes.Index(chunk, []byte("data: "))
		if idx < 0 {
			continue
		}
		data := bytes.TrimSpace(chunk[idx+len("data: "):])
		path := "usage.input_tokens_details.cached_tokens"
		if gjson.GetBytes(data, "response").Exists() {
			path = "response." + path
		}
		if gjson.GetBytes(data, strings.TrimSuffix(path, ".input_tokens_details.cached_tokens")).Exists() {
			data, _ = sjson.SetBytes(data, path, result.CachedTokens)
			chunks[i] = append(append(bytes.Clone(chunk[:idx+len("data: ")]), data...), '\n', '\n')
		}
	}
	return chunks
}

// BuildClaudeCompactionResponse returns a non-stream Responses object with one
// compaction item.
func BuildClaudeCompactionResponse(modelName string, result ClaudeCompactionResult) []byte {
	now := time.Now()
	item := []byte(`{"type":"compaction","status":"completed"}`)
	item, _ = sjson.SetBytes(item, "id", fmt.Sprintf("cmp_claude_compact_%d", now.UnixNano()))
	item, _ = sjson.SetBytes(item, "encrypted_content", result.Capsule)
	usage := []byte(`{"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`)
	usage, _ = sjson.SetBytes(usage, "input_tokens_details.cached_tokens", result.CachedTokens)
	usage, _ = sjson.SetBytes(usage, "input_tokens", result.InputTokens)
	usage, _ = sjson.SetBytes(usage, "output_tokens", result.OutputTokens)
	usage, _ = sjson.SetBytes(usage, "total_tokens", result.InputTokens+result.OutputTokens)
	response := []byte(`{"object":"response","status":"completed","background":false,"error":null}`)
	response, _ = sjson.SetBytes(response, "id", fmt.Sprintf("resp_claude_compact_%d", now.UnixNano()))
	response, _ = sjson.SetBytes(response, "created_at", now.Unix())
	response, _ = sjson.SetBytes(response, "completed_at", now.Unix())
	response, _ = sjson.SetBytes(response, "model", modelName)
	response, _ = sjson.SetRawBytes(response, "output", []byte("["+string(item)+"]"))
	response, _ = sjson.SetRawBytes(response, "usage", usage)
	return response
}
