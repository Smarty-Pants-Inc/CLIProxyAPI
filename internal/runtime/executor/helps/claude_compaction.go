package helps

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ClaudeCompactionBeta enables Anthropic on-demand compaction. Requests that ask
// for a summary and requests that carry the returned block both need it.
const ClaudeCompactionBeta = "compact-2026-09-04"

// claudeCompactionCapsulePrefix marks a Responses compaction item whose
// encrypted_content carries an Anthropic compaction block verbatim.
const claudeCompactionCapsulePrefix = "cpa-claude-compact-v1:"

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
	Capsule      string
	InputTokens  int64
	OutputTokens int64
}

// ParseClaudeCompactionStream extracts exactly one compaction block from an
// upstream Claude SSE response. Any other outcome is an error, so the client
// never receives zero or several compaction items.
func ParseClaudeCompactionStream(data []byte) (ClaudeCompactionResult, error) {
	var result ClaudeCompactionResult
	var block []byte
	blocks := 0
	stopReason := ""
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(nil, 52_428_800)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		event := gjson.ParseBytes(bytes.TrimSpace(line[len("data:"):]))
		switch event.Get("type").String() {
		case "content_block_start":
			if event.Get("content_block.type").String() == "compaction" {
				blocks++
				block = []byte(event.Get("content_block").Raw)
			}
		case "message_delta":
			stopReason = event.Get("delta.stop_reason").String()
			result.InputTokens, result.OutputTokens = claudeCompactionUsage(event.Get("usage"))
		}
	}
	if errScan := scanner.Err(); errScan != nil {
		return result, errScan
	}
	if blocks != 1 || stopReason != "compaction" {
		return result, claudeCompactionError(fmt.Sprintf("claude compaction returned %d compaction blocks with stop_reason %q", blocks, stopReason))
	}
	if !gjson.GetBytes(block, "content").Exists() || gjson.GetBytes(block, "content").Type == gjson.Null {
		return result, claudeCompactionError("claude compaction returned no summary")
	}
	result.Capsule = claudeCompactionCapsulePrefix + base64.RawURLEncoding.EncodeToString(block)
	return result, nil
}

// claudeCompactionUsage sums the billed iterations; top-level usage is zero on
// a summary-only response.
func claudeCompactionUsage(usage gjson.Result) (int64, int64) {
	var input, output int64
	iterations := usage.Get("iterations")
	if iterations.IsArray() && len(iterations.Array()) > 0 {
		for _, iteration := range iterations.Array() {
			input += iteration.Get("input_tokens").Int()
			output += iteration.Get("output_tokens").Int()
		}
		return input, output
	}
	return usage.Get("input_tokens").Int(), usage.Get("output_tokens").Int()
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
	return buildResponsesCompactionStreamChunks("claude", modelName, result.Capsule, int(result.InputTokens), int(result.OutputTokens), int(total))
}

// BuildClaudeCompactionResponse returns a non-stream Responses object with one
// compaction item.
func BuildClaudeCompactionResponse(modelName string, result ClaudeCompactionResult) []byte {
	now := time.Now()
	item := []byte(`{"type":"compaction","status":"completed"}`)
	item, _ = sjson.SetBytes(item, "id", fmt.Sprintf("cmp_claude_compact_%d", now.UnixNano()))
	item, _ = sjson.SetBytes(item, "encrypted_content", result.Capsule)
	usage := []byte(`{"input_tokens_details":{"cached_tokens":0},"output_tokens_details":{"reasoning_tokens":0}}`)
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
