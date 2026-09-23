package helps

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestClaudeModelJSONIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, payload, expected string
		ok                      bool
	}{
		{"exact", `{"model":"claude-opus-5-5"}`, "claude-opus-5-5", true},
		{"normalized-wire-model", `{"model":"k2.5"}`, "k2.5", true},
		{"wrong", `{"model":"claude-sonnet-5"}`, "claude-opus-5-5", false},
		{"missing", `{}`, "claude-opus-5-5", false},
		{"null", `{"model":null}`, "claude-opus-5-5", false},
		{"non-string", `{"model":123}`, "123", false},
		{"blank-expected", `{"model":""}`, "", false},
		{"malformed", `{"model":"claude-opus-5-5"`, "claude-opus-5-5", false},
		{"no-response-alias-rewrite", `{"model":"public-alias"}`, "k2.5", false},
		{"no-response-suffix-rewrite", `{"model":"claude-opus-5-5(high)"}`, "claude-opus-5-5", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateClaudeResponseModel([]byte(tc.payload), tc.expected)
			if (err == nil) != tc.ok {
				t.Fatalf("validation = %v, want success %t", err, tc.ok)
			}
		})
	}
}

func TestClaudeModelStreamIdentity(t *testing.T) {
	const start = "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"model\":\"expected\"}}\n\n"
	const content = "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"MUST_NOT_LEAK\"}}\n\n"
	const ping = "event: ping\ndata: {\"type\":\"ping\"}\n\n"
	for _, tc := range []struct {
		name, stream string
		ok           bool
	}{
		{"exact", start + content, true},
		{"ping-before-start", ping + start + content, true},
		{"empty", "", false},
		{"ping-only", ping, false},
		{"missing-start", content, false},
		{"content-before-start", content + start, false},
		{"wrong", strings.Replace(start, "expected", "wrong", 1) + content, false},
		{"missing", "data: {\"type\":\"message_start\",\"message\":{}}\n\n" + content, false},
		{"malformed", "data: {\n\n" + content, false},
		{"upstream-error", "data: {\"type\":\"error\",\"error\":{\"message\":\"MUST_NOT_LEAK\"}}\n\n", false},
		{"scan-bound", strings.Repeat("x", claudeModelStreamLimit) + "\n" + start, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := GuardClaudeModelStream(strings.NewReader(tc.stream), "expected")
			if !tc.ok {
				if err == nil || r != nil {
					t.Fatalf("unverified stream accepted: %v", err)
				}
				if strings.Contains(err.Error(), "MUST_NOT_LEAK") {
					t.Fatal("upstream payload escaped in error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, err := io.ReadAll(r)
			if err != nil || string(data) != tc.stream {
				t.Fatalf("verified stream changed: %q, %v", data, err)
			}
		})
	}
	t.Run("duplicate-start", func(t *testing.T) {
		r, err := GuardClaudeModelStream(strings.NewReader(start+start+content), "expected")
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(r)
		var mismatch *ClaudeModelMismatchError
		if !errors.As(err, &mismatch) || strings.Contains(string(data), "MUST_NOT_LEAK") {
			t.Fatalf("duplicate identity not stopped: %q, %v", data, err)
		}
	})
}
