package auth

import (
	"bytes"
	"context"
	"testing"
)

// Once a complete delimiter-free event has established Scanner framing, a
// comment inside a held multiline data event is a new SSE line, not JSON.
// The event must register and every original unit must be released.
func TestCompactionOutputRound5ScannerCommentInsideMultilineEvent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		units []string
		data  string
	}{
		{"after comma", []string{`data: {"type":"response.created"}`, `data: {"a":1,`, `: keepalive`, `data: "b":2}`}, "{\"a\":1,\n\"b\":2}"},
		{"after value", []string{`data: {"type":"response.created"}`, `data: {"a":[1`, `: keepalive`, `data: ,2]}`}, "{\"a\":[1\n,2]}"},
		{"after array string", []string{`data: {"type":"response.created"}`, `data: {"a":["x"`, `:`, `data: ]}`}, "{\"a\":[\"x\"\n]}"},
		// A line may end after an object key. Once the stream has proven
		// Scanner framing (a complete event and no wire LF), a leading ':'
		// unit is still a new line.
		{"after key, Scanner proven", []string{`data: {"type":"response.created"}`, `data: {"a"`, `: keepalive`, `data: :1}`}, "{\"a\"\n:1}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var records []string
			observer := &compactionOutputStream{record: func(got []byte) error {
				records = append(records, string(got))
				return ValidateCompactionJSON(context.Background(), got)
			}}
			var delivered [][]byte
			for _, unit := range tc.units {
				ready, err := observer.pushChunks([]byte(unit))
				if err != nil {
					t.Fatalf("unit %q: %v", unit, err)
				}
				delivered = append(delivered, ready...)
			}
			if _, err := observer.finishChunks(); err != nil {
				t.Fatal(err)
			}
			if len(delivered) != len(tc.units) {
				t.Fatalf("units changed: %q", delivered)
			}
			for i := range tc.units {
				if string(delivered[i]) != tc.units[i] {
					t.Fatalf("unit %d changed: %q", i, delivered[i])
				}
			}
			if len(records) == 0 || records[len(records)-1] != tc.data {
				t.Fatalf("records = %q, want last %q", records, tc.data)
			}
		})
	}
}

// After a wire LF, a unit that starts inside the open line is a fragment of it,
// even when it starts with ':'. Taking "1:x" as a comment would hide invalid
// JSON that a downstream byte-stream reader sees, so it must fail closed.
func TestCompactionOutputRound5RawFragmentColonIsNotAComment(t *testing.T) {
	wire := "data: {\"k\":1}\n\ndata: {\"a\":1:x\ndata: }\n\n"
	split := bytes.Index([]byte(wire), []byte(":x"))
	observer := &compactionOutputStream{record: func(got []byte) error {
		return ValidateCompactionJSON(context.Background(), got)
	}}
	var delivered []byte
	var failed error
	for _, part := range []string{wire[:split], wire[split:]} {
		ready, err := observer.push([]byte(part))
		if err != nil {
			failed = err
			break
		}
		delivered = append(delivered, ready...)
	}
	if failed == nil {
		if _, err := observer.finish(); err != nil {
			failed = err
		}
	}
	if failed == nil || bytes.Contains(delivered, []byte(":x")) {
		t.Fatalf("raw fragment was taken as a comment: delivered=%q err=%v", delivered, failed)
	}
}
