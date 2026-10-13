package handlers

import (
	"bytes"
	"testing"
)

func TestSSEFollowup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks []string
		want   string
	}{
		{"string data prefix", []string{`data: {"a":"`, `data: text"}`}, `data: {"a":"data: text"}`},
		{"string event prefix", []string{`data: {"a":"`, `event: text"}`}, `data: {"a":"event: text"}`},
		{"split CRLF", []string{"data: {\"a\":\r", "\n", "data: 1}\r", "\n\r", "\n"}, "data: {\"a\":\ndata: 1}\n\n"},
		{"lone CR", []string{"data: {\"a\":\rdata: 1}\r\r"}, "data: {\"a\":\ndata: 1}\n\n"},
		{"mixed", []string{"event: x\r\ndata: {\"a\":\r: comment\ndata: 1}\n\r"}, "event: x\ndata: {\"a\":\n: comment\ndata: 1}\n\n"},
		{"first event comment after key", []string{"event: x\ndata: {\"a\"\n: comment\ndata: :1}\n\n"}, "event: x\ndata: {\"a\"\n: comment\ndata: :1}\n\n"},
		{"first event comment after event field", []string{"event: x\n: comment\ndata: {\"a\":1}\n\n"}, "event: x\n: comment\ndata: {\"a\":1}\n\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &sseJSONValidationState{}
			var output []byte
			for _, chunk := range tc.chunks {
				out, err := state.AddChunk([]byte(chunk))
				if err != nil {
					t.Fatal(err)
				}
				output = append(output, out...)
			}
			if err := state.Finish(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(bytes.TrimRight(output, "\n"), bytes.TrimRight([]byte(tc.want), "\n")) {
				t.Fatalf("output=%q want=%q", output, tc.want)
			}
		})
	}
}
