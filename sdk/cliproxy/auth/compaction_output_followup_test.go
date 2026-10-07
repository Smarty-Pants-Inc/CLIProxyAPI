package auth

import (
	"bytes"
	"context"
	"testing"
)

func TestSSEFollowup(t *testing.T) {
	for _, tc := range []struct {
		name   string
		chunks []string
		want   string
	}{
		{"string data prefix", []string{`data: {"a":"`, `data: text"}`}, `{"a":"data: text"}`},
		{"string event prefix", []string{`data: {"a":"`, `event: text"}`}, `{"a":"event: text"}`},
		{"split CRLF", []string{"data: {\"a\":\r", "\n", "data: 1}\r", "\n\r", "\n"}, "{\"a\":\n1}"},
		{"lone CR", []string{"data: {\"a\":\rdata: 1}\r\r"}, "{\"a\":\n1}"},
		{"mixed", []string{"event: x\r\ndata: {\"a\":\r: comment\ndata: 1}\n\r"}, "{\"a\":\n1}"},
		{"first event comment after key", []string{"event: x\ndata: {\"a\"\n: comment\ndata: :1}\n\n"}, "{\"a\"\n:1}"},
		{"first event comment after event field", []string{"event: x\n: comment\ndata: {\"a\":1}\n\n"}, "{\"a\":1}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var records []string
			state := &compactionOutputStream{record: func(data []byte) error {
				records = append(records, string(data))
				return ValidateCompactionJSON(context.Background(), data)
			}}
			var output []byte
			for _, chunk := range tc.chunks {
				out, err := state.push([]byte(chunk))
				if err != nil {
					t.Fatal(err)
				}
				output = append(output, out...)
			}
			if _, err := state.finish(); err != nil {
				t.Fatal(err)
			}
			if len(records) != 1 || records[0] != tc.want {
				t.Fatalf("records=%q want=%q", records, tc.want)
			}
			if !bytes.Equal(output, []byte(joinFollowup(tc.chunks))) {
				t.Fatalf("wire changed: %q", output)
			}
		})
	}
}
func joinFollowup(chunks []string) string {
	var b bytes.Buffer
	for _, s := range chunks {
		b.WriteString(s)
	}
	return b.String()
}
