package auth

import (
	"context"
	"testing"
)

// A Scanner line cannot end inside a JSON string, so an SSE fragment that
// starts with an SSE field name inside a string value continues the open line.
func TestCompactionOutputRound4SSEStringSSEPrefixFragments(t *testing.T) {
	for _, prefix := range []string{"id:", "retry:", ":", "data:", "event:"} {
		data := `{"a":"` + prefix + ` ordinary"}`
		wire := "data: " + data + "\n\n"
		for split := 1; split < len(wire); split++ {
			records := 0
			observer := &compactionOutputStream{record: func(got []byte) error {
				records++
				if string(got) != data {
					t.Fatalf("prefix %q split %d: parser changed SSE data: %q", prefix, split, got)
				}
				return ValidateCompactionJSON(context.Background(), got)
			}}
			var delivered []byte
			for _, part := range []string{wire[:split], wire[split:]} {
				ready, err := observer.push([]byte(part))
				if err != nil {
					t.Fatalf("prefix %q split %d: %v", prefix, split, err)
				}
				delivered = append(delivered, ready...)
			}
			if string(delivered) != wire || records != 1 {
				t.Fatalf("prefix %q split %d: delivered=%q records=%d", prefix, split, delivered, records)
			}
		}
	}
}
