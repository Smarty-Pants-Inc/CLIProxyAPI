package helps

import (
	"fmt"
	"testing"
)

// Recorded catch: PR #174 F1. Leading empty data fields are SSE whitespace,
// not corrupt JSON, and must not hide the terminal record from executors.
func TestStreamSSEDataLeadingEmptyDataLines(t *testing.T) {
	const terminal = `{"type":"response.completed","response":{"status":"completed","output":[]}}`
	for _, preserve := range []bool{false, true} {
		for _, count := range []int{2, 3} {
			for _, empty := range []string{"data:", "data: \t "} {
				t.Run(fmt.Sprintf("preserve=%t/count=%d/empty=%q", preserve, count, empty), func(t *testing.T) {
					state := StreamSSEData{PreserveLines: preserve}
					for i := 0; i < count; i++ {
						if _, ready := state.Observe([]byte(empty)); ready {
							t.Fatal("dispatched empty data")
						}
					}
					data, ready := state.Observe([]byte("data: " + terminal))
					if !ready || string(data) != terminal {
						t.Fatalf("terminal lost or changed: ready=%t data=%s", ready, data)
					}
					if !state.Multiline {
						t.Fatal("completed record was not marked multiline")
					}
					if preserve && len(state.Lines) != count+1 {
						t.Fatalf("retained %d wire units, want %d", len(state.Lines), count+1)
					}
					// A delimiterless next record also resets the inspection flags.
					data, ready = state.Observe([]byte("data: " + terminal))
					if !ready || string(data) != terminal || state.Multiline {
						t.Fatalf("state leaked into next record: ready=%t multiline=%t data=%s", ready, state.Multiline, data)
					}
				})
			}
		}
	}
}
