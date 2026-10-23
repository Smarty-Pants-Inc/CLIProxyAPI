//go:build !race

package helps

import (
	"encoding/json"
	"testing"
)

// Race instrumentation adds allocations; this allocation test is meaningful only without -race.
// Recorded catch: PR #174 CI. Inspection buffers must be reused across events;
// owned native wire units are tested separately from the inspection hot path.
func TestStreamSSEAssemblyReusesBuffers(t *testing.T) {
	lines := [][]byte{[]byte(`data: {"type":"response.output_item.done","padding":[`)}
	for i := 0; i < 4096; i++ {
		lines = append(lines, []byte("data: 0,"))
	}
	lines = append(lines, []byte(`data: 0],"item":{"type":"message","content":[]}}`))
	for _, native := range []bool{false, true} {
		name := "delimiterless JSON"
		if native {
			name = "native SSE event"
		}
		t.Run(name, func(t *testing.T) {
			var dataState StreamSSEData
			var eventState StreamSSEEvent
			run := func() {
				var data []byte
				var ready bool
				for i, line := range lines {
					if native {
						data, ready = eventState.Observe(line)
					} else {
						data, ready = dataState.Observe(line)
					}
					if ready && (native || i != len(lines)-1) {
						t.Fatal("dispatched an incomplete event")
					}
				}
				if native {
					data, ready = eventState.Observe(nil)
				} else {
					defer dataState.Observe(nil)
				}
				if !ready || !json.Valid(data) {
					t.Fatalf("lost complete event: ready=%t len=%d", ready, len(data))
				}
			}
			// Explicitly warm capacity before measuring; AllocsPerRun also warms
			// once. Neither scanner-owned data nor inspection needs a unit copy.
			run()
			if allocs := testing.AllocsPerRun(20, run); allocs != 0 {
				t.Fatalf("assembly allocated %g times per event, want zero after warmup", allocs)
			}
		})
	}
}
