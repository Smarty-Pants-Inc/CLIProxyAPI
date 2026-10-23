package helps

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

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

func TestStreamSSEDataPreservesNativeUnits(t *testing.T) {
	state := StreamSSEData{PreserveLines: true}
	units := []string{
		"data:",
		": leading comment",
		`data: {"type":"response.output_item.done",`,
		": keepalive",
		`data: "item":{"type":"compaction","encrypted_content":"signed"}}`,
	}
	var data []byte
	var ready bool
	// Reuse the scanner storage to prove the retained units own their bytes.
	line := make([]byte, 0, 256)
	for i, unit := range units {
		line = append(line[:0], unit...)
		data, ready = state.Observe(line)
		if ready != (i == len(units)-1) {
			t.Fatalf("unit %d ready=%t", i, ready)
		}
	}
	if !json.Valid(data) || bytes.Contains(data, []byte("keepalive")) {
		t.Fatalf("invalid joined inspection data: %s", data)
	}
	if len(state.Lines) != len(units) {
		t.Fatalf("retained %d units, want %d", len(state.Lines), len(units))
	}
	for i, unit := range units {
		if string(state.Lines[i]) != unit {
			t.Fatalf("unit %d changed: %q", i, state.Lines[i])
		}
	}
	state.Observe(nil)
	if len(state.Lines) != 0 {
		t.Fatal("native units leaked across the event boundary")
	}
	data, ready = state.Observe([]byte(`data: {"type":"response.done"}`))
	if !ready || !json.Valid(data) || len(state.Lines) != 0 {
		t.Fatal("previous multiline units leaked into a delimiterless record")
	}
}

func TestStreamSSEDataNativeBufferBounds(t *testing.T) {
	for _, units := range []bool{false, true} {
		state := StreamSSEData{PreserveLines: true}
		state.Observe([]byte(`data: {"type":`))
		if units {
			state.Lines = make([][]byte, 1<<20)
		} else {
			state.wireBytes = 52_428_800
		}
		data, ready := state.Observe([]byte(": comment"))
		if !ready || !IsStreamErrorFrame(data, "") {
			t.Fatalf("units=%t: native buffering overflow was not an error: %s", units, data)
		}
		if len(state.Lines) != 0 {
			t.Fatal("overflow retained native units instead of releasing them")
		}
		state.Observe(nil)
		data, ready = state.Observe([]byte(`data: {"type":"response.done"}`))
		if !ready || !json.Valid(data) || len(state.Lines) != 0 || state.wireBytes != 0 {
			t.Fatal("overflow state leaked into the next event")
		}
	}
}

// Recorded catch: PR #174 S2. A corrupt 1 MB record followed by neutral lines
// must not revalidate its entire pending prefix on each line.
func TestStreamSSEDataPoisonedRecordLinear(t *testing.T) {
	for _, tail := range []string{"0]]", "0] 0", `0] "`, "0,]"} {
		t.Run(tail, func(t *testing.T) {
			var state StreamSSEData
			for _, line := range []string{"data: [", "data: " + strings.Repeat("0,", 1<<19), "data: " + tail, "data: ["} {
				if _, ready := state.Observe([]byte(line)); ready {
					t.Fatal("dispatched corrupt JSON")
				}
			}
			// Measure revalidation on an already-pending 1 MB record, not
			// fixture generation or the initial megabyte's linear scan.
			start := time.Now()
			for i := 0; i < 1000; i++ {
				if _, ready := state.Observe([]byte("data: 0")); ready {
					t.Fatal("dispatched poisoned record")
				}
			}
			elapsed := time.Since(start)
			t.Logf("1 MB pending + 1000 lines: %v", elapsed)
			if elapsed >= 50*time.Millisecond {
				t.Fatalf("poisoned record revalidation exceeded 50 ms: %v", elapsed)
			}
			// Neither a later valid value nor a closing bracket can repair a
			// poisoned record; only its blank-line boundary resets inspection.
			for _, line := range []string{"data: ]", `data: {"ok":true}`} {
				if _, ready := state.Observe([]byte(line)); ready {
					t.Fatal("poisoned record recovered before blank line")
				}
			}
			state.Observe(nil)
			data, ready := state.Observe([]byte(`data: {"ok":true}`))
			if !ready || !json.Valid(data) {
				t.Fatal("blank line did not reset poisoned record")
			}
		})
	}
}

func TestStreamSSEDataJSONCheckpoint(t *testing.T) {
	for _, wire := range []string{
		"data: {\"value\":\"braces } ] and escaped \\\" quote\",\ndata: \"nested\":[{},[]]}",
		"data: {\"type\":\ndata: \"response.done\"}",
		"data: [\ndata: {\"type\":\"response.done\"}]",
	} {
		var state StreamSSEData
		lines := strings.Split(wire, "\n")
		for i, line := range lines {
			data, ready := state.Observe([]byte(line))
			if ready != (i == len(lines)-1) || (ready && !json.Valid(data)) {
				t.Fatalf("checkpoint misclassified line %d of %q: ready=%t data=%s", i, wire, ready, data)
			}
		}
	}
	var state StreamSSEData
	for _, line := range []string{`data: {"type":`, `data: "response.done",}`} {
		if _, ready := state.Observe([]byte(line)); ready {
			t.Fatal("lexical balance bypassed JSON syntax validation")
		}
	}
}
