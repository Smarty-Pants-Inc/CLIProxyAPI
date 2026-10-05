package handlers

import (
	"bytes"
	"fmt"
	"testing"
	"time"
)

// Executors forward one Scanner line per chunk. A 100k-line data event must be
// held until its last line and then released intact, in linear work: the old
// validator rescanned the whole pending event per line and stalled for minutes.
func TestSSEJSONValidationMultilineScannerEventIsLinear(t *testing.T) {
	const count = 100000
	lines := [][]byte{[]byte(`data: {"type":"response.output_item.done","padding":[`)}
	for i := 0; i < count; i++ {
		lines = append(lines, []byte("data: 0,"))
	}
	lines = append(lines, []byte(`data: 0],"item":{"type":"message"}}`))
	completed := []byte(`data: {"type":"response.completed"}`)
	// The event is released whole at its last line; the next one-line event
	// follows as its own unit (the Responses framer owns frame separators).
	want := append(bytes.Join(lines, []byte("\n")), completed...)

	done := make(chan []byte, 1)
	errs := make(chan error, 1)
	go func() {
		state := &sseJSONValidationState{}
		var out []byte
		for i, line := range append(lines, completed) {
			ready, err := state.AddChunk(line)
			if err != nil {
				errs <- err
				return
			}
			if len(ready) > 0 && i < len(lines)-1 {
				errs <- fmt.Errorf("incomplete event released at line %d", i)
				return
			}
			out = append(out, ready...)
		}
		if err := state.Finish(); err != nil {
			errs <- err
			return
		}
		done <- out
	}()
	select {
	case err := <-errs:
		t.Fatal(err)
	case out := <-done:
		if !bytes.Equal(out, want) {
			t.Fatalf("multi-line event changed: got %d bytes want %d", len(out), len(want))
		}
	case <-time.After(10 * time.Second):
		t.Fatal("100k-line SSE event validation is not linear (10s bound; linear work takes milliseconds)")
	}
}
