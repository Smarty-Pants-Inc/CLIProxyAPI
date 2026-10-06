package handlers

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"
)

// F1/L2: continuation lines that end in a value (leading commas, nested
// closers) and raw units that end in LF must not rescan the pending event per
// line. Each case is a 100k-line event held until its last line.
func TestSSEJSONValidationLeadingCommaMultilineIsLinear(t *testing.T) {
	const count = 100000
	for _, tc := range []struct {
		name, first, middle, last, eol string
	}{
		{"leading comma scalar", `data: {"type":"response.output_item.done","padding":[0`, "data: ,0", `data: ],"item":{"type":"message"}}`, ""},
		{"leading comma nested closers", `data: {"type":"response.output_item.done","padding":[{"x":[1]}`, `data: ,{"x":[1],"s":"a]}"}`, `data: ],"item":{"type":"message"}}`, ""},
		{"LF-ending raw units", `data: {"type":"response.output_item.done","padding":[`, "data: 0,", `data: 0],"item":{"type":"message"}}`, "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			units := []string{tc.first + tc.eol}
			for i := 0; i < count; i++ {
				units = append(units, tc.middle+tc.eol)
			}
			units = append(units, tc.last+tc.eol, `data: {"type":"response.completed"}`+tc.eol)
			sep := "\n"
			if tc.eol != "" {
				sep = ""
			}
			event := strings.Join(units[:len(units)-1], sep)
			want := event + units[len(units)-1]

			result := make(chan error, 1)
			go func() {
				state := &sseJSONValidationState{}
				var out []byte
				for i, unit := range units {
					ready, err := state.AddChunk([]byte(unit))
					if err != nil {
						result <- err
						return
					}
					if len(ready) > 0 && i < len(units)-2 {
						result <- fmt.Errorf("incomplete event released at unit %d", i)
						return
					}
					out = append(out, ready...)
				}
				if err := state.Finish(); err != nil {
					result <- err
					return
				}
				if string(out) != want {
					result <- fmt.Errorf("event changed: got %d bytes want %d", len(out), len(want))
					return
				}
				result <- nil
			}()
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("100k-line SSE event validation is not linear (10s bound; linear work takes milliseconds)")
			}
		})
	}
}

// The validator's answer must not change: an invalid tail or a second root is
// still held and rejected at Finish, and a valid scalar is released at once.
func TestSSEJSONValidationIncrementalKeepsDecisions(t *testing.T) {
	for _, tc := range []struct {
		name    string
		units   []string
		release int // index of the first unit that releases output; -1 none
		finish  bool
	}{
		{"object", []string{`data: {"a":`, `1}`}, 1, true},
		{"second root held", []string{`data: {"a":1} {`, `data: }`}, -1, false},
		{"malformed closed root held", []string{`data: {"a" 1`, `data: }`, `data:`}, -1, false},
		{"number fragments", []string{`data: 12`, `34`}, 0, true},
		{"literal fragments", []string{`data: tr`, `ue`}, 1, true},
		{"string root", []string{`data: "a`, `b"`}, 1, true},
		{"unicode space after root", []string{"data: {}\u00a0"}, 0, true},
		{"done", []string{`data: [DONE]`}, 0, true},
		{"no data", []string{`event: ping`}, 0, true},
		{"raw fragment after key", []string{`data: {"k"`, `:1}`}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state := &sseJSONValidationState{}
			first := -1
			var out []byte
			for i, unit := range tc.units {
				ready, err := state.AddChunk([]byte(unit))
				if err != nil {
					t.Fatal(err)
				}
				if len(ready) > 0 && first < 0 {
					first = i
				}
				out = append(out, ready...)
			}
			if first != tc.release {
				t.Fatalf("first release at unit %d, want %d (out %q)", first, tc.release, out)
			}
			if first >= 0 && !bytes.Equal(out, []byte(strings.Join(tc.units, ""))) {
				t.Fatalf("released %q", out)
			}
			if err := state.Finish(); (err == nil) != tc.finish {
				t.Fatalf("Finish err=%v, want ok=%v", err, tc.finish)
			}
		})
	}
}

// F2 downstream: after Scanner framing is established, a comment or id line
// inside a held multiline data event is its own SSE line.
func TestSSEJSONValidationScannerControlInsideMultilineEvent(t *testing.T) {
	for _, control := range []string{": keepalive", "id: 7", "retry: 10"} {
		units := []string{`data: {"a":1,`, control, `data: "b":2}`}
		state := &sseJSONValidationState{}
		if ready, err := state.AddChunk([]byte(`data: {}`)); err != nil || string(ready) != `data: {}` {
			t.Fatalf("establish Scanner framing: ready=%q err=%v", ready, err)
		}
		var out []byte
		for _, unit := range units {
			ready, err := state.AddChunk([]byte(unit))
			if err != nil {
				t.Fatalf("%q: %v", control, err)
			}
			out = append(out, ready...)
		}
		if err := state.Finish(); err != nil {
			t.Fatalf("%q: %v", control, err)
		}
		if want := strings.Join(units, "\n"); string(out) != want {
			t.Fatalf("%q: got %q want %q", control, out, want)
		}
	}
}

func TestSSEJSONValidationScalarColonRequiresFraming(t *testing.T) {
	for _, scalar := range []string{"1", "true", "null", `"value"`} {
		for _, suffix := range [][]string{{":x", "data: }"}, {"", ":", "", "x\ndata: }\n\n"}} {
			t.Run(fmt.Sprintf("%s/%q", scalar, suffix), func(t *testing.T) {
				state := &sseJSONValidationState{}
				units := append([]string{`data: {"a":` + scalar}, suffix...)
				var out []byte
				var failed error
				for _, unit := range units {
					ready, err := state.AddChunk([]byte(unit))
					out = append(out, ready...)
					if err != nil {
						failed = err
						break
					}
				}
				if failed == nil {
					failed = state.Finish()
				}
				if failed == nil || len(out) != 0 {
					t.Fatalf("raw scalar suffix accepted: out=%q err=%v", out, failed)
				}
			})
		}
	}
}
