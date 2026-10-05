package auth

import (
	"bytes"
	"context"
	"errors"
	"runtime"
	"strings"
	"testing"
)

// BASE-compatible RED: retained input is <32 KiB, so >16 MiB of allocation
// volume is repeated-prefix work, not the cost of retaining/validating it once.
// This is a deterministic resource assertion, not an elapsed-time benchmark.
func TestCompactionOutputRound3MultilineAllocationBound(t *testing.T) {
	const count = 4096
	units := make([][]byte, 0, count+2)
	units = append(units, []byte(`data: {"padding":[`))
	for i := 0; i < count; i++ {
		units = append(units, []byte("data: 0,"))
	}
	units = append(units, []byte(`data: 0],"item":`+producedCompaction+`}`))
	records := 0
	observer := &compactionOutputStream{ctx: context.Background(), record: func(data []byte) error {
		records++
		return ValidateCompactionJSON(context.Background(), data)
	}}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	index := 0
	for _, unit := range units {
		ready, err := observer.pushChunks(unit)
		if err != nil {
			t.Fatal(err)
		}
		for _, delivered := range ready {
			if index >= len(units) || !bytes.Equal(delivered, units[index]) || records != 1 {
				t.Fatalf("unit %d changed or released before validation", index)
			}
			index++
		}
	}
	runtime.ReadMemStats(&after)
	if index != len(units) || records != 1 {
		t.Fatalf("delivered=%d records=%d", index, records)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 16<<20 {
		t.Fatalf("framing allocated %d bytes for %d short units; want <=16 MiB (no prefix reconstruction)", allocated, len(units))
	}
}

func TestCompactionOutputRound3RejectsOversizeBeforeRegistration(t *testing.T) {
	records := 0
	observer := &compactionOutputStream{record: func([]byte) error { records++; return nil }}
	wire := []byte(`data: {"padding":"` + strings.Repeat("x", maxCompactionJSONBytes) + `"}`)
	if ready, err := observer.pushChunks(wire); err == nil || len(ready) != 0 || records != 0 {
		t.Fatalf("oversize complete event accepted: ready=%d records=%d error=%v", len(ready), records, err)
	}
}

func TestCompactionOutputRound3MultilineCancellationWithholdsTail(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	records := 0
	observer := &compactionOutputStream{ctx: ctx, record: func([]byte) error { records++; return nil }}
	for _, unit := range []string{`data: {"padding":[`, "data: 0,", "data: 0,"} {
		if ready, err := observer.pushChunks([]byte(unit)); err != nil || len(ready) != 0 {
			t.Fatalf("incomplete event released: %q %v", ready, err)
		}
	}
	cancel()
	if ready, err := observer.pushChunks([]byte(`data: 0]}`)); !errors.Is(err, context.Canceled) || len(ready) != 0 || records != 0 {
		t.Fatalf("canceled tail registered/released: %q %v records=%d", ready, err, records)
	}
}

// GREEN-only instrumentation footer; the saved initial RED files use only BASE
// API. External tests can install the private observer without a production API.
func Round3FramingWorkContext(ctx context.Context, observe func(int)) context.Context {
	return context.WithValue(ctx, compactionFramingWorkKey{}, observe)
}

func TestCompactionOutputRound3HundredThousandUnitsLinear(t *testing.T) {
	for _, signed := range []bool{false, true} {
		t.Run(map[bool]string{false: "ordinary", true: "signed"}[signed], func(t *testing.T) {
			const count = 100000
			units := [][]byte{[]byte(`data: {"type":"response.output_item.done","padding":[`)}
			for i := 0; i < count; i++ {
				units = append(units, []byte("data: 0,"))
			}
			last := `data: 0],"item":{"type":"message","content":[]}}`
			if signed {
				last = `data: 0],"item":` + producedCompaction + `}`
			}
			units = append(units, []byte(last))
			wireBytes, work, records := 0, 0, 0
			registered := false
			ctx := Round3FramingWorkContext(context.Background(), func(n int) { work += n })
			observer := &compactionOutputStream{ctx: ctx, record: func(data []byte) error {
				records++
				if err := ValidateCompactionJSON(ctx, data); err != nil {
					return err
				}
				registered = len(compactionOutputKeys(data)) == 1
				return nil
			}}
			index := 0
			for _, unit := range units {
				wireBytes += len(unit)
				ready, err := observer.pushChunks(unit)
				if err != nil {
					t.Fatal(err)
				}
				for _, output := range ready {
					if !bytes.Equal(output, units[index]) || records != 1 || registered != signed {
						t.Fatalf("unit %d changed or not registered before release", index)
					}
					index++
				}
			}
			if index != len(units) || wireBytes >= 1<<20 || work == 0 || work > 3*wireBytes {
				t.Fatalf("units=%d/%d wire=%d lexical+final visits=%d", index, len(units), wireBytes, work)
			}
		})
	}
}

func TestCompactionOutputRound3RawFragmentCheckpointLinear(t *testing.T) {
	wire := []byte(`data: {"type":"response.output_item.done","padding":"` + strings.Repeat("x", 100000) + `","item":` + producedCompaction + "}\r\n\r\n")
	work, records := 0, 0
	ctx := Round3FramingWorkContext(context.Background(), func(n int) { work += n })
	observer := &compactionOutputStream{ctx: ctx, record: func(data []byte) error {
		records++
		return ValidateCompactionJSON(ctx, data)
	}}
	var delivered []byte
	for _, b := range wire {
		ready, err := observer.push([]byte{b})
		if err != nil {
			t.Fatal(err)
		}
		delivered = append(delivered, ready...)
	}
	if _, err := observer.finish(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(delivered, wire) || records != 1 || work > 3*len(wire) {
		t.Fatalf("raw wire changed or rescanned: records=%d work=%d bytes=%d", records, work, len(wire))
	}
}

func TestCompactionOutputRound3UnitBoundBeforeAppend(t *testing.T) {
	records := 0
	observer := &compactionOutputStream{record: func([]byte) error { records++; return nil }}
	if _, err := observer.pushChunks([]byte(`data: {"padding":"`)); err != nil {
		t.Fatal(err)
	}
	// One-byte raw fragments remain under the 16 MiB byte ceiling, but must
	// not allocate unbounded unit headers. No completed event can escape it.
	for i := 1; i < maxCompactionWireUnits; i++ {
		if ready, err := observer.pushChunks([]byte("x")); err != nil || len(ready) != 0 {
			t.Fatalf("unit %d refused early: %v", i, err)
		}
	}
	if ready, err := observer.pushChunks([]byte(`"}`)); err == nil || len(ready) != 0 || records != 0 {
		t.Fatalf("unit ceiling bypassed on completion: %d %v records=%d", len(ready), err, records)
	}
}

func TestCompactionOutputRound3RawFrameRejectsMultipleRoots(t *testing.T) {
	for _, wire := range []string{
		`data: {"type":"response.output_item.done","item":` + producedCompaction + "}\ndata: {\"extra\":1}\n\n",
		"{\"a\":1}\n{\"b\":2}",
		"{\"a\":1}\nid: extra",
		"{\"a\":1}\nevent: extra",
		"{\"a\":1}\n: comment",
		"{\"a\":1}\nretry: 1000",
	} {
		// SSE holds after observed LF; separate complete raw JSON units
		// permit trailing whitespace and cannot be revoked by later units.
		for split := 0; split <= len(wire); split++ {
			firstLF := strings.IndexByte(wire, '\n')
			if split == firstLF || (wire[0] == '{' && split == firstLF+1) {
				continue
			}
			records := 0
			observer := &compactionOutputStream{record: func([]byte) error { records++; return nil }}
			parts := []string{wire}
			if split > 0 && split < len(wire) {
				parts = []string{wire[:split], wire[split:]}
			}
			refused := false
			for _, part := range parts {
				ready, err := observer.pushChunks([]byte(part))
				if err != nil {
					refused = true
					break
				}
				if len(ready) > 0 {
					t.Fatalf("split %d released multi-root raw frame", split)
				}
			}
			if !refused {
				_, err := observer.finishChunks()
				refused = err != nil
			}
			if !refused || records != 0 {
				t.Fatalf("split %d accepted/registered multi-root raw frame", split)
			}
		}
	}
}

func TestCompactionOutputRound3SignedRawControlSuffixRejectsBeforeRegistration(t *testing.T) {
	root := `{"type":"response.output_item.done","item":` + producedCompaction + `}`
	// Prove this fixture carries recognized signer evidence, not just an
	// ordinary JSON object whose callback happens to be counted.
	if keys := compactionOutputKeys([]byte(root)); len(keys) != 1 {
		t.Fatalf("signed raw fixture has %d recognized keys", len(keys))
	}
	for _, suffix := range []string{"id: extra", "event: extra", ": comment", "retry: 1000"} {
		t.Run(suffix, func(t *testing.T) {
			records := 0
			observer := &compactionOutputStream{record: func(data []byte) error {
				records++
				return ValidateCompactionJSON(context.Background(), data)
			}}
			if ready, err := observer.pushChunks([]byte(root + "\n" + suffix)); err == nil || len(ready) != 0 || records != 0 {
				t.Fatalf("signed raw suffix registered/released: units=%d records=%d error=%v", len(ready), records, err)
			}
		})
	}
}

func TestCompactionOutputRound3LeadingSSEControlsAndSeparateRawUnits(t *testing.T) {
	for _, wire := range []string{
		"data: {\"a\":1}\nid: extra\n\n",
		"id: extra\nevent: ordinary\n: comment\ndata: {\"a\":1}\n\n",
		"id: extra\r\nevent: ordinary\r\n: comment\r\ndata: {\"a\":1}\r\n\r\n",
	} {
		records := 0
		observer := &compactionOutputStream{record: func(data []byte) error {
			records++
			if string(data) != `{"a":1}` {
				t.Fatalf("SSE controls entered data: %q", data)
			}
			return nil
		}}
		ready, err := observer.push([]byte(wire))
		if err != nil || string(ready) != wire || records != 1 {
			t.Fatalf("leading SSE controls changed/refused: %q error=%v records=%d", ready, err, records)
		}
	}
	records := 0
	observer := &compactionOutputStream{record: func(data []byte) error {
		records++
		return ValidateCompactionJSON(context.Background(), data)
	}}
	for _, wire := range []string{"{\"a\":1}\n", "{\"b\":2}\t\r\n"} {
		ready, err := observer.push([]byte(wire))
		if err != nil || string(ready) != wire {
			t.Fatalf("separate raw unit changed/refused: %q %v", ready, err)
		}
	}
	if _, err := observer.finish(); err != nil || records != 2 {
		t.Fatalf("separate raw units: records=%d error=%v", records, err)
	}
}

func TestCompactionOutputRound3NativeLargeInitialSmallDeltasLinear(t *testing.T) {
	const count = 4096
	initial := strings.Repeat("x", 100000)
	assembled := false
	observer := &compactionOutputStream{native: true, ctx: context.Background(), record: func(data []byte) error {
		if bytes.HasPrefix(data, []byte(`{"content":[`)) {
			want := `{"content":[{"type":"compaction","content":"` + initial + strings.Repeat("x", count) + `"}]}`
			assembled = string(data) == want
		}
		return nil
	}}
	start := []byte("data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"compaction\",\"content\":\"" + initial + "\"}}\n\n")
	if ready, err := observer.pushChunks(start); err != nil || len(ready) == 0 {
		t.Fatalf("nonempty native start=%v %v", len(ready), err)
	}
	delta := []byte("data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"content\":\"x\"}}\n\n")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for i := 0; i < count; i++ {
		if ready, err := observer.pushChunks(delta); err != nil || len(ready) != 0 {
			t.Fatalf("delta %d=%v %v", i, len(ready), err)
		}
	}
	if ready, err := observer.pushChunks([]byte("data: {\"type\":\"content_block_stop\",\"index\":0}\n\n")); err != nil || len(ready) != count+1 || !assembled {
		t.Fatalf("native stop=%d %v assembled=%v", len(ready), err, assembled)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("native initial content rescanned per delta: allocated=%d", allocated)
	}
}

func TestCompactionOutputRound3RawPrettyAndLiteralFragments(t *testing.T) {
	for _, wire := range []string{"{\"a\":\n 1}", "{\"a\":\n\n 1}\r\n", "[\n1,2\n]\n", "{\"a\":1}\n", `{"a":"escaped\\\"text"}` + "\t\r\n"} {
		records := 0
		observer := &compactionOutputStream{record: func(data []byte) error {
			records++
			return ValidateCompactionJSON(context.Background(), data)
		}}
		ready, err := observer.push([]byte(wire))
		if err != nil || string(ready) != wire || records != 1 {
			t.Fatalf("raw pretty unit=%q err=%v records=%d", ready, err, records)
		}
		if _, err := observer.finish(); err != nil {
			t.Fatal(err)
		}
	}
	for _, literal := range []string{"true", "false", "null", `"escaped\\\"text"`} {
		wire := "data: " + literal
		for split := 1; split < len(wire); split++ {
			records := 0
			observer := &compactionOutputStream{record: func([]byte) error { records++; return nil }}
			var delivered []byte
			for _, part := range []string{wire[:split], wire[split:]} {
				ready, err := observer.push([]byte(part))
				if err != nil {
					t.Fatalf("literal %s split %d: %v", literal, split, err)
				}
				delivered = append(delivered, ready...)
			}
			if string(delivered) != wire || records != 1 {
				t.Fatalf("literal split %d changed", split)
			}
		}
	}
}

func TestCompactionOutputRound3AllowedScalarAndDoneUnits(t *testing.T) {
	for _, value := range []string{"true", "42", `"ordinary"`, "null", "[DONE]"} {
		for _, wire := range []string{value, "data: " + value, "data: " + value + "\r\n\r\n"} {
			records := 0
			observer := &compactionOutputStream{record: func(data []byte) error {
				records++
				if string(data) != value {
					t.Fatalf("scalar changed: %q", data)
				}
				return nil
			}}
			ready, err := observer.push([]byte(wire))
			if err != nil || string(ready) != wire || records != 1 {
				t.Fatalf("ordinary scalar withheld/changed: %q %v records=%d", ready, err, records)
			}
		}
	}
}

func TestCompactionOutputRound3RawStringSSEPrefixFragments(t *testing.T) {
	for _, prefix := range []string{"id:", "retry:", ":", "data:", "event:"} {
		wire := `{"a":"` + prefix + ` ordinary"}`
		for split := 1; split < len(wire); split++ {
			records := 0
			observer := &compactionOutputStream{record: func(data []byte) error {
				records++
				if string(data) != wire {
					t.Fatalf("prefix %q split %d: parser changed raw string: %q", prefix, split, data)
				}
				return ValidateCompactionJSON(context.Background(), data)
			}}
			var delivered []byte
			for _, part := range []string{wire[:split], wire[split:]} {
				ready, err := observer.pushChunks([]byte(part))
				if err != nil {
					t.Fatalf("prefix %q split %d: %v", prefix, split, err)
				}
				for _, unit := range ready {
					if records != 1 {
						t.Fatalf("raw string released before record: prefix %q split %d", prefix, split)
					}
					delivered = append(delivered, unit...)
				}
			}
			if ready, err := observer.finishChunks(); err != nil || len(ready) != 0 {
				t.Fatalf("raw string tail: %q %v", ready, err)
			}
			if string(delivered) != wire || records != 1 {
				t.Fatalf("prefix %q split %d: wire changed or records=%d", prefix, split, records)
			}
		}
	}
}

func TestCompactionOutputRound3BareControlThenWhitespaceSignedRaw(t *testing.T) {
	root := `{"type":"response.output_item.done","item":{"type":"compaction","encrypted_content":"x"}}`
	// Root arrays are accepted by framing but the production collector only
	// recognizes response containers. Map array items to output for this
	// recorder probe; do not claim production root-array signer registration.
	keyPayload := func(data []byte) []byte {
		trimmed := bytes.TrimSpace(data)
		if len(trimmed) > 0 && trimmed[0] == '[' {
			return []byte(`{"output":` + string(trimmed) + `}`)
		}
		return data
	}
	for _, raw := range []string{root, `[{"type":"compaction","encrypted_content":"x"}]`} {
		wantKeys := compactionOutputKeys(keyPayload([]byte(raw)))
		if len(wantKeys) != 1 {
			t.Fatalf("signed fixture has %d keys", len(wantKeys))
		}
		for _, control := range []string{": ping", "event: ordinary", "id: extra", "retry: 1000"} {
			for _, space := range []string{" ", "\t", "\r", " \t\r "} {
				records := 0
				observer := &compactionOutputStream{record: func(data []byte) error {
					records++
					keys := compactionOutputKeys(keyPayload(data))
					if len(keys) != 1 || keys[0] != wantKeys[0] {
						t.Fatalf("control %q: signed raw key not recognized: %q", control, data)
					}
					return ValidateCompactionJSON(context.Background(), data)
				}}
				ready, err := observer.pushChunks([]byte(control))
				if err != nil || !bytes.Equal(bytes.Join(ready, nil), []byte(control)) || records != 0 {
					t.Fatalf("bare control not prompt: %q %v records=%d", ready, err, records)
				}
				wire := []byte(space + raw)
				ready, err = observer.pushChunks(wire)
				if err != nil || records != 1 || !bytes.Equal(bytes.Join(ready, nil), wire) {
					t.Fatalf("control %q whitespace %q signed raw released without record: %q %v records=%d", control, space, ready, err, records)
				}
				if ready, err := observer.finishChunks(); err != nil || len(ready) != 0 {
					t.Fatalf("signed raw tail: %q %v", ready, err)
				}
			}
		}
	}
}

func TestCompactionOutputRound3ControlFragmentsAndScannerData(t *testing.T) {
	for _, parts := range [][]string{{": pi", "ng"}, {"event: ord", "inary"}, {"id: ex", "tra"}, {"retry: 10", "00"}} {
		records := 0
		observer := &compactionOutputStream{record: func([]byte) error { records++; return nil }}
		for _, part := range parts {
			ready, err := observer.pushChunks([]byte(part))
			if err != nil || string(bytes.Join(ready, nil)) != part || records != 0 {
				t.Fatalf("ordinary control fragment changed: %q %v records=%d", ready, err, records)
			}
		}
		if _, err := observer.finishChunks(); err != nil {
			t.Fatal(err)
		}
	}
	records := 0
	observer := &compactionOutputStream{record: func(data []byte) error {
		records++
		if string(data) != "{\"a\":1,\n\"b\":2}" {
			t.Fatalf("Scanner data lost parser LF: %q", data)
		}
		return ValidateCompactionJSON(context.Background(), data)
	}}
	var delivered []byte
	parts := []string{`data: {"a":1,`, `id: extra`, `data: "b":2}`}
	for _, part := range parts {
		ready, err := observer.pushChunks([]byte(part))
		if err != nil {
			t.Fatal(err)
		}
		for _, unit := range ready {
			delivered = append(delivered, unit...)
		}
	}
	if string(delivered) != parts[0]+parts[1]+parts[2] || records != 1 {
		t.Fatalf("Scanner units changed: %q records=%d", delivered, records)
	}
	if _, err := observer.finishChunks(); err != nil {
		t.Fatal(err)
	}
}
