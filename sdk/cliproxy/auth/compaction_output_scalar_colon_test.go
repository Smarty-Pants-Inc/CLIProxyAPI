package auth

import (
	"bytes"
	"fmt"
	"testing"
)

// S9: before any physical delimiter or completed Scanner event, a colon at a
// chunk boundary must not hide an invalid scalar suffix from JSON validation.
func TestCompactionOutputScalarColonRequiresFraming(t *testing.T) {
	for _, scalar := range []string{"1", "true", "null", `"value"`} {
		prefix := `data: {"type":"response.output_item.done","item":` + producedCompaction + `,"a":` + scalar
		tail := ":x\ndata: }\n\n"
		wire := prefix + tail
		cases := map[string][]string{
			"three units": {prefix, ":x", "data: }"},
			"empty units": {prefix, "", ":", "", "x", "\n", "data: }\n\n"},
		}
		for split := 1; split < len(wire); split++ {
			cases[fmt.Sprintf("wire split %d", split)] = []string{wire[:split], wire[split:]}
		}
		for split := 1; split < len(tail); split++ {
			cases[fmt.Sprintf("tail split %d", split)] = []string{prefix, tail[:split], tail[split:]}
		}
		var bytewise []string
		for i := range wire {
			bytewise = append(bytewise, wire[i:i+1])
		}
		cases["bytewise"] = bytewise
		for name, parts := range cases {
			t.Run(scalar+"/"+name, func(t *testing.T) {
				records, registered := 0, false
				observer := &compactionOutputStream{record: func(data []byte) error {
					records++
					registered = registered || len(compactionOutputKeys(data)) > 0
					return nil
				}}
				var delivered []byte
				var failed error
				for _, part := range parts {
					ready, err := observer.pushChunks([]byte(part))
					delivered = append(delivered, bytes.Join(ready, nil)...)
					if err != nil {
						failed = err
						break
					}
				}
				if failed == nil {
					ready, err := observer.finishChunks()
					delivered = append(delivered, bytes.Join(ready, nil)...)
					failed = err
				}
				if failed == nil || records != 0 || registered || len(delivered) != 0 {
					t.Fatalf("malformed scalar suffix accepted: records=%d registered=%v delivered=%q err=%v", records, registered, delivered, failed)
				}
			})
		}
	}
}

// Physical line endings prove the comment boundary even in the first event.
func TestCompactionOutputScalarColonPhysicalComments(t *testing.T) {
	for _, ending := range []string{"\n", "\r", "\r\n"} {
		wire := `data: {"a":1` + ending + ": comment" + ending + "data: }" + ending + ending
		for split := 1; split < len(wire); split++ {
			t.Run(fmt.Sprintf("%q/split %d", ending, split), func(t *testing.T) {
				records := 0
				observer := &compactionOutputStream{record: func(data []byte) error {
					records++
					if string(data) != "{\"a\":1\n}" {
						t.Fatalf("comment entered JSON: %q", data)
					}
					return nil
				}}
				var delivered []byte
				for _, part := range []string{wire[:split], wire[split:]} {
					ready, err := observer.pushChunks([]byte(part))
					if err != nil {
						t.Fatal(err)
					}
					delivered = append(delivered, bytes.Join(ready, nil)...)
				}
				if _, err := observer.finishChunks(); err != nil {
					t.Fatal(err)
				}
				if records != 1 || string(delivered) != wire {
					t.Fatalf("records=%d delivered=%q want=%q", records, delivered, wire)
				}
			})
		}
	}
}
