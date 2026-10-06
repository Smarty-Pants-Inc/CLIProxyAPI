package sse

import (
	"bytes"
	"testing"
)

func TestLinesEverySplit(t *testing.T) {
	wire := []byte("event: x\r\ndata: {\r: comment\ndata: }\r\n\r")
	want := []byte("event: x\ndata: {\n: comment\ndata: }\n\n")
	for split := 0; split <= len(wire); split++ {
		var lines Lines
		got := append([]byte(nil), lines.Normalize(wire[:split])...)
		got = append(got, lines.Normalize(nil)...)
		got = append(got, lines.Normalize(wire[split:])...)
		if !bytes.Equal(got, want) {
			t.Fatalf("split %d got %q want %q", split, got, want)
		}
	}
	var lines Lines
	var got []byte
	for _, b := range wire {
		got = append(got, lines.Normalize([]byte{b})...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("byte-at-a-time got %q want %q", got, want)
	}
}

func TestStartsLine(t *testing.T) {
	for _, prefix := range []string{"data:", "event:", "id:", "retry:", ":"} {
		if !StartsLine([]byte(prefix), LexicalBoundary{}) {
			t.Fatalf("not recognized: %q", prefix)
		}
		for _, state := range []LexicalBoundary{{InString: true}, {PartialField: true}, {RawJSON: true}} {
			if StartsLine([]byte(prefix), state) {
				t.Fatalf("recognized fragment %q with %+v", prefix, state)
			}
		}
	}
	ambiguous := LexicalBoundary{DataLine: true, Open: true, Colon: true}
	if StartsLine([]byte(": comment"), ambiguous) {
		t.Fatal("unproven Scanner key-colon fragment accepted as comment")
	}
	ambiguous.Scanner = true
	if !StartsLine([]byte(": comment"), ambiguous) {
		t.Fatal("proven Scanner comment rejected")
	}
	ambiguous.AfterBreak = true
	if StartsLine([]byte(": fragment"), ambiguous) {
		t.Fatal("raw byte fragment accepted as comment")
	}
}

// A scalar suffix is just as ambiguous as an object-key colon when the first
// data line has not established Scanner framing.
func TestStartsLineScalarColonRequiresFraming(t *testing.T) {
	for _, state := range []LexicalBoundary{
		{DataLine: true, Open: true},
		{DataLine: true, Open: true, AfterBreak: true},
		{DataLine: true, Open: true, AfterBreak: true, Scanner: true},
	} {
		if StartsLine([]byte(":x"), state) {
			t.Errorf("raw scalar suffix accepted as comment with %+v", state)
		}
	}
	if !StartsLine([]byte(": comment"), LexicalBoundary{DataLine: true, Open: true, Scanner: true}) {
		t.Fatal("proven Scanner comment rejected")
	}
}
