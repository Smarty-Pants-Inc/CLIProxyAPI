package helps

import (
	"bytes"
	"strings"
	"testing"
)

func collectUsageLines(chunks ...[]byte) []string {
	var got []string
	var s StreamUsageLines
	for _, c := range chunks {
		s.Observe(c, func(line []byte) { got = append(got, string(line)) })
	}
	s.Close(func(line []byte) { got = append(got, string(line)) })
	return got
}

// CLIProxyAPI#115 (Astra): a usage event split INSIDE its JSON, at any byte, is observed once and whole.
func TestStreamUsageLinesReassemblesAUsageEventSplitAtEveryByte(t *testing.T) {
	event := `data: {"type":"image_generation.completed","usage":{"input_tokens":12,"output_tokens":34}}`
	stream := []byte("event: x\n" + event + "\n\n")
	for split := 1; split < len(stream); split++ {
		got := collectUsageLines(stream[:split], stream[split:])
		if len(got) != 2 || got[0] != "event: x" || got[1] != event {
			t.Fatalf("split %d: lines = %q", split, got)
		}
	}
}

func TestStreamUsageLinesTreatsCRLFAsOneBoundaryAcrossReads(t *testing.T) {
	for name, chunks := range map[string][][]byte{
		"lf":         {[]byte("a\nb\n")},
		"cr":         {[]byte("a\rb\r")},
		"crlf":       {[]byte("a\r\nb\r\n")},
		"crlf-split": {[]byte("a\r"), []byte("\nb\r"), []byte("\n")},
	} {
		if got := collectUsageLines(chunks...); strings.Join(got, ",") != "a,b" {
			t.Fatalf("%s: lines = %q, want [a b]", name, got)
		}
	}
}

func TestStreamUsageLinesBoundsAnOverlongLine(t *testing.T) {
	var s StreamUsageLines
	var got []string
	observe := func(line []byte) { got = append(got, string(line)) }
	big := bytes.Repeat([]byte("x"), 64*1024)
	for i := 0; i < (MaxStreamUsageLineBytes/len(big))+4; i++ {
		s.Observe(big, observe)
		if len(s.partial) > MaxStreamUsageLineBytes {
			t.Fatalf("held %d bytes, bound %d", len(s.partial), MaxStreamUsageLineBytes)
		}
	}
	s.Observe([]byte("\nnext\n"), observe)
	if strings.Join(got, ",") != "next" {
		t.Fatalf("lines = %q, want only the line after the overlong one", got)
	}
}

func TestStreamUsageLinesObservesAnUnterminatedFinalLine(t *testing.T) {
	if got := collectUsageLines([]byte("a\nlast")); strings.Join(got, ",") != "a,last" {
		t.Fatalf("lines = %q", got)
	}
}
