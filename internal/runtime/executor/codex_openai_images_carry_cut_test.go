package executor

import (
	"bytes"
	"testing"
)

// CLIProxyAPI#115 r2 (CODE+SEC P2): a self-overlapping identifier must not walk the cut back to zero.
func TestCodexImageCarryCutBoundedForSelfOverlappingNeedles(t *testing.T) {
	needles := [][]byte{[]byte("aa"), []byte("0123456789abcdef0123456789abcdef")}
	maxLen := 32
	bound := (maxLen - 1) + len(needles)*maxLen
	for _, size := range []int{2, 33, 1024, 32*1024 + 5, 1 << 20} {
		pending := bytes.Repeat([]byte("a"), size)
		cut := codexImageCarryCut(pending, needles, maxLen)
		if carry := len(pending) - cut; carry > bound {
			t.Fatalf("size %d: carry %d exceeds bound %d", size, carry, bound)
		}
	}
}

func TestCodexImageCarryCutKeepsACrossingIdentifierWhole(t *testing.T) {
	id := []byte("0123456789abcdef0123456789abcdef")
	needles := [][]byte{id}
	for split := 1; split < len(id); split++ {
		pending := append(bytes.Repeat([]byte("x"), 100), id[:split]...)
		cut := codexImageCarryCut(pending, needles, len(id))
		if cut > 100 {
			t.Fatalf("split %d: cut %d emits part of a possible identifier", split, cut)
		}
		whole := append(bytes.Repeat([]byte("x"), 100), id...)
		whole = append(whole, bytes.Repeat([]byte("y"), 10)...)
		if cut := codexImageCarryCut(whole, needles, len(id)); cut != 100 && cut < 100+len(id) {
			t.Fatalf("split %d: cut %d falls inside a complete identifier", split, cut)
		}
	}
}

func TestCodexImageCarryCutInactiveEmitsAll(t *testing.T) {
	if cut := codexImageCarryCut([]byte("abc"), nil, 0); cut != 3 {
		t.Fatalf("cut = %d, want 3", cut)
	}
}
