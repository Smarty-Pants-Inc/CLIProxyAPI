package helps

import (
	"bytes"
	"fmt"
	"testing"
)

func TestCodexIdentityResponseMultiMappingSinglePass(t *testing.T) {
	for _, tc := range []struct {
		name, wire, want string
		mappings         [][2]string
		jsonBody         bool
	}{
		{
			name:     "generated-values-and-whole-tokens",
			wire:     "ab cd tab abc ab_thing abβ ab\u0301",
			want:     "cd ef tab abc ab_thing abβ ab\u0301",
			mappings: [][2]string{{"ab", "cd"}, {"cd", "ef"}},
		},
		{
			name:     "leftmost-longest-and-failed-longer-prefix",
			wire:     "ab.c ab.x abc ab",
			want:     "long short.x abc short",
			mappings: [][2]string{{"ab", "short"}, {"ab.c", "long"}, {"b.c", "wrong"}},
		},
		{
			name:     "first-source-registration",
			wire:     "ab cd",
			want:     "cd ef",
			mappings: [][2]string{{"ab", "cd"}, {"ab", "wrong"}, {"cd", "ef"}},
		},
		{
			name:     "decoded-json-and-no-op-escapes",
			wire:     `{"ab":"\u0061b","cd":"c\u0064","note":"t\u0061b ab\u0301 abβ \"ab\""}`,
			want:     `{"ab":"cd","cd":"c\u0064","note":"t\u0061b ab\u0301 abβ \"cd\""}`,
			mappings: [][2]string{{"ab", "cd"}, {"cd", "cd"}},
			jsonBody: true,
		},
		{
			name:     "generated-text-does-not-set-left-boundary",
			wire:     "ab.x ab-x",
			want:     "!.next ab-x",
			mappings: [][2]string{{"ab", "!"}, {"x", "next"}},
		},
	} {
		for split := 0; split <= len(tc.wire); split++ {
			t.Run(fmt.Sprintf("%s/byte=%d", tc.name, split), func(t *testing.T) {
				w := NewCodexIdentityResponseRewriterWithMappings(tc.mappings, false, tc.jsonBody)
				got := w.Rewrite([]byte(tc.wire[:split]), false)
				got = append(got, w.Rewrite([]byte(tc.wire[split:]), true)...)
				if string(got) != tc.want {
					t.Errorf("got %q, want %q", got, tc.want)
				}
			})
		}
	}
}

func TestCodexIdentityResponseMultiMappingLongestOrderAndBound(t *testing.T) {
	for _, mappings := range [][][2]string{
		{{"ab", "short"}, {"ab.c", "long"}},
		{{"ab.c", "long"}, {"ab", "short"}},
	} {
		w := NewCodexIdentityResponseRewriterWithMappings(mappings, false, false)
		var got []byte
		wire := []byte("ab.c " + string(bytes.Repeat([]byte("ab"), 4096)) + " ab")
		for _, b := range wire {
			got = append(got, w.Rewrite([]byte{b}, false)...)
			if len(w.candidate) > len("ab.c")+4 || len(w.pending) > 12 {
				t.Fatalf("unbounded candidate/escape: %d/%d", len(w.candidate), len(w.pending))
			}
		}
		got = append(got, w.Rewrite(nil, true)...)
		want := "long " + string(bytes.Repeat([]byte("ab"), 4096)) + " short"
		if string(got) != want {
			t.Errorf("longest selection or long-token boundary changed: got %d bytes, want %d", len(got), len(want))
		}
	}
}
