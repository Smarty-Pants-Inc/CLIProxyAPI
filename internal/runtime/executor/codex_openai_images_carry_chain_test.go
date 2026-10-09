package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// #7705: a rotated turn ID overlaps every adjacent pair of cache IDs. The
// former per-needle carry heuristic walks back to its floor inside a cache ID,
// and sequential confuse/expose passes also let turn matches hide cache IDs.
func TestCodexDirectImageStreamRotatedIdentityCarryChain(t *testing.T) {
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	turnID := confused[1:] + confused[:1]
	confusedTurn := codexIdentityConfuseUUID(identityTestAuthID, "turn", turnID)
	const repetitions = 900 // 32,400 bytes: fits in the executor's 32 KiB read.
	wire := strings.Repeat(confused, repetitions)
	want := strings.Repeat(identityTestCacheKey, repetitions)
	for _, tc := range []struct {
		name      string
		fragments [][]byte
	}{
		{"floor-chain", [][]byte{[]byte(wire)}},
		{"split-cache", [][]byte{[]byte(wire[:len(wire)-17]), []byte(wire[len(wire)-17:])}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := identityImageAuth("https://images.example.invalid")
			auth.Attributes["header:X-Codex-Turn-Metadata"] = fmt.Sprintf(`{"turn_id":%q}`, turnID)
			reader := &imageIdentitySplitReader{fragments: tc.fragments}
			transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
				body, errRead := io.ReadAll(req.Body)
				if errRead != nil {
					return nil, errRead
				}
				if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != confused {
					t.Errorf("wire cache key = %q, want %q", got, confused)
				}
				if got := gjson.Get(req.Header.Get("X-Codex-Turn-Metadata"), "turn_id").String(); got != confusedTurn {
					t.Errorf("wire turn ID = %q, want registered rotation's remapping %q", got, confusedTurn)
				}
				return imageIdentityResponse(req, reader, true), nil
			})
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
			result, errStream := NewCodexExecutor(imageIdentityRuleConfig(true, "none")).ExecuteStream(ctx, auth, cliproxyexecutor.Request{
				Model: "gpt-image-2", Payload: identityImagePayload(),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
			if errStream != nil {
				t.Fatalf("ExecuteStream: %v", errStream)
			}
			var output bytes.Buffer
			chunks := 0
			unsafeChunks := 0
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Errorf("stream error: %v", chunk.Err)
				}
				// Each emitted chunk must consist of complete restored cache
				// keys, not just become safe after the consumer joins it.
				if len(chunk.Payload)%len(identityTestCacheKey) != 0 ||
					!bytes.Equal(chunk.Payload, bytes.Repeat([]byte(identityTestCacheKey), len(chunk.Payload)/len(identityTestCacheKey))) {
					unsafeChunks++
				}
				output.Write(chunk.Payload)
				chunks++
			}
			if unsafeChunks != 0 {
				t.Errorf("%d of %d client chunks contain partial or unexposed cache identities", unsafeChunks, chunks)
			}
			if got := output.String(); got != want {
				t.Errorf("rotation carry chain: reassembled client output differs: got %d bytes, want %d restored bytes", len(got), len(want))
			}
			if bytes.Contains(output.Bytes(), []byte(confused)) || bytes.Contains(output.Bytes(), []byte(confusedTurn)) {
				t.Error("rotation carry chain leaks a credential-scoped identity to the client")
			}
			if reader.reads != len(tc.fragments) || !reader.closed || chunks == 0 {
				t.Errorf("reads=%d closed=%t chunks=%d, want %d reads, closed, nonempty output", reader.reads, reader.closed, chunks, len(tc.fragments))
			}
		})
	}
}

// A complete shorter match must not win while a longer original turn ID is
// still possible. Conversely a shorter original turn must not hide the longer
// confused cache ID. These exercise the unified client mapping on the real path
// at every byte split, including exactly the end of the shorter full prefix.
func TestCodexDirectImageStreamCarryLeftmostLongestEverySplit(t *testing.T) {
	confused := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	for _, tc := range []struct {
		name, turnID, wire, want string
	}{
		{"shorter-turn-prefix", confused[:12], confused, identityTestCacheKey},
		{"longer-turn-full-prefix", confused + "-turn", confused + "-turn", confused + "-turn"},
		{"longer-turn-mismatch", confused + "-turn", confused + "-other", identityTestCacheKey + "-other"},
		{"longer-turn-prefix-at-EOF", confused + "-turn", confused, identityTestCacheKey},
	} {
		for split := 1; split < len(tc.wire); split++ {
			t.Run(fmt.Sprintf("%s/byte=%d", tc.name, split), func(t *testing.T) {
				auth := identityImageAuth("https://images.example.invalid")
				auth.Attributes["header:X-Codex-Turn-Metadata"] = fmt.Sprintf(`{"turn_id":%q}`, tc.turnID)
				reader := &imageIdentitySplitReader{fragments: [][]byte{
					[]byte(tc.wire[:split]), []byte(tc.wire[split:]),
				}}
				result := imageChunkTestStream(t, context.Background(), imageIdentityRuleConfig(true, "none"), auth, identityImagePayload(), reader)
				var output bytes.Buffer
				confusedTurn := []byte(codexIdentityConfuseUUID(identityTestAuthID, "turn", tc.turnID))
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Errorf("stream error: %v", chunk.Err)
					}
					if bytes.Contains(chunk.Payload, confusedTurn) {
						t.Error("client chunk contains confused turn ID")
					}
					output.Write(chunk.Payload)
				}
				if got := output.String(); got != tc.want {
					t.Errorf("leftmost-longest restoration: got %q, want %q", got, tc.want)
				}
				if reader.reads != 2 || !reader.closed {
					t.Errorf("reads=%d closed=%t, want 2, true", reader.reads, reader.closed)
				}
			})
		}
	}
}

func TestCodexImageCarryCutLeftmostLongestOverlaps(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pending string
		needles []string
		wantCut int
	}{
		// The full abcd match wins over its prefix and the later bcde.
		{"overlap", "abcde", []string{"ab", "bcde", "abcd"}, 5},
		// Even though ab is complete, abcd can still finish in the next read.
		{"full-prefix", "ab", []string{"ab", "abcd"}, 0},
		{"longer-prefix", "abc", []string{"ab", "abcd"}, 0},
		{"completed-longer-prefix", "abcd", []string{"ab", "abcd"}, 4},
		{"failed-longer-prefix", "abx", []string{"ab", "abcd"}, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Reversing rule order must not change leftmost-longest selection.
			for _, reverse := range []bool{false, true} {
				needles := make([][]byte, len(tc.needles))
				maxLen := 0
				for i, needle := range tc.needles {
					index := i
					if reverse {
						index = len(tc.needles) - 1 - i
					}
					needles[index] = []byte(needle)
					maxLen = max(maxLen, len(needle))
				}
				if got := codexImageCarryCut([]byte(tc.pending), needles, maxLen); got != tc.wantCut {
					t.Errorf("reverse=%t: cut=%d, want leftmost-longest cut=%d", reverse, got, tc.wantCut)
				}
			}
		})
	}
}

func TestCodexImageCarryCutSelfOverlapOneMiBTightBound(t *testing.T) {
	pending := bytes.Repeat([]byte("a"), 1<<20)
	for _, needles := range [][][]byte{
		{[]byte("aa")},
		{[]byte("aa"), []byte("aaa"), []byte("aaaaa")},
		{[]byte("aa"), []byte("0123456789abcdef0123456789abcdef")},
	} {
		maxLen := 0
		for _, needle := range needles {
			maxLen = max(maxLen, len(needle))
		}
		cut := codexImageCarryCut(pending, needles, maxLen)
		if cut < 0 || cut > len(pending) {
			t.Fatalf("invalid cut %d for %d bytes", cut, len(pending))
		}
		if carry := len(pending) - cut; carry > maxLen-1 {
			t.Errorf("maxLen=%d: 1 MiB self-overlap carry=%d, want <=%d", maxLen, carry, maxLen-1)
		}
	}
}
