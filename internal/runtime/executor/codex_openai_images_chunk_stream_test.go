package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

// Every read after the first waits for the test to inspect how many bytes have
// already reached the client. This detects read-ahead/line buffering without
// sleeps, deadlines, or unsynchronized observations of the reader goroutine.
type imageChunkReadGate struct {
	ctx       context.Context
	fragments [][]byte
	nextRead  chan int
	resume    chan struct{}
	bytesRead int
}

func (r *imageChunkReadGate) Read(p []byte) (int, error) {
	if r.bytesRead > 0 {
		select {
		case r.nextRead <- r.bytesRead:
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
		select {
		case <-r.resume:
		case <-r.ctx.Done():
			return 0, r.ctx.Err()
		}
	}
	if len(r.fragments) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.fragments[0])
	r.bytesRead += n
	r.fragments[0] = r.fragments[0][n:]
	if len(r.fragments[0]) == 0 {
		r.fragments = r.fragments[1:]
	}
	// EOF requires another (gated) read: all preceding observations are made
	// while the upstream is still open, not after EOF caused a buffer flush.
	return n, nil
}

func (r *imageChunkReadGate) Close() error { return nil }

func imageChunkTestStream(t *testing.T, ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth, payload []byte, body io.ReadCloser) *cliproxyexecutor.StreamResult {
	t.Helper()
	transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
		return imageIdentityResponse(req, body, true), nil
	})
	ctx = context.WithValue(ctx, "cliproxy.roundtripper", transport)
	result, err := NewCodexExecutor(cfg).ExecuteStream(ctx, auth, cliproxyexecutor.Request{
		Model: "gpt-image-2", Payload: payload,
	}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
	if err != nil {
		t.Fatalf("ExecuteStream: %v", err)
	}
	return result
}

func TestCodexDirectImageStreamInactiveReadChunks(t *testing.T) {
	// Include arbitrary binary bytes, splits inside CRLF and JSON, and a large
	// body without any newline. None may alter the upstream read boundaries.
	fragments := [][]byte{
		[]byte(": comment\r"), []byte("\n\ndata: {\"b64_json\":\""),
		{0, 0xff, 0xc3}, {0xa9}, []byte("AA==\"}\n\n"),
	}
	largeFragments := make([][]byte, 32)
	for i := range largeFragments {
		largeFragments[i] = bytes.Repeat([]byte("A"), 32*1024)
	}
	for _, tc := range []struct {
		name      string
		enabled   bool
		payload   []byte
		fragments [][]byte
	}{
		{"arbitrary-bytes", false, identityImagePayload(), fragments},
		{"1MiB-no-newline", false, identityImagePayload(), largeFragments},
		// The flag alone does not require a carry: there are no replacements
		// when the request has neither a cache key nor any turn identifiers.
		{"enabled-without-identifiers", true, []byte(`{"model":"gpt-image-2","prompt":"otter"}`), fragments},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := &imageChunkReadGate{
				ctx: ctx, fragments: append([][]byte(nil), tc.fragments...),
				nextRead: make(chan int), resume: make(chan struct{}),
			}
			result := imageChunkTestStream(t, ctx, imageIdentityRuleConfig(tc.enabled, "none"), identityImageAuth("https://images.example.invalid"), tc.payload, reader)
			defer func() {
				cancel()
				for range result.Chunks {
				}
			}()
			chunks, forwarded := 0, 0
			for {
				select {
				case chunk, ok := <-result.Chunks:
					if !ok {
						if chunks != len(tc.fragments) {
							t.Fatalf("forwarded %d chunks, want %d upstream reads", chunks, len(tc.fragments))
						}
						return
					}
					if chunk.Err != nil {
						t.Fatalf("stream error: %v", chunk.Err)
					}
					if chunks >= len(tc.fragments) || !bytes.Equal(chunk.Payload, tc.fragments[chunks]) {
						t.Fatalf("chunk %d has %d bytes, want the identical upstream read", chunks, len(chunk.Payload))
					}
					if len(chunk.Payload) > 32*1024 {
						t.Fatalf("chunk has %d bytes, exceeds 32 KiB", len(chunk.Payload))
					}
					chunks++
					forwarded += len(chunk.Payload)
				case bytesRead := <-reader.nextRead:
					if forwarded != bytesRead {
						t.Fatalf("read ahead before forwarding: read=%d forwarded=%d (no newline/EOF yet)", bytesRead, forwarded)
					}
					reader.resume <- struct{}{}
				}
			}
		})
	}
}

func TestCodexDirectImageStreamActiveEveryIdentifierSplit(t *testing.T) {
	const turnID = "client-image-turn-αβ"
	longRuleKey := "operator-image-key-" + strings.Repeat("r", 80)
	confusedKey := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	confusedTurn := codexIdentityConfuseUUID(identityTestAuthID, "turn", turnID)
	for _, tc := range []struct {
		name, needle, original string
	}{
		{"original-cache", identityTestCacheKey, identityTestCacheKey},
		{"confused-cache", confusedKey, identityTestCacheKey},
		{"rule-key", longRuleKey, identityTestCacheKey},
		{"original-turn", turnID, turnID},
		{"confused-turn", confusedTurn, turnID},
	} {
		for split := 1; split < len(tc.needle); split++ {
			t.Run(fmt.Sprintf("%s/byte=%d", tc.name, split), func(t *testing.T) {
				cfg := imageIdentityRuleConfig(true, "none")
				if tc.name == "rule-key" {
					cfg.Payload.Override = []config.PayloadRule{{
						Models: []config.PayloadModelRule{{Name: "gpt-image-2", Protocol: "openai"}},
						Params: map[string]any{"prompt_cache_key": longRuleKey},
					}}
				}
				auth := identityImageAuth("https://images.example.invalid")
				auth.Attributes["header:X-Codex-Turn-Metadata"] = `{"turn_id":"` + turnID + `"}`
				prefix, suffix := "data: {\"revised_prompt\":\"key=", "\"}"
				reader := &imageIdentitySplitReader{fragments: [][]byte{
					[]byte(prefix + tc.needle[:split]), []byte(tc.needle[split:] + suffix),
				}}
				result := imageChunkTestStream(t, context.Background(), cfg, auth, identityImagePayload(), reader)
				var output bytes.Buffer
				wholeIdentifier := false
				for chunk := range result.Chunks {
					if chunk.Err != nil {
						t.Errorf("stream error: %v", chunk.Err)
					}
					wholeIdentifier = wholeIdentifier || bytes.Contains(chunk.Payload, []byte(tc.original))
					output.Write(chunk.Payload)
				}
				if got, want := output.String(), prefix+tc.original+suffix; got != want {
					t.Errorf("split identifier: got %q, want %q", got, want)
				}
				if !wholeIdentifier || reader.reads != 2 || !reader.closed {
					t.Errorf("whole identifier=%t reads=%d closed=%t, want true, 2, true", wholeIdentifier, reader.reads, reader.closed)
				}
			})
		}
	}
}

func TestCodexDirectImageStreamUsageLineBoundaries(t *testing.T) {
	first := `data: {"usage":{"input_tokens":4,"output_tokens":6,"total_tokens":10}}`
	second := `data: {"usage":{"input_tokens":12,"output_tokens":18,"total_tokens":30}}`
	for _, tc := range []struct {
		name      string
		fragments [][]byte
	}{
		{"CR", [][]byte{[]byte(first + "\r\r" + second + "\r\r")}},
		{"LF", [][]byte{[]byte(first + "\n\n" + second + "\n\n")}},
		{"CRLF", [][]byte{[]byte(first + "\r\n\r\n" + second + "\r\n\r\n")}},
		{"split-CRLF", [][]byte{[]byte(first + "\r"), []byte("\n\r"), []byte("\n" + second + "\r"), []byte("\n\r\n")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var observed []string
			var streamUsage helps.StreamUsageBuffer
			for _, fragment := range tc.fragments {
				helps.ObserveStreamUsageChunkLines(fragment, func(line []byte) {
					observed = append(observed, string(line))
					streamUsage.ObserveOpenAIStream(line)
				})
			}
			if len(observed) != 2 || observed[0] != first || observed[1] != second {
				t.Fatalf("usage observations = %q, want each event exactly once and no empty fragments", observed)
			}
			if detail, ok := streamUsage.Detail(); !ok || detail.TotalTokens != 30 {
				t.Errorf("observed usage = %+v, ok=%t, want final event total=30", detail, ok)
			}

			capture := &multiProviderUsageCapture{alias: t.Name(), records: make(chan coreusage.Record, 4)}
			coreusage.RegisterNamedPlugin(t.Name(), capture)
			t.Cleanup(func() { coreusage.RegisterNamedPlugin(t.Name(), multiProviderNoopUsagePlugin{}) })
			ctx := coreusage.WithRequestedModelAlias(context.Background(), t.Name())
			reader := &imageIdentitySplitReader{fragments: append([][]byte(nil), tc.fragments...)}
			result := imageChunkTestStream(t, ctx, imageIdentityRuleConfig(false, "none"), identityImageAuth("https://images.example.invalid"), identityImagePayload(), reader)
			var output bytes.Buffer
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Errorf("stream error: %v", chunk.Err)
				}
				output.Write(chunk.Payload)
			}
			if !bytes.Equal(output.Bytes(), bytes.Join(tc.fragments, nil)) {
				t.Error("line observation changed forwarded bytes")
			}
			record := capture.await(t)
			if record.Detail.InputTokens != 12 || record.Detail.OutputTokens != 18 || record.Detail.TotalTokens != 30 {
				t.Errorf("last event usage = %+v, want input=12 output=18 total=30", record.Detail)
			}
		})
	}
}

func TestCodexDirectImageStreamActiveBoundedCarry(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body := bytes.Repeat([]byte("A"), 4*1024*1024)
	maxLen := len(codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey))
	reader := &imageChunkReadGate{
		ctx: ctx, fragments: [][]byte{body}, nextRead: make(chan int), resume: make(chan struct{}),
	}
	result := imageChunkTestStream(t, ctx, imageIdentityRuleConfig(true, "none"), identityImageAuth("https://images.example.invalid"), identityImagePayload(), reader)
	defer func() {
		cancel()
		for range result.Chunks {
		}
	}()
	var output bytes.Buffer
	peakCarry, chunks, chunksBeforeEOF := 0, 0, 0
	for {
		select {
		case chunk, ok := <-result.Chunks:
			if !ok {
				if !bytes.Equal(output.Bytes(), body) || chunksBeforeEOF < 128 {
					t.Fatalf("forwarded=%d chunks before EOF=%d, want 4 MiB in at least 128 chunks", output.Len(), chunksBeforeEOF)
				}
				t.Logf("4 MiB stream: %d chunks before EOF; peak carry=%d, bound=%d", chunksBeforeEOF, peakCarry, maxLen*2)
				return
			}
			if chunk.Err != nil {
				t.Fatalf("stream error: %v", chunk.Err)
			}
			if len(chunk.Payload) > 32*1024+maxLen*2 {
				t.Fatalf("chunk has %d bytes, exceeds bounded read plus carry", len(chunk.Payload))
			}
			output.Write(chunk.Payload)
			chunks++
		case bytesRead := <-reader.nextRead:
			// Filler contains no identifiers, so input bytes minus emitted
			// bytes is exactly the retained carry, observed before every read.
			carry := bytesRead - output.Len()
			peakCarry = max(peakCarry, carry)
			if carry < 0 || carry > maxLen*2 {
				t.Fatalf("unbounded carry before EOF: read=%d forwarded=%d carry=%d, bound=%d", bytesRead, output.Len(), carry, maxLen*2)
			}
			if bytesRead == len(body) {
				chunksBeforeEOF = chunks
			}
			reader.resume <- struct{}{}
		}
	}
}
