package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// Both PR contracts on the real image stream: split identities/JSON escapes,
// split SSE event framing, longer tokens untouched, and generated values that
// equal another source are never rematched in either view.
func TestCodexDirectImageStreamIdentityWholeTokensSinglePassAcrossEvents(t *testing.T) {
	cache := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	// The hidden cache replacement equals the original turn ID. Conversely,
	// exposing the confused turn generates cache, itself another expose source.
	turn := codexIdentityConfuseUUID(identityTestAuthID, "turn", cache)
	metadata := ": ab\r\nevent: ab\r\nid: ab\r\n"
	firstPrefix := metadata + `data: {"ab":"key stays","hidden":"` + identityTestCacheKey + `","cache":"` + cache + `","turn":"` + turn + `","long":"prefix-ab-suffix ` + cache + `-other","rule":"`
	firstSuffix := `","escaped":"\u0061\u0062"}` + "\r\n\r\n"
	second := "data: table cab key ab rejected; key=" + cache + "; turn=" + turn + "; prefix-ab-suffix\r\n\r\n"
	wire := firstPrefix + "ab" + firstSuffix + second
	want := metadata + `data: {"ab":"key stays","hidden":"` + identityTestCacheKey + `","cache":"` + identityTestCacheKey + `","turn":"` + cache + `","long":"prefix-ab-suffix ` + cache + `-other","rule":"` + identityTestCacheKey + `","escaped":"` + identityTestCacheKey + `"}` + "\r\n\r\n" +
		"data: table cab key " + identityTestCacheKey + " rejected; key=" + identityTestCacheKey + "; turn=" + cache + "; prefix-ab-suffix\r\n\r\n"
	// One run has all three kinds of split simultaneously. The other runs
	// exercise every boundary, including decoded right boundaries and escapes.
	fragmentSets := [][][]byte{{
		[]byte(firstPrefix + "a"),
		[]byte(`b","escaped":"\u0061\u00`),
		[]byte("62\"}\r\n\r"),
		[]byte("\n" + second),
	}}
	for split := 1; split < len(wire); split++ {
		fragmentSets = append(fragmentSets, [][]byte{[]byte(wire[:split]), []byte(wire[split:])})
	}
	for split, fragments := range fragmentSets {
		t.Run(fmt.Sprintf("split=%d", split), func(t *testing.T) {
			cfg := ruleKeyRestoreImageConfig("ab")
			cfg.RequestLog = true
			auth := identityImageAuth("https://images.example.invalid")
			auth.Attributes["header:X-Codex-Turn-Metadata"] = fmt.Sprintf(`{"turn_id":%q}`, cache)
			reader := &imageIdentitySplitReader{fragments: fragments}
			transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
				body, errRead := io.ReadAll(req.Body)
				if errRead != nil {
					return nil, errRead
				}
				if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != "ab" {
					t.Errorf("final rule key = %q, want ab", got)
				}
				if got := gjson.Get(req.Header.Get("X-Codex-Turn-Metadata"), "turn_id").String(); got != turn {
					t.Errorf("wire turn = %q, want %q", got, turn)
				}
				return imageIdentityResponse(req, reader, true), nil
			})
			ginCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
			ctx := context.WithValue(context.Background(), "gin", ginCtx)
			ctx = context.WithValue(ctx, "cliproxy.roundtripper", transport)
			result, err := NewCodexExecutor(cfg).ExecuteStream(ctx, auth, cliproxyexecutor.Request{
				Model: "gpt-image-2", Payload: identityImagePayload(),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
			if err != nil {
				t.Fatalf("ExecuteStream: %v", err)
			}
			var output bytes.Buffer
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Errorf("stream error: %v", chunk.Err)
				}
				output.Write(chunk.Payload)
			}
			if output.String() != want {
				t.Errorf("whole-token single-pass client view:\n got %q\nwant %q", output.String(), want)
			}
			if reader.reads != len(fragments) || !reader.closed {
				t.Errorf("reads=%d closed=%t, want %d and true", reader.reads, reader.closed, len(fragments))
			}
			// Log capture adds separators between chunks. Remove those solely
			// for checking these fields, whose string contents have no newlines.
			logged, exists := ginCtx.Get("API_RESPONSE")
			logBytes, ok := logged.([]byte)
			if !exists || !ok {
				t.Fatalf("API_RESPONSE = %#v, want captured hidden view", logged)
			}
			hidden := strings.NewReplacer("\r", "", "\n", "").Replace(string(logBytes))
			for _, field := range []string{`"hidden":"` + cache + `"`, `"cache":"` + cache + `"`, `"turn":"` + turn + `"`, `"rule":"ab"`, `"escaped":"\u0061\u0062"`} {
				if !strings.Contains(hidden, field) {
					t.Errorf("hidden view missing %s: %s", field, hidden)
				}
			}
		})
	}
}

func TestCodexDirectImageWholeBodyIdentityWholeTokensSinglePass(t *testing.T) {
	cache := codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)
	turn := codexIdentityConfuseUUID(identityTestAuthID, "turn", cache)
	wire := `{"ab":"object key","hidden":"` + identityTestCacheKey + `","cache":"` + cache + `","turn":"` + turn + `","rule":"\u0061b","long":"cab abβ ` + cache + `-other"}`
	want := `{"ab":"object key","hidden":"` + identityTestCacheKey + `","cache":"` + identityTestCacheKey + `","turn":"` + cache + `","rule":"` + identityTestCacheKey + `","long":"cab abβ ` + cache + `-other"}`
	for _, tc := range []struct {
		name   string
		status int
		stream bool
	}{{"success", 200, false}, {"error", 500, false}, {"stream-error", 500, true}} {
		t.Run(tc.name, func(t *testing.T) {
			auth := identityImageAuth("https://images.example.invalid")
			auth.Attributes["header:X-Codex-Turn-Metadata"] = fmt.Sprintf(`{"turn_id":%q}`, cache)
			transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
				_, _ = io.ReadAll(req.Body)
				resp := imageIdentityResponse(req, io.NopCloser(strings.NewReader(wire)), false)
				resp.StatusCode = tc.status
				return resp, nil
			})
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
			exec := NewCodexExecutor(ruleKeyRestoreImageConfig("ab"))
			req := cliproxyexecutor.Request{Model: "gpt-image-2", Payload: identityImagePayload()}
			var got string
			if tc.stream {
				_, err := exec.ExecuteStream(ctx, auth, req, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
				if err == nil {
					t.Fatal("expected status error")
				}
				got = err.Error()
			} else {
				resp, err := exec.Execute(ctx, auth, req, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
				if tc.status == 200 {
					if err != nil {
						t.Fatalf("Execute: %v", err)
					}
					got = string(resp.Payload)
				} else {
					if err == nil {
						t.Fatal("expected status error")
					}
					got = err.Error()
				}
			}
			if got != want {
				t.Errorf("whole-body client view:\n got %q\nwant %q", got, want)
			}
		})
	}
}
