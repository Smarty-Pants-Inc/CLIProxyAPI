package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
	"github.com/tidwall/gjson"
)

// smarty-dev#7599: a short operator-owned key is an identity only as a
// complete string/token, never as part of a word, identifier, JSON key or number.
func ruleKeyRestoreImageConfig(key string) *config.Config {
	cfg := imageIdentityRuleConfig(true, "none")
	cfg.Payload.Override = []config.PayloadRule{{
		Models: []config.PayloadModelRule{{Name: "gpt-image-2", Protocol: "openai"}},
		Params: map[string]any{"prompt_cache_key": key},
	}}
	return cfg
}

func ruleKeyRestoreAssertJSON(t *testing.T, got []byte, want string) {
	t.Helper()
	var actual, expected any
	if err := json.Unmarshal(got, &actual); err != nil {
		t.Fatalf("client payload is no longer JSON: %v: %q", err, got)
	}
	if err := json.Unmarshal([]byte(want), &expected); err != nil {
		t.Fatalf("invalid expected JSON: %v", err)
	}
	if !reflect.DeepEqual(actual, expected) {
		t.Errorf("identity restoration changed non-identity content:\n got %s\nwant %s", got, want)
	}
}

func ruleKeyRestoreImageTransport(t *testing.T, response string, stream bool) imageIdentityRoundTripper {
	t.Helper()
	return imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			return nil, errRead
		}
		if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != "ab" {
			t.Errorf("final payload rule key = %q, want ab", got)
		}
		return imageIdentityResponse(req, io.NopCloser(strings.NewReader(response)), stream), nil
	})
}

func TestCodexRuleKeyRestoreDirectImageJSON(t *testing.T) {
	for _, tc := range []struct {
		name, key, wire, want string
	}{
		{
			name: "short-key-and-escaped-strings", key: "ab",
			wire: `{"created":1,"ab":"object key stays","data":[{"revised_prompt":"table cab prefix-ab-suffix éab abβ ab_thing ab123 key ab rejected; key=ab","exact":"ab","escaped":"\u0061\u0062","escaped_sentence":"quote: \"ab\"; key \u0061b rejected; t\u0061ble","unicode":"αab ab界 ab\u0301","nested":{"ab":"ab"}}]}`,
			want: `{"created":1,"ab":"object key stays","data":[{"revised_prompt":"table cab prefix-ab-suffix éab abβ ab_thing ab123 key ` + identityTestCacheKey + ` rejected; key=` + identityTestCacheKey + `","exact":"` + identityTestCacheKey + `","escaped":"` + identityTestCacheKey + `","escaped_sentence":"quote: \"` + identityTestCacheKey + `\"; key ` + identityTestCacheKey + ` rejected; table","unicode":"αab ab界 ab\u0301","nested":{"ab":"` + identityTestCacheKey + `"}}]}`,
		},
		{
			name: "unicode-escaped-operator-key", key: "😀",
			wire: `{"data":[{"exact":"😀","upper":"\uD83D\uDE00","mixed":"\ud83d\uDE00","lower":"\ud83d\ude00"}]}`,
			want: `{"data":[{"exact":"` + identityTestCacheKey + `","upper":"` + identityTestCacheKey + `","mixed":"` + identityTestCacheKey + `","lower":"` + identityTestCacheKey + `"}]}`,
		},
		{
			name: "numeric-looking-key", key: "12",
			wire: `{"12":"object key stays","number":12,"negative":-12,"decimal":12.5,"exponent":12e2,"data":[{"revised_prompt":"prefix-12-suffix x12 12β key 12 rejected","exact":"12"}]}`,
			want: `{"12":"object key stays","number":12,"negative":-12,"decimal":12.5,"exponent":12e2,"data":[{"revised_prompt":"prefix-12-suffix x12 12β key ` + identityTestCacheKey + ` rejected","exact":"` + identityTestCacheKey + `"}]}`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
				body, errRead := io.ReadAll(req.Body)
				if errRead != nil {
					return nil, errRead
				}
				if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != tc.key {
					t.Errorf("final payload rule key = %q, want %q", got, tc.key)
				}
				return imageIdentityResponse(req, io.NopCloser(strings.NewReader(tc.wire)), false), nil
			})
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
			response, err := NewCodexExecutor(ruleKeyRestoreImageConfig(tc.key)).Execute(ctx, identityImageAuth("https://images.example.invalid"), cliproxyexecutor.Request{
				Model: "gpt-image-2", Payload: identityImagePayload(),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			ruleKeyRestoreAssertJSON(t, response.Payload, tc.want)
		})
	}
}

func TestCodexRuleKeyRestoreHTTPResponsesSSE(t *testing.T) {
	wire := strings.Replace(identityTestCompleted("ab"), `"response":{"id":`, `"response":{"ab":"object key stays","id":`, 1)
	wire = strings.Replace(wire, `"text":"key=ab"`, `"text":"table cab prefix-ab-suffix éab abβ key ab rejected; key=ab"`, 1)
	want := strings.Replace(wire, `"prompt_cache_key":"ab"`, `"prompt_cache_key":"`+identityTestCacheKey+`"`, 1)
	want = strings.Replace(want, "key ab rejected; key=ab", "key "+identityTestCacheKey+" rejected; key="+identityTestCacheKey, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			t.Errorf("read request: %v", errRead)
		}
		if got := gjson.GetBytes(body, "prompt_cache_key").String(); got != "ab" {
			t.Errorf("final payload rule key = %q, want ab", got)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprintf(w, "data: %s\n\n", wire)
	}))
	defer server.Close()
	cfg := identityRuleConfig(true)
	cfg.Payload.Override[0].Params["prompt_cache_key"] = "ab"
	result, err := NewCodexExecutor(cfg).ExecuteStream(context.Background(), identityTestAuth(server.URL), cliproxyexecutor.Request{
		Model: "gpt-5.5", Payload: identityTestPayload(),
	}, cliproxyexecutor.Options{SourceFormat: sdktranslator.FromString("codex"), Stream: true})
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
	found := false
	for _, line := range strings.Split(output.String(), "\n") {
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if gjson.Get(data, "type").String() == "response.completed" {
			found = true
			ruleKeyRestoreAssertJSON(t, []byte(data), want)
		}
	}
	if !found {
		t.Fatalf("no completed response in client SSE: %q", output.String())
	}
}

func TestCodexRuleKeyRestoreHTTPNonJSONError(t *testing.T) {
	const wire = "ab\nkey ab rejected; key=ab; table cab prefix-ab-suffix éab abβ ab_thing ab123"
	want := identityTestCacheKey + "\nkey " + identityTestCacheKey + " rejected; key=" + identityTestCacheKey + "; table cab prefix-ab-suffix éab abβ ab_thing ab123"
	for _, stream := range []bool{false, true} {
		t.Run(fmt.Sprintf("stream=%t", stream), func(t *testing.T) {
			transport := ruleKeyRestoreImageTransport(t, wire, false)
			failingTransport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(req)
				if response != nil {
					response.StatusCode = http.StatusBadRequest
					response.Header.Set("Content-Type", "text/plain")
				}
				return response, err
			})
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", failingTransport)
			exec := NewCodexExecutor(ruleKeyRestoreImageConfig("ab"))
			req := cliproxyexecutor.Request{Model: "gpt-image-2", Payload: identityImagePayload()}
			var err error
			if stream {
				_, err = exec.ExecuteStream(ctx, identityImageAuth("https://images.example.invalid"), req, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
			} else {
				_, err = exec.Execute(ctx, identityImageAuth("https://images.example.invalid"), req, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
			}
			if err == nil || err.Error() != want {
				t.Errorf("non-JSON error = %v, want exact body %q", err, want)
			}
		})
	}
}

func TestCodexRuleKeyRestoreDirectImageSSEEveryReadSplit(t *testing.T) {
	const metadata = ": ab\r\nevent: ab\r\nid: ab\r\n"
	const wireJSON = `{"ab":"object key stays","data":[{"revised_prompt":"table cab prefix-ab-suffix αab ab界 key ab rejected; key=ab","exact":"ab","escaped":"\u0061\u0062","quoted":"\"ab\""}]}`
	wantJSON := `{"ab":"object key stays","data":[{"revised_prompt":"table cab prefix-ab-suffix αab ab界 key ` + identityTestCacheKey + ` rejected; key=` + identityTestCacheKey + `","exact":"` + identityTestCacheKey + `","escaped":"` + identityTestCacheKey + `","quoted":"\"` + identityTestCacheKey + `\""}]}`
	wire := metadata + "data: " + wireJSON + "\r\n\r\n"
	// Every byte boundary includes both sides of ab, its surrounding token
	// characters, UTF-8 runes, JSON escapes and SSE framing, not just a|b.
	for split := 1; split < len(wire); split++ {
		t.Run(fmt.Sprintf("byte=%d", split), func(t *testing.T) {
			reader := &imageIdentitySplitReader{fragments: [][]byte{[]byte(wire[:split]), []byte(wire[split:])}}
			result := imageChunkTestStream(t, context.Background(), ruleKeyRestoreImageConfig("ab"), identityImageAuth("https://images.example.invalid"), identityImagePayload(), reader)
			var output bytes.Buffer
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					t.Errorf("stream error: %v", chunk.Err)
				}
				output.Write(chunk.Payload)
			}
			if reader.reads != 2 || !reader.closed {
				t.Errorf("response body: reads=%d closed=%t, want 2 and true", reader.reads, reader.closed)
			}
			got := output.String()
			if !strings.HasPrefix(got, metadata+"data: ") || !strings.HasSuffix(got, "\r\n\r\n") {
				t.Fatalf("SSE metadata/framing changed: %q", got)
			}
			ruleKeyRestoreAssertJSON(t, []byte(strings.TrimSuffix(strings.TrimPrefix(got, metadata+"data: "), "\r\n\r\n")), wantJSON)
		})
	}
}

func TestCodexRuleKeyRestoreCRDelimitedSSE(t *testing.T) {
	for _, separator := range []string{"\r", "\n", "\r\n"} {
		t.Run(fmt.Sprintf("separator=%q", separator), func(t *testing.T) {
			wire := "extension: keep" + separator + `data: {"ab":"table","exact":"ab"}` + separator + separator
			want := "extension: keep" + separator + `data: {"ab":"table","exact":"` + identityTestCacheKey + `"}` + separator + separator
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", ruleKeyRestoreImageTransport(t, wire, true))
			response, err := NewCodexExecutor(ruleKeyRestoreImageConfig("ab")).Execute(ctx, identityImageAuth("https://images.example.invalid"), cliproxyexecutor.Request{
				Model: "gpt-image-2", Payload: identityImagePayload(),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false))
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if string(response.Payload) != want {
				t.Errorf("SSE string values/framing changed:\n got %q\nwant %q", response.Payload, want)
			}
		})
	}
}

func TestCodexRuleKeyRestoreDirectImageStreamBoundedSelfOverlap(t *testing.T) {
	for _, key := range []string{"ab", "aa"} {
		t.Run(key, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			// The repeated key is one long identifier. It crosses both upstream
			// reads and client emissions; left-context cannot be forgotten at a cut.
			prefix := "data: {\"long\":\"prefix-" + strings.Repeat(key, 48*1024) + "-suffix\",\"exact\":\""
			wire := prefix + key + "\"}\n\n"
			want := prefix + identityTestCacheKey + "\"}\n\n"
			reader := &imageChunkReadGate{
				ctx: ctx, fragments: [][]byte{[]byte(wire)}, nextRead: make(chan int), resume: make(chan struct{}),
			}
			result := imageChunkTestStream(t, ctx, ruleKeyRestoreImageConfig(key), identityImageAuth("https://images.example.invalid"), identityImagePayload(), reader)
			defer func() {
				cancel()
				for range result.Chunks {
				}
			}()
			bound := 2 * max(len(codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)), len(identityTestCacheKey), len(key))
			var output bytes.Buffer
			chunksBeforeTail := 0
			for {
				select {
				case chunk, ok := <-result.Chunks:
					if !ok {
						if output.String() != want {
							t.Errorf("long identifier rewritten or exact key not restored: got %d bytes, want %d", output.Len(), len(want))
						}
						if chunksBeforeTail < 2 {
							t.Errorf("only %d chunks before final read; long identifier was buffered", chunksBeforeTail)
						}
						return
					}
					if chunk.Err != nil {
						t.Fatalf("stream error: %v", chunk.Err)
					}
					if len(chunk.Payload) > 32*1024+bound {
						t.Fatalf("chunk=%d exceeds read plus bounded carry=%d", len(chunk.Payload), 32*1024+bound)
					}
					output.Write(chunk.Payload)
				case bytesRead := <-reader.nextRead:
					if bytesRead < len(prefix) {
						// Until the exact trailing key, every output byte must be
						// unchanged, so byte accounting measures retained carry.
						if !bytes.HasPrefix([]byte(wire), output.Bytes()) {
							t.Fatal("rewrote an embedded key before the long identifier ended")
						}
						carry := bytesRead - output.Len()
						if carry < 0 || carry > bound {
							t.Fatalf("carry=%d (read=%d emitted=%d), bound=%d", carry, bytesRead, output.Len(), bound)
						}
						chunksBeforeTail++
					}
					reader.resume <- struct{}{}
				}
			}
		})
	}
}
