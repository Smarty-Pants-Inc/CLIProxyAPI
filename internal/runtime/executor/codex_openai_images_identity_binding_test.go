package executor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

// Direct images apply media payload rules after cacheHelper. Identity binding
// must therefore use the final media body, not cacheHelper's pre-rule body.
func imageIdentityRuleConfig(enabled bool, rule string) *config.Config {
	cfg := identityImageConfig()
	cfg.Codex.IdentityConfuse = enabled
	models := []config.PayloadModelRule{{Name: "gpt-image-2", Protocol: "openai"}}
	switch rule {
	case "set":
		cfg.Payload.Override = []config.PayloadRule{{Models: models, Params: map[string]any{"prompt_cache_key": identityTestOperatorKey}}}
	case "remove":
		cfg.Payload.Filter = []config.PayloadFilterRule{{Models: models, Params: []string{"prompt_cache_key"}}}
	case "empty":
		cfg.Payload.Override = []config.PayloadRule{{Models: models, Params: map[string]any{"prompt_cache_key": ""}}}
	case "null":
		cfg.Payload.OverrideRaw = []config.PayloadRule{{Models: models, Params: map[string]any{"prompt_cache_key": "null"}}}
	}
	return cfg
}

func imageIdentityHeaderAuth() *cliproxyauth.Auth {
	auth := identityImageAuth("https://images.example.invalid")
	// Populate every session spelling and derived key mirror, including the
	// nested metadata fields. A stale copy must not survive the final rule.
	for name, values := range identityKeyClientHeaders(identityTestCacheKey) {
		auth.Attributes["header:"+name] = values[0]
	}
	auth.Attributes["header:Session_id"] = identityTestCacheKey
	return auth
}

type imageIdentityRoundTripper func(*http.Request) (*http.Response, error)

func (f imageIdentityRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func imageIdentityResponse(req *http.Request, body io.ReadCloser, stream bool) *http.Response {
	contentType := "application/json"
	if stream {
		contentType = "text/event-stream"
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       body,
		Request:    req,
	}
}

func assertImageIdentityFinalRule(t *testing.T, rule string, body []byte, headers http.Header) {
	t.Helper()
	key := gjson.GetBytes(body, "prompt_cache_key")
	switch rule {
	case "set":
		if key.Type != gjson.String || key.String() != identityTestOperatorKey {
			t.Errorf("final body key = %s, want operator-owned string %q", key.Raw, identityTestOperatorKey)
		}
	case "remove":
		if key.Exists() {
			t.Errorf("filtered prompt_cache_key remains in final body: %s", body)
		}
	case "empty":
		if key.Type != gjson.String || key.String() != "" {
			t.Errorf("final prompt_cache_key = %s, want empty string", key.Raw)
		}
	case "null":
		if key.Raw != "null" {
			t.Errorf("final prompt_cache_key = %s, want explicit null", key.Raw)
		}
	}

	wantKey := ""
	wantWindow := ""
	if rule == "set" {
		wantKey = identityTestOperatorKey
		wantWindow = wantKey + ":0"
	}
	// Session header spelling may be preserved or consolidated by the existing
	// header application. Every surviving spelling must agree with the body.
	foundSession := false
	for _, name := range []string{"Session-Id", "Session_id"} {
		if got := headerValueCaseInsensitive(headers, name); got != "" {
			foundSession = true
			if got != wantKey {
				t.Errorf("final %s = %q, want %q bound to final body", name, got, wantKey)
			}
		}
	}
	if rule == "set" && !foundSession {
		t.Error("operator-owned final body key has no matching session header")
	}
	for _, name := range []string{"Conversation_id", "Thread-Id", "X-Client-Request-Id"} {
		if got := headerValueCaseInsensitive(headers, name); got != wantKey {
			t.Errorf("final %s = %q, want %q bound to final body", name, got, wantKey)
		}
	}
	if got := headers.Get("X-Codex-Window-Id"); got != wantWindow {
		t.Errorf("final X-Codex-Window-Id = %q, want %q", got, wantWindow)
	}
	metadata := headers.Get("X-Codex-Turn-Metadata")
	metadataFields := map[string]string{"prompt_cache_key": wantKey}
	checkedHeaders := headers.Clone()
	if rule == "set" {
		// The shared binder's metadata window_id replacement is owned by
		// smarty-dev#7620; this regression covers its existing binding contract.
		checkedHeaders.Del("X-Codex-Turn-Metadata")
	} else {
		metadataFields["window_id"] = wantWindow
	}
	for field, want := range metadataFields {
		got := gjson.Get(metadata, field)
		if got.String() != want || (rule != "set" && got.Exists()) {
			t.Errorf("final turn metadata %s = %s, want %q (absent for removed/empty/null)", field, got.Raw, want)
		}
	}
	for _, stale := range []string{identityTestCacheKey, codexIdentityConfuseUUID(identityTestAuthID, "prompt-cache", identityTestCacheKey)} {
		if headersContain(checkedHeaders, stale) {
			t.Errorf("final headers retain pre-rule identifier %q: %v", stale, headers)
		}
	}
}

func assertImageIdentityAttachedBody(t *testing.T, req *http.Request, finalBody []byte) {
	t.Helper()
	if req.ContentLength != int64(len(finalBody)) {
		t.Errorf("ContentLength = %d, want finalized body length %d", req.ContentLength, len(finalBody))
	}
	if req.GetBody == nil {
		t.Error("GetBody is nil for finalized request")
		return
	}
	replay, errGet := req.GetBody()
	if errGet != nil {
		t.Errorf("GetBody: %v", errGet)
		return
	}
	data, errRead := io.ReadAll(replay)
	if errClose := replay.Close(); errClose != nil {
		t.Errorf("close GetBody reader: %v", errClose)
	}
	if errRead != nil || !bytes.Equal(data, finalBody) {
		t.Errorf("GetBody = %q, error=%v, want finalized Body %q", data, errRead, finalBody)
	}
}

func TestCodexDirectImageExecuteStreamDataAndReadError(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enabled=%t", enabled), func(t *testing.T) {
			readErr := errors.New("image response read failed after trailing data")
			var reader *imageIdentitySplitReader
			var wantOutput string
			transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
				body, errRead := io.ReadAll(req.Body)
				if errRead != nil {
					return nil, errRead
				}
				assertImageIdentityAttachedBody(t, req, body)
				key := gjson.GetBytes(body, "prompt_cache_key").String()
				// Mixed CRLF/LF framing, comments, empty lines, and an
				// unterminated data line must all survive a terminal error.
				prefix := ": comment\r\n\r\nevent: image_generation.completed\ndata: {\"revised_prompt\":\"key="
				wireOutput := prefix + key + "\"}"
				wantOutput = wireOutput
				if enabled {
					wantOutput = strings.ReplaceAll(wireOutput, key, identityTestCacheKey)
				}
				reader = &imageIdentitySplitReader{
					fragments:   [][]byte{[]byte(prefix + key[:len(key)/2]), []byte(key[len(key)/2:] + "\"}")},
					terminalErr: readErr,
				}
				return imageIdentityResponse(req, reader, true), nil
			})
			ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
			exec := NewCodexExecutor(imageIdentityRuleConfig(enabled, "none"))
			result, err := exec.ExecuteStream(ctx, identityImageAuth("https://images.example.invalid"), cliproxyexecutor.Request{
				Model: "gpt-image-2", Payload: identityImagePayload(),
			}, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
			if err != nil {
				t.Fatalf("ExecuteStream: %v", err)
			}
			var output bytes.Buffer
			errorsSeen := 0
			for chunk := range result.Chunks {
				if chunk.Err != nil {
					errorsSeen++
					if !errors.Is(chunk.Err, readErr) {
						t.Errorf("terminal error = %v, want original read error", chunk.Err)
					}
				} else if errorsSeen != 0 {
					t.Error("payload delivered after terminal error")
				}
				output.Write(chunk.Payload)
			}
			if errorsSeen != 1 || reader.reads != 2 || !reader.closed {
				t.Errorf("errors=%d reads=%d closed=%t, want 1, 2, true", errorsSeen, reader.reads, reader.closed)
			}
			if got := output.String(); got != wantOutput {
				t.Errorf("data returned with read error or framing lost:\n got %q\nwant %q", got, wantOutput)
			}
		})
	}
}

func TestCodexDirectImagePayloadRuleIdentityBinding(t *testing.T) {
	for _, path := range []string{codexImagesGenerationsPath, codexImagesEditsPath} {
		for _, stream := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				for _, rule := range []string{"set", "remove", "empty", "null"} {
					t.Run(fmt.Sprintf("%s/stream=%t/enabled=%t/%s", path, stream, enabled, rule), func(t *testing.T) {
						var finalBody []byte
						var finalHeaders http.Header
						transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
							if want := strings.TrimPrefix(path, "/v1"); req.URL.Path != want {
								t.Errorf("upstream path = %q, want direct image path %q", req.URL.Path, want)
							}
							var errRead error
							finalBody, errRead = io.ReadAll(req.Body)
							if errRead != nil {
								return nil, errRead
							}
							assertImageIdentityAttachedBody(t, req, finalBody)
							finalHeaders = req.Header.Clone()
							key := gjson.GetBytes(finalBody, "prompt_cache_key").String()
							response := `{"created":1,"data":[{"b64_json":"AA==","revised_prompt":"key=` + key + `"}]}`
							if stream {
								response = "event: image_generation.completed\ndata: " + response + "\n\n"
							}
							return imageIdentityResponse(req, io.NopCloser(strings.NewReader(response)), stream), nil
						})
						ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
						exec := NewCodexExecutor(imageIdentityRuleConfig(enabled, rule))
						request := cliproxyexecutor.Request{Model: "gpt-image-2", Payload: identityImagePayload()}
						if path == codexImagesEditsPath {
							request.Payload = []byte(`{"model":"gpt-image-2","prompt":"Edit this otter","images":[{"image_url":"data:image/png;base64,AA=="}],"prompt_cache_key":"` + identityTestCacheKey + `"}`)
						}
						var output []byte
						if stream {
							result, err := exec.ExecuteStream(ctx, imageIdentityHeaderAuth(), request, codexOpenAIImageTestOptions(path, true))
							if err != nil {
								t.Fatalf("ExecuteStream: %v", err)
							}
							for chunk := range result.Chunks {
								if chunk.Err != nil {
									t.Errorf("stream error: %v", chunk.Err)
								}
								output = append(output, chunk.Payload...)
							}
						} else {
							response, err := exec.Execute(ctx, imageIdentityHeaderAuth(), request, codexOpenAIImageTestOptions(path, false))
							if err != nil {
								t.Fatalf("Execute: %v", err)
							}
							output = response.Payload
						}
						assertImageIdentityFinalRule(t, rule, finalBody, finalHeaders)
						if rule == "set" {
							want := identityTestOperatorKey
							if enabled {
								want = identityTestCacheKey
							}
							if !bytes.Contains(output, []byte("key="+want)) {
								t.Errorf("client output = %s, want echoed key=%s", output, want)
							}
							if enabled && bytes.Contains(output, []byte(identityTestOperatorKey)) {
								t.Errorf("client output leaks operator-owned key: %s", output)
							}
						}
					})
				}
			}
		}
	}
}

// Each supplied fragment is one Read, independent of network buffering. The
// final Read returns both data and EOF, exercising processing and tail flush.
type imageIdentitySplitReader struct {
	fragments   [][]byte
	terminalErr error
	reads       int
	closed      bool
}

func (r *imageIdentitySplitReader) Read(p []byte) (int, error) {
	if len(r.fragments) == 0 {
		return 0, io.EOF
	}
	r.reads++
	fragment := r.fragments[0]
	n := copy(p, fragment)
	if n < len(fragment) {
		r.fragments[0] = fragment[n:]
		return n, nil
	}
	r.fragments = r.fragments[1:]
	if len(r.fragments) == 0 {
		if r.terminalErr != nil {
			return n, r.terminalErr
		}
		return n, io.EOF
	}
	return n, nil
}

func (r *imageIdentitySplitReader) Close() error {
	r.closed = true
	return nil
}

func TestCodexDirectImageExecuteStreamSplitReadRestoration(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, rule := range []string{"none", "set"} {
			t.Run(fmt.Sprintf("enabled=%t/%s", enabled, rule), func(t *testing.T) {
				var reader *imageIdentitySplitReader
				var wireOutput, wantOutput string
				transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
					body, errRead := io.ReadAll(req.Body)
					if errRead != nil {
						return nil, errRead
					}
					key := gjson.GetBytes(body, "prompt_cache_key").String()
					if key == "" {
						t.Fatal("split-read fixture requires a nonempty wire identifier")
					}
					prefix := "event: image_generation.completed\ndata: {\"revised_prompt\":\"key="
					// The unterminated tail is a prefix of the identifier. A
					// boundary-safe restorer must flush it unchanged at EOF.
					tail := "\n\n: eof-tail=" + key[:len(key)/2]
					wireOutput = prefix + key + "\"}" + tail
					wantOutput = wireOutput
					if enabled {
						wantOutput = strings.ReplaceAll(wireOutput, key, identityTestCacheKey)
					}
					reader = &imageIdentitySplitReader{fragments: [][]byte{
						[]byte(prefix + key[:len(key)/2]),
						[]byte(key[len(key)/2:] + "\"}" + tail),
					}}
					return imageIdentityResponse(req, reader, true), nil
				})
				ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
				exec := NewCodexExecutor(imageIdentityRuleConfig(enabled, rule))
				result, err := exec.ExecuteStream(ctx, identityImageAuth("https://images.example.invalid"), cliproxyexecutor.Request{
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
				// Body.Close precedes Chunks closure, so these observations
				// are synchronized with the reader goroutine without sleeps.
				if reader.reads != 2 || !reader.closed {
					t.Errorf("response reader: reads=%d closed=%t, want two Reads then Close", reader.reads, reader.closed)
				}
				if got := output.String(); got != wantOutput {
					t.Errorf("split identifier/EOF restoration:\n got %q\nwant %q\nwire %q", got, wantOutput, wireOutput)
				}
			})
		}
	}
}

// CLIProxyAPI#116 r2 CODE P2: with no key in the body but a header-only session, a media rule that
// removes or empties prompt_cache_key must still clear the session headers on both image handlers.
func TestCodexDirectImageHeaderOnlySessionClearedByRemovalRule(t *testing.T) {
	for _, stream := range []bool{false, true} {
		for _, rule := range []string{"remove", "empty", "null"} {
			t.Run(fmt.Sprintf("stream=%t/%s", stream, rule), func(t *testing.T) {
				var finalHeaders http.Header
				transport := imageIdentityRoundTripper(func(req *http.Request) (*http.Response, error) {
					_, _ = io.ReadAll(req.Body)
					finalHeaders = req.Header.Clone()
					response := `{"created":1,"data":[{"b64_json":"AA=="}]}`
					if stream {
						response = "event: image_generation.completed\ndata: " + response + "\n\n"
					}
					return imageIdentityResponse(req, io.NopCloser(strings.NewReader(response)), stream), nil
				})
				ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
				exec := NewCodexExecutor(imageIdentityRuleConfig(true, rule))
				request := cliproxyexecutor.Request{Model: "gpt-image-2", Payload: []byte(`{"model":"gpt-image-2","prompt":"A cute baby sea otter"}`)}
				if stream {
					result, err := exec.ExecuteStream(ctx, imageIdentityHeaderAuth(), request, codexOpenAIImageTestOptions(codexImagesGenerationsPath, true))
					if err != nil {
						t.Fatalf("ExecuteStream: %v", err)
					}
					for range result.Chunks {
					}
				} else if _, err := exec.Execute(ctx, imageIdentityHeaderAuth(), request, codexOpenAIImageTestOptions(codexImagesGenerationsPath, false)); err != nil {
					t.Fatalf("Execute: %v", err)
				}
				for _, name := range []string{"Session-Id", "Session_id", "Conversation_id"} {
					if got := headerValueCaseInsensitive(finalHeaders, name); got != "" {
						t.Errorf("%s = %q survives a %s rule on prompt_cache_key", name, got, rule)
					}
				}
			})
		}
	}
}
