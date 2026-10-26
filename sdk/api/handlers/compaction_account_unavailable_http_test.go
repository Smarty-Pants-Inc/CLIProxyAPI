package handlers_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/api/handlers/openai"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdkconfig "github.com/router-for-me/CLIProxyAPI/v8/sdk/config"
)

type deadCompactionHTTPExecutor struct {
	provider, url string
	client        *http.Client
}

func (e *deadCompactionHTTPExecutor) Identifier() string { return e.provider }
func (e *deadCompactionHTTPExecutor) Execute(ctx context.Context, a *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (coreexecutor.Response, error) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(req.Payload))
	if err != nil {
		return coreexecutor.Response{}, err
	}
	r.Header.Set("X-Test-Seat", a.ID)
	resp, err := e.client.Do(r)
	if err != nil {
		return coreexecutor.Response{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return coreexecutor.Response{Payload: body}, err
}
func (e *deadCompactionHTTPExecutor) ExecuteStream(ctx context.Context, a *coreauth.Auth, req coreexecutor.Request, opts coreexecutor.Options) (*coreexecutor.StreamResult, error) {
	resp, err := e.Execute(ctx, a, req, opts)
	if err != nil {
		return nil, err
	}
	chunks := make(chan coreexecutor.StreamChunk, 1)
	wire := "event: response.completed\ndata: {\"type\":\"response.completed\",\"response\":" + string(resp.Payload) + "}\n\n"
	if e.provider == "claude" {
		wire = "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n"
	}
	chunks <- coreexecutor.StreamChunk{Payload: []byte(wire)}
	close(chunks)
	return &coreexecutor.StreamResult{Chunks: chunks}, nil
}
func (*deadCompactionHTTPExecutor) Refresh(_ context.Context, a *coreauth.Auth) (*coreauth.Auth, error) {
	return a, nil
}
func (*deadCompactionHTTPExecutor) CountTokens(context.Context, *coreauth.Auth, coreexecutor.Request, coreexecutor.Options) (coreexecutor.Response, error) {
	return coreexecutor.Response{}, nil
}
func (*deadCompactionHTTPExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

// Recorded regression / trust boundary: exercise production, dead-seat replay,
// HTTP envelopes and upstream non-failover through both public endpoint handlers.
func TestCompactionAccountUnavailableHTTP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, protocol := range []string{"claude", "responses"} {
		for _, stream := range []bool{false, true} {
			for _, kind := range []string{"signed", "protected", "ordinary"} {
				t.Run(fmt.Sprintf("%s/stream-%t/%s", protocol, stream, kind), func(t *testing.T) {
					const model = "dead-compaction-http-model"
					provider, path := "codex", "/v1/responses"
					if protocol == "claude" {
						provider, path = "claude", "/v1/messages"
					}
					aID, bID := t.Name()+"-A", t.Name()+"-B"
					var mu sync.Mutex
					calls := map[string]int{}
					upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						defer mu.Unlock()
						id := r.Header.Get("X-Test-Seat")
						calls[id]++
						w.Header().Set("Content-Type", "application/json")
						body := `{"id":"resp-live","status":"completed","output":[]}`
						if protocol == "claude" {
							body = `{"id":"msg-live","type":"message","role":"assistant","content":[],"stop_reason":"end_turn"}`
						}
						if id == aID && kind != "ordinary" {
							body = `{"id":"resp-compact","status":"completed","output":[{"type":"compaction","encrypted_content":"http-signed-block"}]}`
							if protocol == "claude" {
								body = `{"id":"msg-compact","type":"message","role":"assistant","content":[{"type":"compaction","content":"http-signed-summary"}],"stop_reason":"end_turn"}`
							}
						}
						_, _ = io.WriteString(w, body)
					}))
					defer upstream.Close()
					selector := coreauth.NewSessionAffinitySelector(&coreauth.FillFirstSelector{})
					defer selector.Stop()
					m := coreauth.NewManager(nil, selector, nil)
					m.SetRetryConfig(0, 0, 0)
					m.RegisterExecutor(&deadCompactionHTTPExecutor{provider: provider, url: upstream.URL, client: upstream.Client()})
					for _, id := range []string{aID, bID} {
						if _, err := m.Register(context.Background(), &coreauth.Auth{ID: id, Provider: provider, Status: coreauth.StatusActive, Attributes: map[string]string{"priority": map[bool]string{true: "100", false: "0"}[id == aID]}, Metadata: map[string]any{"access_token": "DO-NOT-LEAK-ACCESS", "refresh_token": "DO-NOT-LEAK-REFRESH"}}); err != nil {
							t.Fatal(err)
						}
						registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
						defer registry.GetGlobalRegistry().UnregisterClient(id)
					}
					base := handlers.NewBaseAPIHandlers(&sdkconfig.SDKConfig{}, m)
					router := gin.New()
					if protocol == "claude" {
						router.POST(path, claude.NewClaudeCodeAPIHandler(base).ClaudeMessages)
					} else {
						router.POST(path, openai.NewOpenAIResponsesAPIHandler(base).Responses)
					}
					request := func(compacted, streaming bool) *httptest.ResponseRecorder {
						content := `"input":[{"role":"user","content":"continue"}]`
						if compacted {
							content = `"input":[{"type":"compaction","encrypted_content":"http-signed-block"},{"role":"user","content":"continue"}]`
						}
						if protocol == "claude" {
							content = `"messages":[{"role":"user","content":"continue"}]`
							if compacted {
								content = `"messages":[{"role":"assistant","content":[{"type":"compaction","content":"http-signed-summary"}]},{"role":"user","content":"continue"}]`
							}
						}
						body := fmt.Sprintf(`{"model":%q,"stream":%t,%s}`, model, streaming, content)
						r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
						r.Header.Set("Content-Type", "application/json")
						r.Header.Set("Session-Id", "http-dead-conversation")

						w := httptest.NewRecorder()
						router.ServeHTTP(w, r)
						return w
					}
					initial := request(false, false)
					if initial.Code != 200 {
						t.Fatalf("production status=%d body=%s", initial.Code, initial.Body.String())
					}
					a, _ := m.GetByID(aID)
					a.Unavailable = true
					a.Status = coreauth.StatusError
					a.LastError = &coreauth.Error{Code: "unauthorized", HTTPStatus: 401, Message: "invalid_grant: DO-NOT-LEAK-UPSTREAM"}

					if _, err := m.Update(context.Background(), a); err != nil {
						t.Fatal(err)
					}
					got := request(kind == "signed", stream)
					mu.Lock()
					aCalls, bCalls := calls[aID], calls[bID]
					mu.Unlock()
					if aCalls != 1 {
						t.Fatalf("dead seat called: A=%d B=%d", aCalls, bCalls)
					}
					if kind == "ordinary" {
						if got.Code != 200 || bCalls != 1 {
							t.Fatalf("ordinary failover: status=%d B=%d body=%s", got.Code, bCalls, got.Body.String())
						}
						return
					}
					if bCalls != 0 {
						t.Fatalf("hard pin failed over to B: %d calls", bCalls)
					}

					digest := sha256.Sum256([]byte(aID))
					message := fmt.Sprintf("the account that produced this conversation's compaction is unavailable; start a new compaction/conversation (account sha256:%x)", digest[:12])
					expected := fmt.Sprintf(`{"error":{"message":%q,"type":"server_error","code":"compaction_account_unavailable","retryable":false}}`, message)
					if protocol == "claude" {
						expected = fmt.Sprintf(`{"type":"error","error":{"type":"api_error","code":"compaction_account_unavailable","message":%q,"retryable":false}}`, message)
					}
					if got.Code != 503 || got.Body.String() != expected || got.Header().Get("Content-Type") != "application/json" {
						t.Fatalf("got status=%d type=%s body=%s; want %s", got.Code, got.Header().Get("Content-Type"), got.Body.String(), expected)
					}
					t.Logf("HTTP 503 %s", got.Body.String())
				})
			}
		}
	}
}
