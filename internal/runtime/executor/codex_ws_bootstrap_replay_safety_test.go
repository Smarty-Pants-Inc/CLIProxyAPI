package executor

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
	"github.com/tidwall/gjson"
)

const (
	WSReplayModel      = "gpt-5.6-terra"
	WSReplayPreamble   = `{"type":"response.created","response":{"id":"resp_replay"}}`
	WSReplayUnsafeTool = `{"type":"response.output_item.added","output_index":0,"item":{"id":"tool_replay","type":"web_search_call","status":"in_progress"}}`
	WSReplayIdentity   = `{"type":"response.in_progress","response":{"id":"resp_replay","model":"gpt-5.6-terra"}}`
	WSReplayCompleted  = `{"type":"response.completed","response":{"id":"resp_secondary","model":"gpt-5.6-terra","status":"completed","output":[]}}`
)

type WSReplayFixture struct {
	manager           *cliproxyauth.Manager
	primaryID         string
	primaryRequests   atomic.Int32
	secondaryRequests atomic.Int32
	observerEvents    [][]byte
}

// WSReplayNewFixture exercises the real conductor and websocket transport with
// two synthetic credentials; the secondary always succeeds if replay is attempted.
func WSReplayNewFixture(t *testing.T, modelLevelCooling bool, frames []string, primaryRules ...config.RequestScopedErrorRule) *WSReplayFixture {
	t.Helper()
	fixture := &WSReplayFixture{primaryID: t.Name() + "-01"}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if errUpgrade != nil {
			t.Errorf("upgrade fixture websocket: %v", errUpgrade)
			return
		}
		defer func() { _ = conn.Close() }()
		_, payload, errRead := conn.ReadMessage()
		if errRead != nil {
			t.Errorf("read fixture request: %v", errRead)
			return
		}
		if got := gjson.GetBytes(payload, "model").String(); got != WSReplayModel {
			t.Errorf("upstream model = %q, want %q", got, WSReplayModel)
			return
		}
		responses := frames
		switch r.Header.Get("Authorization") {
		case "Bearer fixture-primary":
			fixture.primaryRequests.Add(1)
		case "Bearer fixture-secondary":
			fixture.secondaryRequests.Add(1)
			responses = []string{WSReplayCompleted}
		default:
			t.Error("unexpected fixture credential")
			return
		}
		for _, frame := range responses {
			if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(frame)); errWrite != nil {
				// A model-integrity rejection can close the connection immediately.
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	cfg := &config.Config{Codex: config.CodexConfig{ModelLevelCooling: modelLevelCooling}}
	exec := NewCodexWebsocketsExecutor(cfg)
	exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
	t.Cleanup(func() { exec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID) })
	fixture.manager = cliproxyauth.NewManager(nil, &cliproxyauth.FillFirstSelector{}, nil)
	fixture.manager.SetConfig(cfg)
	fixture.manager.SetRetryConfig(0, 0, 0)
	fixture.manager.RegisterExecutor(exec)
	reg := registry.GetGlobalRegistry()
	for i, token := range []string{"fixture-primary", "fixture-secondary"} {
		candidate := &cliproxyauth.Auth{
			ID: fmt.Sprintf("%s-%02d", t.Name(), i+1), Provider: "codex", Status: cliproxyauth.StatusActive,
			Attributes: map[string]string{"api_key": token, "base_url": server.URL, "websockets": "true"},
			Metadata:   map[string]any{"disable_cooling": false},
		}
		if i == 0 && len(primaryRules) != 0 {
			candidate.Metadata["request_scoped_errors"] = primaryRules
		}
		reg.RegisterClient(candidate.ID, "codex", []*registry.ModelInfo{{ID: WSReplayModel}})
		t.Cleanup(func() { reg.UnregisterClient(candidate.ID) })
		if _, errRegister := fixture.manager.Register(context.Background(), candidate); errRegister != nil {
			t.Fatal(errRegister)
		}
	}
	return fixture
}

func (f *WSReplayFixture) WSReplayExecute(t *testing.T) (*cliproxyexecutor.StreamResult, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return f.manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{
		Model: WSReplayModel, Payload: []byte(`{"model":"gpt-5.6-terra","input":[]}`),
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FromString("codex"), Stream: true,
		WebSocketResponseObserver: func(_ context.Context, event cliproxyexecutor.WebSocketResponseEvent) {
			f.observerEvents = append(f.observerEvents, append([]byte(nil), event.Payload...))
		},
	})
}

func (f *WSReplayFixture) WSReplayAssertAttempts(t *testing.T, secondary int32) {
	t.Helper()
	if got := f.primaryRequests.Load(); got != 1 {
		t.Errorf("primary requests = %d, want 1", got)
	}
	if got := f.secondaryRequests.Load(); got != secondary {
		t.Errorf("secondary requests = %d, want %d; unsafe upstream effects must never be replayed", got, secondary)
	}
}

func TestWSReplayDelayedIdentityQuota(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, cooling := range []bool{true, false} {
		for _, quota := range []string{"usage_limit_reached", "insufficient_quota"} {
			for _, field := range []string{"type", "code"} {
				for _, unsafe := range []bool{true, false} {
					t.Run(fmt.Sprintf("cooling=%t/%s/%s/unsafe=%t", cooling, quota, field, unsafe), func(t *testing.T) {
						body := fmt.Sprintf(`{%q:%q,"message":"fixture quota exhausted","resets_in_seconds":3600}`, field, quota)
						terminal := fmt.Sprintf(`{"type":"response.failed","response":{"id":"resp_replay","status":"failed","error":%s}}`, body)
						frames := []string{WSReplayPreamble}
						if unsafe {
							frames = append(frames, WSReplayUnsafeTool)
						}
						frames = append(frames, WSReplayIdentity, terminal)
						fixture := WSReplayNewFixture(t, cooling, frames)
						result, err := fixture.WSReplayExecute(t)
						if err != nil || result == nil {
							t.Fatalf("ExecuteStream = %v, %v; want committed stream", result, err)
						}
						payload, streamErr := drainChunks(result)
						if !unsafe {
							fixture.WSReplayAssertAttempts(t, 1)
							if streamErr != nil || !strings.Contains(payload, "resp_secondary") {
								t.Fatalf("safe bootstrap retry did not succeed: payload=%s err=%v", payload, streamErr)
							}
							return
						}
						fixture.WSReplayAssertAttempts(t, 0)
						lastIndex := -1
						for _, held := range []string{"response.created", "web_search_call", "response.in_progress"} {
							index := strings.Index(payload, held)
							if index <= lastIndex {
								t.Errorf("verified held event %q was discarded or reordered: %s", held, payload)
							}
							lastIndex = index
						}
						if streamErr == nil {
							t.Fatal("quota error discarded instead of delivered in-stream")
						}
						// Reset parsing currently applies only to usage_limit_reached
						// in error.type; preserve that existing contract for other shapes.
						retryAfter := time.Duration(0)
						if quota == "usage_limit_reached" && field == "type" {
							retryAfter = time.Hour
						}
						codexSSEReplayAssertQuota(t, streamErr, !cooling, retryAfter)
						var scoped interface{ IsRequestScoped() bool }
						if errors.As(streamErr, &scoped) && scoped.IsRequestScoped() {
							t.Error("verified in-stream quota must not be wrapped as non-replayable")
						}
						credential, ok := fixture.manager.GetByID(fixture.primaryID)
						if !ok || credential.ModelStates[WSReplayModel] == nil || !credential.ModelStates[WSReplayModel].Quota.Exceeded {
							t.Errorf("committed quota lost cooldown: %+v", credential)
						}
					})
				}
			}
		}
	}
}

func TestWSReplayUnsafeUnverifiedFailure(t *testing.T) {
	for _, failure := range []struct {
		name, frame string
		modelError  bool
	}{
		{"missing_identity", `{"type":"response.completed","response":{"output":[]}}`, true},
		{"unverified_quota", `{"type":"response.failed","response":{"error":{"type":"usage_limit_reached"}}}`, false},
		{"wrong_identity", `{"type":"response.in_progress","response":{"model":"wrong-model"}}`, true},
		{"read_error", "", false},
		{"explicit_status_missing_identity", `{"type":"error","status":429,"error":{"type":"usage_limit_reached","message":"quota"}}`, false},
	} {
		t.Run(failure.name, func(t *testing.T) {
			frames := []string{WSReplayPreamble, WSReplayUnsafeTool}
			if failure.frame != "" {
				frames = append(frames, failure.frame)
			}
			fixture := WSReplayNewFixture(t, true, frames)
			result, err := fixture.WSReplayExecute(t)
			fixture.WSReplayAssertAttempts(t, 0)
			if result != nil || err == nil {
				t.Fatalf("unverified unsafe attempt = %v, %v; want synchronous failure and no output", result, err)
			}
			if len(fixture.observerEvents) != 0 {
				t.Errorf("unverified observer events escaped: %q", fixture.observerEvents)
			}
			var stop interface{ IsRequestStop() bool }
			if !errors.As(err, &stop) || !stop.IsRequestStop() {
				t.Errorf("unsafe synchronous failure lost its replay stop: %T %v", err, err)
			}
			if !failure.modelError && failure.name != "read_error" {
				var scoped interface{ IsRequestScoped() bool }
				if errors.As(err, &scoped) && scoped.IsRequestScoped() {
					t.Error("genuine quota refusal must retain its cooldown")
				}
			}
			if failure.modelError {
				var mismatch *helps.CodexModelMismatchError
				if !errors.As(err, &mismatch) {
					t.Errorf("underlying model error lost: %T %v", err, err)
				}
			} else if failure.name == "read_error" {
				var readError *websocket.CloseError
				if !errors.As(err, &readError) {
					t.Errorf("underlying websocket read error lost: %T %v", err, err)
				}
			} else {
				var status interface{ StatusCode() int }
				if !errors.As(err, &status) || status.StatusCode() != http.StatusTooManyRequests {
					t.Errorf("unverified quota lost underlying 429: %T %v", err, err)
				}
			}
		})
	}
}

func TestWSReplayUnsafeContinueOverride(t *testing.T) {
	for _, failure := range []struct {
		name, frame, match string
		status             int
	}{
		{"missing_identity", `{"type":"response.completed","response":{"output":[]}}`, "is missing", http.StatusBadGateway},
		{"wrong_identity", `{"type":"response.in_progress","response":{"model":"wrong-model"}}`, "does not match", http.StatusBadGateway},
		{"unverified_quota", `{"type":"response.failed","response":{"error":{"type":"usage_limit_reached","message":"fixture quota exhausted"}}}`, "fixture quota exhausted", http.StatusTooManyRequests},
	} {
		for _, action := range []string{"continue", "continue-and-cooldown"} {
			t.Run(failure.name+"/"+action, func(t *testing.T) {
				fixture := WSReplayNewFixture(t, true,
					[]string{WSReplayPreamble, WSReplayUnsafeTool, failure.frame},
					config.RequestScopedErrorRule{Status: failure.status, Match: []string{failure.match}, Action: action},
				)
				result, err := fixture.WSReplayExecute(t)
				fixture.WSReplayAssertAttempts(t, 0)
				if len(fixture.observerEvents) != 0 {
					t.Errorf("unverified observer events escaped through continue override: %q", fixture.observerEvents)
				}
				if result != nil || err == nil {
					t.Fatalf("continue override replayed unsafe attempt: result=%v err=%v", result, err)
				}
				var stop interface{ IsRequestStop() bool }
				if !errors.As(err, &stop) || !stop.IsRequestStop() {
					t.Errorf("continue override lost hard-stop marker: %T %v", err, err)
				}
				var status interface{ StatusCode() int }
				if !errors.As(err, &status) || status.StatusCode() != failure.status || !strings.Contains(err.Error(), failure.match) {
					t.Errorf("original refusal lost through hard-stop wrapper: %T %v", err, err)
				}
			})
		}
	}
}

func TestWSReplayUnsafeVerifiedExplicitStatus(t *testing.T) {
	fixture := WSReplayNewFixture(t, false, []string{WSReplayPreamble, WSReplayUnsafeTool, WSReplayIdentity,
		`{"type":"error","status":429,"error":{"type":"usage_limit_reached","message":"quota","resets_in_seconds":3600}}`,
	})
	result, err := fixture.WSReplayExecute(t)
	fixture.WSReplayAssertAttempts(t, 0)
	if err != nil || result == nil {
		t.Fatalf("verified explicit status = %v, %v; want in-stream error", result, err)
	}
	payload, streamErr := drainChunks(result)
	if !strings.Contains(payload, "web_search_call") {
		t.Errorf("held unsafe event discarded: %s", payload)
	}
	if streamErr == nil {
		t.Fatal("explicit status error lost")
	}
	codexSSEReplayAssertQuota(t, streamErr, true, time.Hour)
}

// CLIProxyAPI#64 security round 3: a response.created/in_progress snapshot is judged by the
// output it carries. Output closes the replay latch; an empty output list keeps it open.
func TestWSReplaySnapshotOutputQuota(t *testing.T) {
	for _, quota := range []string{"usage_limit_reached", "insufficient_quota"} {
		for _, tc := range []struct {
			name, snapshot string
			secondary      int32
		}{
			{"in_progress_server_tool", `{"type":"response.in_progress","response":{"id":"resp_replay","model":"gpt-5.6-terra","output":[{"id":"ws_1","type":"web_search_call","status":"in_progress"}]}}`, 0},
			{"created_server_tool", `{"type":"response.created","response":{"id":"resp_replay","model":"gpt-5.6-terra","output":[{"id":"ws_1","type":"web_search_call","status":"in_progress"}]}}`, 0},
			{"in_progress_text", `{"type":"response.in_progress","response":{"id":"resp_replay","model":"gpt-5.6-terra","output":[{"type":"message","content":[{"type":"output_text","text":"partial"}]}]}}`, 0},
			{"in_progress_empty_output", `{"type":"response.in_progress","response":{"id":"resp_replay","model":"gpt-5.6-terra","output":[]}}`, 1},
		} {
			t.Run(quota+"/"+tc.name, func(t *testing.T) {
				terminal := fmt.Sprintf(`{"type":"response.failed","response":{"id":"resp_replay","status":"failed","error":{"code":%q,"message":"fixture quota exhausted"}}}`, quota)
				fixture := WSReplayNewFixture(t, false, []string{WSReplayPreamble, tc.snapshot, terminal})
				result, err := fixture.WSReplayExecute(t)
				if err == nil && result != nil {
					_, _ = drainChunks(result)
				}
				fixture.WSReplayAssertAttempts(t, tc.secondary)
			})
		}
	}
}
