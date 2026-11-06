package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	"github.com/tidwall/gjson"
)

const acquisitionPrimaryFrame = `{"type":"codex.rate_limits","rate_limits":{"primary":{"used_percent":42,"window_minutes":300,"reset_after_seconds":60}}}`

// Keep: queued receipt is a concurrency boundary. Consumer backpressure must
// not make retained windows or relative resets appear newly acquired.
func TestCodexWebsocketQueuedReadPreservesAcquisition(t *testing.T) {
	ctx := logging.WithResponseHeadersHolder(context.Background())
	t0, t1 := time.Unix(100, 0), time.Unix(200, 0)
	logging.SetResponseHeadersAt(ctx, http.Header{
		"X-Codex-Secondary-Used-Percent": {"20"}, "X-Codex-Credits-Balance": {"10"},
	}, t0)
	conn, wrongConn := &websocket.Conn{}, &websocket.Conn{}
	reads := make(chan codexWebsocketRead, 3)
	reads <- codexWebsocketRead{conn: wrongConn, msgType: websocket.TextMessage, payload: []byte(acquisitionPrimaryFrame), observedAt: time.Unix(999, 0)}
	reads <- codexWebsocketRead{conn: conn, msgType: websocket.TextMessage, payload: []byte(acquisitionPrimaryFrame), observedAt: t1}
	reads <- codexWebsocketRead{conn: conn, msgType: websocket.TextMessage, payload: []byte(`{"type":"response.output_text.delta","delta":"hi"}`), observedAt: time.Unix(300, 0)}
	for i := 0; i < 2; i++ {
		kind, payload, acquired, errRead := readCodexWebsocketMessageObserved(ctx, &codexWebsocketSession{}, conn, reads)
		if errRead != nil || kind != websocket.TextMessage {
			t.Fatalf("queued read: kind=%d err=%v", kind, errRead)
		}
		helps.AppendCodexAPIWebsocketResponseAt(ctx, nil, payload, acquired)
	}
	headers, times := logging.GetResponseHeadersObservation(ctx)
	if headers.Get("X-Codex-Primary-Used-Percent") != "42" || !times["X-Codex-Primary-Used-Percent"].Equal(t1) || !times["X-Codex-Primary-Reset-After-Seconds"].Equal(t1) || !times["X-Codex-Secondary-Used-Percent"].Equal(t0) || !times["X-Codex-Credits-Balance"].Equal(t0) {
		t.Fatalf("queued/backpressured partial evidence changed age: %v %v", headers, times)
	}
	close(reads)
	_, _, acquired, errRead := readCodexWebsocketMessageObserved(ctx, &codexWebsocketSession{}, conn, reads)
	if !errors.Is(errRead, helps.ErrCodexWebsocketSessionClosed) || !acquired.IsZero() {
		t.Fatalf("closed queue acquired evidence: %v %v", acquired, errRead)
	}
}

func TestCodexWebsocketDirectAndSharedReceipt(t *testing.T) {
	for _, shared := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "shared-queue"}[shared], func(t *testing.T) {
			frames := make(chan string)
			stop := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, http.Header{"X-Codex-Secondary-Used-Percent": {"20"}})
				if errUpgrade != nil {
					t.Errorf("upgrade: %v", errUpgrade)
					return
				}
				defer func() { _ = conn.Close() }()
				for {
					select {
					case frame := <-frames:
						if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(frame)); errWrite != nil {
							return
						}
					case <-stop:
						return
					}
				}
			}))
			defer func() { close(stop); server.Close() }()
			exec := NewCodexWebsocketsExecutor(&config.Config{})
			ctx := logging.WithResponseHeadersHolder(context.Background())
			wsURL := "ws" + strings.TrimPrefix(server.URL, "http")
			conn, closer, response, errDial := exec.dialCodexWebsocket(ctx, nil, wsURL, nil)
			if errDial != nil {
				t.Fatal(errDial)
			}
			defer func() { _ = closer.Close() }()
			_, handshake := logging.GetResponseHeadersObservation(ctx)
			if handshake["X-Codex-Secondary-Used-Percent"].IsZero() {
				t.Fatal("successful dial did not capture headers")
			}
			recordAPIWebsocketHandshake(ctx, nil, response, true)
			var sess *codexWebsocketSession
			var reads chan codexWebsocketRead
			if shared {
				sess = &codexWebsocketSession{conn: conn, connCloser: closer, readerConn: conn, authID: "fixture", wsURL: wsURL}
				reads = sess.activate(conn)
				defer sess.clearActive(conn, reads)
				loopDone := make(chan struct{})
				go func() { defer close(loopDone); exec.readUpstreamLoop(sess, conn) }()
				defer func() { _ = closer.Close(); <-loopDone }()
			}
			frames <- acquisitionPrimaryFrame
			var receipt time.Time
			if shared {
				// Taking the original event establishes that ReadMessage has
				// finished before deliberately delaying consumer processing.
				event := <-reads
				receipt = event.observedAt
				reads <- event
			}
			kind, payload, acquired, errRead := readCodexWebsocketMessageObserved(ctx, sess, conn, reads)
			if errRead != nil || kind != websocket.TextMessage || string(payload) != acquisitionPrimaryFrame || acquired.IsZero() || (shared && !acquired.Equal(receipt)) {
				t.Fatalf("frame receipt changed: kind=%d payload=%s acquired=%v receipt=%v err=%v", kind, payload, acquired, receipt, errRead)
			}
			helps.AppendCodexAPIWebsocketResponseAt(ctx, nil, payload, acquired)
			_, merged := logging.GetResponseHeadersObservation(ctx)
			if !merged["X-Codex-Primary-Used-Percent"].Equal(acquired) || !merged["X-Codex-Secondary-Used-Percent"].Equal(handshake["X-Codex-Secondary-Used-Percent"]) {
				t.Fatalf("frame restamped handshake: %v", merged)
			}
			if shared {
				next := logging.WithFreshResponseHeadersHolder(ctx)
				reused, _, reusedResponse, errEnsure := exec.ensureUpstreamConn(next, nil, sess, "fixture", wsURL, nil)
				if errEnsure != nil || reused != conn || reusedResponse != nil {
					t.Fatalf("reuse: conn=%p response=%v err=%v", reused, reusedResponse, errEnsure)
				}
				recordAPIWebsocketHandshake(next, nil, reusedResponse, true)
				if headers, times := logging.GetResponseHeadersObservation(next); len(headers) != 0 || len(times) != 0 {
					t.Fatalf("reused connection created handshake evidence: %v %v", headers, times)
				}
			}
		})
	}
}

// gorilla/websocket v1.5.3 client.go:402 reads up to 1KiB of a rejected
// handshake body inside DialContext. No exact header-receipt hook exists here:
// keep raw/native error evidence but never attest post-body time as acquisition.
func TestCodexWebsocketSlowRejectedUpgradeIsUnverified(t *testing.T) {
	for _, stream := range []bool{false, true} {
		t.Run(map[bool]string{false: "execute", true: "stream"}[stream], func(t *testing.T) {
			releaseBody := make(chan struct{})
			var releaseOnce bool
			release := func() {
				if !releaseOnce {
					releaseOnce = true
					close(releaseBody)
				}
			}
			defer release()
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Codex-Primary-Used-Percent", "42")
				w.Header().Set("X-Codex-Primary-Reset-After-Seconds", "60")
				w.WriteHeader(http.StatusTooManyRequests)
				w.(http.Flusher).Flush()
				<-releaseBody
				_, _ = w.Write([]byte(`{"error":{"message":"fixture quota"}}`))
			}))
			defer func() { release(); server.Close() }()
			firstByte := make(chan struct{})
			ctx := logging.WithResponseHeadersHolder(context.Background())
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{GotFirstResponseByte: func() { close(firstByte) }})
			req, opts := codexWebsocketRequest()
			exec := NewCodexWebsocketsExecutor(&config.Config{})
			done := make(chan error, 1)
			go func() {
				if stream {
					_, errExecute := exec.ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
					done <- errExecute
				} else {
					_, errExecute := exec.Execute(ctx, codexTestAuth(server.URL), req, opts)
					done <- errExecute
				}
			}()
			select {
			case <-firstByte:
			case errEarly := <-done:
				t.Fatalf("returned before rejection-body gate: %v", errEarly)
			}
			release()
			if errExecute := <-done; errExecute == nil {
				t.Fatal("rejected handshake succeeded")
			}
			headers, times := logging.GetResponseHeadersObservation(ctx)
			if headers.Get("X-Codex-Primary-Used-Percent") != "42" {
				t.Fatalf("raw rejection headers lost: %v", headers)
			}
			for key, acquired := range times {
				if !acquired.IsZero() {
					t.Fatalf("post-body rejection time falsely verified %s: %v", key, acquired)
				}
			}
			var quota cliproxyauth.QuotaState
			quota.ObserveResponseHeadersObservationForProvider("codex", headers, times)
			if !quota.ObservedAt.IsZero() || len(quota.SignalObservedAt) != 0 || len(quota.Signals) == 0 {
				t.Fatalf("unverified rejection became known or lost raw signals: %+v", quota)
			}
		})
	}
}

func TestCodexWebsocketReconnectFailureClearsPriorObservation(t *testing.T) {
	ctx := logging.WithResponseHeadersHolder(context.Background())
	logging.SetResponseHeadersAt(ctx, http.Header{"X-Codex-Primary-Used-Percent": {"42"}}, time.Unix(100, 0))
	exec := NewCodexWebsocketsExecutor(&config.Config{})
	_, _, response, errDial := exec.dialCodexWebsocket(ctx, nil, ":invalid-url", nil)
	if errDial == nil || response != nil {
		t.Fatalf("invalid reconnect: response=%v err=%v", response, errDial)
	}
	if headers, times := logging.GetResponseHeadersObservation(ctx); len(headers) != 0 || len(times) != 0 {
		t.Fatalf("failed new transport inherited old connection evidence: %v %v", headers, times)
	}
}

func TestCodexWebsocketExecutorConsumptionKeepsWindowAcquisitions(t *testing.T) {
	for _, path := range []string{"execute", "bootstrap", "ongoing", "duplex"} {
		t.Run(path, func(t *testing.T) {
			stop := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				conn, errUpgrade := (&websocket.Upgrader{}).Upgrade(w, r, http.Header{"X-Codex-Secondary-Used-Percent": {"20"}, "X-Codex-Credits-Balance": {"10"}})
				if errUpgrade != nil {
					t.Errorf("upgrade: %v", errUpgrade)
					return
				}
				defer func() { _ = conn.Close() }()
				if _, _, errRead := conn.ReadMessage(); errRead != nil {
					return
				}
				for _, frame := range []string{codexCreatedEvent, acquisitionPrimaryFrame, codexOutputAddedEvent, codexOutputDeltaEvent, acquisitionPrimaryFrame, codexInProgressEvent, codexCompletedEventBody} {
					if errWrite := conn.WriteMessage(websocket.TextMessage, []byte(frame)); errWrite != nil {
						return
					}
				}
				<-stop
			}))
			defer func() { close(stop); server.Close() }()
			ctx, cancel := context.WithCancel(logging.WithResponseHeadersHolder(context.Background()))
			defer cancel()
			cfg := codexBufferingConfig(path == "bootstrap")
			if path == "duplex" {
				cfg.Codex.ResponseSteering = true
				ctx = cliproxyexecutor.WithWebsocketInput(cliproxyexecutor.WithDownstreamWebsocket(ctx), make(chan cliproxyexecutor.WebsocketInput))
			}
			exec := NewCodexWebsocketsExecutor(cfg)
			exec.store = &codexWebsocketSessionStore{sessions: make(map[string]*codexWebsocketSession)}
			defer exec.CloseExecutionSession(cliproxyauth.CloseAllExecutionSessionsID)
			req, opts := codexWebsocketRequest()
			opts.Metadata = map[string]any{cliproxyexecutor.ExecutionSessionMetadataKey: t.Name()}
			var snapshots []map[string]time.Time
			opts.WebSocketResponseObserver = func(_ context.Context, event cliproxyexecutor.WebSocketResponseEvent) {
				if gjson.GetBytes(event.Payload, "type").String() == "codex.rate_limits" {
					if string(event.Payload) != acquisitionPrimaryFrame {
						t.Errorf("quota payload changed: %s", event.Payload)
					}
					_, times := logging.GetResponseHeadersObservation(ctx)
					snapshots = append(snapshots, times)
				}
			}
			if path == "execute" {
				if _, errExecute := exec.Execute(ctx, codexTestAuth(server.URL), req, opts); errExecute != nil {
					t.Fatal(errExecute)
				}
			} else {
				result, errExecute := exec.ExecuteStream(ctx, codexTestAuth(server.URL), req, opts)
				if errExecute != nil {
					t.Fatal(errExecute)
				}
				if result.Headers.Get("X-Codex-Secondary-Used-Percent") != "20" || result.Headers.Get("X-Codex-Primary-Used-Percent") != "" {
					t.Errorf("frame metadata leaked into raw downstream handshake headers: %v", result.Headers)
				}
				for chunk := range result.Chunks {
					if chunk.Err != nil && ctx.Err() == nil {
						t.Errorf("stream: %v", chunk.Err)
					}
					if path == "duplex" && gjson.GetBytes(chunk.Payload, "type").String() == "response.completed" {
						cancel()
					}
				}
			}
			if len(snapshots) != 2 {
				t.Fatalf("quota observations=%d, want bootstrap and repeated ongoing frame", len(snapshots))
			}
			_, final := logging.GetResponseHeadersObservation(ctx)
			primary, secondary, credits := "X-Codex-Primary-Used-Percent", "X-Codex-Secondary-Used-Percent", "X-Codex-Credits-Balance"
			if snapshots[0][primary].IsZero() || snapshots[1][primary].Before(snapshots[0][primary]) || !snapshots[0][secondary].Equal(snapshots[1][secondary]) || !snapshots[0][credits].Equal(snapshots[1][credits]) || !reflect.DeepEqual(final, snapshots[1]) {
				t.Fatalf("consumer restamped retained/non-quota evidence: snapshots=%v final=%v", snapshots, final)
			}
		})
	}
}

func TestCodexWebsocketQuotaFramesDoNotChangePayloadOrRawHeaders(t *testing.T) {
	payload := []byte(acquisitionPrimaryFrame)
	original := append([]byte(nil), payload...)
	headers := http.Header{"X-Fixture": {"raw"}}
	originalHeaders := headers.Clone()
	ctx := logging.WithResponseHeadersHolder(context.Background())
	logging.SetResponseHeadersAt(ctx, headers, time.Unix(100, 0))
	helps.AppendCodexAPIWebsocketResponseAt(ctx, nil, payload, time.Unix(200, 0))
	if !reflect.DeepEqual(payload, original) || !reflect.DeepEqual(headers, originalHeaders) {
		t.Fatalf("observation changed downstream payload/headers: %s %v", payload, headers)
	}
}
