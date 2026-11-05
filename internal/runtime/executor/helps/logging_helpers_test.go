package helps

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

func TestRequestLoggingDoesNotMarkUpstreamAttempt(t *testing.T) {
	tests := []struct {
		name   string
		record func(context.Context)
	}{
		{
			name: "HTTP",
			record: func(ctx context.Context) {
				RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{URL: "https://api.example.com", Method: http.MethodPost})
			},
		},
		{
			name: "websocket",
			record: func(ctx context.Context) {
				RecordAPIWebsocketRequest(ctx, &config.Config{}, UpstreamRequestLog{URL: "wss://api.example.com", Method: "WEBSOCKET"})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := cliproxyexecutor.WithUpstreamAttemptTracker(context.Background())
			test.record(ctx)
			if cliproxyexecutor.UpstreamAttempted(ctx) {
				t.Fatal("request logging marked an upstream attempt before transport")
			}
		})
	}
}

func TestRecordAPIRequestClonesDeferredBodyWhenRequestLogDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	ginCtx, _ := gin.CreateTestContext(recorder)
	ctx := context.WithValue(context.Background(), "gin", ginCtx)
	body := []byte(`{"model":"original"}`)

	RecordAPIRequest(ctx, &config.Config{}, UpstreamRequestLog{
		URL:    "https://api.example.com/v1/responses",
		Method: http.MethodPost,
		Body:   body,
	})
	body[10] = 'X'

	value, exists := ginCtx.Get(logging.DeferredAPIRequestContextKey)
	if !exists {
		t.Fatal("deferred API request was not captured")
	}
	requests, ok := value.([]logging.DeferredAPIRequest)
	if !ok || len(requests) != 1 {
		t.Fatalf("deferred API requests = %#v, want one request", value)
	}
	captured := string(requests[0]())
	if !strings.Contains(captured, `{"model":"original"}`) {
		t.Fatalf("captured API request = %q, want original body", captured)
	}
}

func TestRecordAPIResponseMetadataStoresHeadersWhenRequestLogDisabled(t *testing.T) {
	ctx := logging.WithResponseHeadersHolder(context.Background())
	headers := http.Header{}
	headers.Add("X-Upstream-Request-Id", "upstream-req-1")

	RecordAPIResponseMetadata(ctx, &config.Config{}, http.StatusOK, headers)
	headers.Set("X-Upstream-Request-Id", "mutated")

	got, acquired := logging.GetResponseHeadersObservation(ctx)
	if acquired["X-Upstream-Request-Id"].IsZero() {
		t.Fatal("HTTP acquisition missing with request logging disabled")
	}
	if got.Get("X-Upstream-Request-Id") != "upstream-req-1" {
		t.Fatalf("response header = %q, want %q", got.Get("X-Upstream-Request-Id"), "upstream-req-1")
	}
}

// Keep: metadata crosses the transport/result boundary with logging disabled.
func TestWebsocketAcquisitionLoggingDoesNotRestamp(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := &config.Config{SDKConfig: config.SDKConfig{RequestLog: enabled}}
		ctx := logging.WithResponseHeadersHolder(context.Background()) // No Gin context.
		t0, t1, t2 := time.Unix(100, 0), time.Unix(200, 0), time.Unix(300, 0)
		headers := http.Header{"X-Codex-Secondary-Used-Percent": {"20"}, "X-Codex-Credits-Balance": {"10"}}
		RecordAPIResponseMetadataAt(ctx, cfg, http.StatusSwitchingProtocols, headers, t0)
		LogAPIWebsocketHandshake(ctx, cfg, http.StatusSwitchingProtocols, headers)
		LogAPIWebsocketUpgradeRejection(ctx, cfg, UpstreamRequestLog{}, http.StatusTooManyRequests, headers, []byte("late body"))
		frame := []byte(`{"type":"codex.rate_limits","rate_limits":{"primary":{"used_percent":42,"window_minutes":300,"reset_after_seconds":60}}}`)
		AppendCodexAPIWebsocketResponseAt(ctx, cfg, frame, t1)
		got, times := logging.GetResponseHeadersObservation(ctx)
		if got.Get("X-Codex-Primary-Used-Percent") != "42" || !times["X-Codex-Primary-Reset-After-Seconds"].Equal(t1) || !times["X-Codex-Secondary-Used-Percent"].Equal(t0) || !times["X-Codex-Credits-Balance"].Equal(t0) {
			t.Fatalf("logging=%t: mixed acquisitions lost: %v %v", enabled, got, times)
		}
		AppendCodexAPIWebsocketResponseAt(ctx, cfg, []byte(`{"type":"response.output_text.delta","delta":"hi"}`), t2)
		_, afterToken := logging.GetResponseHeadersObservation(ctx)
		if !reflect.DeepEqual(times, afterToken) {
			t.Fatalf("non-quota frame refreshed evidence: %v", afterToken)
		}
		AppendCodexAPIWebsocketResponseAt(ctx, cfg, frame, t2)
		_, repeated := logging.GetResponseHeadersObservation(ctx)
		if !repeated["X-Codex-Primary-Used-Percent"].Equal(t2) || !repeated["X-Codex-Secondary-Used-Percent"].Equal(t0) {
			t.Fatalf("real repeated quota frame did not refresh only its fields: %v", repeated)
		}
		AppendCodexAPIWebsocketResponseAt(ctx, cfg, []byte(`{"type":"error","headers":{"retry-after":"60"},"error":{"type":"usage_limit_reached","message":"quota"}}`), t2)
		_, refusal := logging.GetResponseHeadersObservation(ctx)
		if !refusal["Retry-After"].Equal(t2) {
			t.Fatalf("quota error acquisition missing: %v", refusal)
		}
	}
}

func TestLegacyWebsocketUpgradeRejectionDoesNotAttestBodyCompletion(t *testing.T) {
	ctx := logging.WithResponseHeadersHolder(context.Background())
	RecordAPIWebsocketUpgradeRejection(ctx, &config.Config{}, UpstreamRequestLog{}, http.StatusTooManyRequests, http.Header{"Retry-After": {"60"}}, []byte("already-read body"))
	headers, acquired := logging.GetResponseHeadersObservation(ctx)
	if headers.Get("Retry-After") != "60" || !acquired["Retry-After"].IsZero() {
		t.Fatalf("legacy rejected-upgrade logger attested completion: %v %v", headers, acquired)
	}
}

func TestAPIResponseAttemptsAreSeparated(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name              string
		fileBacked        bool
		firstResponseBody []byte
	}{
		{name: "memory backed error"},
		{name: "file backed error", fileBacked: true},
		{name: "memory backed partial body", firstResponseBody: []byte("partial")},
		{name: "file backed partial body", fileBacked: true, firstResponseBody: []byte("partial")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			ginCtx, _ := gin.CreateTestContext(recorder)
			var responseSource *logging.FileBodySource
			if tt.fileBacked {
				var errSource error
				responseSource, errSource = logging.NewFileBodySourceInDir(t.TempDir(), "api-response")
				if errSource != nil {
					t.Fatalf("NewFileBodySourceInDir: %v", errSource)
				}
				t.Cleanup(func() {
					if errCleanup := responseSource.Cleanup(); errCleanup != nil {
						t.Errorf("Cleanup: %v", errCleanup)
					}
				})
				ginCtx.Set(logging.APIResponseSourceContextKey, responseSource)
			}

			ctx := context.WithValue(context.Background(), "gin", ginCtx)
			cfg := &config.Config{SDKConfig: config.SDKConfig{RequestLog: true}}
			RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: "https://api.example.com/first", Method: http.MethodPost})
			if len(tt.firstResponseBody) > 0 {
				AppendAPIResponseChunk(ctx, cfg, tt.firstResponseBody)
			} else {
				RecordAPIResponseError(ctx, cfg, errors.New("EOF"))
			}
			RecordAPIRequest(ctx, cfg, UpstreamRequestLog{URL: "https://api.example.com/second", Method: http.MethodPost})
			RecordAPIResponseError(ctx, cfg, errors.New("retry failed"))

			var response []byte
			if responseSource != nil {
				var errBytes error
				response, errBytes = responseSource.Bytes()
				if errBytes != nil {
					t.Fatalf("responseSource.Bytes: %v", errBytes)
				}
			} else {
				value, exists := ginCtx.Get(apiResponseKey)
				if !exists {
					t.Fatal("API_RESPONSE was not captured")
				}
				response, _ = value.([]byte)
			}

			previousEnd := "Error: EOF"
			if len(tt.firstResponseBody) > 0 {
				previousEnd = string(tt.firstResponseBody)
			}
			wantBoundary := previousEnd + "\n\n=== API RESPONSE 2 ==="
			if !strings.Contains(string(response), wantBoundary) {
				t.Fatalf("API response attempts are not separated by one blank line:\n%q\nwant boundary %q", response, wantBoundary)
			}
		})
	}
}
