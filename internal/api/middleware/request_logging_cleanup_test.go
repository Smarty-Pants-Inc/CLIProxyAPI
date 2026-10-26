package middleware

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
)

// Keep: data safety, regression for raw prompts surviving an aborted stream.
// ReverseProxy supplies a real net/http ErrAbortHandler on a mid-copy failure;
// it is a failure injector for the middleware, not the production SDK handler.
func TestRequestLoggingCleansSpoolsOnStreamAbort(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for _, enabled := range []bool{false, true} {
		for _, failure := range []string{"client_cancel", "upstream_error"} {
			t.Run(fmt.Sprintf("enabled_%t/%s", enabled, failure), func(t *testing.T) {
				logsDir := t.TempDir()
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_, _ = io.Copy(io.Discard, r.Body)
					w.Header().Set("Content-Type", "text/event-stream")
					// A short response with this length produces unexpected EOF after a chunk.
					w.Header().Set("Content-Length", "100000")
					_, _ = io.WriteString(w, "data: synthetic\n\n")
					w.(http.Flusher).Flush()
					if failure == "client_cancel" {
						<-r.Context().Done()
					}
				}))
				defer upstream.Close()
				target, err := url.Parse(upstream.URL)
				if err != nil {
					t.Fatal(err)
				}
				proxy := httputil.NewSingleHostReverseProxy(target)
				proxy.ErrorLog = log.New(io.Discard, "", 0)
				router := gin.New()
				router.Use(RequestLoggingMiddleware(logging.NewFileRequestLogger(enabled, logsDir, "", 10)))
				router.POST("/v1/responses", func(c *gin.Context) { proxy.ServeHTTP(c.Writer, c.Request) })
				done := make(chan any, 1)
				gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					defer func() { done <- recover() }()
					router.ServeHTTP(w, r)
				}))
				defer gateway.Close()
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				req, err := http.NewRequestWithContext(ctx, http.MethodPost, gateway.URL+"/v1/responses", io.NopCloser(strings.NewReader("synthetic prompt")))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				client := gateway.Client()
				client.Timeout = 10 * time.Second
				response, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				line, err := bufio.NewReader(response.Body).ReadString('\n')
				if err != nil || line != "data: synthetic\n" {
					t.Fatalf("first chunk = %q, %v", line, err)
				}
				if failure == "client_cancel" {
					cancel()
				} else {
					_, _ = io.Copy(io.Discard, response.Body)
				}
				select {
				case aborted := <-done:
					if aborted != http.ErrAbortHandler {
						t.Fatalf("panic = %v, want ErrAbortHandler", aborted)
					}
				case <-time.After(10 * time.Second):
					t.Fatal("gateway did not finish aborting")
				}
				assertNoRequestLogSpools(t, logsDir)
			})
		}
	}
}

func assertNoRequestLogSpools(t *testing.T, dir string) {
	t.Helper()
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if strings.HasPrefix(entry.Name(), "request-log-parts-") || strings.HasSuffix(entry.Name(), ".tmp") {
			t.Errorf("request log spool survived request: %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
