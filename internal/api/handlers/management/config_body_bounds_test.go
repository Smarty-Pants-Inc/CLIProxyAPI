package management

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

func TestManagementBodySizeAndCancellation(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelled), func(t *testing.T) {
			h := &Handler{cfg: &config.Config{LogsMaxTotalSizeMB: 7}}
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest("PUT", "/v0/management/logs-max-total-size-mb", bytes.NewReader(bytes.Repeat([]byte("x"), managementBodyLimit+1)))
			if cancelled {
				ctx, cancel := context.WithCancel(c.Request.Context())
				cancel()
				c.Request = c.Request.WithContext(ctx)
			}
			h.PutLogsMaxTotalSizeMB(c)
			want := http.StatusBadRequest
			if cancelled {
				want = http.StatusRequestTimeout
			}
			if rec.Code != want || h.cfg.LogsMaxTotalSizeMB != 7 {
				t.Fatalf("body bound failed: status=%d config=%d", rec.Code, h.cfg.LogsMaxTotalSizeMB)
			}
		})
	}
}

func TestManagementNetworkBodyDeadline(t *testing.T) {
	h := &Handler{cfg: &config.Config{}}
	engine := gin.New()
	engine.PUT("/v0/management/logs-max-total-size-mb", h.PutLogsMaxTotalSizeMB)
	server := httptest.NewServer(withManagementBodyDeadline(engine, 50*time.Millisecond))
	defer server.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprint(conn, "PUT /v0/management/logs-max-total-size-mb HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nContent-Type: application/json\r\n\r\n{\"value\":"); err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("stalled body did not terminate: %v", err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("stalled body status=%d", response.StatusCode)
	}
}
