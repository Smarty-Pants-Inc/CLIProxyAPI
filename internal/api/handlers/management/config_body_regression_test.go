package management

import (
	"io"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type stalledConfigBody struct {
	entered chan struct{}
	release chan struct{}
}

func (b *stalledConfigBody) Read(p []byte) (int, error) {
	close(b.entered)
	<-b.release
	return 0, io.EOF
}
func (b *stalledConfigBody) Close() error { return nil }

func TestStalledConfigBodyDoesNotLockReload(t *testing.T) {
	h := &Handler{cfg: &config.Config{}}
	b := &stalledConfigBody{entered: make(chan struct{}), release: make(chan struct{})}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest("PUT", "/v0/management/logs-max-total-size-mb", b)
	done := make(chan struct{})
	go func() { h.PutLogsMaxTotalSizeMB(c); close(done) }()
	<-b.entered
	setDone := make(chan struct{})
	go func() { h.SetConfig(&config.Config{}); close(setDone) }()
	select {
	case <-setDone:
	case <-time.After(time.Second):
		close(b.release)
		<-done
		<-setDone
		t.Fatal("stalled request body holds SetConfig lock")
	}
	authDone := make(chan struct{})
	go func() { h.AuthenticateManagementKey("127.0.0.1", true, ""); close(authDone) }()
	select {
	case <-authDone:
	case <-time.After(time.Second):
		close(b.release)
		<-done
		<-authDone
		t.Fatal("stalled request body holds authentication lock")
	}
	close(b.release)
	<-done
}
