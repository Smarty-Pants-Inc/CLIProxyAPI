package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
)

func TestForwardStreamCancellationWinsReadyErrorAndEOF(t *testing.T) {
	gin.SetMode(gin.TestMode)
	for i := 0; i < 100; i++ {
		recorder := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(recorder)
		ctx, cancel := context.WithCancel(context.Background())
		c.Request = httptest.NewRequest(http.MethodGet, "/", nil).WithContext(ctx)
		data := make(chan []byte)
		close(data)
		errs := make(chan *interfaces.ErrorMessage, 1)
		errs <- &interfaces.ErrorMessage{StatusCode: 502, Error: errors.New("upstream disconnected")}
		close(errs)
		cancel()
		var got error
		disabled := time.Duration(0)
		(&BaseAPIHandler{}).ForwardStream(c, recorder, func(err error) { got = err }, data, errs, StreamForwardOptions{
			KeepAliveInterval:  &disabled,
			WriteTerminalError: func(*interfaces.ErrorMessage) { t.Fatal("error sent to canceled client") },
			WriteDone:          func() { t.Fatal("success sent to canceled client") },
		})
		if !errors.Is(got, context.Canceled) {
			t.Fatalf("completion = %v, want cancellation", got)
		}
	}
}
