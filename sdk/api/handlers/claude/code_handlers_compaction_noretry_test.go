package claude

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestWriteClaudeErrorResponseCompactionAffinityMissingSetsShouldRetryFalse(t *testing.T) {
	for _, tc := range []struct {
		code string
		want string
	}{{"compaction_affinity_missing", "false"}, {"compaction_affinity_conflict", ""}} {
		t.Run(tc.code, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			handler := &ClaudeCodeAPIHandler{}
			handler.WriteErrorResponse(c, &interfaces.ErrorMessage{
				StatusCode: http.StatusConflict,
				Error:      &coreauth.Error{Code: tc.code, Message: "signed compaction", HTTPStatus: http.StatusConflict},
			})
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409", recorder.Code)
			}
			if !strings.Contains(recorder.Body.String(), tc.code) {
				t.Fatalf("body lacks %s: %s", tc.code, recorder.Body.String())
			}
			if got := recorder.Header().Get("X-Should-Retry"); got != tc.want {
				t.Fatalf("x-should-retry = %q, want %q", got, tc.want)
			}
		})
	}
}
