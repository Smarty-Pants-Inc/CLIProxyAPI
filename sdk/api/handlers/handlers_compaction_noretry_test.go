package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/interfaces"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestWriteErrorResponseShouldRetryOnlyForCompactionAffinityMissing(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"missing", &coreauth.Error{Code: "compaction_affinity_missing", Message: "unknown signer", HTTPStatus: http.StatusConflict}, "false"},
		{"missing-wrapped", coreauth.WithCause(&coreauth.Error{Code: "compaction_affinity_missing", Message: "unknown signer", HTTPStatus: http.StatusConflict}, errors.New("cause")), "false"},
		{"conflict", &coreauth.Error{Code: "compaction_affinity_conflict", Message: "conflict", HTTPStatus: http.StatusConflict}, ""},
		{"plain-409", errors.New("upstream conflict"), ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gin.SetMode(gin.TestMode)
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
			NewBaseAPIHandlers(nil, nil).WriteErrorResponse(c, &interfaces.ErrorMessage{StatusCode: http.StatusConflict, Error: tc.err})
			if recorder.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409", recorder.Code)
			}
			if got := recorder.Header().Get("X-Should-Retry"); got != tc.want {
				t.Fatalf("x-should-retry = %q, want %q", got, tc.want)
			}
		})
	}
}
