package handlers

import (
	"fmt"
	"net/http"
	"testing"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type policyBootstrapHeaderError struct{ error }

func (e policyBootstrapHeaderError) Unwrap() error { return e.error }
func (e policyBootstrapHeaderError) Headers() http.Header {
	return http.Header{"Retry-After": {"handshake-not-error"}}
}

func TestAPIKeySingleAttemptDirectErrorKeepsFailureHeaders(t *testing.T) {
	for _, status := range []int{400, 429, 503} {
		raw := &coreexecutor.ClientUpstreamError{Status: status, Body: []byte("original upstream bytes\n"), Header: http.Header{"Retry-After": {"17"}, "Content-Type": {"application/json"}}, Terminal: true}
		message := executionErrorMessage(fmt.Errorf("execution wrapper: %w", policyBootstrapHeaderError{raw}))
		if message.StatusCode != status || !message.DirectResponse || string(message.Body) != "original upstream bytes\n" || message.Headers.Get("Retry-After") != "17" {
			t.Fatalf("original failure lost: %+v", message)
		}
	}
}
