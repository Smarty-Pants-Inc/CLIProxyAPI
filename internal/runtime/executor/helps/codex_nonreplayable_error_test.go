package helps

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type codexNonReplayableSourceError struct{ retryAfter time.Duration }

func (*codexNonReplayableSourceError) Error() string            { return "unsafe upstream failure" }
func (*codexNonReplayableSourceError) StatusCode() int          { return http.StatusTooManyRequests }
func (*codexNonReplayableSourceError) IsCredentialScoped() bool { return true }
func (*codexNonReplayableSourceError) IsRequestScoped() bool    { return false }
func (e *codexNonReplayableSourceError) RetryAfter() *time.Duration {
	return &e.retryAfter
}

func TestWrapCodexNonReplayableStreamError(t *testing.T) {
	if got := WrapCodexNonReplayableStreamError(nil); got != nil {
		t.Fatalf("nil passthrough = %v", got)
	}
	source := &codexNonReplayableSourceError{retryAfter: 17 * time.Second}
	wrapped := WrapCodexNonReplayableStreamError(source)
	if _, ok := wrapped.(cliproxyexecutor.RequestScopedError); ok {
		t.Fatal("stream wrapper must not implement request scope")
	}
	if errors.Unwrap(wrapped) != source || wrapped.Error() != source.Error() {
		t.Fatal("source identity or message changed")
	}
	for _, err := range []error{wrapped, fmt.Errorf("bootstrap: %w", wrapped)} {
		var stop interface{ IsRequestStop() bool }
		var scoped cliproxyexecutor.RequestScopedError
		var status interface{ StatusCode() int }
		var retry interface{ RetryAfter() *time.Duration }
		var credential interface{ IsCredentialScoped() bool }
		if !errors.Is(err, source) || !errors.As(err, &stop) || !stop.IsRequestStop() {
			t.Fatal("source or stop marker lost")
		}
		if !errors.As(err, &scoped) || scoped.IsRequestScoped() {
			t.Fatal("underlying false request scope changed")
		}
		if !errors.As(err, &status) || status.StatusCode() != 429 || !errors.As(err, &retry) || retry.RetryAfter() != source.RetryAfter() || !errors.As(err, &credential) || !credential.IsCredentialScoped() {
			t.Fatal("upstream quota metadata changed")
		}
	}
}

func TestWrapCodexNonReplayableErrorNil(t *testing.T) {
	if got := WrapCodexNonReplayableError(nil); got != nil {
		t.Fatalf("WrapCodexNonReplayableError(nil) = %v", got)
	}
}

func TestWrapCodexNonReplayableErrorPreservesSource(t *testing.T) {
	source := &codexNonReplayableSourceError{retryAfter: 17 * time.Second}
	wrapped := WrapCodexNonReplayableError(source)
	if wrapped.Error() != source.Error() || errors.Unwrap(wrapped) != source || !errors.Is(wrapped, source) {
		t.Fatalf("wrapper did not preserve source: %v", wrapped)
	}
	var requestScoped cliproxyexecutor.RequestScopedError
	if !errors.As(source, &requestScoped) || requestScoped.IsRequestScoped() {
		t.Fatal("source must remain non-request-scoped")
	}
	for _, err := range []error{wrapped, fmt.Errorf("bootstrap: %w", wrapped)} {
		if !errors.As(err, &requestScoped) || !requestScoped.IsRequestScoped() {
			t.Fatal("wrapper must override the source's false request scope")
		}
		var requestStop interface{ IsRequestStop() bool }
		if !errors.As(err, &requestStop) || !requestStop.IsRequestStop() {
			t.Fatal("wrapper must preserve a hard request-stop marker through the chain")
		}
		var typedSource *codexNonReplayableSourceError
		if !errors.As(err, &typedSource) || typedSource != source {
			t.Fatal("typed source identity was not preserved")
		}
		var status interface{ StatusCode() int }
		var retry interface{ RetryAfter() *time.Duration }
		var credential interface{ IsCredentialScoped() bool }
		if !errors.As(err, &status) || status.StatusCode() != source.StatusCode() {
			t.Fatal("status code was not preserved")
		}
		if !errors.As(err, &retry) || retry.RetryAfter() != source.RetryAfter() {
			t.Fatal("retry-after value was not preserved")
		}
		if !errors.As(err, &credential) || !credential.IsCredentialScoped() {
			t.Fatal("credential scope was not preserved")
		}
	}
}

func TestWrapCodexNonReplayableErrorPreservesModelGuard(t *testing.T) {
	source := NewCodexModelGuard("gpt-5.6-astra").Missing()
	var requestScoped cliproxyexecutor.RequestScopedError
	if errors.As(source, &requestScoped) && requestScoped.IsRequestScoped() {
		t.Fatal("unwrapped model guard must not become request-scoped")
	}
	wrapped := WrapCodexNonReplayableError(source)
	var authErr *cliproxyauth.Error
	if !errors.As(wrapped, &authErr) || authErr.Code != "model_mismatch" || !authErr.Retryable || authErr.HTTPStatus != http.StatusBadGateway {
		t.Fatalf("underlying guard error changed: %v", wrapped)
	}
	if errors.Unwrap(wrapped) != source || wrapped.Error() != source.Error() {
		t.Fatal("guard error identity or message changed")
	}
	var credential interface{ IsCredentialScoped() bool }
	if !errors.As(wrapped, &credential) || !credential.IsCredentialScoped() {
		t.Fatal("model guard credential scope was not preserved")
	}
	if !errors.As(wrapped, &requestScoped) || !requestScoped.IsRequestScoped() {
		t.Fatal("wrapped model guard must become request-scoped")
	}
}
