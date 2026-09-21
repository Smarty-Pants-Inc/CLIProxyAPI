package helps

import (
	"fmt"
	"net/http"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// CodexModelGuard checks the authoritative Responses model before translation.
// Compact and image endpoints do not use this guard.
type CodexModelGuard struct {
	expected string
	observed bool
}

func NewCodexModelGuard(expected string) *CodexModelGuard {
	return &CodexModelGuard{expected: normalizeCodexModelName(expected)}
}

func (g *CodexModelGuard) Authoritative() bool { return g.observed }

func (g *CodexModelGuard) Observe(payload []byte) error {
	model, terminal := extractCodexResponseModelEvent(payload)
	if model == "" {
		if terminal && !g.observed {
			return g.Missing()
		}
		return nil
	}
	if normalizeCodexModelName(model) != g.expected {
		return newCodexModelMismatchError(fmt.Sprintf("upstream response.model %q does not match requested upstream model %q", model, g.expected))
	}
	g.observed = true
	return nil
}

func (g *CodexModelGuard) Missing() error {
	return newCodexModelMismatchError("upstream response.model is missing before downstream exposure")
}

type CodexModelMismatchError struct {
	*cliproxyauth.Error
}

func newCodexModelMismatchError(message string) error {
	return &CodexModelMismatchError{Error: &cliproxyauth.Error{Code: "model_mismatch", Message: message, Retryable: true, HTTPStatus: http.StatusBadGateway}}
}

func (*CodexModelMismatchError) IsCredentialScoped() bool { return true }

func (e *CodexModelMismatchError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Error
}
