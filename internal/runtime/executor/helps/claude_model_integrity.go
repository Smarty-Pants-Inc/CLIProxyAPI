package helps

import (
	"bufio"
	"bytes"
	"io"
	"net/http"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/tidwall/gjson"
)

// ClaudeModelMismatchError stops the request rather than trying a different model.
type ClaudeModelMismatchError struct{ cause *cliproxyauth.Error }

func (e *ClaudeModelMismatchError) Error() string       { return e.cause.Error() }
func (e *ClaudeModelMismatchError) StatusCode() int     { return e.cause.StatusCode() }
func (e *ClaudeModelMismatchError) Unwrap() error       { return e.cause }
func (*ClaudeModelMismatchError) IsRequestScoped() bool { return true }

func claudeModelMismatch() error {
	// Do not include unverified upstream strings in the downstream error.
	return &ClaudeModelMismatchError{&cliproxyauth.Error{
		Code: "model_mismatch", Message: "upstream Claude model is missing or does not match the requested upstream model",
		HTTPStatus: http.StatusBadGateway,
	}}
}

// ValidateClaudeResponseModel runs before model restoration or translation.
func ValidateClaudeResponseModel(data []byte, expected string) error {
	model := gjson.GetBytes(data, "model")
	if !gjson.ValidBytes(data) || expected == "" || model.Type != gjson.String || model.String() != expected {
		return claudeModelMismatch()
	}
	return nil
}

// GuardClaudeModelStream withholds all bytes until message_start identifies the
// actual upstream model. The caller retains ownership of the underlying closer.
func GuardClaudeModelStream(source io.Reader, expected string) (io.Reader, error) {
	g := &claudeModelStream{scanner: bufio.NewScanner(source), expected: expected}
	g.scanner.Buffer(nil, claudeModelStreamLimit)
	var prefix bytes.Buffer
	for !g.verified {
		line, err := g.next()
		if err != nil {
			return nil, err
		}
		if prefix.Len()+len(line) > claudeModelStreamLimit {
			return nil, claudeModelMismatch()
		}
		prefix.Write(line)
	}
	return io.MultiReader(bytes.NewReader(prefix.Bytes()), g), nil
}

const claudeModelStreamLimit = 52_428_800 // Match the executor's existing 50 MB scan bound.

type claudeModelStream struct {
	scanner  *bufio.Scanner
	expected string
	verified bool
	pending  []byte
}

func (g *claudeModelStream) next() ([]byte, error) {
	if !g.scanner.Scan() {
		if err := g.scanner.Err(); err != nil {
			return nil, err
		}
		if !g.verified {
			return nil, claudeModelMismatch()
		}
		return nil, io.EOF
	}
	line := g.scanner.Bytes()
	trimmed := bytes.TrimSpace(line)
	if bytes.HasPrefix(trimmed, []byte("data:")) {
		payload := bytes.TrimSpace(trimmed[len("data:"):])
		if !g.verified && !gjson.ValidBytes(payload) {
			return nil, claudeModelMismatch()
		}
		switch gjson.GetBytes(payload, "type").String() {
		case "message_start":
			if g.verified {
				return nil, claudeModelMismatch()
			}
			if err := ValidateClaudeResponseModel([]byte(gjson.GetBytes(payload, "message").Raw), g.expected); err != nil {
				return nil, err
			}
			g.verified = true
		case "ping":
		default:
			if !g.verified {
				return nil, claudeModelMismatch()
			}
		}
	}
	return append(bytes.Clone(line), '\n'), nil
}

func (g *claudeModelStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(g.pending) == 0 {
		var err error
		g.pending, err = g.next()
		if err != nil {
			return 0, err
		}
	}
	n := copy(p, g.pending)
	g.pending = g.pending[n:]
	return n, nil
}
