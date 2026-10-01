package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"sync/atomic"
)

type clientExecutionPolicyKey struct{}
type clientExecutionPolicy struct {
	model    string
	single   bool
	attempts *atomic.Int32
}

// WithClientExecutionPolicy installs the server-owned, original model anchor.
// Re-entering execution cannot replace it with plugin metadata or an alias.
func WithClientExecutionPolicy(ctx context.Context, model string, single bool) context.Context {
	attempts := &atomic.Int32{}
	if old, _ := ctx.Value(clientExecutionPolicyKey{}).(*clientExecutionPolicy); old != nil {
		model = old.model
		single = single || old.single
		attempts = old.attempts
	}
	return context.WithValue(ctx, clientExecutionPolicyKey{}, &clientExecutionPolicy{model: model, single: single, attempts: attempts})
}
func WithoutClientExecutionPolicy(ctx context.Context) context.Context {
	return context.WithValue(ctx, clientExecutionPolicyKey{}, (*clientExecutionPolicy)(nil))
}
func WithClientExecutionPolicyFromContext(ctx, source context.Context) context.Context {
	if p, _ := source.Value(clientExecutionPolicyKey{}).(*clientExecutionPolicy); p != nil {
		return context.WithValue(ctx, clientExecutionPolicyKey{}, p)
	}
	return ctx
}

// ClaimClientUpstreamAttempt is shared by transport retries, redirects and retained turns.
func ClaimClientUpstreamAttempt(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(clientExecutionPolicyKey{}).(*clientExecutionPolicy)
	if p == nil || !p.single {
		return nil
	}
	if !p.attempts.CompareAndSwap(0, 1) {
		return &ClientExecutionPolicyError{Message: "client API key single-attempt policy forbids another upstream attempt"}
	}
	return nil
}

func ClientExecutionModel(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	p, _ := ctx.Value(clientExecutionPolicyKey{}).(*clientExecutionPolicy)
	if p == nil {
		return ""
	}
	return p.model
}
func ClientSingleAttempt(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	p, _ := ctx.Value(clientExecutionPolicyKey{}).(*clientExecutionPolicy)
	return p != nil && p.single
}
func HasClientExecutionPolicy(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	p, _ := ctx.Value(clientExecutionPolicyKey{}).(*clientExecutionPolicy)
	return p != nil
}

type ClientExecutionPolicyError struct{ Message string }

func (e *ClientExecutionPolicyError) Error() string       { return e.Message }
func (*ClientExecutionPolicyError) StatusCode() int       { return http.StatusForbidden }
func (*ClientExecutionPolicyError) IsRequestScoped() bool { return true }

func ValidateClientExecutionModel(ctx context.Context, model string) error {
	if !HasClientExecutionPolicy(ctx) {
		return nil
	}
	original := ClientExecutionModel(ctx)
	if original == "" || model != original {
		return &ClientExecutionPolicyError{Message: "client API key policy forbids model substitution"}
	}
	return nil
}

// ValidateClientWireModel checks the actual serialized model, after translation,
// payload defaults and interceptors. Unknown representations fail closed.
func ValidateClientWireModel(ctx context.Context, payload []byte, inherited bool) error {
	if !HasClientExecutionPolicy(ctx) {
		return nil
	}
	if err := rejectDuplicateClientModelKeys(payload); err != nil {
		return err
	}
	var body map[string]json.RawMessage
	if json.Unmarshal(payload, &body) != nil {
		return &ClientExecutionPolicyError{Message: "cannot verify upstream model for client API key policy"}
	}
	found, err := validateClientWireModelFields(ctx, body)
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	if inherited {
		var eventType string
		_ = json.Unmarshal(body["type"], &eventType)
		if eventType == "response.steer" {
			return nil
		}
	}
	return ValidateClientExecutionModel(ctx, "")
}

// Upstream parsers disagree on first/last duplicate keys. Refuse ambiguity in
// every object that can carry the wire model, before map decoding loses it.
func rejectDuplicateClientModelKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return &ClientExecutionPolicyError{Message: "cannot verify upstream model object"}
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return &ClientExecutionPolicyError{Message: "invalid upstream model object"}
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return err
		}
		if key == "model" || key == "request" || key == "session" {
			if seen[key] {
				return &ClientExecutionPolicyError{Message: "ambiguous duplicate upstream model fields"}
			}
			seen[key] = true
			if key != "model" {
				if err := rejectDuplicateClientModelKeys(raw); err != nil {
					return err
				}
			}
		}
	}
	_, err = decoder.Token()
	return err
}

func validateClientWireModelFields(ctx context.Context, body map[string]json.RawMessage) (bool, error) {
	found := false
	objects := []map[string]json.RawMessage{body}
	for _, field := range []string{"request", "session"} {
		var nested map[string]json.RawMessage
		if raw, ok := body[field]; ok && json.Unmarshal(raw, &nested) == nil {
			objects = append(objects, nested)
		}
	}
	for _, object := range objects {
		if raw, ok := object["model"]; ok {
			var model string
			if json.Unmarshal(raw, &model) != nil {
				return false, &ClientExecutionPolicyError{Message: "invalid upstream model for client API key policy"}
			}
			if err := ValidateClientExecutionModel(ctx, model); err != nil {
				return false, err
			}
			found = true
		}
	}
	return found, nil
}

func ValidateClientHTTPRequest(req *http.Request) error {
	ctx := req.Context()
	if !HasClientExecutionPolicy(ctx) {
		return nil
	}
	var payload []byte
	if req.Body != nil {
		var err error
		payload, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(payload))
		if err != nil {
			return err
		}
	}
	media, params, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if media == "multipart/form-data" {
		reader := multipart.NewReader(bytes.NewReader(payload), params["boundary"])
		found := false
		for {
			part, err := reader.NextPart()
			if err == io.EOF {
				break
			}
			if err != nil {
				return &ClientExecutionPolicyError{Message: "cannot verify malformed upstream multipart payload"}
			}
			if part.FormName() == "model" {
				value, err := io.ReadAll(part)
				if err != nil {
					return err
				}
				if err := ValidateClientExecutionModel(ctx, string(value)); err != nil {
					return err
				}
				found = true
			}
		}
		if found {
			return nil
		}
	}
	// Gemini/Vertex encode the model in the resource path, not the JSON body.
	if index := strings.LastIndex(req.URL.Path, "/models/"); index >= 0 {
		model := req.URL.Path[index+len("/models/"):]
		model = strings.SplitN(model, ":", 2)[0]
		if err := ValidateClientExecutionModel(ctx, model); err != nil {
			return err
		}
		if err := rejectDuplicateClientModelKeys(payload); err != nil {
			return err
		}
		var body map[string]json.RawMessage
		if json.Unmarshal(payload, &body) != nil {
			return &ClientExecutionPolicyError{Message: "cannot verify upstream payload model"}
		}
		_, err := validateClientWireModelFields(ctx, body)
		return err
	}
	return ValidateClientWireModel(ctx, payload, false)
}

// ClientUpstreamError retains the response before provider-specific classifiers
// can rewrite its status/body. Headers include the original Retry-After value.
type ClientUpstreamError struct {
	Status   int
	Body     []byte
	Header   http.Header
	Terminal bool
}

func (e *ClientUpstreamError) Error() string {
	return fmt.Sprintf("upstream status %d: %s", e.Status, e.Body)
}
func (e *ClientUpstreamError) StatusCode() int       { return e.Status }
func (e *ClientUpstreamError) ResponseBody() []byte  { return append([]byte(nil), e.Body...) }
func (e *ClientUpstreamError) Headers() http.Header  { return e.Header.Clone() }
func (e *ClientUpstreamError) DirectResponse() bool  { return true }
func (e *ClientUpstreamError) IsRequestScoped() bool { return e.Terminal }

func PreserveClientUpstreamError(ctx context.Context, status int, body []byte, headers http.Header) error {
	return &ClientUpstreamError{Status: status, Body: append([]byte(nil), body...), Header: headers.Clone(), Terminal: ClientSingleAttempt(ctx) || status == http.StatusBadRequest}
}
