package live

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/clienterror"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	coreusage "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

type syncOnceCloser struct {
	once  sync.Once
	close func() error
	err   error
}

func (c *syncOnceCloser) Close() error { c.once.Do(func() { c.err = c.close() }); return c.err }

func (h *Handler) poolModeEnabled() bool {
	return h != nil && h.authManager != nil && h.authManager.PoolMode()
}

func writePoolLiveError(c *gin.Context, status int, code string) {
	c.JSON(status, gin.H{"error": gin.H{"code": code, "message": code}})
}

func writePoolLiveFailure(c *gin.Context, err error) {
	status := clienterror.HTTPStatusFromErrorOr(err, http.StatusServiceUnavailable)
	code := "api_key_pool_path_unavailable"
	var policyErr *auth.Error
	if errors.As(err, &policyErr) && (strings.HasPrefix(policyErr.Code, "api_key_pool_") || policyErr.Code == "api_key_model_forbidden") {
		code = policyErr.Code
	}
	writePoolLiveError(c, status, code)
}

// Only authentication middleware's native access result is authority. Never read
// competing Authorization/X-Api-Key/query headers here or admit a client secret.
func (h *Handler) poolLivePrincipal(c *gin.Context) (string, string, bool) {
	principal, provider := requestOwner(c)
	if !coreusage.IsNativeAccessProvider(provider) || principal == "" {
		writePoolLiveError(c, http.StatusForbidden, "api_key_pool_unclassified")
		return "", "", false
	}
	if _, secret := c.Get(ClientSecretPrincipalContextKey); secret {
		writePoolLiveError(c, http.StatusServiceUnavailable, "api_key_pool_path_unavailable")
		return "", "", false
	}
	poolID, class, err := h.authManager.PoolPrincipal(principal)
	if err != nil {
		writePoolLiveFailure(c, err)
		return "", "", false
	}
	if class != string(config.PoolClassHuman) {
		writePoolLiveError(c, http.StatusServiceUnavailable, "api_key_pool_path_unavailable")
		return "", "", false
	}
	return principal, poolID, true
}

func (h *Handler) beginPoolCall(ctx context.Context, principal, model string) (context.Context, *liveCallLifetime, func(), error) {
	// Admission and the shutdown snapshot share the handler lock. Close cannot
	// miss a lease acquired immediately before its fence, including bootstrap.
	h.mediaRelayMu.Lock()
	defer h.mediaRelayMu.Unlock()
	if h.poolClosed {
		return ctx, nil, nil, &auth.Error{Code: "api_key_pool_path_unavailable", Message: "api_key_pool_path_unavailable", HTTPStatus: 503}
	}
	ctx, op, err := h.authManager.BeginPoolOperation(ctx, principal, model, auth.PoolLiveCall)
	if err != nil {
		return ctx, nil, nil, err
	}
	ctx, lifetime := newLiveCallLifetime(ctx, op)
	done, _ := lifetime.beginWork()
	context.AfterFunc(ctx, func() { lifetime.requestClose("operation_canceled") })
	if h.poolCalls == nil {
		h.poolCalls = make(map[*liveCallLifetime]struct{})
	}
	h.poolCalls[lifetime] = struct{}{}
	go func() {
		lifetime.waitClosed()
		h.mediaRelayMu.Lock()
		delete(h.poolCalls, lifetime)
		h.mediaRelayMu.Unlock()
	}()
	return ctx, lifetime, done, nil
}

// canonicalPoolLiveRequest accepts the same JSON/multipart voice business input,
// but not direct SDP/client-secret aliases. Keep the original canonical view for
// payload rule gates; built-in normalization happens only to the prepared view.
func canonicalPoolLiveRequest(body []byte, contentType string) ([]byte, []byte, string, error) {
	mediaType, _, errType := mime.ParseMediaType(contentType)
	if errType != nil || (mediaType != "application/json" && mediaType != "multipart/form-data") {
		return nil, nil, "", errors.New("live requires JSON or multipart")
	}
	canonical, _, model, err := prepareCallRequest(body, contentType)
	if err != nil {
		return nil, nil, "", err
	}
	if !validUniqueJSONObject(canonical) {
		return nil, nil, "", errors.New("ambiguous live object")
	}
	var root map[string]json.RawMessage
	if err = json.Unmarshal(canonical, &root); err != nil || root == nil {
		return nil, nil, "", errors.New("invalid live object")
	}
	for key := range root {
		if key != "sdp" && key != "session" && key != "model" {
			return nil, nil, "", errors.New("unsupported live field")
		}
	}
	var sdp string
	if err = json.Unmarshal(root["sdp"], &sdp); err != nil || strings.TrimSpace(sdp) == "" {
		return nil, nil, "", errors.New("live requires SDP")
	}
	if raw, exists := root["model"]; exists {
		var value string
		if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" {
			return nil, nil, "", errors.New("invalid live model")
		}
	}
	var session map[string]json.RawMessage
	if raw, exists := root["session"]; exists {
		if err = json.Unmarshal(raw, &session); err != nil || session == nil {
			return nil, nil, "", errors.New("invalid live session")
		}
	} else {
		session = make(map[string]json.RawMessage)
	}
	if raw, exists := session["model"]; exists {
		var value string
		if json.Unmarshal(raw, &value) != nil || strings.TrimSpace(value) == "" {
			return nil, nil, "", errors.New("invalid live model")
		}
	}
	original, err := json.Marshal(root)
	if err != nil {
		return nil, nil, "", err
	}
	model = codexRealtimeModel(model)
	encodedModel, _ := json.Marshal(model)
	session["model"] = encodedModel
	root["session"], err = json.Marshal(session)
	if err != nil {
		return nil, nil, "", err
	}
	delete(root, "model")
	prepared, err := json.Marshal(root)
	return original, prepared, model, err
}

// finalizePoolLivePayload is the final semantic barrier: built-ins and relay SDP
// replacement must already be complete. Validation below is strictly read-only.
func finalizePoolLivePayload(ctx context.Context, cfg *config.Config, model, contentType string, original, prepared []byte, headers http.Header) ([]byte, string, error) {
	if contentType != "application/json" {
		return nil, "", errors.New("unsupported live payload")
	}
	offer, err := callRequestSDP(prepared, contentType)
	if err != nil {
		return nil, "", err
	}
	opts := coreexecutor.Options{SourceFormat: translator.FormatOpenAIResponse, Headers: headers, Metadata: map[string]any{coreexecutor.RequestPathMetadataKey: "/v1/live"}}
	finalize := helps.NewTrackedPayloadFinalizer(cfg, "codex", model, "openai-response", "", original, coreexecutor.Request{Model: model}, opts, "session.model", "sdp")
	ctx = helps.WithTrackedPayloadFinalizer(ctx, finalize)
	final, _ := helps.FinalizePayloadTracked(ctx, prepared)
	if !validUniqueJSONObject(final) {
		return nil, "", errors.New("unsafe configured live shape")
	}
	var payload struct {
		SDP     string                     `json:"sdp"`
		Session map[string]json.RawMessage `json:"session"`
	}
	if json.Unmarshal(final, &payload) != nil || payload.Session == nil || payload.SDP != offer {
		return nil, "", errors.New("unsafe configured live payload")
	}
	var finalModel string
	if json.Unmarshal(payload.Session["model"], &finalModel) != nil {
		return nil, "", errors.New("unsafe configured live model shape")
	}
	if finalModel != model {
		return nil, "", &auth.Error{Code: "api_key_model_forbidden", Message: "api_key_model_forbidden", HTTPStatus: http.StatusForbidden}
	}
	// Deny aliases that could create a second target/model authority. Never repair
	// configured values or restore a field filtered by the user's rules.
	var root map[string]json.RawMessage
	if json.Unmarshal(final, &root) != nil || len(root) != 2 || root["sdp"] == nil || root["session"] == nil {
		return nil, "", errors.New("unsafe configured live shape")
	}
	return final, "application/json", nil
}

func (h *Handler) handlePoolLive(c *gin.Context) {
	if c.Request.Method != http.MethodPost || c.Request.URL.Path != "/v1/live" {
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	principal, _, ok := h.poolLivePrincipal(c)
	if !ok {
		return
	}
	body, err := readBody(c.Request.Body)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errBodyTooLarge) {
			status = http.StatusRequestEntityTooLarge
		}
		writePoolLiveError(c, status, "invalid_live_request")
		return
	}
	original, prepared, model, err := canonicalPoolLiveRequest(body, c.GetHeader("Content-Type"))
	if err != nil {
		writePoolLiveError(c, http.StatusBadRequest, "invalid_live_request")
		return
	}
	cfg, relay, relayErr := h.currentRuntime()
	if relayErr != nil || relay == nil {
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	ctx := context.WithValue(c.Request.Context(), "gin", c)
	ctx, lifetime, workDone, err := h.beginPoolCall(ctx, principal, model)
	if err != nil {
		writePoolLiveFailure(c, err)
		return
	}
	op := lifetime.op
	retained := false
	defer func() {
		workDone()
		if !retained {
			lifetime.requestClose("bootstrap_not_retained")
			lifetime.waitClosed()
		}
	}()
	selected, err := h.authManager.SelectPoolLiveAuth(ctx, "")
	if err != nil {
		writePoolLiveFailure(c, err)
		return
	}
	if selected == nil {
		writePoolLiveError(c, 503, "api_key_pool_unavailable")
		return
	}
	clientOffer, err := callRequestSDP(prepared, "application/json")
	if err != nil {
		writePoolLiveError(c, 400, "invalid_live_request")
		return
	}
	media, offer, err := relay.NewSession(ctx, clientOffer, mediaSessionRoute{proxyURL: proxyURLForAuth(cfg, selected), credential: mediaCredentialName(selected, selected.EnsureIndex()), authIndex: selected.EnsureIndex(), poolLive: true, onClose: lifetime.requestClose})
	if media != nil {
		lifetime.setMedia(media)
	}
	if err != nil || media == nil {
		writePoolLiveError(c, 502, "live_media_unavailable")
		return
	}
	// A factory must preserve failures that happened before binding the callback.
	media.SetCloseHandler(lifetime.requestClose)
	prepared, _, err = replaceCallRequestSDP(prepared, "application/json", offer)
	if err != nil {
		writePoolLiveError(c, 400, "invalid_live_request")
		return
	}
	headers := protocolHeaders(c.Request.Header)
	prepared, contentType, err := finalizePoolLivePayload(ctx, cfg, model, "application/json", original, prepared, c.Request.Header)
	if err != nil {
		writePoolLiveFailure(c, err)
		return
	}
	headers.Set("Content-Type", contentType)
	req, err := h.authManager.NewPoolLiveRequest(ctx, selected, "", prepared, headers)
	if err != nil {
		writePoolLiveFailure(c, err)
		return
	}
	response, err := h.authManager.SendPoolLiveRequest(req)
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		writePoolLiveFailure(c, err)
		return
	}
	if response == nil || response.Body == nil {
		writePoolLiveError(c, 502, "live_upstream_unavailable")
		return
	}
	// Cancellation can close an in-progress bootstrap read; body cleanup is still
	// completed synchronously before transfer or request-owner release.
	var closeBodyOnce syncOnceCloser
	closeBodyOnce.close = response.Body.Close
	unregisterBody := lifetime.resources.add(closeBodyOnce.Close)
	defer func() { _ = closeBodyOnce.Close(); unregisterBody() }()
	answer, errRead := readLimitedBody(response.Body)
	errClose := closeBodyOnce.Close()
	if errRead != nil || errClose != nil {
		writePoolLiveError(c, 502, "live_upstream_unavailable")
		return
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Provider error bodies are not local policy errors and may contain secrets.
		writePoolLiveError(c, response.StatusCode, "live_upstream_unavailable")
		return
	}
	callID := callIDFromLocation(response.Header.Get("Location"))
	if callID == "" || h.sessions == nil {
		writePoolLiveError(c, 502, "live_upstream_unavailable")
		return
	}
	upstreamAnswer, err := callResponseSDP(answer, response.Header.Get("Content-Type"))
	if err != nil {
		writePoolLiveError(c, 502, "live_upstream_unavailable")
		return
	}
	media.SetCallID(callID)
	downstreamAnswer, err := media.AcceptUpstreamAnswer(ctx, upstreamAnswer)
	if err != nil {
		writePoolLiveError(c, 502, "live_media_unavailable")
		return
	}
	if err = lifetime.transfer(callID); err != nil {
		writePoolLiveFailure(c, err)
		return
	}
	owner, provider := requestOwner(c)
	session := h.sessions.put(callID, liveSession{authID: selected.ID, model: model, ownerPrincipal: owner, ownerProvider: provider, media: media, poolOp: op, lifetime: lifetime, resources: lifetime.resources})
	if session.callID == "" {
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	lifetime.bindStoredCall(func() { h.sessions.complete(session, "call_closing") })
	if ctx.Err() != nil {
		h.sessions.complete(session, "bootstrap_canceled")
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	// Local call attribution, not a provider-controlled external URL.
	responseHeaders := callResponseHeaders(response.Header)
	responseHeaders.Set("Location", "/v1/live/"+callID)
	responseHeaders.Set("Content-Type", "application/sdp")
	writeResponseHeaders(c.Writer.Header(), responseHeaders)
	c.Status(response.StatusCode)
	if _, err = io.Copy(c.Writer, bytes.NewReader([]byte(downstreamAnswer))); err != nil {
		h.sessions.complete(session, "response_write_failed")
		return
	}
	retained = true
}
