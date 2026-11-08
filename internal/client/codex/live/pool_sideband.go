package live

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// The dependency is private. Tests can replace dial construction in export_test.go
// without changing the production URL, manager minting, or final send validation.
var poolLiveSidebandDialer = newProxyAwareSidebandDialer

func (h *Handler) handlePoolSideband(c *gin.Context) {
	callID := c.Param("call_id")
	if c.Request.Method != http.MethodGet || !callIDPattern.MatchString(callID) || c.Request.URL.Path != "/v1/live/"+callID {
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	principal, poolID, ok := h.poolLivePrincipal(c)
	if !ok {
		return
	}
	if !websocket.IsWebSocketUpgrade(c.Request) {
		c.Header("Upgrade", "websocket")
		writePoolLiveError(c, http.StatusUpgradeRequired, "websocket_upgrade_required")
		return
	}
	if h.sessions == nil {
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	session, claim := h.sessions.claim(callID)
	switch claim {
	case sessionClaimMissing:
		writePoolLiveError(c, http.StatusNotFound, "live_call_not_found")
		return
	case sessionClaimBusy:
		writePoolLiveError(c, http.StatusConflict, "live_call_already_joining")
		return
	}
	_, provider := requestOwner(c)
	if session.ownerPrincipal != principal || session.ownerProvider != provider || session.poolOp == nil || !session.poolOp.IsPoolOperation() || session.poolOp.PoolID() != poolID || session.poolOp.PoolClass() != string(config.PoolClassHuman) || session.poolOp.PoolKind() != auth.PoolLiveCall || session.lifetime == nil {
		h.sessions.release(session)
		writePoolLiveError(c, http.StatusForbidden, "api_key_pool_live_scope_mismatch")
		return
	}
	workDone, ok := session.lifetime.beginWork()
	if !ok {
		h.sessions.release(session)
		writePoolLiveError(c, 404, "live_call_not_found")
		return
	}
	consume := false
	ctx, cancel := context.WithCancel(session.lifetime.ctx)
	stopRequestCancel := context.AfterFunc(c.Request.Context(), cancel)
	resources := &liveSessionResources{}
	resources.add(func() error { cancel(); return nil })
	unregister := session.lifetime.resources.add(func() error { resources.requestClose(); return nil })
	defer func() {
		cancel()
		stopRequestCancel()
		// A failed join releases its claim only after pending dial/socket/copy work
		// has terminated. It does not cancel media or release the call lease.
		resources.close()
		unregister()
		workDone()
		if consume {
			h.sessions.complete(session, "session_closed")
		} else {
			h.sessions.release(session)
		}
	}()
	ctx = auth.WithKeyPolicy(context.WithValue(ctx, "gin", c), session.poolOp)
	selected, err := h.authManager.SelectPoolLiveAuth(ctx, session.authID)
	if err != nil {
		consume = poolLiveIdentityFailure(err)
		writePoolLiveFailure(c, err)
		return
	}
	if selected == nil || selected.ID != session.authID {
		consume = true
		writePoolLiveError(c, 503, "api_key_pool_identity_unverified")
		return
	}
	req, err := h.authManager.NewPoolLiveRequest(ctx, selected, callID, nil, protocolHeaders(c.Request.Header))
	if err != nil {
		consume = poolLiveIdentityFailure(err)
		writePoolLiveFailure(c, err)
		return
	}
	upstreamURL := *req.URL
	upstreamURL.Scheme = "wss"
	dialer := poolLiveSidebandDialer(h.currentConfig(), selected)
	closeDialOnCancel(dialer, ctx)
	// No user subprotocols or later credential/header mutations. WSS scheme is
	// transport framing of the exact manager-approved stored-call GET.
	if err = auth.CheckKeyPolicySend(req); err != nil {
		consume = poolLiveIdentityFailure(err)
		writePoolLiveFailure(c, err)
		return
	}
	upstream, response, err := dialer.DialContext(ctx, upstreamURL.String(), req.Header)
	if err != nil {
		status := http.StatusBadGateway
		if response != nil {
			if response.StatusCode >= 400 && response.StatusCode <= 599 {
				status = response.StatusCode
			}
			if response.Body != nil {
				_ = response.Body.Close()
			}
		}
		writePoolLiveError(c, status, "live_sideband_upstream_unavailable")
		return
	}
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	resources.add(websocketCloseFunc("pool-upstream", upstream))
	if ctx.Err() != nil {
		writePoolLiveError(c, 503, "api_key_pool_path_unavailable")
		return
	}
	downstream, err := sidebandUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	resources.add(websocketCloseFunc("pool-downstream", downstream))
	consume = true
	_ = relayPoolWebsockets(downstream, upstream)
}

func poolLiveIdentityFailure(err error) bool {
	var policyErr *auth.Error
	return errors.As(err, &policyErr) && policyErr.Code == "api_key_pool_identity_unverified"
}

var errPoolLiveControl = errors.New("api_key_pool_path_unavailable")

// Only the actual staged voice protocol can carry downstream business controls.
// In particular neither session.update nor a nested model/target can repin media.
func validatePoolLiveControl(data []byte, isString bool) error {
	if !isString || len(data) > mediaDataMessageMaxSize || !validUniqueJSONObject(data) {
		return errPoolLiveControl
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(data, &root) != nil || root == nil {
		return errPoolLiveControl
	}
	var kind string
	if json.Unmarshal(root["type"], &kind) != nil {
		return errPoolLiveControl
	}
	allowed := map[string]bool{"type": true}
	switch kind {
	case "session.close":
	case "delegation.context.append", "session.context.append":
		allowed["content"], allowed["channel"] = true, true
		if kind == "delegation.context.append" {
			allowed["delegation_item_id"] = true
			var id string
			if json.Unmarshal(root["delegation_item_id"], &id) != nil || id == "" || len(id) > 1024 || strings.ContainsFunc(id, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				return errPoolLiveControl
			}
		}
		if raw, exists := root["channel"]; exists {
			var channel string
			if json.Unmarshal(raw, &channel) != nil || (channel != "speakable" && channel != "commentary") {
				return errPoolLiveControl
			}
		}
		var content []map[string]json.RawMessage
		if json.Unmarshal(root["content"], &content) != nil || len(content) == 0 {
			return errPoolLiveControl
		}
		for _, part := range content {
			var typ, text string
			if len(part) != 2 || json.Unmarshal(part["type"], &typ) != nil || typ != "input_text" || json.Unmarshal(part["text"], &text) != nil {
				return errPoolLiveControl
			}
		}
	default:
		return errPoolLiveControl
	}
	for field := range root {
		if !allowed[field] {
			return errPoolLiveControl
		}
	}
	return nil
}

func relayPoolWebsockets(downstream, upstream *websocket.Conn) error {
	downstream.SetReadLimit(mediaDataMessageMaxSize)
	results := make(chan error, 2)
	go func() {
		for {
			kind, payload, err := downstream.ReadMessage()
			if err == nil {
				err = validatePoolLiveControl(payload, kind == websocket.TextMessage)
			}
			if err == nil {
				err = upstream.WriteMessage(kind, payload)
			}
			if err != nil {
				results <- err
				return
			}
		}
	}()
	go func() { results <- copyWebsocket(downstream, upstream) }()
	err := <-results
	if errors.Is(err, errPoolLiveControl) {
		payload := websocket.FormatCloseMessage(websocket.ClosePolicyViolation, "api_key_pool_path_unavailable")
		_ = downstream.WriteControl(websocket.CloseMessage, payload, time.Time{})
		_ = upstream.WriteControl(websocket.CloseMessage, payload, time.Time{})
	}
	// Closing transports unblocks both copy workers. No blocking close handshake
	// or post-connect deadline is needed to prove local completion.
	_ = downstream.Close()
	_ = upstream.Close()
	<-results
	return err
}
