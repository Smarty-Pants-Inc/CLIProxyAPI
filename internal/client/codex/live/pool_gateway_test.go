package live_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/api"
	live "github.com/router-for-me/CLIProxyAPI/v8/internal/client/codex/live"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	sdkaccess "github.com/router-for-me/CLIProxyAPI/v8/sdk/access"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// Hard user-flow gate: real native access/routes and manager proof/admission,
// local synthetic upstream, TWO genuine Pion WebRTC legs with audio RTP and
// DataChannel, then stored-call WSS. Nothing here attests a real provider identity.
func TestPoolLiveRealGatewayTwoLegMediaAndSideband(t *testing.T) {
	client, err := live.PoolWebRTCAPIForTest(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	provider, err := live.PoolWebRTCAPIForTest(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = provider.Close() }()
	clientAudio, err := webrtc.NewTrackLocalStaticRTP(live.PoolOpusCodecForTest(), "client-audio", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientSender, err := client.AddTrack(clientAudio)
	if err != nil {
		t.Fatal(err)
	}
	providerAudio, err := webrtc.NewTrackLocalStaticRTP(live.PoolOpusCodecForTest(), "provider-audio", "provider")
	if err != nil {
		t.Fatal(err)
	}
	providerSender, err := provider.AddTrack(providerAudio)
	if err != nil {
		t.Fatal(err)
	}
	peerDone := make(chan struct{})
	defer close(peerDone)
	go live.PoolDrainRTCPForTest(clientSender, peerDone)
	go live.PoolDrainRTCPForTest(providerSender, peerDone)
	clientData, err := client.CreateDataChannel("oai-events", nil)
	if err != nil {
		t.Fatal(err)
	}
	clientMessages := make(chan string, 8)
	clientData.OnMessage(func(message webrtc.DataChannelMessage) { clientMessages <- string(message.Data) })
	providerChannels := make(chan *webrtc.DataChannel, 1)
	providerMessages := make(chan string, 8)
	provider.OnDataChannel(func(channel *webrtc.DataChannel) {
		channel.OnMessage(func(message webrtc.DataChannelMessage) { providerMessages <- string(message.Data) })
		providerChannels <- channel
	})
	clientRTP, providerRTP := make(chan []byte, 1), make(chan []byte, 1)
	client.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		packet, _, errRead := track.ReadRTP()
		if errRead == nil {
			clientRTP <- append([]byte(nil), packet.Payload...)
		}
	})
	provider.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		packet, _, errRead := track.ReadRTP()
		if errRead == nil {
			providerRTP <- append([]byte(nil), packet.Payload...)
		}
	})
	clientOffer := live.PoolOfferForTest(t, client)
	var upstreamSends, bootstrapSends, sidebandSends atomic.Int32
	var rejectJoin atomic.Bool
	rejectJoin.Store(true)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamSends.Add(1)
		if r.Header.Get("Authorization") != "Bearer synthetic-human-access" || r.Header.Get("Chatgpt-Account-Id") != "synthetic-human-entitlement" {
			t.Errorf("foreign or unpinned credential reached local provider")
		}
		switch r.URL.Path {
		case "/backend-api/codex/realtime/calls":
			bootstrapSends.Add(1)
			if r.Method != http.MethodPost || r.URL.RawQuery != "intent=quicksilver&architecture=avas" {
				t.Errorf("unexpected native bootstrap target %s %s", r.Method, r.URL)
			}
			var payload struct {
				SDP     string                               `json:"sdp"`
				Session struct{ Model, Instructions string } `json:"session"`
			}
			if errDecode := json.NewDecoder(r.Body).Decode(&payload); errDecode != nil {
				t.Error(errDecode)
				w.WriteHeader(502)
				return
			}
			if payload.SDP == clientOffer || payload.Session.Model != "gpt-live-1-codex" || payload.Session.Instructions != "safe-configured-instructions" {
				t.Errorf("relay/final payload not on wire: model=%s instructions=%s replacedSDP=%v", payload.Session.Model, payload.Session.Instructions, payload.SDP != clientOffer)
			}
			if errRemote := provider.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: payload.SDP}); errRemote != nil {
				t.Error(errRemote)
				w.WriteHeader(502)
				return
			}
			gathered := webrtc.GatheringCompletePromise(provider)
			answer, errAnswer := provider.CreateAnswer(nil)
			if errAnswer != nil {
				t.Error(errAnswer)
				w.WriteHeader(502)
				return
			}
			if errLocal := provider.SetLocalDescription(answer); errLocal != nil {
				t.Error(errLocal)
				w.WriteHeader(502)
				return
			}
			select {
			case <-gathered:
			case <-r.Context().Done():
				return
			}
			w.Header().Set("Location", "/v1/live/rtc_e2e")
			w.Header().Set("Content-Type", "application/sdp")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, provider.LocalDescription().SDP)
		case "/v1/live/rtc_e2e":
			sidebandSends.Add(1)
			if rejectJoin.Swap(false) {
				w.WriteHeader(502)
				return
			}
			conn, errUpgrade := upgrader.Upgrade(w, r, nil)
			if errUpgrade != nil {
				t.Error(errUpgrade)
				return
			}
			defer func() { _ = conn.Close() }()
			for {
				kind, body, errRead := conn.ReadMessage()
				if errRead != nil {
					return
				}
				if errWrite := conn.WriteMessage(kind, body); errWrite != nil {
					return
				}
			}
		default:
			t.Errorf("unsupported upstream target %s", r.URL)
			w.WriteHeader(500)
		}
	}))
	defer upstream.Close()
	live.PoolSidebandUpstreamForTest(t, upstream)
	manager, cfg := live.NewPoolLiveManagerForTest(t, func(ctx context.Context, _ *auth.Auth, req *http.Request) (*http.Response, error) {
		// Test-only trusted executor maps the exact approved native request into
		// our local fixture. Production origin/guard/minting are not modified.
		if req.URL.String() != "https://chatgpt.com/backend-api/codex/realtime/calls?intent=quicksilver&architecture=avas" {
			return nil, fmt.Errorf("unexpected minted target")
		}
		body, errRead := io.ReadAll(req.Body)
		if errRead != nil {
			return nil, errRead
		}
		local, errLocal := http.NewRequestWithContext(ctx, req.Method, upstream.URL+req.URL.RequestURI(), bytes.NewReader(body))
		if errLocal != nil {
			return nil, errLocal
		}
		local.Header = req.Header.Clone()
		return upstream.Client().Do(local)
	})
	cfg.Payload.Override = []config.PayloadRule{{Models: []config.PayloadModelRule{{Name: "gpt-live-1-codex", Protocol: "openai-response"}}, Params: map[string]any{"session.instructions": "safe-configured-instructions"}}}
	server := api.NewServer(cfg, manager, sdkaccess.NewManager(), "")
	defer func() {
		if errStop := server.Stop(context.Background()); errStop != nil {
			t.Error(errStop)
		}
	}()
	gateway := httptest.NewServer(server.Handler())
	defer gateway.Close()
	// Hold the agent pool at cap, yet leave the human pool available.
	_, agentOp, err := manager.BeginPoolOperation(context.Background(), live.PoolAgentKeyForTest, "gpt-5.4", auth.PoolResponses)
	if err != nil {
		t.Fatal(err)
	}
	defer agentOp.Finish()
	post := func(key, path, body string) (int, http.Header, []byte) {
		t.Helper()
		req, errRequest := http.NewRequest("POST", gateway.URL+path, strings.NewReader(body))
		if errRequest != nil {
			t.Fatal(errRequest)
		}
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("OpenAI-Alpha", "quicksilver=v2")
		req.Header.Set("Originator", "Codex Desktop")
		req.Header.Set("X-Session-Id", "synthetic-live-session")
		req.Header.Set("Session-Id", "synthetic-conversation")
		req.Header.Set("Thread-Id", "synthetic-conversation")
		response, errSend := gateway.Client().Do(req)
		if errSend != nil {
			t.Fatal(errSend)
		}
		payload, errRead := io.ReadAll(response.Body)
		errClose := response.Body.Close()
		if errRead != nil || errClose != nil {
			t.Fatalf("response cleanup: %v %v", errRead, errClose)
		}
		return response.StatusCode, response.Header, payload
	}
	body, _ := json.Marshal(map[string]any{"sdp": clientOffer, "session": map[string]any{"model": "gpt-live-1-codex", "instructions": "original", "audio": map[string]any{"output": map[string]any{"voice": "marin"}}, "delegation": map[string]any{"type": "client"}}})
	status, headers, answer := post(live.PoolHumanKeyForTest, "/v1/live", string(body))
	if status != 201 || headers.Get("Location") != "/v1/live/rtc_e2e" {
		t.Fatalf("POST = %d %s %s", status, headers, answer)
	}
	if err = client.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: string(answer)}); err != nil {
		t.Fatal(err)
	}
	if status, _, payload := post(live.PoolHumanKeyForTest, "/v1/live", string(body)); status != 429 {
		t.Fatalf("second human POST = %d %s", status, payload)
	}
	if status, _, payload := post(live.PoolAgentKeyForTest, "/v1/responses", `{"model":"gpt-5.4","input":"hello"}`); status != 429 {
		t.Fatalf("saturated agent = %d %s", status, payload)
	}
	wsURL := "ws" + strings.TrimPrefix(gateway.URL, "http") + "/v1/live/rtc_e2e"
	dial := func(key, target string) (*websocket.Conn, *http.Response, error) {
		return websocket.DefaultDialer.Dial(target, http.Header{"Authorization": {"Bearer " + key}, "OpenAI-Alpha": {"quicksilver=v2"}, "Originator": {"Codex Desktop"}, "X-Session-Id": {"synthetic-live-session"}, "Session-Id": {"synthetic-conversation"}, "Thread-Id": {"synthetic-conversation"}})
	}
	plain, err := http.NewRequest("GET", gateway.URL+"/v1/live/rtc_e2e", nil)
	if err != nil {
		t.Fatal(err)
	}
	plain.Header.Set("Authorization", "Bearer "+live.PoolHumanKeyForTest)
	plainResponse, err := gateway.Client().Do(plain)
	if err != nil {
		t.Fatal(err)
	}
	_ = plainResponse.Body.Close()
	if plainResponse.StatusCode != 426 {
		t.Fatalf("non-WS join = %d", plainResponse.StatusCode)
	}
	missing, missingResponse, missingErr := dial(live.PoolHumanKeyForTest, "ws"+strings.TrimPrefix(gateway.URL, "http")+"/v1/live/rtc_missing")
	if missing != nil {
		_ = missing.Close()
	}
	if missingErr == nil || missingResponse == nil || missingResponse.StatusCode != 404 {
		t.Fatalf("missing join = %v %#v", missingErr, missingResponse)
	}
	_ = missingResponse.Body.Close()
	// Failed handshake releases only its claim; the existing media lease remains.
	failed, response, err := dial(live.PoolHumanKeyForTest, wsURL)
	if failed != nil {
		_ = failed.Close()
	}
	if err == nil || response == nil || response.StatusCode != 502 {
		t.Fatalf("failed join = %v %#v", err, response)
	}
	_ = response.Body.Close()
	if status, _, payload := post(live.PoolHumanKeyForTest, "/v1/live", string(body)); status != 429 {
		t.Fatalf("failed join released lease: %d %s", status, payload)
	}
	beforeForeign := upstreamSends.Load()
	foreign, response, err := dial(live.PoolOtherHumanKeyForTest, wsURL)
	if foreign != nil {
		_ = foreign.Close()
	}
	if err == nil || response == nil || response.StatusCode != 403 {
		t.Fatalf("same-pool foreign join = %v %#v", err, response)
	}
	_ = response.Body.Close()
	if upstreamSends.Load() != beforeForeign {
		t.Fatal("foreign key reached upstream")
	}
	joined, response, err := dial(live.PoolHumanKeyForTest, wsURL)
	if err != nil {
		if response != nil {
			payload, _ := io.ReadAll(response.Body)
			_ = response.Body.Close()
			t.Fatalf("original WSS failed under cap1: %v %s", err, payload)
		}
		t.Fatal(err)
	}
	defer func() { _ = joined.Close() }()
	busy, busyResponse, busyErr := dial(live.PoolHumanKeyForTest, wsURL)
	if busy != nil {
		_ = busy.Close()
	}
	if busyErr == nil || busyResponse == nil || busyResponse.StatusCode != 409 {
		t.Fatalf("competing claim = %v %#v", busyErr, busyResponse)
	}
	_ = busyResponse.Body.Close()
	control := `{"type":"session.context.append","content":[{"type":"input_text","text":"sideband hello"}]}`
	if err = joined.WriteMessage(websocket.TextMessage, []byte(control)); err != nil {
		t.Fatal(err)
	}
	_, echo, err := joined.ReadMessage()
	if err != nil || string(echo) != control {
		t.Fatalf("WSS bridge = %s %v", echo, err)
	}
	var providerData *webrtc.DataChannel
	select {
	case providerData = <-providerChannels:
	case <-time.After(10 * time.Second):
		t.Fatal("provider DataChannel not established")
	}
	live.PoolWaitChannelForTest(t, clientData)
	live.PoolWaitChannelForTest(t, providerData)
	dataControl := `{"type":"delegation.context.append","delegation_item_id":"item-1","channel":"speakable","content":[{"type":"input_text","text":"media hello"}]}`
	if err = clientData.SendText(dataControl); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-providerMessages:
		if got != dataControl {
			t.Fatalf("provider DC = %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("client-to-provider DC not relayed")
	}
	serverEvent := `{"type":"session.started","session":{"id":"synthetic-session"}}`
	if err = providerData.SendText(serverEvent); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-clientMessages:
		if got != serverEvent {
			t.Fatalf("client DC = %s", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("provider-to-client DC not relayed")
	}
	live.PoolSendRTPForTest(t, clientAudio, []byte{0xf8, 0xff, 0xfe}, providerRTP)
	live.PoolSendRTPForTest(t, providerAudio, []byte{0xf8, 0xfe, 0xfd}, clientRTP)
	// Public unsupported aliases must fail before any upstream business send,
	// even for the human key; saturated agents never borrow that credential.
	beforeDenied := upstreamSends.Load()
	conflicting, err := http.NewRequest("POST", gateway.URL+"/v1/live", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	conflicting.Header.Set("Authorization", "Bearer "+live.PoolAgentKeyForTest)
	conflicting.Header.Set("X-Api-Key", live.PoolHumanKeyForTest)
	conflicting.Header.Set("Content-Type", "application/json")
	conflictingResponse, err := gateway.Client().Do(conflicting)
	if err != nil {
		t.Fatal(err)
	}
	_ = conflictingResponse.Body.Close()
	if conflictingResponse.StatusCode != 503 {
		t.Fatalf("competing headers escaped authenticated agent principal: %d", conflictingResponse.StatusCode)
	}
	for _, path := range []string{"/v1/realtime", "/v1/realtime/calls", "/v1/realtime/client_secrets", "/v1/realtime/sessions", "/v1/realtime/transcription_sessions", "/v1/realtime/translations", "/v1/realtime/translations/client_secrets", "/v1/realtime/calls/rtc_e2e/hangup"} {
		if status, _, payload := post(live.PoolHumanKeyForTest, path, `{}`); status != 503 {
			t.Errorf("alias %s = %d %s", path, status, payload)
		}
	}
	for _, target := range []string{wsURL, "ws" + strings.TrimPrefix(gateway.URL, "http") + "/v1/realtime", "ws" + strings.TrimPrefix(gateway.URL, "http") + "/v1/responses"} {
		conn, resp, errDial := dial(live.PoolAgentKeyForTest, target)
		if conn != nil {
			_ = conn.Close()
		}
		if errDial == nil || resp == nil || resp.StatusCode != 503 {
			t.Errorf("agent WS %s = %v %#v", target, errDial, resp)
		}
		if resp != nil {
			_ = resp.Body.Close()
		}
	}
	if upstreamSends.Load() != beforeDenied || bootstrapSends.Load() != 1 || sidebandSends.Load() != 2 {
		t.Fatalf("unexpected upstream sends all=%d bootstrap=%d sideband=%d", upstreamSends.Load(), bootstrapSends.Load(), sidebandSends.Load())
	}
	// Exercise the actual pooled DataChannel binding, not just its validator.
	// A model-switch control must close this pinned call without reaching the
	// local provider; the WSS close is an event receipt, not a sleep/poll.
	wsClosed := make(chan error, 1)
	go func() { _, _, errRead := joined.ReadMessage(); wsClosed <- errRead }()
	if err = clientData.SendText(`{"type":"session.update","session":{"model":"foreign-model"}}`); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-providerMessages:
		t.Fatalf("forbidden DataChannel control reached provider: %s", payload)
	case errRead := <-wsClosed:
		if errRead == nil {
			t.Fatal("policy rejection did not close stored call")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("unknown DataChannel control did not terminate call")
	}
	// Shutdown traverses real API -> Handler.Close -> raw-sideband join -> peer
	// close -> media workers -> FinishLive. It must return with capacity released.
	if err = server.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, next, err := manager.BeginPoolOperation(context.Background(), live.PoolHumanKeyForTest, "gpt-live-1-codex", auth.PoolLiveCall)
	if err != nil {
		t.Fatalf("shutdown did not release human slot: %v", err)
	}
	next.Finish()
}
