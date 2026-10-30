package live

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gorilla/websocket"
	"github.com/pion/webrtc/v4"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// These helpers exist only in the augmented test package. They cannot be used by
// a production caller to replace origins, transport, identity, or admission.
const PoolHumanKeyForTest = poolHumanKey
const PoolOtherHumanKeyForTest = poolOtherHumanKey
const PoolAgentKeyForTest = poolAgentKey

func NewPoolLiveManagerForTest(t *testing.T, send func(context.Context, *auth.Auth, *http.Request) (*http.Response, error)) (*auth.Manager, *config.Config) {
	cfg := newPoolLiveTestConfig()
	manager, _ := newPoolLiveTestManager(t, cfg, send)
	return manager, cfg
}

func PoolWebRTCAPIForTest(t *testing.T) *webrtc.API   { return newTestWebRTCAPI(t) }
func PoolOpusCodecForTest() webrtc.RTPCodecCapability { return opusCodec }
func PoolOfferForTest(t *testing.T, peer *webrtc.PeerConnection) string {
	return completeOffer(t, peer)
}
func PoolAnswerForTest(t *testing.T, peer *webrtc.PeerConnection) string {
	return completeAnswer(t, peer)
}
func PoolWaitChannelForTest(t *testing.T, channel *webrtc.DataChannel) {
	waitDataChannelOpen(t, channel)
}
func PoolSendRTPForTest(t *testing.T, track *webrtc.TrackLocalStaticRTP, payload []byte, received <-chan []byte) {
	sendTestRTP(t, track, payload, received)
}
func PoolDrainRTCPForTest(sender *webrtc.RTPSender, done <-chan struct{}) {
	drainRTCP("external-test", sender, done)
}

func PoolSidebandUpstreamForTest(t *testing.T, upstream *httptest.Server) {
	t.Helper()
	address, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	previous := poolLiveSidebandDialer
	poolLiveSidebandDialer = func(_ *config.Config, _ *auth.Auth) *websocket.Dialer {
		return &websocket.Dialer{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: address.Hostname(), MinVersion: tls.VersionTLS12}, NetDialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
			if target != "api.openai.com:443" {
				return nil, fmt.Errorf("unexpected fixture target %q", target)
			}
			return (&net.Dialer{}).DialContext(ctx, network, address.Host)
		}}
	}
	t.Cleanup(func() { poolLiveSidebandDialer = previous })
}
