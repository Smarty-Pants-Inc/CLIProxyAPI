package live

import (
	"context"
	"sync"
	"testing"

	"github.com/pion/webrtc/v4"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// Data safety keep reason (R2 B1): real RTP/RTCP readers block in Pion, not in
// preMediaWork. Peer closure must unblock them before WaitClosed releases a slot.
func TestPionPoolMediaCloseUnblocksRTPRTCPBeforeWorkerWait(t *testing.T) {
	client, err := newTestWebRTCAPI(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestPeerConnection(t, client)
	provider, err := newTestWebRTCAPI(t).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		t.Fatal(err)
	}
	defer closeTestPeerConnection(t, provider)
	peerDone := make(chan struct{})
	defer close(peerDone)
	clientTrack, err := webrtc.NewTrackLocalStaticRTP(opusCodec, "client", "client")
	if err != nil {
		t.Fatal(err)
	}
	clientSender, err := client.AddTrack(clientTrack)
	if err != nil {
		t.Fatal(err)
	}
	go drainRTCP("test-client", clientSender, peerDone)
	providerTrack, err := webrtc.NewTrackLocalStaticRTP(opusCodec, "provider", "provider")
	if err != nil {
		t.Fatal(err)
	}
	providerSender, err := provider.AddTrack(providerTrack)
	if err != nil {
		t.Fatal(err)
	}
	go drainRTCP("test-provider", providerSender, peerDone)
	clientChannel, err := client.CreateDataChannel(realtimeDataChannelLabel, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Pion's default handler immediately closes an undeclared remote channel.
	// Accept the real relay channel so this fixture keeps its media leg alive.
	providerChannels := make(chan *webrtc.DataChannel, 1)
	provider.OnDataChannel(func(channel *webrtc.DataChannel) { providerChannels <- channel })
	clientRTP, providerRTP := make(chan []byte, 1), make(chan []byte, 1)
	client.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		p, _, errRead := track.ReadRTP()
		if errRead == nil {
			clientRTP <- append([]byte(nil), p.Payload...)
		}
	})
	provider.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		p, _, errRead := track.ReadRTP()
		if errRead == nil {
			providerRTP <- append([]byte(nil), p.Payload...)
		}
	})
	relay, err := newPionMediaRelay(config.CodexLiveMediaRelayConfig{Enabled: true, MaxSessions: 1})
	if err != nil {
		t.Fatal(err)
	}
	media, offer, err := relay.NewSession(context.Background(), completeOffer(t, client), mediaSessionRoute{})
	if err != nil {
		t.Fatal(err)
	}
	session := media.(*pionMediaSession)
	defer func() { _ = media.Close() }()
	if err = provider.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer}); err != nil {
		t.Fatal(err)
	}
	answer, err := media.AcceptUpstreamAnswer(context.Background(), completeAnswer(t, provider))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer}); err != nil {
		t.Fatal(err)
	}
	waitDataChannelOpen(t, clientChannel)
	waitDataChannelOpen(t, receiveDataChannel(t, providerChannels))
	// Each completion proves both native relay RTP readers are running. After
	// these packets they return to ReadRTP; RTCP drains run for both senders too.
	sendTestRTP(t, clientTrack, []byte{0xf8, 0xff, 0xfe}, providerRTP)
	sendTestRTP(t, providerTrack, []byte{0xf8, 0xfe, 0xfd}, clientRTP)
	workerEntered, workerRelease := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(workerRelease) }) }
	defer release()
	if !session.workers.start(func() { close(workerEntered); <-workerRelease }) {
		t.Fatal("worker registration refused")
	}
	waitLiveEvent(t, workerEntered, "extra media cleanup barrier")
	downClosed, upClosed := make(chan struct{}), make(chan struct{})
	var downOnce, upOnce sync.Once
	session.downstream.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateClosed {
			downOnce.Do(func() { close(downClosed) })
		}
	})
	session.upstream.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		if state == webrtc.PeerConnectionStateClosed {
			upOnce.Do(func() { close(upClosed) })
		}
	})
	closed := make(chan struct{})
	go func() { _ = media.CloseWithReason("test_order"); close(closed) }()
	waitLiveEvent(t, downClosed, "downstream peer close before media worker wait")
	waitLiveEvent(t, upClosed, "upstream peer close before media worker wait")
	select {
	case <-closed:
		t.Fatal("media close completed before worker cleanup")
	default:
	}
	relay.limiter.mu.Lock()
	active := relay.limiter.active
	relay.limiter.mu.Unlock()
	if active != 1 {
		t.Fatalf("media slot released before worker cleanup: %d", active)
	}
	if session.workers.start(func() {}) {
		t.Fatal("late worker registration accepted")
	}
	release()
	waitLiveEvent(t, closed, "all RTP/RTCP/DC workers joined")
	if err = media.WaitClosed(); err != nil {
		t.Fatal(err)
	}
	relay.limiter.mu.Lock()
	active = relay.limiter.active
	relay.limiter.mu.Unlock()
	if active != 0 {
		t.Fatalf("media slot not released: %d", active)
	}
}

func TestPionCloseAndFailureBeforeHandlerBindingRecorded(t *testing.T) {
	for _, failure := range []bool{false, true} {
		session := &pionMediaSession{done: make(chan struct{}), closed: make(chan struct{}), poolLive: true}
		if failure {
			session.fail("early_failure", nil)
		} else if err := session.CloseWithReason("early_close"); err != nil {
			t.Fatal(err)
		}
		called := make(chan string, 1)
		session.SetCloseHandler(func(reason string) { called <- reason })
		select {
		case reason := <-called:
			if reason == "" {
				t.Fatal("empty close reason")
			}
		default:
			t.Fatal("early close/failure was forgotten")
		}
		if err := session.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveResourcesConcurrentCloseWaitsAndReentrantRequestDoesNot(t *testing.T) {
	resources := &liveSessionResources{}
	entered, release, first, second := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	resources.add(func() error { resources.requestClose(); close(entered); <-release; return nil })
	go func() { resources.close(); close(first) }()
	waitLiveEvent(t, entered, "reentrant closer entered")
	go func() { resources.close(); close(second) }()
	select {
	case <-first:
		t.Fatal("first close returned early")
	default:
	}
	select {
	case <-second:
		t.Fatal("concurrent close returned early")
	default:
	}
	close(release)
	waitLiveEvent(t, first, "first close completion")
	waitLiveEvent(t, second, "concurrent close completion")
}
