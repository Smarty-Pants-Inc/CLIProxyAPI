package live

import (
	"context"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// liveCallLifetime owns the lease explicitly. preMediaWork must never include
// media readers: their peers must be closed before those readers can terminate.
type liveCallLifetime struct {
	mu           sync.Mutex
	closing      bool
	transferred  bool
	done         chan struct{}
	ctx          context.Context
	cancel       context.CancelFunc
	preMediaWork sync.WaitGroup
	resources    *liveSessionResources
	media        mediaRelaySession
	op           *auth.KeyPolicyOperation
	onClosing    func()
}

func newLiveCallLifetime(ctx context.Context, op *auth.KeyPolicyOperation) (context.Context, *liveCallLifetime) {
	ctx, cancel := context.WithCancel(ctx)
	return ctx, &liveCallLifetime{done: make(chan struct{}), ctx: ctx, cancel: cancel, resources: &liveSessionResources{}, op: op}
}

func (l *liveCallLifetime) beginWork() (func(), bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return nil, false
	}
	l.preMediaWork.Add(1)
	var once sync.Once
	return func() { once.Do(l.preMediaWork.Done) }, true
}

func (l *liveCallLifetime) setMedia(media mediaRelaySession) {
	// Bootstrap is registered pre-media work. Finalization cannot inspect media
	// until bootstrap has left that barrier, even when close won this race.
	l.mu.Lock()
	l.media = media
	l.mu.Unlock()
}

// bindStoredCall handles close-before-publication as well as later failures.
// Store callbacks only remove/revoke; they never wait for this finalizer.
func (l *liveCallLifetime) bindStoredCall(onClosing func()) {
	l.mu.Lock()
	l.onClosing = onClosing
	closing := l.closing
	l.mu.Unlock()
	if closing && onClosing != nil {
		onClosing()
	}
}

func (l *liveCallLifetime) transfer(callID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closing {
		return context.Canceled
	}
	if err := l.op.TransferToLive(callID); err != nil {
		return err
	}
	l.transferred = true
	return nil
}

// requestClose is callback-safe: revoke and cancel now, finalize off the caller's
// stack. No callback/registered worker is allowed to wait for its own completion.
func (l *liveCallLifetime) requestClose(reason string) {
	if l == nil {
		return
	}
	l.mu.Lock()
	if l.closing {
		l.mu.Unlock()
		return
	}
	l.closing = true
	onClosing := l.onClosing
	l.cancel()
	l.mu.Unlock()
	if onClosing != nil {
		onClosing()
	}
	l.resources.requestClose()
	go func() {
		l.resources.close()
		l.preMediaWork.Wait()
		l.mu.Lock()
		media, transferred := l.media, l.transferred
		l.mu.Unlock()
		if media != nil {
			_ = media.CloseWithReason(reason)
			_ = media.WaitClosed()
		}
		if l.op != nil {
			if transferred {
				l.op.FinishLive()
			} else {
				l.op.Finish()
			}
		}
		close(l.done)
	}()
}

func (l *liveCallLifetime) waitClosed() {
	if l != nil {
		<-l.done
	}
}

// mediaWorkerGroup linearizes registration with shutdown. It is separate from
// pre-media work so shutdown can close peers before joining blocked RTP/RTCP.
type mediaWorkerGroup struct {
	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup
}

func (g *mediaWorkerGroup) enter() (func(), bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closing {
		return nil, false
	}
	g.wg.Add(1)
	return g.wg.Done, true
}

func (g *mediaWorkerGroup) start(work func()) bool {
	done, ok := g.enter()
	if ok {
		go func() { defer done(); work() }()
	}
	return ok
}

func (g *mediaWorkerGroup) stop() { g.mu.Lock(); g.closing = true; g.mu.Unlock() }
func (g *mediaWorkerGroup) wait() { g.wg.Wait() }
