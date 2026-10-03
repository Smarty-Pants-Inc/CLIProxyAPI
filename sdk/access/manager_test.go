package access

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// rejectingGate is the old Home plugin gate: the client has a central
// credential but not the plugin's grant.
type rejectingGate struct{}

func (rejectingGate) Identifier() string { return "plugin:gate:auth" }

func (rejectingGate) Authenticate(context.Context, *http.Request) (*Result, *AuthError) {
	return nil, NewInvalidCredentialError()
}

// Round 5 (PR #50 security P1): a request that is inside Authenticate while a
// first failed Home activation arms denyAll and then installs the empty
// provider list must see the old gate or the denial, never old denyAll=false
// with the new empty list. The hook pauses the request after it read the
// admission state; the writer then runs the service_plugins.go order
// (SetDenyAll(true), then SetProviders(empty)) for 0, 1 and 2 steps.
func TestAuthenticateAdmissionSnapshotIsAtomicDuringFailedActivation(t *testing.T) {
	writer := []func(*Manager){
		func(m *Manager) { m.SetDenyAll(true) },
		func(m *Manager) { m.SetProviders(nil) },
	}
	for steps := 0; steps <= len(writer); steps++ {
		m := NewManager()
		m.SetProviders([]Provider{rejectingGate{}})

		paused := make(chan struct{})
		resume := make(chan struct{})
		afterAdmissionRead = func() {
			close(paused)
			<-resume
		}
		type outcome struct {
			res *Result
			err *AuthError
		}
		done := make(chan outcome, 1)
		go func() {
			res, err := m.Authenticate(context.Background(), httptest.NewRequest("POST", "/v1/chat/completions", nil))
			done <- outcome{res, err}
		}()

		<-paused
		for _, step := range writer[:steps] {
			step(m)
		}
		close(resume)
		got := <-done
		afterAdmissionRead = nil

		if got.err == nil {
			t.Fatalf("writer steps %d: request admitted (result %+v) by a mixed old-denyAll/new-provider snapshot", steps, got.res)
		}
	}
}
