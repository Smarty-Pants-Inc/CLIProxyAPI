package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type nonReplayableTestStop struct{ error }

func (e *nonReplayableTestStop) Unwrap() error     { return e.error }
func (*nonReplayableTestStop) IsRequestStop() bool { return true }

type nonReplayableStopExecutor struct {
	*unauthorizedRefreshExecutor
	status int
}

func (e *nonReplayableStopExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	resp, err := e.unauthorizedRefreshExecutor.Execute(ctx, auth, req, opts)
	if err != nil {
		return resp, &nonReplayableTestStop{error: &Error{HTTPStatus: e.status, Message: "work already dispatched"}}
	}
	return resp, nil
}

// Recorded catch: PR #174 r9 N-5. A stop without request scope must retain
// credential cooling and must not replay through OAuth refresh or auth rotation.
func TestManager_Execute_NonReplayableStopCoolsWithoutRefreshOrFailover(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusBadGateway} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			m, executor, primary, backup, model := newUnauthorizedRefreshFixture(t, false)
			m.RegisterExecutor(&nonReplayableStopExecutor{unauthorizedRefreshExecutor: executor, status: status})
			m.SetRetryConfig(2, 0, 2)
			resp, err := m.Execute(context.Background(), []string{"codex"}, cliproxyexecutor.Request{Model: model}, cliproxyexecutor.Options{})
			var statusErr interface{ StatusCode() int }
			if !isRequestStopError(err) || !errors.As(err, &statusErr) || statusErr.StatusCode() != status || len(resp.Payload) != 0 {
				t.Fatalf("want original %d stop and empty body, got err=%v body=%s", status, err, resp.Payload)
			}
			if got := executor.ExecuteCalls(); len(got) != 1 || got[0] != primary.ID {
				t.Errorf("Execute calls=%v, want primary exactly once", got)
			}
			if got := executor.RefreshCalls(); got != 0 {
				t.Errorf("Refresh calls=%d, want 0 after non-replayable work", got)
			}
			updated, exists := m.GetByID(primary.ID)
			if !exists {
				t.Fatal("primary disappeared")
			}
			cooled := updated.Unavailable || !updated.NextRetryAfter.IsZero()
			for _, state := range updated.ModelStates {
				cooled = cooled || state.Unavailable || !state.NextRetryAfter.IsZero()
			}
			if !cooled {
				t.Error("primary not cooled after upstream failure")
			}
			updatedBackup, exists := m.GetByID(backup.ID)
			if !exists || updatedBackup.Unavailable || !updatedBackup.NextRetryAfter.IsZero() || len(updatedBackup.ModelStates) != 0 {
				t.Error("unused backup must remain untouched")
			}
		})
	}
}
