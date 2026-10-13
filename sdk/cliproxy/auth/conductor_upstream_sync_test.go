package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCanceledUpstreamCooldownKeepsLocalAffinityStopsNeutral(t *testing.T) {
	local := wrapRequestStopError(errors.Join(
		&Error{Code: "compaction_affinity_missing", Message: "compaction_affinity_missing"},
		issue6503QuotaError{retryAfter: 10 * time.Minute},
	))
	manager, authID, model, errStream := runIssue6503CanceledStream(t, local)
	if !errors.Is(errStream, context.Canceled) {
		t.Fatalf("ExecuteStream() error = %v, want context.Canceled", errStream)
	}
	auth, ok := manager.GetByID(authID)
	if !ok || auth == nil {
		t.Fatal("auth not registered")
	}
	if auth.Unavailable || !auth.NextRetryAfter.IsZero() {
		t.Fatalf("local affinity stop cooled auth: unavailable=%t next=%v", auth.Unavailable, auth.NextRetryAfter)
	}
	if state := auth.ModelStates[model]; state != nil && (state.Unavailable || !state.NextRetryAfter.IsZero() || state.Quota.Exceeded) {
		t.Fatalf("local affinity stop cooled model: %#v", state)
	}
}
