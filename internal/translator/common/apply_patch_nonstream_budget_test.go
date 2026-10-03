package common

import (
	"strings"
	"testing"

	applypatch "github.com/router-for-me/CLIProxyAPI/v8/internal/client/codex/apply-patch"
)

// A nonstreaming patch snapshot is charged to the same per-response budget as
// streaming events before it is decoded or retained.
func TestRound3NonStreamPatchResponseBudget(t *testing.T) {
	b := NewApplyPatchResponsesBridge(patchResponsesRequest)
	raw := []byte(`{"id":"r","output":[` + patchItem("function_call", "a", "c", "apply_patch", applypatch.WrapInput(strings.Repeat("x", applyPatchMaxBytes))) + `]}`)
	if out, err := b.TransformNonStream(raw); err == nil {
		t.Fatalf("oversized nonstream patch accepted (%d bytes out)", len(out))
	}
	small := NewApplyPatchResponsesBridge(patchResponsesRequest)
	if _, err := small.TransformNonStream([]byte(`{"id":"r","output":[` + patchItem("function_call", "a", "c", "apply_patch", applypatch.WrapInput("p")) + `]}`)); err != nil {
		t.Fatalf("small nonstream patch rejected: %v", err)
	}
}
