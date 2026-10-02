package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

func TestCodexZeroTranslatedReplaySafety(t *testing.T) {
	defer setCodexBootstrapNowForTest(func() time.Time { return time.Unix(1_700_000_000, 0) })()
	for _, transport := range []string{"sse", "sse_budget_exhausted"} {
		for _, cooling := range []bool{true, false} {
			for _, quota := range []string{"usage_limit_reached", "insufficient_quota"} {
				for _, unsafe := range []bool{true, false} {
					t.Run(fmt.Sprintf("%s/model_cooling=%t/%s/unsafe=%t", transport, cooling, quota, unsafe), func(t *testing.T) {
						responseID := "resp_sse_replay"
						tool, identity := codexSSEReplayTool, codexSSEReplayIdentity
						// response.created emits a Gemini chunk and masks the conductor's
						// zero-payload retry path. None of these nonterminal events do.
						frames := []string{fmt.Sprintf(`{"type":"response.in_progress","response":{"id":%q}}`, responseID)}
						if strings.HasSuffix(transport, "_budget_exhausted") {
							// Verify identity before exhausting the frame budget. The tool
							// then starts only in the live loop, still without any payload.
							for i := 0; i <= codexBootstrapMaxBufferedFrames; i++ {
								frames = append(frames, identity)
							}
						}
						if unsafe {
							frames = append(frames, tool)
						}
						frames = append(frames, identity)
						if unsafe {
							// Unlike identity, searching is not bootstrap-bufferable: it
							// enters the live loop without committing a Gemini payload.
							itemID := "search_sse_replay"
							frames = append(frames, fmt.Sprintf(`{"type":"response.web_search_call.searching","item_id":%q,"output_index":0}`, itemID))
						}
						var translationState any
						for _, frame := range frames {
							chunks := sdktranslator.TranslateStream(context.Background(), sdktranslator.FromString("codex"), sdktranslator.FromString("gemini"), codexSSEReplayModel, nil, nil, []byte("data: "+frame), &translationState)
							if len(chunks) != 0 {
								t.Fatalf("nonterminal fixture must translate to ZERO chunks: frame=%s chunks=%q", frame, chunks)
							}
						}
						frames = append(frames, fmt.Sprintf(`{"type":"response.failed","response":{"id":%q,"status":"failed","error":{"type":%q,"message":"fixture quota exhausted","resets_in_seconds":3600}}}`, responseID, quota))
						manager, firstAttempts, secondAttempts, primaryID := codexSSEReplayManager(t, frames, cooling)
						ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						defer cancel()
						result, err := manager.ExecuteStream(ctx, []string{"codex"}, cliproxyexecutor.Request{
							Model: codexSSEReplayModel, Payload: []byte(`{"model":"gpt-5.6-terra","input":[]}`),
						}, cliproxyexecutor.Options{
							SourceFormat: sdktranslator.FromString("codex"), ResponseFormat: sdktranslator.FromString("gemini"), Stream: true,
						})
						var payload string
						var streamErr error
						if result != nil {
							payload, streamErr = drainChunks(result)
						}
						first, second := firstAttempts.Load(), secondAttempts.Load()
						wantSecond := int32(0)
						if !unsafe {
							wantSecond = 1
						}
						if first != 1 || second != wantSecond {
							t.Errorf("attempts = %d,%d, want 1,%d", first, second, wantSecond)
						}
						if !unsafe {
							if result == nil || err != nil || streamErr != nil || !strings.Contains(payload, `"candidates"`) || !strings.Contains(payload, `"usageMetadata"`) {
								t.Errorf("safe retry must return Gemini success: result=%v err=%v streamErr=%v payload=%s", result, err, streamErr, payload)
							}
							if strings.Contains(payload, responseID) {
								t.Error("safe retry leaked primary response")
							}
							return
						}
						if result != nil || payload != "" || streamErr != nil {
							t.Errorf("unsafe zero-translated stream must fail synchronously with no output: result=%v payload=%s streamErr=%v", result, payload, streamErr)
						}
						if err == nil {
							t.Error("unsafe zero-translated stream lost synchronous quota error")
						} else {
							if !strings.Contains(err.Error(), quota) || !strings.Contains(err.Error(), "fixture quota exhausted") {
								t.Errorf("original quota refusal lost: %T %v", err, err)
							}
							retryAfter := time.Duration(0)
							if quota == "usage_limit_reached" {
								retryAfter = time.Hour
							}
							// Manager wraps bootstrap failures; inspect the public error chain.
							var status interface{ StatusCode() int }
							if !errors.As(err, &status) || status.StatusCode() != 429 {
								t.Errorf("quota status lost: %T %v", err, err)
							}
							var scoped interface{ IsCredentialScoped() bool }
							if !errors.As(err, &scoped) || scoped.IsCredentialScoped() != !cooling {
								t.Errorf("quota cooling scope lost: %T %v", err, err)
							}
							var retry interface{ RetryAfter() *time.Duration }
							if !errors.As(err, &retry) {
								t.Errorf("quota reset interface lost: %T %v", err, err)
							} else if got := retry.RetryAfter(); (retryAfter == 0 && got != nil) || (retryAfter != 0 && (got == nil || *got != retryAfter)) {
								t.Errorf("RetryAfter = %v, want %v", got, retryAfter)
							}
							var requestScoped interface{ IsRequestScoped() bool }
							if errors.As(err, &requestScoped) && requestScoped.IsRequestScoped() {
								t.Error("verified quota incorrectly became request-scoped")
							}
							var stop interface{ IsRequestStop() bool }
							if !errors.As(err, &stop) || !stop.IsRequestStop() {
								t.Errorf("unsafe terminal quota lost request-stop marker: %T %v", err, err)
							}
						}
						credential, ok := manager.GetByID(primaryID)
						if !ok || credential.ModelStates[codexSSEReplayModel] == nil || !credential.ModelStates[codexSSEReplayModel].Quota.Exceeded || !credential.ModelStates[codexSSEReplayModel].NextRetryAfter.After(time.Now()) {
							t.Errorf("primary quota cooldown was lost: %+v", credential)
						}
					})
				}
			}
		}
	}
}
