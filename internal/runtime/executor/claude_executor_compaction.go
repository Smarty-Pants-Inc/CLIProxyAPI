package executor

import (
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// prepareClaudeResponsesCompaction maps Codex Responses compaction items to
// Anthropic on-demand compaction. Only Responses input with a Responses result
// can carry the round-trip compaction item; other routes are unchanged.
func prepareClaudeResponsesCompaction(req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Request, cliproxyexecutor.Options, helps.ClaudeResponsesCompaction, error) {
	var state helps.ClaudeResponsesCompaction
	if opts.SourceFormat != sdktranslator.FormatOpenAIResponse || cliproxyexecutor.ResponseFormatOrSource(opts) != sdktranslator.FormatOpenAIResponse {
		return req, opts, state, nil
	}
	payload, state, err := helps.PrepareClaudeResponsesCompaction(req.Payload)
	if err != nil {
		return req, opts, state, statusErr{code: http.StatusBadRequest, msg: err.Error()}
	}
	req.Payload = payload
	if len(opts.OriginalRequest) > 0 {
		original, _, errOriginal := helps.PrepareClaudeResponsesCompaction(opts.OriginalRequest)
		if errOriginal != nil {
			return req, opts, state, statusErr{code: http.StatusBadRequest, msg: errOriginal.Error()}
		}
		opts.OriginalRequest = original
	}
	return req, opts, state, nil
}
