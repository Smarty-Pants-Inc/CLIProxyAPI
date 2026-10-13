package helps

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// PayloadFinalizer applies user rules to a fully prepared business payload.
// Each rebuilt attempt must start from the unconfigured body, not a previous result.
type PayloadFinalizer func([]byte) []byte

// NewPayloadFinalizer snapshots matching context before built-in request mutations.
func NewPayloadFinalizer(cfg *config.Config, executor, model, protocol, root string, original []byte, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) PayloadFinalizer {
	finalize := NewTrackedPayloadFinalizer(cfg, executor, model, protocol, root, original, req, opts)
	return func(body []byte) []byte {
		out, _ := finalize(body)
		return out
	}
}

// TrackedPayloadFinalizer also reports paths targeted by applied user rules.
type TrackedPayloadFinalizer func([]byte) ([]byte, map[string]bool)

// NewTrackedPayloadFinalizer tracks rule intent without applying rules twice.
func NewTrackedPayloadFinalizer(cfg *config.Config, executor, model, protocol, root string, original []byte, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, trackedPaths ...string) TrackedPayloadFinalizer {
	requestedModel := PayloadRequestedModel(opts, req.Model)
	requestPath := PayloadRequestPath(opts)
	headers := opts.Headers.Clone()
	source := append([]byte(nil), original...)
	return func(body []byte) ([]byte, map[string]bool) {
		return ApplyPayloadConfigWithTrackedPathsForExecutor(cfg, executor, model, protocol, opts.SourceFormat.String(), root, body, source, requestedModel, requestPath, headers, trackedPaths...)
	}
}

type payloadFinalizerKey struct{}

// WithPayloadFinalizer carries the final barrier through shared request builders.
func WithPayloadFinalizer(ctx context.Context, finalize PayloadFinalizer) context.Context {
	return context.WithValue(ctx, payloadFinalizerKey{}, finalize)
}

// WithTrackedPayloadFinalizer carries the final barrier and its rule intent.
func WithTrackedPayloadFinalizer(ctx context.Context, finalize TrackedPayloadFinalizer) context.Context {
	return context.WithValue(ctx, payloadFinalizerKey{}, finalize)
}

// FinalizePayload runs immediately before serialization or transport framing.
func FinalizePayload(ctx context.Context, body []byte) []byte {
	out, _ := FinalizePayloadTracked(ctx, body)
	return out
}

// FinalizePayloadTracked applies the barrier once and returns targeted paths.
func FinalizePayloadTracked(ctx context.Context, body []byte) ([]byte, map[string]bool) {
	switch finalize := ctx.Value(payloadFinalizerKey{}).(type) {
	case TrackedPayloadFinalizer:
		if finalize != nil {
			return finalize(body)
		}
	case PayloadFinalizer:
		if finalize != nil {
			return finalize(body), nil
		}
	}
	return body, nil
}
