package pluginhost

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func (h *Host) callHostModelExecuteStream(ctx context.Context, request []byte) ([]byte, error) {
	var req rpcHostModelExecutionRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host model execution stream request: %w", errUnmarshal)
	}
	if !req.Stream {
		return nil, fmt.Errorf("host.model.execute_stream requires stream=true")
	}
	if errProxy := validateHostModelProxy(req.ProxyURL); errProxy != nil {
		return nil, errProxy
	}
	executor := h.currentModelExecutor()
	if executor == nil {
		return nil, fmt.Errorf("host model executor is unavailable")
	}
	callbackCtx := ctx
	// Identity-free internal calls retain their existing executor validation path.
	// Native calls and all explicitly scoped calls must prove active ownership.
	if req.HostCallbackID != "" || hostCallbackPluginIDFromContext(ctx) != "" || hostCallbackInstanceFromContext(ctx) != nil {
		var errOwner error
		callbackCtx, errOwner = h.requireActiveCallbackContext(ctx, req.HostCallbackID)
		if errOwner != nil {
			return nil, errOwner
		}
	}
	if callbackCtx == nil {
		callbackCtx = context.Background()
	}
	skipPluginID := h.callbackCallerPluginID(ctx, req.HostCallbackID)
	streamCtx, cancel := newStreamContext(callbackCtx)
	// Attach before ExecuteModelStream, which can block during upstream startup.
	stopScopeCleanup := func() {}
	if req.HostCallbackID != "" {
		var attached bool
		stopScopeCleanup, attached = h.addCallbackCleanupHandle(req.HostCallbackID, cancel)
		if !attached {
			cancel()
			return nil, fmt.Errorf("host callback context closed while starting model stream")
		}
	}
	keepStream := false
	defer func() {
		if !keepStream {
			stopScopeCleanup()
			cancel()
		}
	}()
	if err := streamCtx.Err(); err != nil {
		return nil, err
	}
	stream, errMsg := executor.ExecuteModelStream(streamCtx, modelExecutionRequestFromPlugin(req.HostModelExecutionRequest, skipPluginID))
	if errMsg != nil {
		return nil, modelExecutionError(errMsg)
	}
	if err := streamCtx.Err(); err != nil {
		return nil, err
	}
	streamID := ""
	if h.modelStreams != nil {
		streamID = h.modelStreams.open(req.HostCallbackID, stream.Chunks, cancel)
	}
	if streamID == "" {
		return nil, fmt.Errorf("host model stream bridge is unavailable")
	}
	if req.HostCallbackID != "" {
		stopStreamCleanup, attached := h.addCallbackCleanupHandle(req.HostCallbackID, func() {
			h.modelStreams.close(streamID)
		})
		stopScopeCleanup()
		stopScopeCleanup = stopStreamCleanup
		if !attached {
			return nil, context.Canceled
		}
	}
	if !h.modelStreams.attachLifetime(streamID, streamCtx, stopScopeCleanup) {
		return nil, context.Canceled
	}
	raw, err := marshalRPCResult(pluginapi.HostModelStreamResponse{StatusCode: stream.StatusCode, Headers: cloneHeader(stream.Headers), StreamID: streamID})
	if err != nil {
		h.modelStreams.close(streamID)
		return nil, err
	}
	keepStream = true
	return raw, nil
}

func (h *Host) callHostModelStreamRead(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostModelStreamReadRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host model stream read request: %w", errUnmarshal)
	}
	if h == nil || h.modelStreams == nil {
		return nil, fmt.Errorf("host model stream bridge is unavailable")
	}
	if req.StreamID == "" {
		return nil, fmt.Errorf("model stream id is required")
	}
	owner, err := h.requireActiveCallbackContext(ctx, req.HostCallbackID)
	if err != nil {
		return nil, err
	}
	// Preserve BOTH the owning invocation lifetime and cancellation of this read.
	readCtx, cancel := context.WithCancel(owner)
	defer cancel()
	if ctx != nil {
		stop := context.AfterFunc(ctx, cancel)
		defer stop()
	}
	chunk, done, errRead := h.modelStreams.read(readCtx, req.StreamID, req.HostCallbackID)
	if errRead != nil {
		return nil, errRead
	}
	if _, errOwner := h.requireActiveCallbackContext(ctx, req.HostCallbackID); errOwner != nil {
		return nil, errOwner
	}
	resp := pluginapi.HostModelStreamReadResponse{Payload: append([]byte(nil), chunk.Payload...), Done: done}
	if chunk.Err != nil {
		resp.Error = chunk.Err.Error()
		resp.Done = true
	}
	return marshalRPCResult(resp)
}

func (h *Host) callHostModelStreamClose(ctx context.Context, request []byte) ([]byte, error) {
	var req pluginapi.HostModelStreamCloseRequest
	if errUnmarshal := json.Unmarshal(request, &req); errUnmarshal != nil {
		return nil, fmt.Errorf("decode host model stream close request: %w", errUnmarshal)
	}
	if h == nil || h.modelStreams == nil {
		return nil, fmt.Errorf("host model stream bridge is unavailable")
	}
	if req.StreamID == "" {
		return nil, fmt.Errorf("model stream id is required")
	}
	if _, err := h.requireActiveCallbackContext(ctx, req.HostCallbackID); err != nil {
		return nil, err
	}
	if err := h.modelStreams.closeOwned(req.StreamID, req.HostCallbackID); err != nil {
		return nil, err
	}
	return marshalRPCResult(rpcEmptyResponse{})
}
