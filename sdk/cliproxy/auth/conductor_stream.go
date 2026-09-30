package auth

import (
	"context"
	"net/http"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

type streamBootstrapError struct {
	cause   error
	headers http.Header
}

func cloneHTTPHeader(headers http.Header) http.Header {
	if headers == nil {
		return nil
	}
	return headers.Clone()
}

func newStreamBootstrapError(err error, headers http.Header) error {
	if err == nil {
		return nil
	}
	upstreamAttempt := hasUpstreamExecutionAttempt(err)
	err = unwrapUpstreamExecutionAttempt(err)
	bootstrapErr := &streamBootstrapError{
		cause:   err,
		headers: cloneHTTPHeader(headers),
	}
	if upstreamAttempt {
		return markUpstreamExecutionAttempt(bootstrapErr)
	}
	return bootstrapErr
}

func (e *streamBootstrapError) Error() string {
	if e == nil || e.cause == nil {
		return ""
	}
	return e.cause.Error()
}

func (e *streamBootstrapError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func (e *streamBootstrapError) Headers() http.Header {
	if e == nil {
		return nil
	}
	return cloneHTTPHeader(e.headers)
}

func streamErrorResult(headers http.Header, err error) *cliproxyexecutor.StreamResult {
	ch := make(chan cliproxyexecutor.StreamChunk, 1)
	ch <- cliproxyexecutor.StreamChunk{Err: err}
	close(ch)
	return &cliproxyexecutor.StreamResult{
		Headers: cloneHTTPHeader(headers),
		Chunks:  ch,
	}
}

func validateStreamResult(result *cliproxyexecutor.StreamResult, err error) (*cliproxyexecutor.StreamResult, error) {
	if err != nil {
		return result, err
	}
	if result == nil || result.Chunks == nil {
		return result, &Error{Code: "empty_stream", Message: "upstream stream has no source", Retryable: true}
	}
	return result, nil
}

func readStreamBootstrap(ctx context.Context, ch <-chan cliproxyexecutor.StreamChunk) ([]cliproxyexecutor.StreamChunk, bool, error) {
	if ch == nil {
		return nil, true, nil
	}
	buffered := make([]cliproxyexecutor.StreamChunk, 0, 1)
	for {
		var (
			chunk cliproxyexecutor.StreamChunk
			ok    bool
		)
		if ctx != nil {
			select {
			case <-ctx.Done():
				return nil, false, ctx.Err()
			case chunk, ok = <-ch:
			}
		} else {
			chunk, ok = <-ch
		}
		if !ok {
			return buffered, true, nil
		}
		if chunk.Err != nil {
			return nil, false, chunk.Err
		}
		buffered = append(buffered, chunk)
		if len(chunk.Payload) > 0 {
			return buffered, false, nil
		}
	}
}

func (m *Manager) wrapStreamResult(ctx context.Context, auth *Auth, provider, resultModel, routeModel string, headers http.Header, buffered []cliproxyexecutor.StreamChunk, remaining <-chan cliproxyexecutor.StreamChunk, aliasResult OAuthModelAliasResult, ephemeralResult bool, opts cliproxyexecutor.Options, producerCancels ...context.CancelFunc) *cliproxyexecutor.StreamResult {
	if ctx == nil {
		ctx = context.Background()
	}
	// The consumer retains the live parent context so canceling a rejected
	// producer cannot suppress delivery of its typed local terminal error.
	cancelProducer := func() {
		for _, cancel := range producerCancels {
			if cancel != nil {
				cancel()
			}
		}
	}
	out := make(chan cliproxyexecutor.StreamChunk)
	streamStart := time.Now()
	go func() {
		defer close(out)
		defer cancelProducer()
		var failed bool
		forward := true
		var rewriter *StreamRewriter
		if aliasResult.ForceMapping && strings.TrimSpace(aliasResult.OriginalAlias) != "" {
			rewriter = NewStreamRewriter(StreamRewriteOptions{RewriteModel: aliasResult.OriginalAlias})
		}
		forwardChunk := func(chunk cliproxyexecutor.StreamChunk) bool {
			if ctx.Err() != nil {
				return false
			}
			if IsLocalCompactionAffinityStop(chunk.Err) {
				// Local admission failures are not upstream execution results.
				failed = true
			}
			if chunk.Err != nil && !failed {
				failed = true
				entry := logEntryWithRequestID(ctx)
				warnLogUpstreamFailure(ctx, entry, provider, resultModel, auth, time.Since(streamStart), chunk.Err)
				rerr := resultErrorFromError(chunk.Err)
				action, okAction := matchRequestScopedErrorAction(auth, chunk.Err, m.runtimeConfigSnapshot())
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: opts}
				result.RetryAfter = retryAfterFromError(chunk.Err)
				result.CredentialScope = isCredentialScopedError(chunk.Err)
				applyRequestScopedActionToResult(action, okAction, &result)
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			}
			if !forward {
				return false
			}
			if chunk.Err != nil {
				cancelProducer()
				select {
				case <-ctx.Done():
					forward = false
				case out <- chunk:
				}
				return false
			}
			if len(chunk.Payload) == 0 {
				return true
			}
			payload := rewriteForceMappedStreamChunk(rewriter, chunk.Payload)
			if len(payload) == 0 {
				return true
			}
			chunk.Payload = payload
			select {
			case <-ctx.Done():
				forward = false
				return false
			case out <- chunk:
				return true
			}
		}
		var observer *compactionOutputStream
		format := cliproxyexecutor.ResponseFormatOrSource(opts)
		if format == sdktranslator.FormatOpenAIResponse || format == sdktranslator.FormatCodex || format == sdktranslator.FormatClaude {
			if record := m.newCompactionOutputRecorder(ctx, auth.ID, opts); record != nil {
				observer = &compactionOutputStream{native: format == sdktranslator.FormatClaude, ctx: ctx, record: record}
			}
		}
		forwardPayloads := func(payloads [][]byte) bool {
			for _, payload := range payloads {
				if len(payload) > 0 && !forwardChunk(cliproxyexecutor.StreamChunk{Payload: payload}) {
					return false
				}
			}
			return true
		}
		emit := func(chunk cliproxyexecutor.StreamChunk) bool {
			if ctx.Err() != nil {
				return false
			}
			if observer != nil && len(chunk.Payload) > 0 {
				payloads, errSave := observer.pushChunks(chunk.Payload)
				if errSave != nil {
					// Fail closed before these event bytes are visible. This local
					// error must not enter upstream failure/cooldown accounting.
					failed = true
					cancelProducer()
					forwardChunk(cliproxyexecutor.StreamChunk{Err: wrapRequestStopError(errSave)})
					return false
				}
				if !forwardPayloads(payloads) {
					return false
				}
				chunk.Payload = nil
			}
			if observer != nil && chunk.Err != nil {
				payloads, errSave := observer.finishChunks()
				if errSave != nil {
					failed = true
					cancelProducer()
					forwardChunk(cliproxyexecutor.StreamChunk{Err: wrapRequestStopError(errSave)})
					return false
				}
				if !forwardPayloads(payloads) {
					return false
				}
			}
			return forwardChunk(chunk)
		}
		for _, chunk := range buffered {
			if ok := emit(chunk); !ok {
				return
			}
		}
	readRemaining:
		for {
			select {
			case <-ctx.Done():
				return
			case chunk, ok := <-remaining:
				if !ok {
					break readRemaining
				}
				if !emit(chunk) {
					return
				}
			}
		}
		if observer != nil {
			payloads, errSave := observer.finishChunks()
			if errSave != nil {
				failed = true
				cancelProducer()
				forwardChunk(cliproxyexecutor.StreamChunk{Err: wrapRequestStopError(errSave)})
				return
			}
			if !forwardPayloads(payloads) {
				return
			}
		}
		if tail := finishForceMappedStreamChunks(rewriter); len(tail) > 0 {
			tailChunk := cliproxyexecutor.StreamChunk{Payload: tail}
			if !forwardChunk(tailChunk) {
				return
			}
		}
		if !failed && ctx.Err() == nil && (ephemeralResult || claudeOAuthRequestCancellation(ctx, auth, nil) == nil) {
			m.recordExecutionResult(ctx, Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: true, Options: opts}, auth, ephemeralResult)
		}
	}()
	return &cliproxyexecutor.StreamResult{Headers: headers, Chunks: out}
}

func (m *Manager) executeStreamWithModelPool(ctx context.Context, executor ProviderExecutor, auth *Auth, provider string, req cliproxyexecutor.Request, opts cliproxyexecutor.Options, routeModel, executionModel string, execModels []string, pooled bool, aliasResult OAuthModelAliasResult, routing *apiKeyModelRoutingSnapshot, allowRetry bool, ephemeralResult bool) (*cliproxyexecutor.StreamResult, error) {
	if executor == nil {
		return nil, &Error{Code: "executor_not_found", Message: "executor not registered"}
	}
	ctx = contextWithRequestedModelAlias(ctx, opts, routeModel)
	baseCtx := ctx
	var lastErr error
	var upstreamErr error
	didRefreshOnUnauthorized := false
	for idx, execModel := range execModels {
		ctx = newUpstreamAttemptContext(baseCtx)
		resultModel := m.stateModelForExecution(auth, routeModel, execModel, pooled)
		execReq := req
		execReq.Model = execModel
		if executionModel != "" {
			execReq.Model = executionModel
		}
		execOpts := opts
		var errIntercept error
		execReq, execOpts, errIntercept = applyRequestAfterAuthInterceptor(ctx, executor, provider, execReq, execOpts, requestedModelAliasFromOptions(execOpts, routeModel), auth.ID)
		if errIntercept != nil {
			return nil, errIntercept
		}
		if executionModel == "" {
			execReq = attachResolvedAPIKeyModelInfo(routing, execReq, auth, routeModel, execModel)
		}
		if errCtx := ctx.Err(); errCtx != nil {
			return nil, errCtx
		}
		entry := logEntryWithRequestID(ctx)
		payload := execOpts.OriginalRequest
		if len(payload) == 0 {
			payload = execReq.Payload
		}
		execOpts.Metadata = ensureCanonicalSessionMetadata(execOpts.Metadata, execOpts.Headers, payload)
		ctx = syncMetadataSessionToContext(ctx, execOpts.Metadata)
		startStream := time.Now()
		// Own only the producer context. Keep request authority/metadata and
		// consumer delivery on the parent, never in a retained cancelable child.
		producerCtx, cancelAttempt := context.WithCancel(ctx)
		streamResult, errStream := executor.ExecuteStream(producerCtx, auth, execReq, execOpts)
		errStream = markUpstreamExecutionAttemptFromContext(ctx, errStream)
		if hasUpstreamExecutionAttempt(errStream) {
			upstreamErr = errStream
		}
		durationStream := time.Since(startStream)
		if errStream != nil {
			cancelAttempt()
			if errCtx := ctx.Err(); errCtx != nil {
				return nil, errCtx
			}
			if allowRetry && !ephemeralResult {
				alreadyTried := didRefreshOnUnauthorized
				refreshed, okRefresh := m.tryRefreshAfterUnauthorized(newUpstreamAttemptContext(ctx), auth, errStream, alreadyTried)
				if okRefresh {
					auth = refreshed
					publishSelectedAuthMetadata(execOpts.Metadata, auth)
					didRefreshOnUnauthorized = true
					ctx = newUpstreamAttemptContext(baseCtx)
					ctx = syncMetadataSessionToContext(ctx, execOpts.Metadata)
					producerCtx, cancelAttempt = context.WithCancel(ctx)
					startRetry := time.Now()
					streamResult, errStream = executor.ExecuteStream(producerCtx, auth, execReq, execOpts)
					errStream = markUpstreamExecutionAttemptFromContext(ctx, errStream)
					if hasUpstreamExecutionAttempt(errStream) {
						upstreamErr = errStream
					}
					durationRetry := time.Since(startRetry)
					if errStream != nil {
						cancelAttempt()
						warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, durationRetry, errStream)
						if errCtx := ctx.Err(); errCtx != nil {
							return nil, errCtx
						}
					}
				} else {
					warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, durationStream, errStream)
				}
			} else {
				warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, durationStream, errStream)
			}
		}
		if !ephemeralResult {
			if errCancel := claudeOAuthRequestCancellation(ctx, auth, errStream); errCancel != nil {
				cancelAttempt()
				return nil, errCancel
			}
		}
		streamResult, errStream = validateStreamResult(streamResult, errStream)
		errStream = markUpstreamExecutionAttemptFromContext(ctx, errStream)
		if errStream != nil {
			cancelAttempt()
			rerr := resultErrorFromError(errStream)
			action, okAction := matchRequestScopedErrorAction(auth, errStream, m.runtimeConfigSnapshot())
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts}
			result.RetryAfter = retryAfterFromError(errStream)
			if isCredentialScopedError(errStream) {
				result.CredentialScope = true
			}
			applyRequestScopedActionToResult(action, okAction, &result)
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			if okAction {
				if isRequestScopedStop(action, okAction) {
					return nil, wrapRequestStopError(errStream)
				}
				lastErr = errStream
				if result.CredentialScope {
					return nil, preferredExecutionAttemptError(errStream, upstreamErr)
				}
				continue
			}
			if isRequestInvalidError(errStream) {
				return nil, errStream
			}
			lastErr = errStream
			if result.CredentialScope {
				return nil, preferredExecutionAttemptError(errStream, upstreamErr)
			}
			continue
		}

		buffered, closed, bootstrapErr := readStreamBootstrap(ctx, streamResult.Chunks)
		bootstrapErr = markUpstreamExecutionAttemptFromContext(ctx, bootstrapErr)
		if hasUpstreamExecutionAttempt(bootstrapErr) {
			upstreamErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
		}
		if bootstrapErr != nil {
			cancelAttempt()
			if errCtx := ctx.Err(); errCtx != nil {
				return nil, errCtx
			}
			if allowRetry && !ephemeralResult {
				alreadyTried := didRefreshOnUnauthorized
				refreshed, okRefresh := m.tryRefreshAfterUnauthorized(newUpstreamAttemptContext(ctx), auth, bootstrapErr, alreadyTried)
				if okRefresh {
					auth = refreshed
					publishSelectedAuthMetadata(execOpts.Metadata, auth)
					didRefreshOnUnauthorized = true
					ctx = newUpstreamAttemptContext(baseCtx)
					ctx = syncMetadataSessionToContext(ctx, execOpts.Metadata)
					producerCtx, cancelAttempt = context.WithCancel(ctx)
					startRetry := time.Now()
					retryStream, retryErr := executor.ExecuteStream(producerCtx, auth, execReq, execOpts)
					retryErr = markUpstreamExecutionAttemptFromContext(ctx, retryErr)
					retryStream, retryErr = validateStreamResult(retryStream, retryErr)
					retryErr = markUpstreamExecutionAttemptFromContext(ctx, retryErr)
					if retryErr != nil {
						cancelAttempt()
						if errCtx := ctx.Err(); errCtx != nil {
							return nil, errCtx
						}
						bootstrapErr = retryErr
						warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startRetry), bootstrapErr)
						streamResult = &cliproxyexecutor.StreamResult{}
					} else {
						streamResult = retryStream
						buffered, closed, bootstrapErr = readStreamBootstrap(ctx, streamResult.Chunks)
						bootstrapErr = markUpstreamExecutionAttemptFromContext(ctx, bootstrapErr)
						if bootstrapErr != nil {
							cancelAttempt()
							warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startRetry), bootstrapErr)
						}
					}
				} else {
					warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startStream), bootstrapErr)
				}
			} else {
				warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startStream), bootstrapErr)
			}
			if hasUpstreamExecutionAttempt(bootstrapErr) {
				upstreamErr = newStreamBootstrapError(bootstrapErr, streamResult.Headers)
			}
		}
		if !ephemeralResult {
			if errCancel := claudeOAuthRequestCancellation(ctx, auth, bootstrapErr); errCancel != nil {
				cancelAttempt()
				return nil, errCancel
			}
		}
		if bootstrapErr != nil {
			action, okAction := matchRequestScopedErrorAction(auth, bootstrapErr, m.runtimeConfigSnapshot())
			if okAction {
				rerr := resultErrorFromError(bootstrapErr)
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				if isCredentialScopedError(bootstrapErr) {
					result.CredentialScope = true
				}
				applyRequestScopedActionToResult(action, okAction, &result)
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
				if isRequestScopedStop(action, okAction) {
					return nil, wrapRequestStopError(bootstrapErr)
				}
				lastErr = bootstrapErr
				if result.CredentialScope {
					currentErr := newStreamBootstrapError(bootstrapErr, streamResult.Headers)
					return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
				}
				continue
			}
			if isRequestInvalidError(bootstrapErr) {
				rerr := resultErrorFromError(bootstrapErr)
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				if isCredentialScopedError(bootstrapErr) {
					result.CredentialScope = true
				}
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
				return nil, bootstrapErr
			}
			if idx < len(execModels)-1 {
				rerr := resultErrorFromError(bootstrapErr)
				result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts}
				result.RetryAfter = retryAfterFromError(bootstrapErr)
				if isCredentialScopedError(bootstrapErr) {
					result.CredentialScope = true
				}
				m.recordExecutionResult(ctx, result, auth, ephemeralResult)
				lastErr = bootstrapErr
				if result.CredentialScope {
					currentErr := newStreamBootstrapError(bootstrapErr, streamResult.Headers)
					return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
				}
				continue
			}
			rerr := resultErrorFromError(bootstrapErr)
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: rerr, Options: execOpts}
			result.RetryAfter = retryAfterFromError(bootstrapErr)
			if isCredentialScopedError(bootstrapErr) {
				result.CredentialScope = true
			}
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			currentErr := newStreamBootstrapError(bootstrapErr, streamResult.Headers)
			return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
		}

		if closed && len(buffered) == 0 {
			cancelAttempt()
			emptyErr := markUpstreamExecutionAttemptFromContext(ctx, &Error{Code: "empty_stream", Message: "upstream stream closed before first payload", Retryable: true})
			currentErr := newStreamBootstrapError(emptyErr, streamResult.Headers)
			if hasUpstreamExecutionAttempt(emptyErr) {
				upstreamErr = currentErr
			}
			warnLogUpstreamFailure(ctx, entry, provider, execModel, auth, time.Since(startStream), emptyErr)
			result := Result{AuthID: auth.ID, Provider: provider, Model: resultModel, RouteModel: routeModel, Success: false, Error: resultErrorFromError(emptyErr), Options: execOpts}
			m.recordExecutionResult(ctx, result, auth, ephemeralResult)
			if idx < len(execModels)-1 {
				lastErr = emptyErr
				continue
			}
			return nil, preferredExecutionAttemptError(currentErr, upstreamErr)
		}

		remaining := streamResult.Chunks
		if closed {
			closedCh := make(chan cliproxyexecutor.StreamChunk)
			close(closedCh)
			remaining = closedCh
		}
		attemptAliasResult := resolveAttemptAliasResult(routing, auth, routeModel, execModel, aliasResult)
		return m.wrapStreamResult(ctx, auth.Clone(), provider, resultModel, routeModel, streamResult.Headers, buffered, remaining, attemptAliasResult, ephemeralResult, execOpts, cancelAttempt), nil
	}
	if lastErr == nil {
		lastErr = &Error{Code: "auth_not_found", Message: "no upstream model available"}
	}
	return nil, preferredExecutionAttemptError(lastErr, upstreamErr)
}
