package helps

type codexNonReplayableStreamError struct{ error }

func (e *codexNonReplayableStreamError) Unwrap() error       { return e.error }
func (e *codexNonReplayableStreamError) IsRequestStop() bool { return true }

// WrapCodexNonReplayableStreamError stops replay while retaining upstream error scope.
func WrapCodexNonReplayableStreamError(err error) error {
	if err == nil {
		return nil
	}
	return &codexNonReplayableStreamError{error: err}
}

type codexNonReplayableError struct{ error }

func (e *codexNonReplayableError) Unwrap() error         { return e.error }
func (e *codexNonReplayableError) IsRequestScoped() bool { return true }
func (e *codexNonReplayableError) IsRequestStop() bool   { return true }

// WrapCodexNonReplayableError marks an unsafe Codex failure as a request-scoped stop.
func WrapCodexNonReplayableError(err error) error {
	if err == nil {
		return nil
	}
	return &codexNonReplayableError{error: err}
}
