package main

// gitTokenStoreDisabledError identifies the temporary startup refusal for the
// Git backend. Its recovery swaps credential directories, including lockfiles,
// so per-file refresh locking cannot fence recovery until #12467 is fixed.
type gitTokenStoreDisabledError struct{}

func (*gitTokenStoreDisabledError) Error() string {
	return "git token store disabled in this build: recovery can bypass the Codex credential lock (smarty-dev#12467)"
}

// sharedTokenStoreDisabledError identifies backends whose local credential locks
// cannot fence a different gateway's persist after a remote credential deletion.
// They need a durable tombstone and conditional writes before startup is safe.
type sharedTokenStoreDisabledError struct {
	backend string
}

func (e *sharedTokenStoreDisabledError) Error() string {
	return e.backend + " token store disabled in this build: shared-store refresh persistence can resurrect deleted credentials (smarty-dev#13064)"
}

func validateTokenStoreStartup(useGitStore, usePostgresStore, useObjectStore bool) error {
	// Match the backend selection order in main.
	if usePostgresStore {
		return &sharedTokenStoreDisabledError{backend: "postgres"}
	}
	if useObjectStore {
		return &sharedTokenStoreDisabledError{backend: "object"}
	}
	if useGitStore {
		return &gitTokenStoreDisabledError{}
	}
	return nil
}
