package main

// gitTokenStoreDisabledError identifies the temporary startup refusal for the
// Git backend. Its recovery swaps credential directories, including lockfiles,
// so per-file refresh locking cannot fence recovery until #12467 is fixed.
type gitTokenStoreDisabledError struct{}

func (*gitTokenStoreDisabledError) Error() string {
	return "git token store disabled in this build: recovery can bypass the Codex credential lock (smarty-dev#12467)"
}

func validateTokenStoreStartup(useGitStore bool) error {
	if useGitStore {
		return &gitTokenStoreDisabledError{}
	}
	return nil
}
