package auth

// Failure scopes recorded in Auth.FailureScope, from narrowest to widest.
const (
	// FailureScopeModel: every failure was recorded against a specific model
	// (MarkResult with a model), so it lives on that model's state.
	FailureScopeModel = "model"
	// FailureScopeCredentialQuota: a credential-wide failure was recorded, and
	// every credential-wide failure was a quota refusal (HTTP 429, not forced).
	FailureScopeCredentialQuota = "credential_quota"
	// FailureScopeCredential: a credential-wide failure other than a quota
	// refusal was recorded (401/403, forced cooldown, transient, refresh, ...).
	FailureScopeCredential = "credential"
	// FailureScopeUnknown: an error was restored or merged without a recorded
	// scope; its provenance cannot be established.
	FailureScopeUnknown = "unknown"
)

func failureScopeRank(scope string) int {
	switch scope {
	case "":
		return 0
	case FailureScopeModel:
		return 1
	case FailureScopeCredentialQuota:
		return 2
	case FailureScopeCredential:
		return 3
	default:
		return 4 // unknown or unrecognised values are the widest
	}
}

// widenFailureScope records a failure of the given scope on auth. The recorded
// scope only ever widens until the auth-level error is cleared.
func widenFailureScope(auth *Auth, scope string) {
	if auth == nil {
		return
	}
	if failureScopeRank(scope) > failureScopeRank(auth.FailureScope) {
		auth.FailureScope = scope
	}
}

// credentialFailureScope is the scope of a failure recorded on the whole credential.
func credentialFailureScope(err *Error) string {
	if err != nil && quotaOnlyError(err) {
		return FailureScopeCredentialQuota
	}
	return FailureScopeCredential
}

// failureScopeAllowsQuotaRelease reports whether the explicitly recorded scope
// proves that no credential-wide non-quota failure is part of the hold. A
// missing, unknown or credential-wide non-quota scope declines the release.
func failureScopeAllowsQuotaRelease(auth *Auth) bool {
	switch auth.FailureScope {
	case FailureScopeModel, FailureScopeCredentialQuota:
		return true
	default:
		return false
	}
}
