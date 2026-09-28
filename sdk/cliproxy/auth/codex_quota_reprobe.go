package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	log "github.com/sirupsen/logrus"
)

const (
	// codexQuotaReprobeInterval is how often held Codex accounts are re-checked.
	codexQuotaReprobeInterval = time.Hour
	codexQuotaReprobeTimeout  = 15 * time.Second
	codexUsageURL             = "https://chatgpt.com/backend-api/wham/usage"
)

// codexQuotaReprobeIntervalEnv overrides the re-probe interval (a positive Go
// duration). It exists so an isolated gateway run can exercise the ticker.
const codexQuotaReprobeIntervalEnv = "CLIPROXY_CODEX_QUOTA_REPROBE_INTERVAL"

// codexQuotaReprobeMinInterval is the production floor for the override: shorter
// values are clamped to it so the environment cannot turn the re-probe into a
// tight polling loop against the usage endpoint. Only in-package tests lower it.
var codexQuotaReprobeMinInterval = time.Minute

func codexQuotaReprobeIntervalFromEnv() time.Duration {
	raw := strings.TrimSpace(os.Getenv(codexQuotaReprobeIntervalEnv))
	if raw == "" {
		return codexQuotaReprobeInterval
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Warnf("ignoring invalid %s=%q", codexQuotaReprobeIntervalEnv, raw)
		return codexQuotaReprobeInterval
	}
	if d < codexQuotaReprobeMinInterval {
		log.Warnf("%s=%q is below the minimum; using %s", codexQuotaReprobeIntervalEnv, raw, codexQuotaReprobeMinInterval)
		return codexQuotaReprobeMinInterval
	}
	return d
}

// codexQuotaBeforeRegistryPublish, when set by a test, runs after the manager
// release is committed and before the registry projection is published.
var codexQuotaBeforeRegistryPublish func(authID string)

// codexQuotaReprobeURL is a variable so tests can point the probe at a local server.
var codexQuotaReprobeURL = codexUsageURL

type codexUsageRateLimit struct {
	Allowed      *bool `json:"allowed"`
	LimitReached *bool `json:"limit_reached"`
}

// codexUsageAllows reports whether a /wham/usage body shows the account can
// serve requests now. Release needs an explicit "allowed": true and no
// "limit_reached": true on the general limit; a missing, null or non-boolean
// "allowed" is not approval and keeps the hold. A body that also reports a
// separately limited feature (additional_rate_limits) as exhausted or not
// allowed keeps the hold too, since that limit cannot be mapped to models.
func codexUsageAllows(body []byte) bool {
	var payload struct {
		RateLimit            *codexUsageRateLimit `json:"rate_limit"`
		AdditionalRateLimits []struct {
			RateLimit *codexUsageRateLimit `json:"rate_limit"`
		} `json:"additional_rate_limits"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.RateLimit == nil {
		return false
	}
	rl := payload.RateLimit
	if rl.Allowed == nil || !*rl.Allowed || (rl.LimitReached != nil && *rl.LimitReached) {
		return false
	}
	for _, extra := range payload.AdditionalRateLimits {
		if extra.RateLimit == nil {
			continue
		}
		if (extra.RateLimit.Allowed != nil && !*extra.RateLimit.Allowed) || (extra.RateLimit.LimitReached != nil && *extra.RateLimit.LimitReached) {
			return false
		}
	}
	return true
}

func isQuotaHoldReason(reason string) bool {
	return reason == "quota" || reason == "credential_quota"
}

// quotaOnlyError reports whether a recorded error is nothing but a quota refusal.
func quotaOnlyError(err *Error) bool {
	return err == nil || (err.HTTPStatus == http.StatusTooManyRequests && err.Code != ErrorCodeForceCooldown)
}

// codexQuotaHeld reports whether an enabled Codex OAuth account is held by a
// quota cooldown that has not yet reached its upstream reset.
func codexQuotaHeld(auth *Auth, now time.Time) bool {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
		return false
	}
	if auth.Attributes != nil && strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return false // API-key accounts have no /wham/usage endpoint.
	}
	if auth.Quota.Exceeded && isQuotaHoldReason(auth.Quota.Reason) && auth.Quota.NextRecoverAt.After(now) {
		return true
	}
	for _, state := range auth.ModelStates {
		if state != nil && state.Quota.Exceeded && isQuotaHoldReason(state.Quota.Reason) && state.Quota.NextRecoverAt.After(now) {
			return true
		}
	}
	return false
}

// releaseModelQuotaHold clears a model state only when its sole restriction is a
// quota hold. Disabled states, non-quota errors (model support, auth, forced
// cooldown, cloudflare) and retry deadlines beyond the quota reset are kept.
func releaseModelQuotaHold(state *ModelState, now time.Time) bool {
	if state == nil || state.Status == StatusDisabled {
		return false
	}
	if !state.Quota.Exceeded || !isQuotaHoldReason(state.Quota.Reason) || !quotaOnlyError(state.LastError) {
		return false
	}
	if state.NextRetryAfter.After(state.Quota.NextRecoverAt) {
		return false // an independent, longer deadline outlives the quota hold
	}
	resetModelState(state, now)
	return true
}

// releaseCodexQuotaHoldLocked clears only the quota hold a successful usage probe
// justifies. It reports whether anything changed. Caller holds m.mu.
//
// The release applies only when the quota hold is the account's sole
// credential-wide restriction: an auth-level non-quota error or forced cooldown
// keeps the whole hold, and sibling model restrictions are left untouched.
func releaseCodexQuotaHoldLocked(auth *Auth, now time.Time) bool {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled {
		return false
	}
	// Provenance comes only from the scope recorded where each failure was
	// recorded (Auth.FailureScope), never from comparing error values: a
	// credential-wide non-quota failure, or any failure of unknown scope, keeps
	// the whole hold. Its deadline may have been folded into the quota deadline
	// by applyAuthFailureState, so deadlines cannot prove it is gone either.
	if !failureScopeAllowsQuotaRelease(auth) {
		return false
	}
	if len(auth.ModelStates) == 0 {
		if !auth.Quota.Exceeded || !isQuotaHoldReason(auth.Quota.Reason) || !quotaOnlyError(auth.LastError) {
			return false
		}
		if auth.NextRetryAfter.After(auth.Quota.NextRecoverAt) {
			return false
		}
		clearAuthStateOnSuccess(auth, now)
		return true
	}

	credentialHold := auth.Quota.Exceeded && auth.Quota.Reason == "credential_quota"
	if credentialHold {
		// The credential-scope path keeps NextRetryAfter equal to the quota reset;
		// anything else means an auth-level failure landed on top of it.
		if !auth.NextRetryAfter.Equal(auth.Quota.NextRecoverAt) {
			return false
		}
	} else {
		// Account availability must be fully derived from model states; an
		// independent auth-level restriction is left alone.
		derived := auth.Clone()
		updateAggregatedAvailability(derived, now)
		if derived.Unavailable != auth.Unavailable || !derived.NextRetryAfter.Equal(auth.NextRetryAfter) {
			return false
		}
	}

	changed := false
	for _, state := range auth.ModelStates {
		if releaseModelQuotaHold(state, now) {
			changed = true
		}
	}
	if credentialHold {
		auth.Unavailable = false
		auth.NextRetryAfter = time.Time{}
		changed = true
	}
	if !changed {
		return false
	}
	// Re-derive the account view from what remains; quota states that were kept
	// re-establish the aggregated quota hold.
	applyCooldownFields(&auth.Quota, QuotaState{})
	updateAggregatedAvailability(auth, now)
	if !hasModelError(auth, now) {
		auth.LastError = nil
		auth.FailureScope = ""
		auth.StatusMessage = ""
		auth.Status = StatusActive
	}
	return true
}

// codexReprobeTarget is a probed credential snapshot together with the model
// registry registration it was taken against.
type codexReprobeTarget struct {
	auth *Auth
	// registryEpoch is the registry's registration epoch for auth.ID when the
	// snapshot was taken. The registry projection is published against this
	// epoch only, so a replacement registration is never touched.
	registryEpoch uint64
}

// codexReprobeSnapshot validates the queued ID immediately before its probe and
// returns a clone bound to the live manager and registry registrations. Nil
// means skip.
func (m *Manager) codexReprobeSnapshot(authID string, now time.Time) *codexReprobeTarget {
	m.mu.RLock()
	defer m.mu.RUnlock()
	auth := m.auths[authID]
	if !codexQuotaHeld(auth, now) {
		return nil
	}
	return &codexReprobeTarget{
		auth:          auth.Clone(),
		registryEpoch: registry.GetGlobalRegistry().ClientRegistrationEpoch(authID),
	}
}

// applyCodexQuotaRelease releases the probed credential's quota hold under the
// manager lock, only if it is still the exact registration and state that was
// probed and the lifecycle has not been cancelled. The registry projection is
// then published only to the registry registration the snapshot was bound to.
func (m *Manager) applyCodexQuotaRelease(ctx context.Context, target *codexReprobeTarget) (bool, error) {
	probed := target.auth
	now := time.Now()
	m.mu.Lock()
	current := m.auths[probed.ID]
	if ctx.Err() != nil || current == nil ||
		current.RegistrationEpoch != probed.RegistrationEpoch ||
		current.Generation != probed.Generation ||
		!codexQuotaHeld(current, now) {
		m.mu.Unlock()
		return false, nil
	}
	var recordsBefore []CooldownStateRecord
	trackCooldownState := m.cooldownStore != nil
	if trackCooldownState {
		recordsBefore = m.cooldownStateRecordsForAuthLocked(current, now)
	}
	if !releaseCodexQuotaHoldLocked(current, now) {
		m.mu.Unlock()
		return false, nil
	}
	current.Generation++
	current.UpdatedAt = now
	snapshot := current.Clone()
	cooldownStateChanged := false
	if trackCooldownState {
		cooldownStateChanged = !cooldownStateRecordsEqual(recordsBefore, m.cooldownStateRecordsForAuthLocked(current, now))
	}
	errPersist := m.persist(ctx, current)
	m.mu.Unlock()

	if cooldownStateChanged {
		m.persistCooldownStates(context.Background())
	}
	if codexQuotaBeforeRegistryPublish != nil {
		codexQuotaBeforeRegistryPublish(snapshot.ID)
	}
	// Publish against the registration captured with the probed snapshot, never
	// against whatever registration is current now: a replacement registered in
	// the meantime has a new epoch and is left untouched (ApplyClientModelProjections
	// re-checks the epoch atomically, so a replacement racing this call is safe too).
	reg := registry.GetGlobalRegistry()
	supportedModels, regEpoch := reg.GetModelsAndEpochForClient(snapshot.ID)
	if regEpoch != target.registryEpoch {
		log.Debugf("codex quota re-probe: registry registration changed, projection dropped | auth=%s", snapshot.ID)
	} else {
		projections := make([]registry.ClientModelProjection, 0, len(supportedModels))
		for _, sm := range supportedModels {
			if sm == nil || strings.TrimSpace(sm.ID) == "" {
				continue
			}
			projections = append(projections, m.clientModelProjectionForAuth(snapshot, sm.ID, now))
		}
		reg.ApplyClientModelProjections(snapshot.ID, target.registryEpoch, snapshot.Generation, projections)
	}
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	return true, errPersist
}

// reprobeHeldCodexQuotas asks /wham/usage about every held Codex account and
// releases the quota hold early when upstream says the account is available
// again. It returns the IDs it released.
//
// A cycle probes each held account at most once, and cycles never overlap: a
// cycle that starts while another is still running (for example after
// StartAutoRefresh replaced the loop) is skipped.
func (m *Manager) reprobeHeldCodexQuotas(ctx context.Context) []string {
	if m == nil {
		return nil
	}
	if !m.codexReprobeCycle.TryLock() {
		log.Debug("codex quota re-probe: previous cycle still running, skipped")
		return nil
	}
	defer m.codexReprobeCycle.Unlock()
	now := time.Now()
	// The queue holds each held ID once (m.auths is keyed by ID), and it is the
	// only source of probes in this cycle: at most one probe per held account.
	var queued []string
	m.mu.RLock()
	for id, auth := range m.auths {
		if codexQuotaHeld(auth, now) {
			queued = append(queued, id)
		}
	}
	m.mu.RUnlock()

	var released []string
	for _, id := range queued {
		if ctx.Err() != nil {
			return released
		}
		// Re-read the live credential right before the request: an account
		// disabled, removed or released while earlier probes ran is skipped.
		target := m.codexReprobeSnapshot(id, time.Now())
		if target == nil {
			continue
		}
		probed := target.auth
		ok, errProbe := m.probeCodexUsage(ctx, probed)
		if errProbe != nil {
			log.Debugf("codex quota re-probe failed | auth=%s err=%v", id, errProbe)
			continue
		}
		if !ok {
			continue
		}
		applied, errApply := m.applyCodexQuotaRelease(ctx, target)
		if errApply != nil {
			log.Warnf("codex quota re-probe: release persist failed | auth=%s err=%v", id, errApply)
		}
		if !applied {
			log.Debugf("codex quota re-probe: result dropped (credential changed, released or cancelled) | auth=%s", id)
			continue
		}
		log.Infof("codex quota re-probe: usage shows account available, quota hold released early | auth=%s held_until=%s", id, probed.Quota.NextRecoverAt.Format(time.RFC3339))
		released = append(released, id)
	}
	return released
}

func (m *Manager) probeCodexUsage(ctx context.Context, auth *Auth) (bool, error) {
	probeCtx, cancel := context.WithTimeout(ctx, codexQuotaReprobeTimeout)
	defer cancel()
	req, errReq := http.NewRequestWithContext(probeCtx, http.MethodGet, codexQuotaReprobeURL, nil)
	if errReq != nil {
		return false, errReq
	}
	req.Header.Set("Accept", "application/json")
	if auth.Metadata != nil {
		if accountID, ok := auth.Metadata["account_id"].(string); ok && strings.TrimSpace(accountID) != "" {
			req.Header.Set("Chatgpt-Account-Id", accountID)
		}
	}
	resp, errDo := m.HttpRequest(probeCtx, auth, req)
	if errDo != nil {
		return false, errDo
	}
	defer func() { _ = resp.Body.Close() }()
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if errRead != nil {
		return false, errRead
	}
	if resp.StatusCode != http.StatusOK {
		return false, &Error{Code: "codex_usage_probe", Message: resp.Status, HTTPStatus: resp.StatusCode}
	}
	return codexUsageAllows(body), nil
}

// runCodexQuotaReprobe re-probes held Codex accounts every interval until ctx ends.
func (m *Manager) runCodexQuotaReprobe(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.reprobeHeldCodexQuotas(ctx)
		}
	}
}
