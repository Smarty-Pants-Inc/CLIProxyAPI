package auth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const (
	// codexQuotaReprobeInterval is how often held Codex accounts are re-checked.
	codexQuotaReprobeInterval = time.Hour
	codexQuotaReprobeTimeout  = 15 * time.Second
	codexUsageURL             = "https://chatgpt.com/backend-api/wham/usage"
)

// codexQuotaReprobeURL is a variable so tests can point the probe at a local server.
var codexQuotaReprobeURL = codexUsageURL

// codexUsageAllows reports whether a /wham/usage body shows the account can
// serve requests now. A body without an explicit rate_limit verdict is never
// treated as available, so an unknown shape keeps the hold.
func codexUsageAllows(body []byte) bool {
	var payload struct {
		RateLimit *struct {
			Allowed      *bool `json:"allowed"`
			LimitReached *bool `json:"limit_reached"`
		} `json:"rate_limit"`
	}
	if json.Unmarshal(body, &payload) != nil || payload.RateLimit == nil {
		return false
	}
	rl := payload.RateLimit
	if rl.Allowed == nil && rl.LimitReached == nil {
		return false
	}
	return (rl.Allowed == nil || *rl.Allowed) && (rl.LimitReached == nil || !*rl.LimitReached)
}

// codexQuotaHeld reports whether a Codex OAuth account is held by a quota
// cooldown that has not yet reached its upstream reset.
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
	if auth.Quota.Exceeded && auth.Quota.NextRecoverAt.After(now) {
		return true
	}
	for _, state := range auth.ModelStates {
		if state != nil && state.Quota.Exceeded && state.Quota.NextRecoverAt.After(now) {
			return true
		}
	}
	return false
}

// reprobeHeldCodexQuotas asks /wham/usage about every held Codex account and
// releases the hold early when upstream says the account is available again.
// It returns the IDs it released.
func (m *Manager) reprobeHeldCodexQuotas(ctx context.Context) []string {
	if m == nil {
		return nil
	}
	now := time.Now()
	var held []*Auth
	m.mu.RLock()
	for _, auth := range m.auths {
		if codexQuotaHeld(auth, now) {
			held = append(held, auth.Clone())
		}
	}
	m.mu.RUnlock()

	var released []string
	for _, auth := range held {
		if ctx.Err() != nil {
			return released
		}
		ok, errProbe := m.probeCodexUsage(ctx, auth)
		if errProbe != nil {
			log.Debugf("codex quota re-probe failed | auth=%s err=%v", auth.ID, errProbe)
			continue
		}
		if !ok {
			continue
		}
		if _, _, errReset := m.ResetQuota(ctx, auth.ID); errReset != nil {
			log.Warnf("codex quota re-probe: release failed | auth=%s err=%v", auth.ID, errReset)
			continue
		}
		log.Infof("codex quota re-probe: usage shows account available, hold released early | auth=%s held_until=%s", auth.ID, auth.Quota.NextRecoverAt.Format(time.RFC3339))
		released = append(released, auth.ID)
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
