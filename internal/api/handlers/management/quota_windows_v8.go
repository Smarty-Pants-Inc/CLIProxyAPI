package management

import (
	"time"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// addAuthFileQuotaWindowsV8 adds a separate evidence view for maintained v8
// callers. It neither replaces the legacy observations nor changes cooldowns.
func addAuthFileQuotaWindowsV8(c *gin.Context, entry gin.H, auth *coreauth.Auth, observedAt time.Time) {
	if !c.GetBool(ConfigV8ContextKey) {
		return
	}
	provenance := coreauth.QuotaWindowProvenance{
		Source:         "cpa.response_headers",
		TimestampBasis: "header_acquisition",
	}
	// observedAt is the list's evaluation time, not a new acquisition time. The
	// parser independently requires per-signal acquisition evidence in Quota.
	entry["quota_normalized"] = coreauth.NormalizeQuotaWindows(auth.Provider, auth.Quota, observedAt, provenance)
	models := make(map[string]coreauth.QuotaWindowsView, len(auth.ModelStates))
	for model, state := range auth.ModelStates {
		if state == nil {
			continue
		}
		// Keep exact recorded model keys, including those with no observation.
		// Missing evidence stays unknown; account windows imply no model scope.
		models[model] = coreauth.NormalizeQuotaWindows(auth.Provider, state.Quota, observedAt, provenance)
	}
	entry["model_quotas_normalized"] = models
}
