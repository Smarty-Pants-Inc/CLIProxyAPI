package management

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type quotaWindowsV8ListResponse struct {
	ObservedAt time.Time                    `json:"observed_at"`
	Files      []map[string]json.RawMessage `json:"files"`
	Total      int                          `json:"total"`
	Page       int                          `json:"page"`
	PageSize   int                          `json:"page_size"`
	HasMore    bool                         `json:"has_more"`
}

func requestQuotaWindowsV8List(t *testing.T, h *Handler, marker any, query string) quotaWindowsV8ListResponse {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	// Exercise the real handler with the same context marker as v8 middleware,
	// without adding or claiming a production route registration.
	c.Request = httptest.NewRequest(http.MethodGet, "/auth-files"+query, nil)
	if marker != nil {
		c.Set(ConfigV8ContextKey, marker)
	}
	h.ListAuthFiles(c)
	if recorder.Code != http.StatusOK {
		t.Fatalf("ListAuthFiles status = %d: %s", recorder.Code, recorder.Body.String())
	}
	var response quotaWindowsV8ListResponse
	if errDecode := json.Unmarshal(recorder.Body.Bytes(), &response); errDecode != nil {
		t.Fatal(errDecode)
	}
	if response.ObservedAt.IsZero() {
		t.Fatal("missing list evaluation time")
	}
	return response
}

func quotaWindowsV8Handler(t *testing.T, auth *coreauth.Auth, home bool) (*Handler, *coreauth.Manager) {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	cfg := &config.Config{}
	cfg.Home.Enabled = home
	manager.SetConfig(cfg)
	if _, errRegister := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); errRegister != nil {
		t.Fatal(errRegister)
	}
	return &Handler{authManager: manager}, manager
}

func quotaWindowsV8Observation(at time.Time, used string) coreauth.QuotaState {
	signals := map[string]string{
		"X-Codex-Primary-Used-Percent":          used,
		"X-Codex-Primary-Window-Minutes":        "10080",
		"X-Codex-Primary-Reset-At":              strconv.FormatInt(at.Add(time.Hour).Unix(), 10),
		"X-Codex-Secondary-Window-Minutes":      "0",
		"X-Codex-Secondary-Used-Percent":        "0",
		"X-Codex-Secondary-Reset-After-Seconds": "0",
		"X-Codex-Active-Limit":                  "premium",
		"X-Codex-Credits-Has-Credits":           "True",
		"X-Codex-Credits-Unlimited":             "True",
		"X-Codex-Credits-Balance":               "42",
	}
	acquired := make(map[string]time.Time, len(signals))
	for key := range signals {
		acquired[key] = at
	}
	return coreauth.QuotaState{ObservedAt: at, Signals: signals, SignalObservedAt: acquired}
}

func quotaWindowsV8Auth(id, provider string, quota coreauth.QuotaState) *coreauth.Auth {
	return &coreauth.Auth{
		ID: id, Index: "index-" + id, Provider: provider, Status: coreauth.StatusActive,
		Attributes: map[string]string{"runtime_only": "true"}, Quota: quota,
	}
}

func decodeQuotaWindowsV8(t *testing.T, raw json.RawMessage) coreauth.QuotaWindowsView {
	t.Helper()
	if len(raw) == 0 || string(raw) == "null" {
		t.Fatal("missing normalized quota view")
	}
	var view coreauth.QuotaWindowsView
	if errDecode := json.Unmarshal(raw, &view); errDecode != nil {
		t.Fatal(errDecode)
	}
	return view
}

func decodeModelQuotaWindowsV8(t *testing.T, raw json.RawMessage) map[string]coreauth.QuotaWindowsView {
	t.Helper()
	var models map[string]coreauth.QuotaWindowsView
	if errDecode := json.Unmarshal(raw, &models); errDecode != nil {
		t.Fatal(errDecode)
	}
	if models == nil {
		t.Fatal("model_quotas_normalized must be an object, not null")
	}
	return models
}

func primaryQuotaWindowV8(t *testing.T, view coreauth.QuotaWindowsView) coreauth.QuotaWindowView {
	t.Helper()
	for _, window := range view.Windows {
		if window.UpstreamWindow == "primary" {
			return window
		}
	}
	t.Fatalf("missing primary window: %+v", view)
	return coreauth.QuotaWindowView{}
}

func assertQuotaWindowV8Time(t *testing.T, window coreauth.QuotaWindowView, acquiredAt, evaluatedAt time.Time) {
	t.Helper()
	wantObserved := float64(acquiredAt.Unix()) + float64(acquiredAt.Nanosecond())/1e9
	if window.ObservedAt == nil || math.Abs(*window.ObservedAt-wantObserved) > 1e-6 {
		t.Fatalf("observed_at = %v, want original acquisition %v", window.ObservedAt, wantObserved)
	}
	wantAge := evaluatedAt.Sub(acquiredAt).Seconds()
	if window.AgeSeconds == nil || math.Abs(*window.AgeSeconds-wantAge) > 1e-6 {
		t.Fatalf("age_seconds = %v, want list-time age %v", window.AgeSeconds, wantAge)
	}
	if window.Source != "cpa.response_headers" || window.TimestampBasis != "header_acquisition" {
		t.Fatalf("wrong provenance: %+v", window)
	}
}

func assertQuotaWindowsV8JSONEqual(t *testing.T, got json.RawMessage, want any) {
	t.Helper()
	wantJSON, errMarshal := json.Marshal(want)
	if errMarshal != nil {
		t.Fatal(errMarshal)
	}
	var gotValue, wantValue any
	if errDecode := json.Unmarshal(got, &gotValue); errDecode != nil {
		t.Fatal(errDecode)
	}
	if errDecode := json.Unmarshal(wantJSON, &wantValue); errDecode != nil {
		t.Fatal(errDecode)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Fatalf("JSON changed: got %s; want %s", got, wantJSON)
	}
}

func TestListAuthFilesQuotaWindowsV8AccountAndExactModel(t *testing.T) {
	// ListAuthFiles owns its wall clock. Capture one fixture acquisition well
	// inside the freshness boundary; all assertions use its returned list time.
	acquiredAt := time.Now().UTC().Add(-time.Minute)
	modelAt := acquiredAt.Add(-5 * time.Second)
	const exactModel = "Provider/Exact MODEL:variant@v1"
	auth := quotaWindowsV8Auth("account", "codex", quotaWindowsV8Observation(acquiredAt, "9"))
	auth.ModelStates = map[string]*coreauth.ModelState{
		exactModel: {Status: coreauth.StatusActive, Quota: quotaWindowsV8Observation(modelAt, "99")},
		"empty":    {Status: coreauth.StatusActive},
		"nil":      nil,
	}
	h, manager := quotaWindowsV8Handler(t, auth, false)
	before, _ := manager.GetByID(auth.ID)
	for _, query := range []string{"", "?page=1&page_size=1"} {
		t.Run(query, func(t *testing.T) {
			legacy := requestQuotaWindowsV8List(t, h, nil, query)
			response := requestQuotaWindowsV8List(t, h, true, query)
			if len(legacy.Files) != 1 || len(response.Files) != 1 {
				t.Fatalf("unexpected files: legacy=%d v8=%d", len(legacy.Files), len(response.Files))
			}
			oldFile, file := legacy.Files[0], response.Files[0]
			if _, exists := oldFile["quota_normalized"]; exists {
				t.Fatal("v0 gained quota_normalized")
			}
			if _, exists := oldFile["model_quotas_normalized"]; exists {
				t.Fatal("v0 gained model_quotas_normalized")
			}
			view := decodeQuotaWindowsV8(t, file["quota_normalized"])
			primary := primaryQuotaWindowV8(t, view)
			if view.State != "known" || primary.State != "known" || primary.DurationSeconds == nil || *primary.DurationSeconds != 604800 || primary.UsedPercent == nil || *primary.UsedPercent != 9 || primary.HeadroomPercent == nil || *primary.HeadroomPercent != 91 {
				t.Fatalf("wrong account window: %+v", view)
			}
			assertQuotaWindowV8Time(t, primary, acquiredAt, response.ObservedAt)
			var wire struct {
				Windows []map[string]json.RawMessage `json:"windows"`
			}
			if errDecode := json.Unmarshal(file["quota_normalized"], &wire); errDecode != nil {
				t.Fatal(errDecode)
			}
			sawAbsent := false
			for _, window := range wire.Windows {
				if string(window["upstream_window"]) != `"secondary"` {
					continue
				}
				sawAbsent = true
				if string(window["state"]) != `"not_applicable"` {
					t.Fatalf("zero-minute slot became free capacity: %s", file["quota_normalized"])
				}
				for _, key := range []string{"duration_seconds", "used_percent", "headroom_percent", "reset_at"} {
					if string(window[key]) != "null" {
						t.Fatalf("absent slot must serialize explicit %s:null: %s", key, file["quota_normalized"])
					}
				}
			}
			if !sawAbsent {
				t.Fatal("explicit absent source slot was lost")
			}
			models := decodeModelQuotaWindowsV8(t, file["model_quotas_normalized"])
			if len(models) != 2 {
				t.Fatalf("model keys inferred, rewritten, or lost: %+v", models)
			}
			modelView, exists := models[exactModel]
			if !exists {
				t.Fatalf("exact model key missing: %+v", models)
			}
			modelPrimary := primaryQuotaWindowV8(t, modelView)
			if modelView.State != "exhausted" || modelPrimary.UsedPercent == nil || *modelPrimary.UsedPercent != 99 || modelPrimary.HeadroomPercent == nil || *modelPrimary.HeadroomPercent != 1 {
				t.Fatalf("credits or account evidence cleared model exhaustion: %+v", modelView)
			}
			assertQuotaWindowV8Time(t, modelPrimary, modelAt, response.ObservedAt)
			if models["empty"].State != "unknown" {
				t.Fatalf("missing model evidence became capacity: %+v", models["empty"])
			}
			for _, key := range []string{"quota", "model_quotas", "status", "status_message", "disabled", "unavailable", "auth_index", "cooldowns"} {
				if !reflect.DeepEqual(oldFile[key], file[key]) {
					t.Fatalf("legacy field %q changed: v0=%s v8=%s", key, oldFile[key], file[key])
				}
			}
			assertQuotaWindowsV8JSONEqual(t, file["quota"], quotaObservationPayloadForProvider(before.Provider, before.Quota))
			assertQuotaWindowsV8JSONEqual(t, file["model_quotas"], modelQuotaObservationPayload(before.Provider, before.ModelStates))
			if query != "" && (response.Total != 1 || response.Page != 1 || response.PageSize != 1 || response.HasMore) {
				t.Fatalf("pagination envelope changed: %+v", response)
			}
		})
	}
	after, _ := manager.GetByID(auth.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("ListAuthFiles mutated its source observations or health")
	}
}

func TestListAuthFilesQuotaWindowsV8RepeatedGETKeepsAcquisition(t *testing.T) {
	acquiredAt := time.Now().UTC().Add(-301 * time.Second)
	quota := quotaWindowsV8Observation(acquiredAt, "9")
	// A fresh legacy scalar must not freshen older per-header acquisition.
	quota.ObservedAt = acquiredAt.Add(300 * time.Second)
	auth := quotaWindowsV8Auth("stale", "codex", quota)
	auth.ModelStates = map[string]*coreauth.ModelState{"exact-model": {Quota: quota.Clone()}}
	h, manager := quotaWindowsV8Handler(t, auth, false)
	before, _ := manager.GetByID(auth.ID)
	var previousObserved *float64
	for _, query := range []string{"", "?page=1&page_size=1"} {
		response := requestQuotaWindowsV8List(t, h, true, query)
		if len(response.Files) != 1 {
			t.Fatalf("files = %d, want 1", len(response.Files))
		}
		file := response.Files[0]
		view := decodeQuotaWindowsV8(t, file["quota_normalized"])
		modelView := decodeModelQuotaWindowsV8(t, file["model_quotas_normalized"])["exact-model"]
		for _, current := range []coreauth.QuotaWindowsView{view, modelView} {
			primary := primaryQuotaWindowV8(t, current)
			if current.State != "stale" || primary.State != "stale" || primary.Reason != "observation_expired" || primary.AgeSeconds == nil || *primary.AgeSeconds <= 300 {
				t.Fatalf("GET refreshed stale evidence: %+v", current)
			}
			assertQuotaWindowV8Time(t, primary, acquiredAt, response.ObservedAt)
			if previousObserved != nil && *previousObserved != *primary.ObservedAt {
				t.Fatal("GET replaced original acquisition time")
			}
			previousObserved = primary.ObservedAt
		}
		assertQuotaWindowsV8JSONEqual(t, file["quota"], quotaObservationPayload(quota))
	}
	after, _ := manager.GetByID(auth.ID)
	if !reflect.DeepEqual(before, after) {
		t.Fatal("repeated GET changed retained quota state")
	}
}

func TestListAuthFilesQuotaWindowsV8UnknownObservations(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	legacy := quotaWindowsV8Observation(at, "9")
	legacy.SignalObservedAt = nil
	for _, test := range []struct {
		name     string
		provider string
		quota    coreauth.QuotaState
	}{
		{name: "legacy scalar timestamp", provider: "codex", quota: legacy},
		{name: "missing observation", provider: "codex"},
		{name: "unsupported Kimi", provider: "kimi", quota: quotaWindowsV8Observation(at, "0")},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth := quotaWindowsV8Auth("unknown", test.provider, test.quota)
			auth.ModelStates = map[string]*coreauth.ModelState{"exact-model": {Quota: test.quota.Clone()}}
			h, _ := quotaWindowsV8Handler(t, auth, false)
			for _, query := range []string{"", "?page=1&page_size=1"} {
				response := requestQuotaWindowsV8List(t, h, true, query)
				if len(response.Files) != 1 {
					t.Fatalf("files = %d, want 1", len(response.Files))
				}
				file := response.Files[0]
				account := decodeQuotaWindowsV8(t, file["quota_normalized"])
				model := decodeModelQuotaWindowsV8(t, file["model_quotas_normalized"])["exact-model"]
				for _, view := range []coreauth.QuotaWindowsView{account, model} {
					if view.State != "unknown" || view.Reason == "" {
						t.Fatalf("missing/unverified/unsupported observation became known: %+v", view)
					}
					if test.provider == "kimi" && (view.Reason != "unsupported_provider" || view.Windows == nil || len(view.Windows) != 0) {
						t.Fatalf("Kimi was not explicitly unsupported: %+v", view)
					}
					if test.name == "legacy scalar timestamp" {
						primary := primaryQuotaWindowV8(t, view)
						if primary.State != "unknown" || primary.TimestampBasis != "unknown" || primary.UsedPercent == nil || *primary.UsedPercent != 9 {
							t.Fatalf("caller label certified legacy scalar or erased measured evidence: %+v", primary)
						}
					}
					if test.name == "missing observation" {
						for _, window := range view.Windows {
							if window.UsedPercent != nil || window.HeadroomPercent != nil || window.ObservedAt != nil || window.AgeSeconds != nil {
								t.Fatalf("missing observation fabricated capacity/time: %+v", window)
							}
						}
					}
				}
				assertQuotaWindowsV8JSONEqual(t, file["quota"], quotaObservationPayloadForProvider(test.provider, test.quota))
			}
		})
	}
}

func TestListAuthFilesQuotaWindowsV8PreservesCooldownAndHealth(t *testing.T) {
	now := time.Now().UTC()
	next := now.Add(time.Hour)
	for _, home := range []bool{false, true} {
		t.Run(strconv.FormatBool(home), func(t *testing.T) {
			quota := quotaWindowsV8Observation(now.Add(-time.Minute), "9")
			quota.Exceeded, quota.Reason, quota.NextRecoverAt = true, "credential_quota", next
			auth := quotaWindowsV8Auth("cooldown", "codex", quota)
			auth.Status, auth.StatusMessage, auth.Unavailable, auth.NextRetryAfter = coreauth.StatusError, "cooldown fixture", true, next
			auth.ModelStates = map[string]*coreauth.ModelState{"exact-model": {
				Status: coreauth.StatusError, Unavailable: true, NextRetryAfter: next,
				Quota:     coreauth.QuotaState{Exceeded: true, Reason: "quota", NextRecoverAt: next, BackoffLevel: 3},
				LastError: &coreauth.Error{HTTPStatus: 429},
			}}
			h, manager := quotaWindowsV8Handler(t, auth, home)
			before, _ := manager.GetByID(auth.ID)
			modelState := before.ModelStates["exact-model"]
			if home {
				if before.Unavailable || !before.NextRetryAfter.IsZero() || before.Quota.Exceeded || before.Quota.Reason != "" || !before.Quota.NextRecoverAt.IsZero() || before.Quota.BackoffLevel != 0 || modelState == nil || modelState.Unavailable || !modelState.NextRetryAfter.IsZero() || modelState.Quota.Exceeded || modelState.Quota.Reason != "" || !modelState.Quota.NextRecoverAt.IsZero() || modelState.Quota.BackoffLevel != 0 {
					t.Fatalf("Home registration did not clear locally owned cooldown state: %+v", before)
				}
			} else if before.Status != coreauth.StatusError || before.StatusMessage != "cooldown fixture" || !before.Unavailable || !before.NextRetryAfter.Equal(next) || !before.Quota.Exceeded || before.Quota.Reason != "credential_quota" || !before.Quota.NextRecoverAt.Equal(next) || modelState == nil || modelState.Status != coreauth.StatusError || !modelState.Unavailable || !modelState.NextRetryAfter.Equal(next) || !modelState.Quota.Exceeded || modelState.Quota.Reason != "quota" || !modelState.Quota.NextRecoverAt.Equal(next) || modelState.Quota.BackoffLevel != 3 || modelState.LastError == nil || modelState.LastError.HTTPStatus != http.StatusTooManyRequests {
				t.Fatalf("non-Home registration did not retain the unhealthy cooldown fixture: %+v", before)
			}
			for _, query := range []string{"", "?page=1&page_size=1"} {
				var legacyFile, v8File map[string]json.RawMessage
				for _, marker := range []any{nil, true} {
					response := requestQuotaWindowsV8List(t, h, marker, query)
					if len(response.Files) != 1 {
						t.Fatalf("files = %d, want 1", len(response.Files))
					}
					file := response.Files[0]
					wantUnavailable, wantStatus, wantStatusMessage, wantNextRetry := reconcileAuthFileCooldownState(before, response.ObservedAt)
					assertQuotaWindowsV8JSONEqual(t, file["status"], wantStatus)
					assertQuotaWindowsV8JSONEqual(t, file["status_message"], wantStatusMessage)
					assertQuotaWindowsV8JSONEqual(t, file["unavailable"], wantUnavailable)
					assertQuotaWindowsV8JSONEqual(t, file["disabled"], before.Disabled)
					if wantNextRetry.IsZero() {
						if _, exists := file["next_retry_after"]; exists {
							t.Fatalf("unexpected next_retry_after for registered state: %s", file["next_retry_after"])
						}
					} else {
						assertQuotaWindowsV8JSONEqual(t, file["next_retry_after"], wantNextRetry)
					}
					if home {
						assertQuotaWindowsV8JSONEqual(t, file["cooldowns"], nil)
					} else {
						assertQuotaWindowsV8JSONEqual(t, file["cooldowns"], coreauth.CooldownSnapshotForAuth(before, response.ObservedAt))
					}
					assertQuotaWindowsV8JSONEqual(t, file["quota"], quotaObservationPayloadForProvider(before.Provider, before.Quota))
					if marker == nil {
						legacyFile = file
					} else {
						v8File = file
					}
					if marker == true && decodeQuotaWindowsV8(t, file["quota_normalized"]).State != "known" {
						t.Fatal("scheduler state was substituted for passive quota evidence")
					}
				}
				for _, key := range []string{"status", "status_message", "disabled", "unavailable", "next_retry_after", "quota", "model_quotas"} {
					if !reflect.DeepEqual(legacyFile[key], v8File[key]) {
						t.Fatalf("legacy field %q changed between v0 and v8: v0=%s v8=%s", key, legacyFile[key], v8File[key])
					}
				}
			}
			after, _ := manager.GetByID(auth.ID)
			if !reflect.DeepEqual(before, after) {
				t.Fatal("GET changed scheduler/health state")
			}
		})
	}
}

func TestListAuthFilesQuotaWindowsV8RequiresBooleanContextMarker(t *testing.T) {
	auth := quotaWindowsV8Auth("marker", "codex", coreauth.QuotaState{})
	h, _ := quotaWindowsV8Handler(t, auth, false)
	for _, marker := range []any{nil, false, "true"} {
		response := requestQuotaWindowsV8List(t, h, marker, "")
		if len(response.Files) != 1 {
			t.Fatalf("files = %d, want 1", len(response.Files))
		}
		for _, key := range []string{"quota_normalized", "model_quotas_normalized"} {
			if _, exists := response.Files[0][key]; exists {
				t.Fatalf("non-v8 marker %v exposed %s", marker, key)
			}
		}
	}
	response := requestQuotaWindowsV8List(t, h, true, "")
	models := decodeModelQuotaWindowsV8(t, response.Files[0]["model_quotas_normalized"])
	if len(models) != 0 {
		t.Fatalf("model applicability inferred from account: %+v", models)
	}
}

func TestAddAuthFileQuotaWindowsV8UsesSuppliedEvaluationTime(t *testing.T) {
	acquiredAt := time.Date(2026, time.January, 2, 3, 4, 5, 250000000, time.UTC)
	auth := quotaWindowsV8Auth("fixed-clock", "codex", quotaWindowsV8Observation(acquiredAt, "9"))
	const exactSnapshotKey = " Opaque/Exact Key (thinking):v1 "
	auth.ModelStates = map[string]*coreauth.ModelState{exactSnapshotKey: {Quota: auth.Quota.Clone()}}
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Set(ConfigV8ContextKey, true)
	for _, test := range []struct {
		elapsed time.Duration
		state   string
	}{
		{elapsed: 300 * time.Second, state: "known"},
		{elapsed: 300*time.Second + time.Millisecond, state: "stale"},
	} {
		entry := gin.H{}
		now := acquiredAt.Add(test.elapsed)
		addAuthFileQuotaWindowsV8(c, entry, auth, now)
		view, ok := entry["quota_normalized"].(coreauth.QuotaWindowsView)
		if !ok || view.State != test.state {
			t.Fatalf("elapsed=%s: %+v, want %s", test.elapsed, entry["quota_normalized"], test.state)
		}
		assertQuotaWindowV8Time(t, primaryQuotaWindowV8(t, view), acquiredAt, now)
		models, ok := entry["model_quotas_normalized"].(map[string]coreauth.QuotaWindowsView)
		if !ok || len(models) != 1 || models[exactSnapshotKey].State != test.state {
			t.Fatalf("exact snapshot model key changed: %+v", entry["model_quotas_normalized"])
		}
	}
}

func TestListAuthFilesQuotaWindowsV8Claude(t *testing.T) {
	at := time.Now().UTC().Add(-time.Minute)
	signals := map[string]string{
		"Anthropic-Ratelimit-Unified-5h-Utilization": "0.29",
		"Anthropic-Ratelimit-Unified-5h-Reset":       strconv.FormatInt(at.Add(time.Hour).Unix(), 10),
		"Anthropic-Ratelimit-Unified-7d-Utilization": "0.56",
		"Anthropic-Ratelimit-Unified-7d-Reset":       strconv.FormatInt(at.Add(24*time.Hour).Unix(), 10),
	}
	acquired := make(map[string]time.Time, len(signals))
	for key := range signals {
		acquired[key] = at
	}
	auth := quotaWindowsV8Auth("claude", "claude", coreauth.QuotaState{ObservedAt: at, Signals: signals, SignalObservedAt: acquired})
	h, _ := quotaWindowsV8Handler(t, auth, false)
	for _, query := range []string{"", "?page=1&page_size=1"} {
		response := requestQuotaWindowsV8List(t, h, true, query)
		if len(response.Files) != 1 {
			t.Fatalf("files = %d, want 1", len(response.Files))
		}
		view := decodeQuotaWindowsV8(t, response.Files[0]["quota_normalized"])
		if view.State != "known" || len(view.Windows) != 2 {
			t.Fatalf("wrong Claude projection: %+v", view)
		}
		for _, window := range view.Windows {
			used, duration := 29.0, int64(18000)
			if window.UpstreamWindow == "7d" {
				used, duration = 56, 604800
			} else if window.UpstreamWindow != "5h" {
				t.Fatalf("invented Claude window: %+v", window)
			}
			if window.UsedPercent == nil || math.Abs(*window.UsedPercent-used) > 1e-9 || window.DurationSeconds == nil || *window.DurationSeconds != duration {
				t.Fatalf("wrong Claude units: %+v", window)
			}
			assertQuotaWindowV8Time(t, window, at, response.ObservedAt)
		}
	}
}
