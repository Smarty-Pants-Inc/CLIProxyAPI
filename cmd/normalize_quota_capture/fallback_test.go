package main

import (
	"os"
	"testing"
	"time"
)

const (
	fallbackTestEvaluation = "2026-11-06T12:01:00Z"
	fallbackTestReceipt    = "2026-11-06T12:00:45Z"
	fallbackTestBasis      = "fallback:auth-files+used_percent"
)

type fallbackTestOutput struct {
	raw     []byte
	sidecar map[string]any
	err     error
}

func fallbackTestObservation(row map[string]any, observedAt string) map[string]any {
	return producerTestAuthObservation([]map[string]any{row}, observedAt)
}

func fallbackTestCooldown(scope, reason string) map[string]any {
	return map[string]any{
		"scope":             scope,
		"model_key":         "gpt-6-luna",
		"reason":            reason,
		"retry_at":          "2026-11-06T12:02:00Z",
		"remaining_seconds": 60,
	}
}

func fallbackTestSetAcquisition(seat map[string]any, key, acquiredAt string) {
	acquisitions := producerTestMap(seat, "response_headers_observed_at")
	if acquiredAt == "" {
		delete(acquisitions, key)
		return
	}
	acquisitions[key] = acquiredAt
}

func fallbackTestRunV1(t *testing.T, seat, observation map[string]any) fallbackTestOutput {
	t.Helper()
	files := producerTestWriteScenarioWithObservation(t,
		producerTestCapture(seat),
		[]map[string]any{producerTestRoute("fallback-route", producerTestAuthA, "gpt-6-luna", "low")},
		observation,
	)
	raw, err := producerTestRun(t, files, fallbackTestEvaluation)
	output := fallbackTestOutput{raw: raw, err: err}
	if err == nil {
		output.sidecar = producerTestDecodeFileObject(t, files.sidecarPath)
	}
	return output
}

func fallbackTestRunV2(t *testing.T, seat, observation map[string]any) fallbackTestOutput {
	t.Helper()
	chain := newIncrementalTestChain(t)
	row := incrementalTestConvertRow(t, seat)
	invocation := chain.prepare(t, []map[string]any{row}, fallbackTestReceipt, 1, true)
	incrementalTestWrite(t, incrementalTestArg(invocation.args, "--auth-files-observation"), observation)
	invocation.inputs = nil // The observation was intentionally replaced before the run.

	stdout, errCreate := os.Create(invocation.artifact)
	if errCreate != nil {
		t.Fatal(errCreate)
	}
	errRun := run(invocation.args, stdout)
	errClose := stdout.Close()
	if errRun != nil {
		return fallbackTestOutput{err: errRun}
	}
	if errClose != nil {
		return fallbackTestOutput{err: errClose}
	}
	raw, errRead := os.ReadFile(invocation.artifact)
	if errRead != nil {
		t.Fatal(errRead)
	}
	sidecarRaw, errSidecar := os.ReadFile(invocation.sidecar)
	if errSidecar != nil {
		t.Fatal(errSidecar)
	}
	return fallbackTestOutput{
		raw:     raw,
		sidecar: producerTestDecodeObject(t, sidecarRaw),
	}
}

func fallbackTestAssertBoth(t *testing.T, seat, observation map[string]any, want *bool, wantBasis, requireComplete bool) (fallbackTestOutput, fallbackTestOutput) {
	t.Helper()
	v1 := fallbackTestRunV1(t, seat, observation)
	fallbackTestAssertV1(t, v1, want, wantBasis)
	v2 := fallbackTestRunV2(t, seat, observation)
	fallbackTestAssertV2(t, v2, want, wantBasis, requireComplete)
	return v1, v2
}

func fallbackTestAssertV1(t *testing.T, output fallbackTestOutput, want *bool, wantBasis bool) {
	t.Helper()
	if output.err != nil {
		if want != nil {
			t.Fatalf("v1 producer rejected a fixture expected to resolve %v: %v", *want, output.err)
		}
		if len(output.raw) != 0 {
			t.Fatalf("v1 refusal emitted stdout: %q", output.raw)
		}
		return
	}
	if len(output.raw) == 0 {
		t.Fatal("v1 producer returned success without an artifact")
	}
	record := producerTestOptionalHealth(t, output.sidecar, producerTestAuthA)
	if want == nil {
		if record != nil {
			if _, ok := record["limit_reached"].(bool); ok {
				t.Fatalf("v1 unknown evidence became limit_reached: %+v", record)
			}
			if _, ok := record["limit_reached_basis"]; ok {
				t.Fatalf("v1 unknown evidence acquired a fallback basis: %+v", record)
			}
		}
		return
	}
	if record == nil || producerTestBool(t, record, "limit_reached") != *want {
		t.Fatalf("v1 limit_reached record = %+v, want %v", record, *want)
	}
	if wantBasis {
		if got := producerTestString(t, record, "limit_reached_basis"); got != fallbackTestBasis {
			t.Fatalf("v1 limit_reached_basis = %q, want %q", got, fallbackTestBasis)
		}
	} else if _, exists := record["limit_reached_basis"]; exists {
		t.Fatalf("explicit-only v1 health changed its old wire shape: %+v", record)
	}
}

func fallbackTestV2Health(t *testing.T, output fallbackTestOutput) (map[string]any, map[string]any) {
	t.Helper()
	view := producerTestDecodeObject(t, output.raw)
	signals := producerTestOptionalObject(view["signals"])
	authSignals := producerTestOptionalObject(signals[producerTestAuthA])
	health := producerTestOptionalObject(authSignals["health"])
	record := producerTestOptionalHealth(t, output.sidecar, producerTestAuthA)
	return health, record
}

func fallbackTestAssertV2(t *testing.T, output fallbackTestOutput, want *bool, wantBasis, requireComplete bool) {
	t.Helper()
	if output.err != nil {
		if want != nil {
			t.Fatalf("v2 producer rejected a fixture expected to resolve %v: %v", *want, output.err)
		}
		return
	}
	if len(output.raw) == 0 {
		t.Fatal("v2 producer returned success without an artifact")
	}
	health, record := fallbackTestV2Health(t, output)
	if want == nil {
		if _, ok := health["limit_reached"].(bool); ok {
			t.Fatalf("v2 unknown evidence became limit_reached: %+v", health)
		}
		if basis, ok := health["limit_reached_basis"].(string); ok && basis != "" {
			t.Fatalf("v2 unknown evidence acquired a fallback basis: %+v", health)
		}
		if record != nil {
			if _, ok := record["limit_reached"].(bool); ok {
				t.Fatalf("v2 sidecar unknown evidence became limit_reached: %+v", record)
			}
			if _, ok := record["limit_reached_basis"]; ok {
				t.Fatalf("v2 sidecar unknown evidence acquired a fallback basis: %+v", record)
			}
		}
		return
	}
	if producerTestBool(t, health, "limit_reached") != *want {
		t.Fatalf("v2 limit_reached = %+v, want %v", health["limit_reached"], *want)
	}
	if record == nil || producerTestBool(t, record, "limit_reached") != *want {
		t.Fatalf("v2 sidecar limit_reached record = %+v, want %v", record, *want)
	}
	if wantBasis {
		if got := producerTestString(t, health, "limit_reached_basis"); got != fallbackTestBasis {
			t.Fatalf("v2 limit_reached_basis = %q, want %q", got, fallbackTestBasis)
		}
		if got := producerTestString(t, record, "limit_reached_basis"); got != fallbackTestBasis {
			t.Fatalf("v2 sidecar limit_reached_basis = %q, want %q", got, fallbackTestBasis)
		}
	} else if _, exists := health["limit_reached_basis"]; exists {
		t.Fatalf("explicit-only v2 health changed its old wire shape: %+v", health)
	} else if _, exists := record["limit_reached_basis"]; exists {
		t.Fatalf("explicit-only v2 sidecar health changed its old wire shape: %+v", record)
	}
	if requireComplete {
		if health["status"] != "complete" || record == nil {
			t.Fatalf("fresh fallback evidence did not produce complete v2 health: %+v", health)
		}
		for _, key := range []string{"active", "cooldown", "limit_reached"} {
			if _, ok := health[key].(bool); !ok {
				t.Fatalf("complete v2 health has no typed %s: %+v", key, health)
			}
		}
		if _, ok := health["source_observed_at"].(string); !ok {
			t.Fatalf("complete v2 health has no auth-files receipt: %+v", health)
		}
		if _, ok := record["observed_at"].(string); !ok {
			t.Fatalf("complete v2 sidecar health has no observed_at: %+v", record)
		}
	}
}

func fallbackTestStringSet(t *testing.T, value any) map[string]bool {
	t.Helper()
	result := make(map[string]bool)
	for _, raw := range producerTestArray(t, value) {
		key, ok := raw.(string)
		if !ok {
			t.Fatalf("limit_used_keys contains %T, want string", raw)
		}
		result[key] = true
	}
	return result
}

func TestFallbackLimitReachedFromFreshUsedPercentV1AndV2(t *testing.T) {
	for _, tc := range []struct {
		name      string
		seat      func(t *testing.T) map[string]any
		want      *bool
		wantBasis bool
		complete  bool
	}{
		{
			name: "fresh_primary_below_100_with_explicitly_absent_secondary",
			seat: func(t *testing.T) map[string]any {
				return producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
			},
			want: producerTestBoolPointer(false), wantBasis: true, complete: true,
		},
		{
			name: "both_required_windows_below_100",
			seat: func(t *testing.T) map[string]any {
				seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
				producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
				return seat
			},
			want: producerTestBoolPointer(false), wantBasis: true, complete: true,
		},
		{
			name: "ninety_nine_is_below_limit_fallback_even_if_native_quota_is_exhausted",
			seat: func(t *testing.T) map[string]any {
				return producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "99", false)
			},
			want: producerTestBoolPointer(false), wantBasis: true, complete: true,
		},
		{
			name: "hundred_is_true_with_unknown_required_sibling",
			seat: func(t *testing.T) map[string]any {
				seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "100", false)
				producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
				producerTestDeleteHeader(t, seat, "X-Codex-Secondary-Used-Percent")
				return seat
			},
			want: producerTestBoolPointer(true), wantBasis: true, complete: true,
		},
		{
			name: "over_hundred_is_true_with_unknown_required_sibling",
			seat: func(t *testing.T) map[string]any {
				seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "100.25", false)
				producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
				producerTestDeleteHeader(t, seat, "X-Codex-Secondary-Used-Percent")
				return seat
			},
			want: producerTestBoolPointer(true), wantBasis: true, complete: true,
		},
		{
			name: "secondary_at_100_is_true_even_when_primary_percent_is_unknown",
			seat: func(t *testing.T) map[string]any {
				seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
				producerTestDeleteHeader(t, seat, "X-Codex-Primary-Used-Percent")
				producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
				producerTestSetHeader(t, seat, "X-Codex-Secondary-Used-Percent", "100", "2026-11-06T12:00:30Z")
				return seat
			},
			want: producerTestBoolPointer(true), wantBasis: true, complete: true,
		},
		{
			name: "fresh_zero_duration_excludes_secondary_even_at_100",
			seat: func(t *testing.T) map[string]any {
				seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
				producerTestSetHeader(t, seat, "X-Codex-Secondary-Used-Percent", "100", "2026-11-06T12:00:30Z")
				return seat
			},
			want: producerTestBoolPointer(false), wantBasis: true, complete: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			row := producerTestAuthRow(producerTestAuthA)
			v1, v2 := fallbackTestAssertBoth(t, tc.seat(t), fallbackTestObservation(row, fallbackTestReceipt), tc.want, tc.wantBasis, tc.complete)
			if tc.name == "ninety_nine_is_below_limit_fallback_even_if_native_quota_is_exhausted" {
				artifact := producerTestDecodeObject(t, v1.raw)
				seat := producerTestObject(t, producerTestArray(t, artifact["seats"])[0])
				primary := producerTestWindow(t, producerTestObject(t, seat["quota"]), "primary")
				if producerTestString(t, primary, "state") != "exhausted" {
					t.Fatalf("99%% native window state changed while fallback is below 100: %+v", primary)
				}
			}
			if tc.name == "hundred_is_true_with_unknown_required_sibling" || tc.name == "over_hundred_is_true_with_unknown_required_sibling" {
				artifact := producerTestDecodeObject(t, v1.raw)
				seat := producerTestObject(t, producerTestArray(t, artifact["seats"])[0])
				if got := producerTestString(t, producerTestWindow(t, producerTestObject(t, seat["quota"]), "secondary"), "state"); got != "unknown" {
					t.Fatalf("fixture did not retain its unknown sibling counterexample: %q", got)
				}
				view := producerTestDecodeObject(t, v2.raw)
				seat = producerTestObject(t, producerTestArray(t, view["seats"])[0])
				if got := producerTestString(t, producerTestWindow(t, producerTestObject(t, seat["quota"]), "secondary"), "state"); got != "unknown" {
					t.Fatalf("v2 fixture did not retain its unknown sibling counterexample: %q", got)
				}
			}
		})
	}
}

func TestFallbackRequiresAtLeastOneRequiredWindow(t *testing.T) {
	t.Run("all_windows_explicitly_absent_is_not_vacuous_false", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
		producerTestSetHeader(t, seat, "X-Codex-Primary-Window-Minutes", "0", "2026-11-06T12:00:30Z")
		producerTestSetHeader(t, seat, "X-Codex-Secondary-Window-Minutes", "0", "2026-11-06T12:00:30Z")
		fallbackTestAssertBoth(t, seat,
			fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt), nil, false, false)
	})

	t.Run("missing_required_secondary_percent_is_unknown", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
		producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
		producerTestDeleteHeader(t, seat, "X-Codex-Secondary-Used-Percent")
		fallbackTestAssertBoth(t, seat,
			fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt), nil, false, false)
	})
}

func TestFallbackQuotaCooldownIsIndependentPositiveEvidence(t *testing.T) {
	for _, tc := range []struct {
		name          string
		scope         string
		reason        string
		complete      bool
		wantNoPercent bool
	}{
		{name: "credential_quota_reason", scope: "credential", reason: "credential_quota", complete: true, wantNoPercent: true},
		{name: "model_quota_reason", scope: "model", reason: "quota", complete: true, wantNoPercent: true},
		{name: "known_quota_reason_vetoes_even_unknown_scope", scope: "future-scope", reason: "quota", complete: false, wantNoPercent: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
			producerTestDeleteHeader(t, seat, "X-Codex-Primary-Used-Percent")
			authRow := producerTestAuthRow(producerTestAuthA)
			authRow["cooldowns"] = []any{fallbackTestCooldown(tc.scope, tc.reason)}
			v1, v2 := fallbackTestAssertBoth(t, seat, fallbackTestObservation(authRow, fallbackTestReceipt),
				producerTestBoolPointer(true), true, tc.complete)
			if tc.wantNoPercent {
				for _, item := range []struct {
					label  string
					output fallbackTestOutput
					v2     bool
				}{{"v1", v1, false}, {"v2", v2, true}} {
					var health map[string]any
					if item.v2 {
						health, _ = fallbackTestV2Health(t, item.output)
					} else {
						health = producerTestOptionalHealth(t, item.output.sidecar, producerTestAuthA)
					}
					if item.v2 {
						if keys, ok := health["limit_used_keys"]; ok {
							for key := range fallbackTestStringSet(t, keys) {
								if key == "X-Codex-Primary-Used-Percent" || key == "X-Codex-Secondary-Used-Percent" {
									t.Fatalf("cooldown-only TRUE fabricated a used-percent key in %s: %+v", item.label, health)
								}
							}
						}
					}
				}
			}
		})
	}
}

func TestFallbackKnownModelNonQuotaCooldownStillAllowsBelow100False(t *testing.T) {
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
	authRow := producerTestAuthRow(producerTestAuthA)
	authRow["cooldowns"] = []any{fallbackTestCooldown("model", "model_not_supported")}
	fallbackTestAssertBoth(t, seat, fallbackTestObservation(authRow, fallbackTestReceipt), producerTestBoolPointer(false), true, true)
}

func TestFallbackUnknownAuthOrCooldownEvidenceNeverBecomesFalse(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(observation map[string]any, row map[string]any)
	}{
		{name: "missing_auth_row", mutate: func(observation map[string]any, _ map[string]any) { observation["files"] = []any{} }},
		{name: "duplicate_auth_identity", mutate: func(observation map[string]any, row map[string]any) {
			observation["files"] = append(producerTestArrayNoT(observation["files"]), row)
		}},
		{name: "cross_gateway_receipt", mutate: func(observation map[string]any, _ map[string]any) { observation["gateway_id"] = "other-gateway" }},
		{name: "missing_receipt", mutate: func(observation map[string]any, _ map[string]any) { delete(observation, "observed_at") }},
		{name: "null_receipt", mutate: func(observation map[string]any, _ map[string]any) { observation["observed_at"] = nil }},
		{name: "malformed_receipt", mutate: func(observation map[string]any, _ map[string]any) { observation["observed_at"] = "not-a-timestamp" }},
		{name: "stale_receipt", mutate: func(observation map[string]any, _ map[string]any) {
			observation["observed_at"] = "2026-11-06T11:55:59Z"
		}},
		{name: "future_receipt", mutate: func(observation map[string]any, _ map[string]any) {
			observation["observed_at"] = "2026-11-06T12:01:00.000000001Z"
		}},
		{name: "malformed_files_value", mutate: func(observation map[string]any, _ map[string]any) {
			observation["files"] = map[string]any{"wrong": "shape"}
		}},
		{name: "wrong_provider", mutate: func(_ map[string]any, row map[string]any) { row["provider"] = "claude" }},
		{name: "missing_status", mutate: func(_ map[string]any, row map[string]any) { delete(row, "status") }},
		{name: "null_status", mutate: func(_ map[string]any, row map[string]any) { row["status"] = nil }},
		{name: "wrong_typed_status", mutate: func(_ map[string]any, row map[string]any) { row["status"] = true }},
		{name: "inactive_status", mutate: func(_ map[string]any, row map[string]any) { row["status"] = "refreshing" }},
		{name: "missing_disabled", mutate: func(_ map[string]any, row map[string]any) { delete(row, "disabled") }},
		{name: "null_disabled", mutate: func(_ map[string]any, row map[string]any) { row["disabled"] = nil }},
		{name: "wrong_typed_disabled", mutate: func(_ map[string]any, row map[string]any) { row["disabled"] = "false" }},
		{name: "disabled", mutate: func(_ map[string]any, row map[string]any) { row["disabled"] = true }},
		{name: "missing_unavailable", mutate: func(_ map[string]any, row map[string]any) { delete(row, "unavailable") }},
		{name: "null_unavailable", mutate: func(_ map[string]any, row map[string]any) { row["unavailable"] = nil }},
		{name: "wrong_typed_unavailable", mutate: func(_ map[string]any, row map[string]any) { row["unavailable"] = 0 }},
		{name: "unavailable", mutate: func(_ map[string]any, row map[string]any) { row["unavailable"] = true }},
		{name: "missing_cooldown_list", mutate: func(_ map[string]any, row map[string]any) { delete(row, "cooldowns") }},
		{name: "null_cooldown_list", mutate: func(_ map[string]any, row map[string]any) { row["cooldowns"] = nil }},
		{name: "malformed_cooldown_list", mutate: func(_ map[string]any, row map[string]any) { row["cooldowns"] = "not-an-array" }},
		{name: "malformed_cooldown_entry", mutate: func(_ map[string]any, row map[string]any) { row["cooldowns"] = []any{"not-an-object"} }},
		{name: "unknown_cooldown_scope", mutate: func(_ map[string]any, row map[string]any) {
			row["cooldowns"] = []any{fallbackTestCooldown("future-scope", "model_not_supported")}
		}},
		{name: "unknown_model_cooldown_reason", mutate: func(_ map[string]any, row map[string]any) {
			row["cooldowns"] = []any{fallbackTestCooldown("model", "future-reason")}
		}},
		{name: "missing_model_cooldown_reason", mutate: func(_ map[string]any, row map[string]any) {
			row["cooldowns"] = []any{map[string]any{"scope": "model", "model_key": "gpt-6-luna"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
			row := producerTestAuthRow(producerTestAuthA)
			observation := fallbackTestObservation(row, fallbackTestReceipt)
			tc.mutate(observation, row)
			fallbackTestAssertBoth(t, seat, observation, nil, false, false)
		})
	}
}

func TestFallbackFreshnessIsInclusiveAt300SecondsForEachClock(t *testing.T) {
	for _, source := range []string{"auth_receipt", "used_percent", "window_membership"} {
		for _, tc := range []struct {
			name string
			age  time.Duration
			want *bool
		}{
			{name: "exactly_300_seconds", age: 300 * time.Second, want: producerTestBoolPointer(false)},
			{name: "300_seconds_plus_one_nanosecond", age: 300*time.Second + time.Nanosecond},
		} {
			t.Run(source+"/"+tc.name, func(t *testing.T) {
				at := func(age time.Duration) string {
					eval, err := time.Parse(time.RFC3339Nano, fallbackTestEvaluation)
					if err != nil {
						t.Fatal(err)
					}
					return eval.Add(-age).Format(time.RFC3339Nano)
				}
				seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
				readAt := fallbackTestReceipt
				switch source {
				case "auth_receipt":
					readAt = at(tc.age)
				case "used_percent":
					fallbackTestSetAcquisition(seat, "X-Codex-Primary-Used-Percent", at(tc.age))
				case "window_membership":
					fallbackTestSetAcquisition(seat, "X-Codex-Secondary-Window-Minutes", at(tc.age))
				}
				fallbackTestAssertBoth(t, seat,
					fallbackTestObservation(producerTestAuthRow(producerTestAuthA), readAt), tc.want, tc.want != nil, tc.want != nil)
			})
		}
	}
}

func TestFallbackMissingMalformedAndUnfreshPercentOrMembershipStaysUnknown(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, seat map[string]any)
	}{
		{name: "missing_primary_percent", mutate: func(t *testing.T, seat map[string]any) {
			producerTestDeleteHeader(t, seat, "X-Codex-Primary-Used-Percent")
		}},
		{name: "negative_percent", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "-1", "2026-11-06T12:00:30Z")
		}},
		{name: "nan_percent", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "NaN", "2026-11-06T12:00:30Z")
		}},
		{name: "infinity_percent", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "Infinity", "2026-11-06T12:00:30Z")
		}},
		{name: "inf_percent", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "Inf", "2026-11-06T12:00:30Z")
		}},
		{name: "exponent_percent", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "1e2", "2026-11-06T12:00:30Z")
		}},
		{name: "percent_suffix_is_not_decimal", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "20%", "2026-11-06T12:00:30Z")
		}},
		{name: "missing_used_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Primary-Used-Percent", "")
		}},
		{name: "malformed_used_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Primary-Used-Percent", "not-a-timestamp")
		}},
		{name: "future_used_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Primary-Used-Percent", "2026-11-06T12:01:00.000000001Z")
		}},
		{name: "stale_used_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Primary-Used-Percent", "2026-11-06T11:55:59.999999999Z")
		}},
		{name: "missing_secondary_membership", mutate: func(t *testing.T, seat map[string]any) {
			producerTestDeleteHeader(t, seat, "X-Codex-Secondary-Window-Minutes")
		}},
		{name: "null_secondary_membership", mutate: func(_ *testing.T, seat map[string]any) {
			producerTestMap(seat, "headers")["X-Codex-Secondary-Window-Minutes"] = nil
		}},
		{name: "malformed_secondary_membership", mutate: func(t *testing.T, seat map[string]any) {
			producerTestSetHeader(t, seat, "X-Codex-Secondary-Window-Minutes", "not-a-duration", "2026-11-06T12:00:30Z")
		}},
		{name: "missing_membership_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Secondary-Window-Minutes", "")
		}},
		{name: "malformed_membership_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Secondary-Window-Minutes", "not-a-timestamp")
		}},
		{name: "future_membership_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Secondary-Window-Minutes", "2026-11-06T12:01:00.000000001Z")
		}},
		{name: "stale_membership_acquisition", mutate: func(_ *testing.T, seat map[string]any) {
			fallbackTestSetAcquisition(seat, "X-Codex-Secondary-Window-Minutes", "2026-11-06T11:55:59.999999999Z")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
			tc.mutate(t, seat)
			fallbackTestAssertBoth(t, seat,
				fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt), nil, false, false)
		})
	}
}

// Keep reason: CPA193's aggregate-only regression crossed the native collector /
// producer-health boundary on both CLI paths; explicit presence is not absence.
func TestFallbackAggregateFlagsArePresentNotWindowAttributionV1AndV2(t *testing.T) {
	const acquiredAt = "2026-11-06T12:00:30Z"
	for _, tc := range []struct {
		name   string
		flags  map[string][]string
		flagAt string
		want   *bool
	}{
		{name: "true_absence_still_allows_fresh_safe_fallback_false", want: producerTestBoolPointer(false)},
		{name: "fresh_aggregate_only", flags: map[string][]string{"X-Codex-Allowed": {"true"}, "X-Codex-Limit-Reached": {"false"}}, flagAt: acquiredAt},
		{name: "allowed_alone_is_present", flags: map[string][]string{"X-Codex-Allowed": {"true"}}, flagAt: acquiredAt},
		{name: "limit_reached_alone_is_present", flags: map[string][]string{"X-Codex-Limit-Reached": {"false"}}, flagAt: acquiredAt},
		{name: "aggregate_rejection_is_not_window_attribution", flags: map[string][]string{"X-Codex-Allowed": {"false"}, "X-Codex-Limit-Reached": {"true"}}, flagAt: acquiredAt},
		{name: "malformed_aggregate_value_is_present", flags: map[string][]string{"X-Codex-Allowed": {"maybe"}}, flagAt: acquiredAt},
		{name: "collector_dropped_empty_value_is_present", flags: map[string][]string{"X-Codex-Limit-Reached": {""}}, flagAt: acquiredAt},
		{name: "empty_aggregate_array_is_present", flags: map[string][]string{"X-Codex-Allowed": {}}, flagAt: acquiredAt},
		{name: "stale_aggregate_only_is_present", flags: map[string][]string{"X-Codex-Allowed": {"true"}}, flagAt: "2026-11-06T11:55:59Z"},
		{name: "unclocked_aggregate_only_is_present", flags: map[string][]string{"X-Codex-Allowed": {"true"}}},
		{name: "malformed_aggregate_clock_is_present", flags: map[string][]string{"X-Codex-Limit-Reached": {"false"}}, flagAt: "not-a-timestamp"},
		{name: "future_aggregate_only_is_present", flags: map[string][]string{"X-Codex-Limit-Reached": {"false"}}, flagAt: "2026-11-06T12:01:00.000000001Z"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, acquiredAt, "20", false)
			for key, values := range tc.flags {
				producerTestMap(seat, "headers")[key] = values
				fallbackTestSetAcquisition(seat, key, tc.flagAt)
			}
			v1, v2 := fallbackTestAssertBoth(t, seat,
				fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt), tc.want, tc.want != nil, tc.want != nil)
			if v1.err != nil || v2.err != nil {
				t.Fatalf("aggregate-presence fixture must produce artifacts: v1=%v v2=%v", v1.err, v2.err)
			}
			if tc.want != nil {
				return
			}
			health, _ := fallbackTestV2Health(t, v2)
			if health["status"] != "partial" {
				t.Fatalf("aggregate-only evidence completed v2 health: %+v", health)
			}
			if len(fallbackTestStringSet(t, health["limit_used_keys"])) != 0 || len(producerTestObject(t, health["limit_acquired_at"])) != 0 {
				t.Fatalf("aggregate-only evidence gained window attribution: %+v", health)
			}
		})
	}
}

func TestFallbackAggregatePresencePreservesIndependentVetoesAndExplicitWindows(t *testing.T) {
	const acquiredAt = "2026-11-06T12:00:30Z"
	for _, tc := range []struct {
		name      string
		mutate    func(t *testing.T, seat, authRow map[string]any)
		want      *bool
		wantBasis bool
		complete  bool
	}{
		{
			name: "fresh_100_percent_veto_despite_inactive_auth",
			mutate: func(t *testing.T, seat, authRow map[string]any) {
				producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "100", acquiredAt)
				authRow["disabled"] = true
			},
			want: producerTestBoolPointer(true), wantBasis: true, complete: true,
		},
		{
			name: "fresh_over_100_percent_veto_despite_unknown_cooldowns",
			mutate: func(t *testing.T, seat, authRow map[string]any) {
				producerTestSetHeader(t, seat, "X-Codex-Primary-Used-Percent", "100.25", acquiredAt)
				authRow["cooldowns"] = nil
			},
			want: producerTestBoolPointer(true), wantBasis: true,
		},
		{
			name: "fresh_quota_cooldown_veto_without_percent",
			mutate: func(t *testing.T, seat, authRow map[string]any) {
				producerTestDeleteHeader(t, seat, "X-Codex-Primary-Used-Percent")
				authRow["cooldowns"] = []any{fallbackTestCooldown("model", "quota")}
			},
			want: producerTestBoolPointer(true), wantBasis: true, complete: true,
		},
		{
			name: "explicit_per_window_healthy_preserves_old_shape",
			mutate: func(t *testing.T, seat, _ map[string]any) {
				producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", "true", acquiredAt)
				producerTestSetHeader(t, seat, "X-Codex-Primary-Limit-Reached", "false", acquiredAt)
			},
			want: producerTestBoolPointer(false), complete: true,
		},
		{
			name: "explicit_per_window_rejection_preserves_precedence",
			mutate: func(t *testing.T, seat, _ map[string]any) {
				producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", "false", acquiredAt)
			},
			want: producerTestBoolPointer(true), complete: true,
		},
		{
			name: "aggregate_blocks_missing_sibling_fallback_not_explicit_primary",
			mutate: func(t *testing.T, seat, _ map[string]any) {
				producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", "true", acquiredAt)
				producerTestAddSecondary(t, seat, acquiredAt, "", "")
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, acquiredAt, "20", false)
			producerTestSetHeader(t, seat, "X-Codex-Allowed", "true", "2026-11-06T12:00:40Z")
			producerTestSetHeader(t, seat, "X-Codex-Limit-Reached", "false", "2026-11-06T12:00:40Z")
			authRow := producerTestAuthRow(producerTestAuthA)
			tc.mutate(t, seat, authRow)
			v1, v2 := fallbackTestAssertBoth(t, seat, fallbackTestObservation(authRow, fallbackTestReceipt), tc.want, tc.wantBasis, tc.complete)
			if v1.err != nil || v2.err != nil {
				t.Fatalf("aggregate precedence fixture must produce artifacts: v1=%v v2=%v", v1.err, v2.err)
			}
			health, record := fallbackTestV2Health(t, v2)
			keys := fallbackTestStringSet(t, health["limit_used_keys"])
			if keys["X-Codex-Allowed"] || keys["X-Codex-Limit-Reached"] {
				t.Fatalf("aggregate flags were attributed to required windows: %+v", health)
			}
			if tc.want != nil {
				wantAt := acquiredAt
				if tc.name == "fresh_quota_cooldown_veto_without_percent" {
					wantAt = fallbackTestReceipt
				}
				for _, item := range []map[string]any{producerTestOptionalHealth(t, v1.sidecar, producerTestAuthA), record} {
					if got := producerTestString(t, item, "observed_at"); got != wantAt {
						t.Fatalf("aggregate acquisition replaced original decision clock: got %s want %s", got, wantAt)
					}
				}
			}
		})
	}
}

func TestFallbackMixedExplicitAndPercentWindowsRespectPrecedence(t *testing.T) {
	t.Run("explicit_primary_and_fallback_secondary_below_100_is_false", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
		fallbackTestAssertBoth(t, seat, fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt),
			producerTestBoolPointer(false), true, true)
	})

	t.Run("explicit_primary_rejection_vetoes_below_100_fallback", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", "false", "2026-11-06T12:00:30Z")
		producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
		fallbackTestAssertBoth(t, seat, fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt),
			producerTestBoolPointer(true), false, true)
	})

	t.Run("fallback_exhaustion_vetoes_explicit_primary_below_100", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
		producerTestSetHeader(t, seat, "X-Codex-Secondary-Used-Percent", "100", "2026-11-06T12:00:30Z")
		fallbackTestAssertBoth(t, seat, fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt),
			producerTestBoolPointer(true), true, true)
	})

	for _, tc := range []struct {
		name       string
		value      string
		acquiredAt string
	}{
		{name: "malformed_present_allowed_flag", value: "maybe", acquiredAt: "2026-11-06T12:00:30Z"},
		{name: "stale_present_allowed_flag", value: "true", acquiredAt: "2026-11-06T11:55:59.999999999Z"},
		{name: "unclocked_present_allowed_flag", value: "true", acquiredAt: ""},
	} {
		t.Run(tc.name+"_cannot_fall_back", func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
			producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", tc.value, tc.acquiredAt)
			fallbackTestAssertBoth(t, seat, fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt), nil, false, false)
		})
	}
}

func TestFallbackExplicitOnlyPreservesWireShapeAndPositivePrecedence(t *testing.T) {
	for _, tc := range []struct {
		name  string
		allow string
		limit string
		want  bool
	}{
		{name: "explicit_healthy", allow: "true", limit: "false", want: false},
		{name: "allowed_false_is_explicit_rejection", allow: "false", limit: "false", want: true},
		{name: "limit_reached_true_is_explicit_rejection", allow: "true", limit: "true", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
			producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", tc.allow, "2026-11-06T12:00:30Z")
			producerTestSetHeader(t, seat, "X-Codex-Primary-Limit-Reached", tc.limit, "2026-11-06T12:00:30Z")
			fallbackTestAssertBoth(t, seat,
				fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt),
				producerTestBoolPointer(tc.want), false, true)
		})
	}
}

func TestFallbackV2RecordsUsedKeysOriginalClocksAndOldestEvidence(t *testing.T) {
	const (
		primaryAt   = "2026-11-06T13:00:00.123456789+01:00"
		secondaryAt = "2026-11-06T07:00:10.123456789-05:00"
		receiptAt   = "2026-11-06T12:00:45.987654321Z"
	)
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, primaryAt, "20", false)
	producerTestAddSecondary(t, seat, secondaryAt, "", "")
	observation := fallbackTestObservation(producerTestAuthRow(producerTestAuthA), receiptAt)
	v1, v2 := fallbackTestAssertBoth(t, seat, observation, producerTestBoolPointer(false), true, true)

	v1Record := producerTestOptionalHealth(t, v1.sidecar, producerTestAuthA)
	v1Observed, err := time.Parse(time.RFC3339Nano, producerTestString(t, v1Record, "observed_at"))
	if err != nil {
		t.Fatal(err)
	}
	primaryTime, err := time.Parse(time.RFC3339Nano, primaryAt)
	if err != nil || !v1Observed.Equal(primaryTime) {
		t.Fatalf("v1 health time %s was not the oldest used-percentage acquisition %s", v1Observed, primaryAt)
	}

	view := producerTestDecodeObject(t, v2.raw)
	signals := producerTestObject(t, producerTestObject(t, view["signals"])[producerTestAuthA])
	health := producerTestObject(t, signals["health"])
	keys := fallbackTestStringSet(t, health["limit_used_keys"])
	for _, key := range []string{"X-Codex-Primary-Used-Percent", "X-Codex-Secondary-Used-Percent"} {
		if !keys[key] {
			t.Fatalf("v2 fallback omitted used-percent evidence key %q: %+v", key, health)
		}
	}
	if len(keys) != 2 {
		t.Fatalf("v2 fallback recorded keys that did not contribute to this decision: %+v", health)
	}
	acquired := producerTestObject(t, health["limit_acquired_at"])
	if producerTestString(t, acquired, "X-Codex-Primary-Used-Percent") != primaryAt ||
		producerTestString(t, acquired, "X-Codex-Secondary-Used-Percent") != secondaryAt || len(acquired) != 2 {
		t.Fatalf("v2 fallback rewrote or added non-contributing acquisition strings: %+v", acquired)
	}
	record := producerTestOptionalHealth(t, v2.sidecar, producerTestAuthA)
	observed, err := time.Parse(time.RFC3339Nano, producerTestString(t, record, "observed_at"))
	if err != nil || !observed.Equal(primaryTime) || observed.Equal(mustFallbackTestTime(t, receiptAt)) {
		t.Fatalf("v2 health clock was promoted to auth receipt instead of oldest used evidence: %+v", record)
	}
}

func TestFallbackV2RecordsFreshAbsentWindowMembership(t *testing.T) {
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
	output := fallbackTestRunV2(t, seat, fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt))
	fallbackTestAssertV2(t, output, producerTestBoolPointer(false), true, true)

	view := producerTestDecodeObject(t, output.raw)
	signals := producerTestObject(t, producerTestObject(t, view["signals"])[producerTestAuthA])
	health := producerTestObject(t, signals["health"])
	keys := fallbackTestStringSet(t, health["limit_used_keys"])
	if len(keys) != 2 || !keys["X-Codex-Primary-Used-Percent"] || !keys["X-Codex-Secondary-Window-Minutes"] {
		t.Fatalf("v2 fallback did not record exactly its used-percent and absence-membership keys: %+v", health)
	}
	acquired := producerTestObject(t, health["limit_acquired_at"])
	if len(acquired) != 2 ||
		producerTestString(t, acquired, "X-Codex-Primary-Used-Percent") != "2026-11-06T12:00:30Z" ||
		producerTestString(t, acquired, "X-Codex-Secondary-Window-Minutes") != "2026-11-06T12:00:30Z" {
		t.Fatalf("v2 fallback did not preserve original membership acquisition: %+v", acquired)
	}
}

func mustFallbackTestTime(t *testing.T, raw string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

func TestFallbackCaptureAndRequestClocksDoNotFreshenOldUsedPercent(t *testing.T) {
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T11:55:59.999999999Z", "20", false)
	seat["timestamp"], seat["timestamp_ms"], seat["created_at_ms"] = fallbackTestEvaluation, int64(1793966460000), int64(1793966460000)
	capture := producerTestCapture(seat)
	capture["captured_at"] = fallbackTestEvaluation
	observation := fallbackTestObservation(producerTestAuthRow(producerTestAuthA), fallbackTestReceipt)
	files := producerTestWriteScenarioWithObservation(t, capture,
		[]map[string]any{producerTestRoute("fallback-route", producerTestAuthA, "gpt-6-luna", "low")}, observation)
	v1Raw, err := producerTestRun(t, files, fallbackTestEvaluation)
	if err != nil {
		t.Fatalf("v1 stale-clock fixture rejected: %v", err)
	}
	v1Record := producerTestOptionalHealth(t, producerTestDecodeFileObject(t, files.sidecarPath), producerTestAuthA)
	if v1Record != nil {
		if _, ok := v1Record["limit_reached"].(bool); ok {
			t.Fatalf("capture/evaluation/request clocks freshened old used-percent: %+v", v1Record)
		}
	}
	if len(v1Raw) == 0 {
		t.Fatal("v1 stale-clock fixture emitted no artifact")
	}
	v2 := fallbackTestRunV2(t, seat, observation)
	fallbackTestAssertV2(t, v2, nil, false, false)
}

func TestFallbackCheckpointNeedsNewQuotaAfterStaleOrUncertainPack(t *testing.T) {
	for _, scenario := range []string{"stale_used_percent", "failed_health_and_missing_used_clock"} {
		t.Run(scenario, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			positiveSeat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
			positive := chain.step(t, []map[string]any{incrementalTestConvertRow(t, positiveSeat)}, "2026-11-06T12:00:40Z")
			incrementalTestAssertStatus(t, positive, "selected", "selected")
			fallbackTestAssertV2Output(t, positive.raw, positive.sidecar, producerTestBoolPointer(false), true, true)

			uncertainSeat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 2, "2026-11-06T12:00:41Z", "20", false)
			readAt := "2026-11-06T12:00:45Z"
			if scenario == "stale_used_percent" {
				fallbackTestSetAcquisition(uncertainSeat, "X-Codex-Primary-Used-Percent", "2026-11-06T11:55:59Z")
			} else {
				fallbackTestSetAcquisition(uncertainSeat, "X-Codex-Primary-Used-Percent", "")
				readAt = ""
			}
			uncertain := chain.step(t, []map[string]any{incrementalTestConvertRow(t, uncertainSeat)}, readAt)
			incrementalTestAssertStatus(t, uncertain, "uncertain", "uncertain")
			fallbackTestAssertV2Output(t, uncertain.raw, uncertain.sidecar, nil, false, false)

			// A later successful auth-files read alone cannot revive the checkpoint's
			// uncertain quota pack or use the retained positive row as new evidence.
			healthOnly := chain.step(t, nil, "2026-11-06T12:00:50Z")
			incrementalTestAssertStatus(t, healthOnly, "uncertain", "uncertain")
			fallbackTestAssertV2Output(t, healthOnly.raw, healthOnly.sidecar, nil, false, false)

			freshSeat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 3, "2026-11-06T12:00:51Z", "20", false)
			recovered := chain.step(t, []map[string]any{incrementalTestConvertRow(t, freshSeat)}, "2026-11-06T12:00:55Z")
			incrementalTestAssertStatus(t, recovered, "selected", "selected")
			fallbackTestAssertV2Output(t, recovered.raw, recovered.sidecar, producerTestBoolPointer(false), true, true)
		})
	}
}

func fallbackTestAssertV2Output(t *testing.T, raw []byte, sidecar map[string]any, want *bool, wantBasis, requireComplete bool) {
	t.Helper()
	fallbackTestAssertV2(t, fallbackTestOutput{raw: raw, sidecar: sidecar}, want, wantBasis, requireComplete)
}
