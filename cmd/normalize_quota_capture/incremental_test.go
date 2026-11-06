package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// All incremental fixtures below are synthetic/replay. Keep reason: acquisition
// trust boundary and data safety across the real CLI disk/checkpoint/restart
// seam, including failure paths that cannot be proved by a parser-only test.
type incrementalTestChain struct {
	dir        string
	roster     string
	checkpoint string
	cursor     int64
	tick       int
}

type incrementalTestInvocation struct {
	args       []string
	checkpoint string
	sidecar    string
	artifact   string
	inputs     []producerTestSnapshot
	through    int64
}

type incrementalTestResult struct {
	view       incrementalView
	checkpoint quotaCheckpoint
	sidecar    map[string]any
	raw        []byte
	stateRaw   []byte
}

func newIncrementalTestChain(t *testing.T, routes ...map[string]any) *incrementalTestChain {
	t.Helper()
	if len(routes) == 0 {
		routes = []map[string]any{producerTestRoute("exact-route-a", producerTestAuthA, "gpt-6-luna", "low")}
	}
	chain := &incrementalTestChain{dir: t.TempDir()}
	chain.roster = filepath.Join(chain.dir, "roster.json")
	incrementalTestWrite(t, chain.roster, map[string]any{"routes": producerTestAnyMaps(routes)})
	return chain
}

func incrementalTestWrite(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if errWrite := os.WriteFile(path, raw, 0600); errWrite != nil {
		t.Fatal(errWrite)
	}
}

func incrementalTestRow(t *testing.T, id int64, acquired, used string) map[string]any {
	t.Helper()
	return incrementalTestConvertRow(t, producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", id, acquired, used, true))
}

func incrementalTestConvertRow(t *testing.T, seat map[string]any) map[string]any {
	t.Helper()
	row := make(map[string]any)
	for _, key := range []string{"id", "provider", "auth_index", "model", "reasoning_effort", "timestamp", "timestamp_ms", "created_at_ms"} {
		if value, exists := seat[key]; exists {
			row[key] = value
		}
	}
	for _, pair := range [][2]string{{"headers", "quota_json"}, {"response_headers_observed_at", "quota_observed_at_json"}} {
		value, exists := seat[pair[0]]
		if !exists || value == nil {
			row[pair[1]] = nil
			continue
		}
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		row[pair[1]] = string(raw)
	}
	return row
}

func (chain *incrementalTestChain) prepare(t *testing.T, rows []map[string]any, receipt string, through int64, caughtUp bool) incrementalTestInvocation {
	t.Helper()
	chain.tick++
	dir := filepath.Join(chain.dir, fmt.Sprintf("generation-%03d", chain.tick))
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	input, health := filepath.Join(dir, "delta.json"), filepath.Join(dir, "auth.json")
	captured := "2026-11-06T12:00:10Z"
	if at, errParse := time.Parse(time.RFC3339Nano, receipt); errParse == nil {
		captured = at.Add(-time.Nanosecond).UTC().Format(time.RFC3339Nano)
	}
	delta := map[string]any{
		"schema_version": deltaSchema, "gateway_id": producerGateway,
		"captured_at": captured, "after_id": strconv.FormatInt(chain.cursor, 10),
		"through_id": strconv.FormatInt(through, 10), "caught_up": caughtUp, "rows": producerTestAnyMaps(rows),
	}
	incrementalTestWrite(t, input, delta)
	observation := producerTestAuthObservation([]map[string]any{producerTestAuthRow(producerTestAuthA), producerTestAuthRow(producerTestAuthB)}, receipt)
	if receipt == "" {
		observation = map[string]any{"gateway_id": producerGateway, "files": []any{}}
	}
	incrementalTestWrite(t, health, observation)
	invocation := incrementalTestInvocation{
		checkpoint: filepath.Join(dir, "next.json"), sidecar: filepath.Join(dir, "section-2.provenance.json"),
		artifact: filepath.Join(dir, "section-2.json"), through: through,
	}
	invocation.args = []string{
		"--input", input, "--source-version", testSourceVersion, "--roster", chain.roster,
		"--auth-files-observation", health, "--checkpoint-out", invocation.checkpoint,
		"--provenance-output", invocation.sidecar, "--artifact-file", "section-2.json",
		"--evaluation-time", "2026-11-06T12:01:00Z",
	}
	paths := []string{input, chain.roster, health}
	if chain.checkpoint != "" {
		invocation.args = append(invocation.args, "--checkpoint-in", chain.checkpoint)
		paths = append(paths, chain.checkpoint)
	}
	for _, path := range paths {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		invocation.inputs = append(invocation.inputs, producerTestSnapshot{path, raw, info.ModTime()})
	}
	return invocation
}

func (chain *incrementalTestChain) execute(t *testing.T, invocation incrementalTestInvocation) incrementalTestResult {
	t.Helper()
	stdout, err := os.Create(invocation.artifact)
	if err != nil {
		t.Fatal(err)
	}
	errRun := run(invocation.args, stdout)
	errClose := stdout.Close()
	if errRun != nil || errClose != nil {
		t.Fatalf("synthetic incremental CLI run=%v close=%v", errRun, errClose)
	}
	producerTestAssertInputsUnchanged(t, invocation.inputs)
	var result incrementalTestResult
	result.raw, err = os.ReadFile(invocation.artifact)
	if err != nil {
		t.Fatal(err)
	}
	result.stateRaw, err = os.ReadFile(invocation.checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(result.raw, &result.view); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(result.stateRaw, &result.checkpoint); err != nil {
		t.Fatal(err)
	}
	result.sidecar = producerTestDecodeFileObject(t, invocation.sidecar)
	if result.view.NextCheckpointSHA256 != producerTestSHA256(result.stateRaw) || producerTestString(t, result.sidecar, "artifact_sha256") != producerTestSHA256(result.raw) {
		t.Fatal("exact checkpoint/stdout bytes (including newline) were not bound")
	}
	if !bytes.HasSuffix(result.raw, []byte("\n")) || !bytes.HasSuffix(result.stateRaw, []byte("\n")) {
		t.Fatal("staging generation lost final newline")
	}
	if chain.checkpoint == "" {
		if result.view.PriorCheckpointSHA256 != nil {
			t.Fatal("bootstrap fabricated a prior checkpoint")
		}
	} else {
		raw, err := os.ReadFile(chain.checkpoint)
		if err != nil || result.view.PriorCheckpointSHA256 == nil || *result.view.PriorCheckpointSHA256 != producerTestSHA256(raw) {
			t.Fatal("restart did not bind exact immutable checkpoint-IN bytes")
		}
	}
	id := result.view.CapacitySnapshotID
	result.view.CapacitySnapshotID = ""
	preimage, err := json.Marshal(result.view)
	if err != nil || id != "sha256:"+producerTestSHA256(preimage) {
		t.Fatal("v2 content ID did not bind the entire normalized envelope")
	}
	result.view.CapacitySnapshotID = id
	chain.checkpoint, chain.cursor = invocation.checkpoint, invocation.through
	return result
}

func (chain *incrementalTestChain) step(t *testing.T, rows []map[string]any, receipt string) incrementalTestResult {
	t.Helper()
	through := chain.cursor
	if len(rows) > 0 {
		through = rows[len(rows)-1]["id"].(int64)
	}
	return chain.execute(t, chain.prepare(t, rows, receipt, through, true))
}

func incrementalTestAssertStatus(t *testing.T, result incrementalTestResult, evidence, effective string) {
	t.Helper()
	if len(result.view.AuthStatuses) != 1 {
		t.Fatalf("unexpected configured coverage: %+v", result.view.AuthStatuses)
	}
	status := result.view.AuthStatuses[0]
	if status.EvidenceStatus != evidence || status.EffectiveStatus != effective {
		t.Fatalf("status=%+v, want %s/%s", status, evidence, effective)
	}
	if effective != "selected" {
		if status.ObservedAt != nil || result.view.AsOf != nil {
			t.Fatal("unknown/catching-up evidence acquired an authoritative publication clock")
		}
		for _, seat := range result.view.Seats {
			if seat.Quota.State != "unknown" || len(seat.Quota.Windows) != 0 {
				t.Fatal("hidden retained positive became current capacity")
			}
		}
		if len(producerTestOptionalObject(result.sidecar["route_projection"])) != 0 {
			t.Fatal("unknown evidence gained a positive route projection")
		}
	}
}

func incrementalTestPrimary(t *testing.T, result incrementalTestResult) string {
	t.Helper()
	if len(result.view.Seats) != 1 {
		t.Fatalf("want one observed seat: %+v", result.view)
	}
	return findWindow(t, result.view.Seats[0].normalizedSeat, "primary").State
}

func TestIncrementalSyntheticRestartNewerDepletedMalformedNeverFallsBack(t *testing.T) {
	for _, used := range []string{"99", "not-a-number"} {
		t.Run(used, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			positive := chain.step(t, []map[string]any{incrementalTestRow(t, 100, "2026-11-06T12:00:00.000000001Z", "12")}, "2026-11-06T12:00:10Z")
			if incrementalTestPrimary(t, positive) != "known" {
				t.Fatal("synthetic positive was not known")
			}
			newer := chain.step(t, []map[string]any{incrementalTestRow(t, 101, "2026-11-06T12:00:00.000000002Z", used)}, "2026-11-06T12:00:20Z")
			late := chain.step(t, []map[string]any{incrementalTestRow(t, 9000000000000000000, "2026-11-06T12:00:00.000000001Z", "2")}, "2026-11-06T12:00:30Z")
			want := "exhausted"
			if used == "not-a-number" {
				want = "unknown"
			}
			if incrementalTestPrimary(t, newer) != want || incrementalTestPrimary(t, late) != want || late.checkpoint.Auths[0].Anchor.ID != 101 {
				t.Fatal("a larger insertion ID resurrected an older positive")
			}
			if late.view.ThroughID != "9000000000000000000" {
				t.Fatal("cursor lost BIGINT precision")
			}
		})
	}
}

func TestIncrementalSyntheticEqualAcquisitionUsesIDAtNanosecondPrecision(t *testing.T) {
	chain := newIncrementalTestChain(t)
	chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00.123456789Z", "12")}, "2026-11-06T12:00:10Z")
	second := chain.step(t, []map[string]any{incrementalTestRow(t, 2, "2026-11-06T12:00:00.123456789Z", "99")}, "2026-11-06T12:00:20Z")
	if second.checkpoint.Auths[0].Anchor.ID != 2 || incrementalTestPrimary(t, second) != "exhausted" {
		t.Fatal("equal acquisition did not use native ID tie-break")
	}
}

func TestIncrementalSyntheticF1NoObservationDoesNotInvalidateRefreshOrRecover(t *testing.T) {
	for _, quota := range []any{nil, "null", "{}", `{"X-Oai-Request-Id":["transport-only"],"X-Codex-Turn-State":["idle"],"Anthropic-Ratelimit-Unified-Status":["allowed"]}`} {
		t.Run(fmt.Sprint(quota), func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			row := incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")
			row["quota_json"], row["quota_observed_at_json"] = quota, nil
			cold := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:10Z")
			incrementalTestAssertStatus(t, cold, "unobserved", "unobserved")
			if cold.view.ObservedSeats != 0 || len(cold.view.Seats) != 0 || cold.checkpoint.Auths[0].Anchor != nil || cold.checkpoint.Auths[0].RecoveryAfter != nil {
				t.Fatal("no-quota usage row fabricated an observed seat/bound")
			}
			positive := chain.step(t, []map[string]any{incrementalTestRow(t, 2, "2026-11-06T12:00:15Z", "12")}, "2026-11-06T12:00:20Z")
			row["id"] = int64(3)
			noQuota := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:30Z")
			if !reflect.DeepEqual(positive.checkpoint.Auths[0], noQuota.checkpoint.Auths[0]) || incrementalTestPrimary(t, noQuota) != "known" {
				t.Fatal("F1 no-observation changed retained quota state")
			}
			unknown := incrementalTestRow(t, 4, "", "20")
			unknown["quota_observed_at_json"] = nil
			u := chain.step(t, []map[string]any{unknown}, "2026-11-06T12:00:40Z")
			row["id"] = int64(5)
			e := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:50Z")
			none := chain.step(t, nil, "2026-11-06T12:00:55Z")
			for _, result := range []incrementalTestResult{u, e, none} {
				incrementalTestAssertStatus(t, result, "uncertain", "uncertain")
				if *result.checkpoint.Auths[0].RecoveryAfter != "2026-11-06T12:00:40Z" {
					t.Fatal("E/no-new-rows slid a recovery receipt")
				}
			}
			recovered := chain.step(t, []map[string]any{incrementalTestRow(t, 6, "2026-11-06T12:00:45Z", "99")}, "2026-11-06T12:00:56Z")
			incrementalTestAssertStatus(t, recovered, "selected", "selected")
			if incrementalTestPrimary(t, recovered) != "exhausted" {
				t.Fatal("post-bound recovery did not normalize the actual depleted pack")
			}
		})
	}
}

func TestIncrementalSyntheticF3FailedGETThenReceiptAloneThenFreshQuota(t *testing.T) {
	chain := newIncrementalTestChain(t)
	chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
	u := incrementalTestRow(t, 2, "", "20")
	u["quota_observed_at_json"] = nil
	failed := chain.step(t, []map[string]any{u}, "")
	incrementalTestAssertStatus(t, failed, "uncertain", "uncertain")
	if failed.checkpoint.Auths[0].RecoveryAfter != nil || len(producerTestOptionalObject(failed.sidecar["auth_health"])) != 0 {
		t.Fatal("failed GET reused last-success health or invented a recovery bound")
	}
	// This positive is delivered with the first successful GET. It cannot use
	// that same tick's receipt (F6); the receipt bounds only a future tick.
	bound := chain.step(t, []map[string]any{incrementalTestRow(t, 3, "2026-11-06T12:00:20Z", "12")}, "2026-11-06T12:00:30Z")
	incrementalTestAssertStatus(t, bound, "uncertain", "uncertain")
	healthOnly := chain.step(t, nil, "2026-11-06T12:00:40Z")
	incrementalTestAssertStatus(t, healthOnly, "uncertain", "uncertain")
	if *healthOnly.checkpoint.Auths[0].RecoveryAfter != "2026-11-06T12:00:30Z" {
		t.Fatal("established bound slid on health-only receipt")
	}
	old := chain.step(t, []map[string]any{incrementalTestRow(t, 4, "2026-11-06T12:00:29Z", "12")}, "2026-11-06T12:00:45Z")
	incrementalTestAssertStatus(t, old, "uncertain", "uncertain")
	recovered := chain.step(t, []map[string]any{incrementalTestRow(t, 5, "2026-11-06T12:00:35Z", "12")}, "2026-11-06T12:00:50Z")
	incrementalTestAssertStatus(t, recovered, "selected", "selected")
	if incrementalTestPrimary(t, recovered) != "known" {
		t.Fatal("genuinely post-bound quota did not recover through SDK")
	}
}

func TestIncrementalSyntheticF6NewUnknownInvalidatesCheckpointInBoundInEitherPageOrder(t *testing.T) {
	for _, order := range []string{"P101_then_U102", "U102_then_P103"} {
		t.Run(order, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			chain.step(t, []map[string]any{incrementalTestRow(t, 99, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
			u100 := incrementalTestRow(t, 100, "", "20")
			u100["quota_observed_at_json"] = nil
			chain.step(t, []map[string]any{u100}, "2026-11-06T12:00:10Z")
			u102 := incrementalTestRow(t, 102, "", "20")
			u102["quota_observed_at_json"] = nil
			p := incrementalTestRow(t, 101, "2026-11-06T12:00:20Z", "12")
			rows := []map[string]any{p, u102}
			if order == "U102_then_P103" {
				p["id"] = int64(103)
				rows = []map[string]any{u102, p}
			}
			result := chain.step(t, rows, "2026-11-06T12:00:30Z")
			incrementalTestAssertStatus(t, result, "uncertain", "uncertain")
			if result.checkpoint.Auths[0].LastUncertainID != 102 || *result.checkpoint.Auths[0].RecoveryAfter != "2026-11-06T12:00:30Z" {
				t.Fatal("NEW U did not invalidate/rebound its own uncertainty")
			}
		})
	}
}

func TestIncrementalSyntheticQuotaBearing429AndMalformedPresenceParticipate(t *testing.T) {
	for _, raw := range []string{
		`{"X-Codex-Primary-Used-Percent":[]}`,
		`{"X-Codex-Primary-Used-Percent":null}`,
		`{"X-Codex-Primary-Used-Percent":"wrong-shape"}`,
		`{"X-Codex-Opaque-Namespace":[]}`,
		`{"X-Codex-Safety-Buffering-Enabled":["true"]}`,
	} {
		t.Run(raw, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
			row := incrementalTestRow(t, 2, "", "12")
			row["quota_json"], row["quota_observed_at_json"] = raw, nil
			result := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:10Z")
			incrementalTestAssertStatus(t, result, "uncertain", "uncertain")
		})
	}
	chain := newIncrementalTestChain(t)
	chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
	row := incrementalTestRow(t, 2, "2026-11-06T12:00:10Z", "99")
	row["failed"], row["status_code"], row["tokens"] = true, 429, 0
	limited := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:15Z")
	if incrementalTestPrimary(t, limited) != "exhausted" {
		t.Fatal("quota-bearing 429 was filtered")
	}
	late := incrementalTestRow(t, 3, "2026-11-06T12:00:00Z", "12")
	late["failed"], late["status_code"] = false, 200
	if incrementalTestPrimary(t, chain.step(t, []map[string]any{late}, "2026-11-06T12:00:20Z")) != "exhausted" {
		t.Fatal("late successful old positive beat quota-bearing refusal")
	}
}

func TestIncrementalSyntheticMalformedSQLTextShapesAreUnknownNotNoObservation(t *testing.T) {
	for _, quota := range []string{"{broken-private", "[]", `"scalar-private"`, "42"} {
		t.Run(quota, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			row := incrementalTestRow(t, 1, "", "12")
			row["quota_json"] = quota
			result := chain.step(t, []map[string]any{row}, "")
			incrementalTestAssertStatus(t, result, "uncertain", "uncertain")
			if result.checkpoint.Auths[0].Uncertain.Marker != "malformed_quota_text" || bytes.Contains(result.raw, []byte("private")) {
				t.Fatal("malformed text was echoed or dropped instead of digest unknown")
			}
		})
	}
	for _, clocks := range []any{nil, "null", "[]", "broken-private", `{"X-Codex-Primary-Used-Percent":null}`, `{"X-Codex-Primary-Used-Percent":17}`} {
		t.Run(fmt.Sprint(clocks), func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			row := incrementalTestRow(t, 1, "", "12")
			row["quota_observed_at_json"] = clocks
			incrementalTestAssertStatus(t, chain.step(t, []map[string]any{row}, ""), "uncertain", "uncertain")
		})
	}
}

func TestIncrementalSyntheticLosslessNullableOriginalClocksAndWholePackIntervals(t *testing.T) {
	const early = "2026-11-06T13:00:00.123456789+01:00"
	const late = "2026-11-06T07:00:10.123456789-05:00"
	chain := newIncrementalTestChain(t)
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, early, "12", true)
	producerTestAddSecondary(t, seat, late, "true", "false")
	row := incrementalTestConvertRow(t, seat)
	first := chain.step(t, []map[string]any{row}, "2026-11-06T13:00:20.123456789+01:00")
	if incrementalTestPrimary(t, first) != "known" || findWindow(t, first.view.Seats[0].normalizedSeat, "secondary").State != "known" {
		t.Fatal("separately coherent SDK windows lost independent clocks")
	}
	signals := first.view.Signals[producerTestAuthA]
	if *signals.QuotaAcquiredAt["X-Codex-Primary-Used-Percent"] != early || *signals.QuotaAcquiredAt["X-Codex-Secondary-Used-Percent"] != late || *signals.Health.SourceObservedAt != "2026-11-06T13:00:20.123456789+01:00" || *signals.ObservedAt != "2026-11-06T12:00:00.123456789Z" {
		t.Fatal("original zone/nanoseconds or oldest native publication clock was lost")
	}
	// A disjoint, independently clocked interval replaces the whole pack.
	seat = producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 2, "2026-11-06T12:00:11Z", "20", true)
	producerTestAddSecondary(t, seat, "2026-11-06T12:00:12Z", "true", "false")
	disjoint := chain.step(t, []map[string]any{incrementalTestConvertRow(t, seat)}, "2026-11-06T12:00:30Z")
	if disjoint.checkpoint.Auths[0].Anchor.ID != 2 {
		t.Fatal("safe disjoint interval did not replace atomic pack")
	}
	seat = producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 3, "2026-11-06T12:00:11.5Z", "1", true)
	producerTestAddSecondary(t, seat, "2026-11-06T12:00:13Z", "true", "false")
	overlap := chain.step(t, []map[string]any{incrementalTestConvertRow(t, seat)}, "2026-11-06T12:00:35Z")
	incrementalTestAssertStatus(t, overlap, "uncertain", "uncertain")
	if overlap.checkpoint.Auths[0].Unbounded || overlap.checkpoint.Auths[0].RecoveryAfter != nil {
		t.Fatal("complete overlap incorrectly required a missing-clock receipt")
	}
	ordered := chain.step(t, []map[string]any{incrementalTestRow(t, 4, "2026-11-06T12:00:14Z", "12")}, "2026-11-06T12:00:40Z")
	incrementalTestAssertStatus(t, ordered, "selected", "selected")
	// Null is retained as null, not changed to an acquisition or lost in an
	// attempted map[string]string decode. Anchor remains hidden behind U.
	seat = producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 5, early, "12", true)
	producerTestMap(seat, "response_headers_observed_at")["X-Codex-Primary-Used-Percent"] = nil
	unknown := chain.step(t, []map[string]any{incrementalTestConvertRow(t, seat)}, "2026-11-06T12:00:45Z")
	incrementalTestAssertStatus(t, unknown, "uncertain", "uncertain")
	signals = unknown.view.Signals[producerTestAuthA]
	if string(signals.CurrentPack.ResponseHeadersObservedAt["X-Codex-Primary-Used-Percent"]) != "null" || signals.QuotaAcquiredAt["X-Codex-Primary-Used-Percent"] != nil || signals.RetainedAnchor.ID != 4 {
		t.Fatal("nullable raw map was restamped or ordered anchor was exposed")
	}
}

func TestIncrementalSyntheticSDKMixedWithinWindowRemainsUnknown(t *testing.T) {
	chain := newIncrementalTestChain(t)
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:00Z", "12", true)
	producerTestMap(seat, "response_headers_observed_at")["X-Codex-Primary-Used-Percent"] = "2026-11-06T12:00:00.000000001Z"
	result := chain.step(t, []map[string]any{incrementalTestConvertRow(t, seat)}, "2026-11-06T12:00:10Z")
	if incrementalTestPrimary(t, result) != "unknown" || findWindow(t, result.view.Seats[0].normalizedSeat, "primary").Reason != "mixed_observation_times" {
		t.Fatal("native adapter equalized per-header clocks or bypassed SDK coherence")
	}
}

func TestIncrementalSyntheticNoRowsFreshness300AndOneNanosecond(t *testing.T) {
	chain := newIncrementalTestChain(t)
	first := chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00.123456789Z", "12")}, "2026-11-06T12:00:10Z")
	for _, tc := range []struct{ evaluation, state string }{
		{"2026-11-06T12:05:00.123456789Z", "known"},
		{"2026-11-06T12:05:00.123456790Z", "stale"},
	} {
		invocation := chain.prepare(t, nil, tc.evaluation, chain.cursor, true)
		invocation.args = incrementalTestSetArg(invocation.args, "--evaluation-time", tc.evaluation)
		result := chain.execute(t, invocation)
		if incrementalTestPrimary(t, result) != tc.state || !bytes.Equal(first.stateRaw, result.stateRaw) || *result.view.Signals[producerTestAuthA].QuotaAcquiredAt["X-Codex-Primary-Used-Percent"] != "2026-11-06T12:00:00.123456789Z" {
			t.Fatal("evaluation restamped quota or failed the inclusive native freshness edge")
		}
	}
}

func TestIncrementalSyntheticIndependentTypedHealthAndHealthOnlyNewReceipt(t *testing.T) {
	chain := newIncrementalTestChain(t)
	first := chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z")
	second := chain.step(t, nil, "2026-11-06T12:00:20.000000001Z")
	if !bytes.Equal(first.stateRaw, second.stateRaw) || first.view.CapacitySnapshotID == second.view.CapacitySnapshotID || *second.view.Signals[producerTestAuthA].QuotaObservedAt != "2026-11-06T12:00:00Z" || *second.view.Signals[producerTestAuthA].Health.ActiveObservedAt != "2026-11-06T12:00:20.000000001Z" {
		t.Fatal("health-only receipt did not change provenance independently of quota")
	}
	projection := producerTestObject(t, second.sidecar["route_projection"])
	entry := producerTestObject(t, projection["exact-route-a"])
	producerTestExactKeys(t, entry, "v2 projection", []string{"seat_index", "origin_route_id", "origin"})
	producerTestExactKeys(t, producerTestObject(t, entry["origin"]), "v2 origin", []string{"gateway_id", "provider", "auth_index", "model", "reasoning_effort"})
	for _, scope := range []string{"model", "credential", "unknown"} {
		invocation := chain.prepare(t, nil, "2026-11-06T12:00:30Z", chain.cursor, true)
		healthPath := incrementalTestArg(invocation.args, "--auth-files-observation")
		file := producerTestAuthRow(producerTestAuthA)
		file["cooldowns"] = []any{producerTestCooldown(scope, "gpt-6-luna")}
		file["disabled"] = "false" // Untyped is unknown, never a default false.
		incrementalTestWrite(t, healthPath, producerTestAuthObservation([]map[string]any{file}, "2026-11-06T12:00:30Z"))
		invocation.inputs = nil // This fixture was intentionally changed before run.
		result := chain.execute(t, invocation)
		signals := result.view.Signals[producerTestAuthA]
		if signals.Health.Active != nil || signals.ObservedAt != nil || signals.Health.Status != "partial" {
			t.Fatal("partial/untyped health became complete publication evidence")
		}
		if scope == "unknown" {
			if signals.Health.Cooldown != nil {
				t.Fatal("unknown cooldown scope granted auth-wide false")
			}
		} else if signals.Health.Cooldown == nil || *signals.Health.Cooldown != (scope == "credential") {
			t.Fatal("model cooldown was widened or credential cooldown was lost")
		}
	}
	failed := chain.step(t, nil, "")
	if len(producerTestOptionalObject(failed.sidecar["auth_health"])) != 0 || failed.view.Signals[producerTestAuthA].Health.SourceObservedAt != nil || failed.view.Signals[producerTestAuthA].ObservedAt != nil {
		t.Fatal("failed GET reused previous health/receipt")
	}
}

func TestIncrementalSyntheticBoundedPagesLosingRowsRestartAndNoPartialPositive(t *testing.T) {
	chain := newIncrementalTestChain(t)
	initial := chain.prepare(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:20Z", "12")}, "2026-11-06T12:00:30Z", 1, false)
	partial := chain.execute(t, initial)
	incrementalTestAssertStatus(t, partial, "selected", "source_catching_up")
	firstPack, err := json.Marshal(partial.checkpoint.Auths[0].Anchor)
	if err != nil {
		t.Fatal(err)
	}
	for page := int64(0); page < 12; page++ {
		rows := make([]map[string]any, 0, 40)
		for offset := int64(0); offset < 40; offset++ {
			rows = append(rows, incrementalTestRow(t, 2+page*40+offset, "2026-11-06T12:00:00Z", "1"))
		}
		last := rows[len(rows)-1]["id"].(int64)
		result := chain.execute(t, chain.prepare(t, rows, "2026-11-06T12:00:30Z", last, false))
		incrementalTestAssertStatus(t, result, "selected", "source_catching_up")
		pack, err := json.Marshal(result.checkpoint.Auths[0].Anchor)
		if err != nil || !bytes.Equal(firstPack, pack) || result.checkpoint.Auths[0].Uncertain != nil || len(result.stateRaw) > 6000 {
			t.Fatal("losing rows grew history or displaced acquisition anchor")
		}
	}
	caughtUp := chain.step(t, nil, "2026-11-06T12:00:40Z")
	if incrementalTestPrimary(t, caughtUp) != "known" {
		t.Fatal("completed bootstrap did not expose actual retained evidence")
	}
}

func TestIncrementalSyntheticOversizedPackIsDigestUnknownNotTruncatedPositive(t *testing.T) {
	chain := newIncrementalTestChain(t)
	chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 2, "2026-11-06T12:00:10Z", "1", true)
	producerTestMap(seat, "headers")["X-Codex-Opaque"] = []string{strings.Repeat("raw-private", 10000)}
	result := chain.step(t, []map[string]any{incrementalTestConvertRow(t, seat)}, "2026-11-06T12:00:20Z")
	incrementalTestAssertStatus(t, result, "uncertain", "uncertain")
	pack := result.checkpoint.Auths[0].Uncertain
	raw, err := json.Marshal(pack)
	if err != nil || len(raw) > maxRetainedPack || pack.Marker != "pack_too_large" || !lowerHex(pack.TransportSHA256, 64) || pack.Headers != nil || bytes.Contains(result.stateRaw, []byte("raw-private")) {
		t.Fatal("oversized pack was retained/truncated into usable evidence")
	}
}

func TestIncrementalSyntheticUnobservedConfiguredCoverageDoesNotInventSeatsOrRoutes(t *testing.T) {
	chain := newIncrementalTestChain(t,
		producerTestRoute("a", producerTestAuthA, "gpt-6-luna", "low"),
		producerTestRoute("b", producerTestAuthB, "gpt-6-astra", "max"),
	)
	result := chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z")
	if result.view.ObservedSeats != 1 || len(result.view.Seats) != 1 || len(result.view.AuthStatuses) != 2 || result.view.AsOf != nil || result.view.AuthStatuses[1].EvidenceStatus != "unobserved" || result.view.Signals[producerTestAuthB].CurrentPack != nil || len(producerTestOptionalObject(result.sidecar["route_projection"])) != 1 {
		t.Fatal("configured-unobserved auth became observed or invalidated an independent auth's evidence")
	}
	if result.view.Signals[producerTestAuthA].QuotaObservedAt == nil {
		t.Fatal("global null erased independent auth clock")
	}
}

func incrementalTestArg(args []string, name string) string {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == name {
			return args[index+1]
		}
	}
	return ""
}

func incrementalTestSetArg(args []string, name, value string) []string {
	result := append([]string(nil), args...)
	for index := 0; index+1 < len(result); index++ {
		if result[index] == name {
			result[index+1] = value
			return result
		}
	}
	return append(result, name, value)
}

func TestIncrementalSyntheticOuterCursorSourceRosterAndCheckpointErrorsAreSanitized(t *testing.T) {
	for _, mutation := range []string{"schema", "gateway", "after_noncanonical", "through_overflow", "bootstrap_jump", "row_id_absent", "row_id_string", "row_order", "row_scope", "row_provider", "raw_not_sql_text", "not_caught_up_empty", "not_caught_up_wrong_through", "bad_roster", "bad_health", "lone_checkpoint_in", "as_of", "wrong_checkpoint", "empty_checkpoint", "empty_checkpoint_option"} {
		t.Run(mutation, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			invocation := chain.prepare(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z", 1, true)
			path := incrementalTestArg(invocation.args, "--input")
			delta := producerTestDecodeFileObject(t, path)
			row := producerTestObject(t, producerTestArray(t, delta["rows"])[0])
			switch mutation {
			case "schema":
				delta["schema_version"] = producerTestSecret
			case "gateway":
				delta["gateway_id"] = "ryzen1-cpa" // Wrapper publication scope is not native origin.
			case "after_noncanonical":
				delta["after_id"] = "00"
			case "through_overflow":
				delta["through_id"] = "9223372036854775808"
			case "bootstrap_jump":
				delta["after_id"], delta["through_id"], row["id"] = "1", "2", 2
			case "row_id_absent":
				delete(row, "id")
			case "row_id_string":
				row["id"] = "1"
			case "row_order":
				delta["rows"] = []any{row, row}
			case "row_scope":
				row["auth_index"] = producerTestAuthB
			case "row_provider":
				row["provider"] = "claude"
			case "raw_not_sql_text":
				row["quota_json"] = map[string]any{"private": producerTestSecret}
			case "not_caught_up_empty":
				delta["rows"], delta["caught_up"] = []any{}, false
			case "not_caught_up_wrong_through":
				delta["through_id"], delta["caught_up"] = "2", false
			case "bad_roster":
				incrementalTestWrite(t, chain.roster, map[string]any{"routes": []any{producerTestRoute("duplicate", producerTestAuthA, "gpt-6-luna", "low"), producerTestRoute("duplicate", producerTestAuthA, "gpt-6-luna", "max")}})
			case "bad_health":
				incrementalTestWrite(t, incrementalTestArg(invocation.args, "--auth-files-observation"), map[string]any{"files": producerTestSecret})
			case "lone_checkpoint_in":
				invocation.args = append(producerTestRemoveFlag(invocation.args, "--checkpoint-out"), "--checkpoint-in", path)
			case "as_of":
				invocation.args = append(invocation.args, "--as-of", producerTestEvaluation)
			case "wrong_checkpoint":
				invocation.args = append(invocation.args, "--checkpoint-in", path)
			case "empty_checkpoint_option":
				invocation.args = append(invocation.args, "--checkpoint-in", "")
			case "empty_checkpoint":
				prior := filepath.Join(chain.dir, "not-native.json")
				incrementalTestWrite(t, prior, map[string]any{})
				invocation.args = append(invocation.args, "--checkpoint-in", prior)
			}
			incrementalTestWrite(t, path, delta)
			var stdout bytes.Buffer
			err := run(invocation.args, &stdout)
			if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), producerTestSecret) || strings.Contains(err.Error(), chain.dir) {
				t.Fatalf("invalid outer input produced output/success or echoed data: %v", err)
			}
			producerTestAssertSidecarAbsent(t, invocation.sidecar)
			producerTestAssertSidecarAbsent(t, invocation.checkpoint)
		})
	}
}

func TestIncrementalSyntheticCheckpointBindingAndCrossAliasesRefuseBeforeOutput(t *testing.T) {
	for _, mutation := range []string{"cursor", "roster", "input_output", "checkpoint_in_out", "outputs_equal", "hardlink_input", "symlink_parent", "dangling_symlink", "artifact_output"} {
		t.Run(mutation, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z")
			invocation := chain.prepare(t, nil, "2026-11-06T12:00:20Z", chain.cursor, true)
			switch mutation {
			case "cursor":
				path := incrementalTestArg(invocation.args, "--input")
				delta := producerTestDecodeFileObject(t, path)
				delta["after_id"], delta["through_id"] = "0", "1"
				incrementalTestWrite(t, path, delta)
			case "roster":
				raw, err := os.ReadFile(chain.roster)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(chain.roster, append(raw, ' '), 0600); err != nil {
					t.Fatal(err)
				}
			case "input_output":
				invocation.args = incrementalTestSetArg(invocation.args, "--checkpoint-out", incrementalTestArg(invocation.args, "--input"))
			case "checkpoint_in_out":
				invocation.args = incrementalTestSetArg(invocation.args, "--checkpoint-out", chain.checkpoint)
			case "outputs_equal":
				invocation.args = incrementalTestSetArg(invocation.args, "--checkpoint-out", invocation.sidecar)
			case "hardlink_input":
				if err := os.Link(chain.checkpoint, invocation.checkpoint); err != nil {
					t.Skipf("hardlink unavailable: %v", err)
				}
			case "symlink_parent":
				alias := filepath.Join(chain.dir, "generation-alias")
				if err := os.Symlink(filepath.Dir(invocation.sidecar), alias); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
				invocation.args = incrementalTestSetArg(invocation.args, "--checkpoint-out", filepath.Join(alias, filepath.Base(invocation.sidecar)))
			case "dangling_symlink":
				if err := os.Symlink(invocation.sidecar, invocation.checkpoint); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			case "artifact_output":
				invocation.args = incrementalTestSetArg(invocation.args, "--checkpoint-out", invocation.artifact)
			}
			var stdout bytes.Buffer
			err := run(invocation.args, &stdout)
			if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), chain.dir) {
				t.Fatal("mismatched state/alias accepted or leaked a path")
			}
		})
	}
}

type incrementalShortWriter struct{}

func (incrementalShortWriter) Write(raw []byte) (int, error) { return len(raw) / 2, nil }

func TestIncrementalSyntheticShortStdoutAndStagingWriteFailuresAreNotSuccess(t *testing.T) {
	for _, failure := range []string{"short_stdout", "error_stdout", "checkpoint_write", "sidecar_write"} {
		t.Run(failure, func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z")
			row := incrementalTestRow(t, 2, "", "12")
			row["quota_observed_at_json"] = nil
			invocation := chain.prepare(t, []map[string]any{row}, "2026-11-06T12:00:20Z", 2, true)
			var buffer bytes.Buffer
			var stdout io.Writer = &buffer
			switch failure {
			case "short_stdout":
				stdout = incrementalShortWriter{}
			case "error_stdout":
				stdout = failingWriter{}
			case "checkpoint_write":
				if err := os.Mkdir(invocation.checkpoint, 0700); err != nil {
					t.Fatal(err)
				}
			case "sidecar_write":
				if err := os.Mkdir(invocation.sidecar, 0700); err != nil {
					t.Fatal(err)
				}
			}
			err := run(invocation.args, stdout)
			if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), chain.dir) {
				t.Fatal("write failure returned success or echoed writer/path data")
			}
			producerTestAssertInputsUnchanged(t, invocation.inputs)
			if buffer.Len() != 0 {
				t.Fatal("file staging failure emitted a valid stdout artifact")
			}
			if failure == "checkpoint_write" {
				producerTestAssertSidecarAbsent(t, invocation.sidecar)
			}
			// A sidecar/stdout failure may leave staged next-state bytes. They
			// are not a committed cursor; wrapper must reject the generation.
		})
	}
}

// These frozen v1 wire templates are derived from the pre-incremental command
// at CPA925, not from v2 or from the current serializer's struct definitions.
// Generic JSON indentation and byte hashing only fill provenance placeholders.
func incrementalTestV1Golden(t *testing.T, preimage string) ([]byte, string) {
	t.Helper()
	id := "sha256:" + producerTestSHA256([]byte(preimage))
	withID := strings.Replace(preimage, `,"source_capture_sha256":`, `,"capacity_snapshot_id":"`+id+`","source_capture_sha256":`, 1)
	return incrementalTestIndent(t, withID), id
}

func incrementalTestIndent(t *testing.T, compact string) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := json.Indent(&out, []byte(compact), "", "  "); err != nil {
		t.Fatal(err)
	}
	return append(out.Bytes(), '\n')
}

func TestIncrementalLegacyWithoutFlagsFixedReplayBytesAndRefusals(t *testing.T) {
	const captured = "2026-11-06T12:00:59Z"
	emptyRaw := []byte(`{"captured_at":"2026-11-06T12:00:59Z","seats":[]}`)
	input := writeCapture(t, emptyRaw)
	preimage := `{"schema_version":"seat_quota_windows.v1","source_capture_sha256":"` + producerTestSHA256(emptyRaw) + `","source_version":"` + testSourceVersion + `","source":"usage_events","as_of":"` + producerTestEvaluation + `","captured_at":"` + captured + `","captured_at_basis":"capture_fetch_time_not_acquisition","observed_seats":0,"roster_completeness":"unverified","seats":[]}`
	expected, _ := incrementalTestV1Golden(t, preimage)
	var stdout bytes.Buffer
	if err := run(cliArgs(input, producerTestEvaluation), &stdout); err != nil || !bytes.Equal(stdout.Bytes(), expected) {
		t.Fatalf("unflagged v1 legacy bytes changed: err=%v\ngot=%s\nwant=%s", err, stdout.Bytes(), expected)
	}
	// A provenance invocation that v1 refused must not fall through to v2's
	// explicit unknown success unless checkpoint-out was actually requested.
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "", "12", true)
	files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), producerTestEvaluation)
	stdout.Reset()
	err := run(producerTestBaseArgs(files, producerTestEvaluation), &stdout)
	if err == nil || err.Error() != "producer capture has no source header acquisition" || stdout.Len() != 0 {
		t.Fatal("v1 all-acquisition-free refusal changed")
	}
	producerTestAssertSidecarAbsent(t, files.sidecarPath)
}

func TestIncrementalProducerWithoutFlagsFixedReplayStdoutAndSidecarBytes(t *testing.T) {
	const acquired = "2026-11-06T12:00:00.000000001Z"
	capture := map[string]any{
		"captured_at": "2026-11-06T12:00:59Z", "gateway_id": producerGateway,
		"seats": []any{map[string]any{"auth_index": producerTestAuthA, "provider": "codex", "model": "gpt-6-luna", "headers": map[string]any{"X-Codex-Plan-Type": []string{"pro"}}, "response_headers_observed_at": map[string]any{"X-Codex-Plan-Type": acquired}}},
	}
	files := producerTestWriteScenario(t, capture, nil, nil, "")
	window := func(slot string) string {
		return `{"limit_key":"x-codex","upstream_window":"` + slot + `","duration_seconds":null,"used_percent":null,"headroom_percent":null,"reset_at":null,"observed_at":null,"age_seconds":null,"source":"usage_events","timestamp_basis":"unknown","state":"unknown","reason":"not_observed"}`
	}
	seat := `{"auth_index":"1111111111111111","provider":"codex","observed_model":"gpt-6-luna","observed_model_basis":"usage_event_request_model_not_quota_scope","quota_scope":"unverified","health":"unknown","credits_approval":"unverified","cooldown_until":null,"next_retry_at":null,"quota":{"state":"unknown","reason":"metadata_only","windows":[` + window("primary") + `,` + window("secondary") + `],"plan":"pro","credits":{"has_credits":null,"unlimited":null,"balance":null,"can_purchase":null,"has_payment_method":null,"exhausted_included":null}},"non_acquisition_diagnostics":{"request_timestamp":null,"request_timestamp_ms":null,"request_timestamp_basis":"request_started_not_acquisition","row_insert_timestamp_ms":null,"row_insert_timestamp_basis":"row_inserted_not_acquisition"}}`
	captureHash := producerTestSHA256(files.captureRaw)
	preimage := `{"schema_version":"seat_quota_windows.v1","source_capture_sha256":"` + captureHash + `","source_version":"` + producerTestSourceVersion + `","source":"usage_events","as_of":"` + acquired + `","captured_at":"2026-11-06T12:00:59Z","captured_at_basis":"capture_fetch_time_not_acquisition","observed_seats":1,"roster_completeness":"unverified","seats":[` + seat + `]}`
	expected, id := incrementalTestV1Golden(t, preimage)
	stdout, err := producerTestRun(t, files, producerTestEvaluation)
	if err != nil || !bytes.Equal(stdout, expected) {
		t.Fatalf("unflagged v1 producer stdout changed: err=%v\ngot=%s\nwant=%s", err, stdout, expected)
	}
	artifactHash := producerTestSHA256(expected)
	expectedSidecar := `{"artifact_file":"section-2.json","artifact_sha256":"` + artifactHash + `","verification":{"source_commit":"` + producerTestSourceVersion + `","as_of":"` + acquired + `","schema_version":"seat_quota_windows.v1","capacity_snapshot_id":"` + id + `","artifact_sha256":"` + artifactHash + `","source_capture_sha256":"` + captureHash + `","roster_sha256":"` + producerTestSHA256(files.rosterRaw) + `","auth_files_observation_sha256":"` + producerTestSHA256(files.authRaw) + `","observed_seats":1,"observed_by_provider":{"codex":1},"window_states":{"unknown":2},"evaluated_at":"` + producerTestEvaluation + `","evaluation_time_basis":"explicit_offline_replay"},"route_projection":{},"auth_health":{}}`
	actualSidecar, err := os.ReadFile(files.sidecarPath)
	if err != nil || !bytes.Equal(actualSidecar, incrementalTestIndent(t, expectedSidecar)) {
		t.Fatalf("unflagged v1 sidecar changed: err=%v\ngot=%s\nwant=%s", err, actualSidecar, expectedSidecar)
	}
}

func TestIncrementalSyntheticStalePostBoundPackCannotRecoverThenFreshMalformedCan(t *testing.T) {
	chain := newIncrementalTestChain(t)
	u := incrementalTestRow(t, 1, "", "12")
	u["quota_observed_at_json"] = nil
	chain.step(t, []map[string]any{u}, "2026-11-06T12:00:20Z")
	invocation := chain.prepare(t, []map[string]any{incrementalTestRow(t, 2, "2026-11-06T12:01:00Z", "12")}, "2026-11-06T12:10:00Z", 2, true)
	invocation.args = incrementalTestSetArg(invocation.args, "--evaluation-time", "2026-11-06T12:10:00Z")
	stale := chain.execute(t, invocation)
	incrementalTestAssertStatus(t, stale, "uncertain", "uncertain")
	if *stale.checkpoint.Auths[0].RecoveryAfter != "2026-11-06T12:00:20Z" {
		t.Fatal("staleness/reset passage slid missing-time bound")
	}
	invocation = chain.prepare(t, []map[string]any{incrementalTestRow(t, 3, "2026-11-06T12:09:00Z", "invalid-number")}, "2026-11-06T12:10:00Z", 3, true)
	invocation.args = incrementalTestSetArg(invocation.args, "--evaluation-time", "2026-11-06T12:10:00Z")
	malformed := chain.execute(t, invocation)
	incrementalTestAssertStatus(t, malformed, "selected", "selected")
	if incrementalTestPrimary(t, malformed) != "unknown" || malformed.checkpoint.Auths[0].Anchor.ID != 3 {
		t.Fatal("fresh malformed pack was skipped instead of selected before SDK parsing")
	}
}

func TestIncrementalSyntheticEmptyBootstrapAndNoQuotaIgnoreUnusedMalformedClockColumn(t *testing.T) {
	chain := newIncrementalTestChain(t)
	empty := chain.step(t, nil, "")
	incrementalTestAssertStatus(t, empty, "unobserved", "unobserved")
	for index, clocks := range []string{"malformed-map-private", strings.Repeat("unused-private", maxRetainedPack)} {
		row := incrementalTestRow(t, int64(index+1), "", "12")
		row["quota_json"], row["quota_observed_at_json"] = "{}", clocks
		result := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:20Z")
		incrementalTestAssertStatus(t, result, "unobserved", "unobserved")
		if result.checkpoint.Auths[0].Uncertain != nil || result.checkpoint.Auths[0].RecoveryAfter != nil || bytes.Contains(result.stateRaw, []byte("private")) {
			t.Fatal("unused clock column turned proven no-observation into quota evidence")
		}
	}
}

func TestIncrementalSyntheticCompleteClockMalformedShapesReplaceBeforeSDK(t *testing.T) {
	for _, malformed := range []any{nil, []string{}, "not-an-array", 17} {
		t.Run(fmt.Sprint(malformed), func(t *testing.T) {
			chain := newIncrementalTestChain(t)
			chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 2, "2026-11-06T12:00:10Z", "12", true)
			producerTestMap(seat, "headers")["X-Codex-Primary-Used-Percent"] = malformed
			newer := chain.step(t, []map[string]any{incrementalTestConvertRow(t, seat)}, "2026-11-06T12:00:15Z")
			late := chain.step(t, []map[string]any{incrementalTestRow(t, 3, "2026-11-06T12:00:00Z", "1")}, "2026-11-06T12:00:20Z")
			for _, result := range []incrementalTestResult{newer, late} {
				if result.checkpoint.Auths[0].Anchor.ID != 2 || result.checkpoint.Auths[0].Uncertain != nil || result.view.Seats[0].Quota.State != "unknown" || len(result.view.Seats[0].Quota.Windows) != 0 {
					t.Fatal("malformed present shape was filtered or lost ordering to an older positive")
				}
			}
		})
	}
}

func TestIncrementalSyntheticManyUnknownPagesKeepOnlyOneRepresentativeAndAnchor(t *testing.T) {
	chain := newIncrementalTestChain(t)
	chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:05Z")
	for page := int64(0); page < 8; page++ {
		rows := make([]map[string]any, 0, 30)
		for offset := int64(0); offset < 30; offset++ {
			row := incrementalTestRow(t, 2+page*30+offset, "", "20")
			row["quota_observed_at_json"] = nil
			rows = append(rows, row)
		}
		result := chain.step(t, rows, "2026-11-06T12:00:30Z")
		incrementalTestAssertStatus(t, result, "uncertain", "uncertain")
		state := result.checkpoint.Auths[0]
		if state.Anchor.ID != 1 || state.Uncertain.ID != chain.cursor || state.LastUncertainID != chain.cursor || len(result.stateRaw) > 10000 {
			t.Fatal("unknown pages accumulated history or lost the retained anchor/last U")
		}
	}
}

func TestIncrementalSyntheticFileBackedStdoutCannotAliasImmutableInput(t *testing.T) {
	chain := newIncrementalTestChain(t)
	invocation := chain.prepare(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z", 1, true)
	file, errOpen := os.OpenFile(incrementalTestArg(invocation.args, "--input"), os.O_RDWR, 0600)
	if errOpen != nil {
		t.Fatal(errOpen)
	}
	errRun := run(invocation.args, file)
	errClose := file.Close()
	if errRun == nil || errClose != nil || strings.Contains(errRun.Error(), chain.dir) {
		t.Fatalf("stdout input alias run=%v close=%v", errRun, errClose)
	}
	producerTestAssertInputsUnchanged(t, invocation.inputs)
	producerTestAssertSidecarAbsent(t, invocation.checkpoint)
	producerTestAssertSidecarAbsent(t, invocation.sidecar)
}

func TestIncrementalSyntheticProjectionUsesOnlyExactSameRowModelAndEffort(t *testing.T) {
	for _, tc := range []struct{ name, model, effort, route string }{
		{"exact_low_not_sibling", "gpt-6-luna", "low", "low-route"},
		{"exact_max_not_sibling", "gpt-6-luna", "max", "max-route"},
		{"missing_effort_not_inferred", "gpt-6-luna", "", ""},
		{"missing_model_not_inferred", "", "low", ""},
		{"different_model_not_equivalent", "gpt-6-astra", "low", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := newIncrementalTestChain(t,
				producerTestRoute("low-route", producerTestAuthA, "gpt-6-luna", "low"),
				producerTestRoute("max-route", producerTestAuthA, "gpt-6-luna", "max"),
			)
			row := incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")
			row["model"], row["reasoning_effort"] = tc.model, tc.effort
			if tc.effort == "" {
				delete(row, "reasoning_effort")
			}
			result := chain.step(t, []map[string]any{row}, "2026-11-06T12:00:10Z")
			projection := producerTestOptionalObject(result.sidecar["route_projection"])
			if tc.route == "" {
				if len(projection) != 0 {
					t.Fatal("missing/mismatched source origin was inferred from roster")
				}
			} else if len(projection) != 1 || projection[tc.route] == nil {
				t.Fatal("one atomic pack was fanned out or bound to a sibling profile")
			}
		})
	}
}

func TestIncrementalSyntheticRecoveryRequiresFreshNonFutureClocksAndCompetitorCeiling(t *testing.T) {
	chain := newIncrementalTestChain(t)
	chain.step(t, []map[string]any{incrementalTestRow(t, 1, "2026-11-06T12:00:00Z", "12")}, "2026-11-06T12:00:10Z")
	future := incrementalTestRow(t, 2, "2099-01-01T00:00:00Z", "1")
	unknown := chain.step(t, []map[string]any{future}, "2026-11-06T12:00:20Z")
	incrementalTestAssertStatus(t, unknown, "uncertain", "uncertain")
	if *unknown.checkpoint.Auths[0].Ceiling != "2026-11-06T12:00:00Z" {
		t.Fatal("future acquisition poisoned scalar competitor ceiling")
	}
	valid := chain.step(t, []map[string]any{incrementalTestRow(t, 3, "2026-11-06T12:00:25Z", "12")}, "2026-11-06T12:00:30Z")
	incrementalTestAssertStatus(t, valid, "selected", "selected")
}
