package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const testSourceVersion = "cb337ca6ded1729c36f1cc6162e4ce36169f1fec"
const testAsOf = "2026-11-05T10:45:39Z"

// Reduced real rows from quota-capture-2026-11-05T104539Z.json: original
// auth_index, model, timestamps and header arrays are retained verbatim. These
// rows deliberately have NO acquisition provenance. Recent events are omitted.
const realCaptureFixture = `{
  "captured_at": "2026-11-05T10:45:39Z",
  "source": "ryzen1 CLIProxyAPI usage store usage_events (last ~60000 ids)",
  "seats": [
    {
      "provider": "codex", "seat": "dev10", "auth_index": "5882ba1cc83fe223", "model": "gpt-6.1-sol", "status": 200,
      "timestamp_ms": 1793875459059, "timestamp": "2026-11-05T10:44:19.059768+00:00", "created_at_ms": 1793875522055,
      "headers": {
        "X-Codex-Active-Limit": ["premium"],
        "X-Codex-Credits-Balance": ["0"],
        "X-Codex-Credits-Has-Credits": ["False"],
        "X-Codex-Credits-Unlimited": ["False"],
        "X-Codex-Plan-Type": ["pro"],
        "X-Codex-Primary-Over-Secondary-Limit-Percent": ["0"],
        "X-Codex-Primary-Reset-After-Seconds": ["504864"],
        "X-Codex-Primary-Reset-At": ["1794380322"],
        "X-Codex-Primary-Used-Percent": ["5"],
        "X-Codex-Primary-Window-Minutes": ["10080"],
        "X-Codex-Safety-Buffering-Enabled": ["true"],
        "X-Codex-Safety-Buffering-Faster-Model": ["gpt-6-luna"],
        "X-Codex-Secondary-Reset-After-Seconds": ["0"],
        "X-Codex-Secondary-Reset-At": [""],
        "X-Codex-Secondary-Used-Percent": ["0"],
        "X-Codex-Secondary-Window-Minutes": ["0"]
      }
    },
    {
      "provider": "claude", "seat": "dev10", "auth_index": "24d5a4c1bc6479a3", "model": "claude-opus-5-5", "status": 200,
      "timestamp_ms": 1793875522759, "timestamp": "2026-11-05T10:45:22.759611+00:00", "created_at_ms": 1793875534543,
      "headers": {
        "Anthropic-Ratelimit-Unified-7d-Reset": ["1793923200"],
        "Anthropic-Ratelimit-Unified-7d-Status": ["allowed"],
        "Anthropic-Ratelimit-Unified-7d-Utilization": ["0.53"],
        "Anthropic-Ratelimit-Unified-Fallback-Percentage": ["0.5"],
        "Anthropic-Ratelimit-Unified-Overage-Disabled-Reason": ["org_level_disabled"],
        "Anthropic-Ratelimit-Unified-Overage-Status": ["rejected"],
        "Anthropic-Ratelimit-Unified-Representative-Claim": ["seven_day"],
        "Anthropic-Ratelimit-Unified-Reset": ["1793923200"],
        "Anthropic-Ratelimit-Unified-Status": ["allowed"]
      }
    }
  ]
}`

// This is a real CLI flow through run's argument parser, disk read and stdout
// writer, not a test of a parallel provider parser. Keep reason: acquisition
// trust boundary/data safety, including a historical response's sentinel zero.
func TestRunRealCaptureFileToStdoutDeterministic(t *testing.T) {
	input := writeCapture(t, []byte(realCaptureFixture))
	before, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(t.TempDir(), "stdout.json")
	stdout, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	errRun := run(cliArgs(input, testAsOf), stdout)
	errClose := stdout.Close()
	if errRun != nil || errClose != nil {
		t.Fatalf("run=%v close=%v", errRun, errClose)
	}
	first, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		var repeat bytes.Buffer
		if errRepeat := run(cliArgs(input, testAsOf), &repeat); errRepeat != nil {
			t.Fatal(errRepeat)
		}
		if !bytes.Equal(first, repeat.Bytes()) {
			t.Fatal("same input bytes and args produced different stdout")
		}
	}
	after, err := os.Stat(input)
	if err != nil {
		t.Fatal(err)
	}
	unchanged, err := os.ReadFile(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != realCaptureFixture || !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("input capture was changed/restamped")
	}
	view := decodeOutput(t, first)
	if view.SchemaVersion != schemaVersion || view.SourceVersion != testSourceVersion || view.Source != "usage_events" || view.AsOf != testAsOf {
		t.Fatalf("missing explicit schema/version/source/clock: %+v", view)
	}
	if view.CapturedAt != testAsOf || view.CapturedAtBasis != "capture_fetch_time_not_acquisition" || view.RosterCompleteness != "unverified" || view.ObservedSeats != 2 {
		t.Fatalf("capture or roster provenance: %+v", view)
	}
	if len(view.Seats) != 2 || view.Seats[0].AuthIndex != "24d5a4c1bc6479a3" || view.Seats[1].AuthIndex != "5882ba1cc83fe223" {
		t.Fatalf("auth_index order/identity changed: %+v", view.Seats)
	}
	hash := sha256.Sum256([]byte(realCaptureFixture))
	if view.SourceCaptureSHA256 != hex.EncodeToString(hash[:]) {
		t.Fatal("source hash is not of exact capture bytes")
	}
	id := view.CapacitySnapshotID
	view.CapacitySnapshotID = ""
	preimage, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	snapshotHash := sha256.Sum256(preimage)
	if id != "sha256:"+hex.EncodeToString(snapshotHash[:]) {
		t.Fatal("snapshot ID does not bind the normalized envelope")
	}
	for _, seat := range view.Seats {
		if seat.QuotaScope != "unverified" || seat.Health != "unknown" || seat.CreditsApproval != "unverified" || seat.CooldownUntil != nil || seat.NextRetryAt != nil {
			t.Fatalf("unsupported scope/health/approval/retry inference: %+v", seat)
		}
		if seat.ObservedModel == nil || seat.ObservedModelBasis != "usage_event_request_model_not_quota_scope" {
			t.Fatalf("exact request-model provenance missing: %+v", seat)
		}
		for _, window := range seat.Quota.Windows {
			if window.State != "unknown" || window.ObservedAt != nil || window.AgeSeconds != nil || window.TimestampBasis != "unknown" || window.Source != "usage_events" {
				t.Fatalf("legacy evidence was freshened: %+v", window)
			}
		}
	}
	claude := view.Seats[0]
	weekly := findWindow(t, claude, "7d")
	if weekly.DurationSeconds == nil || *weekly.DurationSeconds != 604800 || value(weekly.UsedPercent) != 53 || value(weekly.HeadroomPercent) != 47 || value(weekly.ResetAt) != 1793923200 {
		t.Fatalf("Claude numeric diagnostics lost: %+v", weekly)
	}
	if *claude.ObservedModel != "claude-opus-5-5" || claude.Quota.Credits.OverageStatus != "rejected" {
		t.Fatalf("Claude model or unattributed metadata: %+v", claude)
	}
	codex := view.Seats[1]
	primary, secondary := findWindow(t, codex, "primary"), findWindow(t, codex, "secondary")
	if primary.DurationSeconds == nil || *primary.DurationSeconds != 604800 || value(primary.UsedPercent) != 5 || value(primary.HeadroomPercent) != 95 || value(primary.ResetAt) != 1794380322 {
		t.Fatalf("weekly Codex primary misclassified: %+v", primary)
	}
	if secondary.DurationSeconds != nil || secondary.UsedPercent != nil || secondary.HeadroomPercent != nil || secondary.ResetAt != nil {
		t.Fatalf("unverified sentinel zero became free capacity: %+v", secondary)
	}
	if len(primary.Diagnostics) == 0 || primary.Diagnostics[0].Code != "unresolved_relative_timing" {
		t.Fatalf("relative timing was fabricated: %+v", primary.Diagnostics)
	}
	if *codex.ObservedModel != "gpt-6.1-sol" || codex.Quota.Credits.HasCredits == nil || *codex.Quota.Credits.HasCredits || value(codex.Quota.Credits.Balance) != 0 {
		t.Fatalf("Codex observed model/false credits lost: %+v", codex)
	}
	diagnostic := codex.NonAcquisitionDiagnostics
	if diagnostic.RequestTimestamp == nil || *diagnostic.RequestTimestamp != "2026-11-05T10:44:19.059768Z" || diagnostic.RequestTimestampMS == nil || *diagnostic.RequestTimestampMS != 1793875459059 || diagnostic.RowInsertTimestampMS == nil || *diagnostic.RowInsertTimestampMS != 1793875522055 || diagnostic.RequestTimestampBasis != "request_started_not_acquisition" || diagnostic.RowInsertBasis != "row_inserted_not_acquisition" {
		t.Fatalf("non-acquisition diagnostics not preserved/labelled: %+v", diagnostic)
	}
}

func TestRunReplayDoesNotRestampAndIDsBindArguments(t *testing.T) {
	input := writeCapture(t, []byte(realCaptureFixture))
	first := invoke(t, input, testAsOf)
	later := invoke(t, input, "2026-11-05T10:50:39Z")
	if first.CapacitySnapshotID == later.CapacitySnapshotID || first.SourceCaptureSHA256 != later.SourceCaptureSHA256 || first.CapturedAt != later.CapturedAt {
		t.Fatal("clock change failed to bind ID or restamped capture")
	}
	for _, seat := range later.Seats {
		for _, window := range seat.Quota.Windows {
			if window.State != "unknown" || window.ObservedAt != nil || window.AgeSeconds != nil {
				t.Fatalf("replay manufactured acquisition: %+v", window)
			}
		}
	}
	var differentVersion bytes.Buffer
	args := cliArgs(input, testAsOf)
	args[len(args)-1] = strings.Repeat("a", 40)
	if err := run(args, &differentVersion); err != nil {
		t.Fatal(err)
	}
	if decodeOutput(t, differentVersion.Bytes()).CapacitySnapshotID == first.CapacitySnapshotID {
		t.Fatal("source version not bound into snapshot ID")
	}
	otherPath := writeCapture(t, []byte(realCaptureFixture))
	if invoke(t, otherPath, testAsOf).CapacitySnapshotID != first.CapacitySnapshotID {
		t.Fatal("input path leaked into content ID")
	}
}

func TestRunExplicitAcquisitionMapFreshness(t *testing.T) {
	// Synthetic acquisition timestamps are deliberately added to the real row;
	// they are NOT recovered timestamps from the historical capture.
	for _, tc := range []struct {
		name, acquired, wantState, wantBasis string
	}{
		{"fresh", "2026-11-05T10:44:39.123456789Z", "known", "header_acquisition"},
		{"boundary", "2026-11-05T10:40:39.123456789Z", "known", "header_acquisition"},
		{"expired", "2026-11-05T10:40:39.123456788Z", "stale", "header_acquisition"},
		{"future", "2026-11-05T10:45:40Z", "unknown", "header_acquisition"},
		{"invalid", "not-a-timestamp", "unknown", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := fixture(t)
			capture.Seats = capture.Seats[1:]
			seat := &capture.Seats[0]
			seat.ResponseHeadersObservedAt = make(map[string]string)
			for key := range seat.Headers {
				seat.ResponseHeadersObservedAt[key] = tc.acquired
			}
			out := invoke(t, writeJSONCapture(t, capture), "2026-11-05T10:45:39.123456789Z")
			weekly := findWindow(t, out.Seats[0], "7d")
			if weekly.State != tc.wantState || weekly.TimestampBasis != tc.wantBasis {
				t.Fatalf("explicit acquisition state/basis: %+v", weekly)
			}
			if tc.name == "fresh" && (weekly.ObservedAt == nil || weekly.AgeSeconds == nil || *weekly.AgeSeconds != 60) {
				t.Fatalf("nanosecond acquisition not retained: %+v", weekly)
			}
			if tc.name == "invalid" && (weekly.ObservedAt != nil || len(out.Seats[0].Diagnostics) == 0) {
				t.Fatalf("invalid wire time used or not diagnosed: %+v", out.Seats[0])
			}
		})
	}
	capture := fixture(t)
	capture.Seats = capture.Seats[1:]
	capture.Seats[0].ResponseHeadersObservedAt = map[string]string{
		"Anthropic-Ratelimit-Unified-7d-Utilization": "2026-11-05T10:44:39Z",
	}
	partial := findWindow(t, invoke(t, writeJSONCapture(t, capture), testAsOf).Seats[0], "7d")
	if partial.State != "unknown" || partial.TimestampBasis != "unknown" {
		t.Fatalf("partial map verified unrelated reset/status: %+v", partial)
	}
}

func TestRunMalformedWindowDoesNotEraseValidSibling(t *testing.T) {
	capture := fixture(t)
	capture.Seats = capture.Seats[:1]
	seat := &capture.Seats[0]
	delete(seat.Headers, "X-Codex-Primary-Reset-After-Seconds")
	seat.Headers["X-Codex-Secondary-Window-Minutes"] = []string{"300"}
	seat.Headers["X-Codex-Secondary-Used-Percent"] = []string{"NaN"}
	seat.Headers["X-Codex-Secondary-Reset-At"] = []string{"1793880000"}
	delete(seat.Headers, "X-Codex-Secondary-Reset-After-Seconds")
	seat.ResponseHeadersObservedAt = make(map[string]string)
	for key := range seat.Headers {
		seat.ResponseHeadersObservedAt[key] = "2026-11-05T10:44:39Z"
	}
	out := invoke(t, writeJSONCapture(t, capture), testAsOf)
	primary, secondary := findWindow(t, out.Seats[0], "primary"), findWindow(t, out.Seats[0], "secondary")
	if primary.State != "known" || value(primary.HeadroomPercent) != 95 || secondary.State != "unknown" || secondary.UsedPercent != nil {
		t.Fatalf("malformed sibling poisoned valid evidence: primary=%+v secondary=%+v", primary, secondary)
	}
}

func TestRunDropsUnapprovedFieldsAndDoesNotInferKimiOrRoutes(t *testing.T) {
	const secret = "DO-NOT-ECHO-private@example.invalid-secret-token-request-id"
	capture := fixture(t)
	raw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]any
	if errDecode := json.Unmarshal(raw, &object); errDecode != nil {
		t.Fatal(errDecode)
	}
	object["source"], object["note"], object["token"] = secret, secret, secret
	rows := object["seats"].([]any)
	for _, row := range rows {
		seat := row.(map[string]any)
		seat["seat"], seat["email"], seat["request_id"], seat["timestamp"] = secret, secret, secret, secret
		seat["route_id"], seat["eligible"], seat["health"], seat["credits_approval"] = secret, true, "healthy", "approved"
		headers := seat["headers"].(map[string]any)
		headers["Authorization"], headers["X-Oai-Request-Id"], headers["Unknown-Header"] = []string{secret}, []string{secret}, []string{secret}
	}
	rows = append(rows, map[string]any{"auth_index": "0000000000000001", "provider": "kimi", "model": secret, "headers": map[string]any{}}, map[string]any{"auth_index": "0000000000000002", "provider": secret, "model": secret})
	object["seats"] = rows
	var stdout bytes.Buffer
	if errRun := run(cliArgs(writeJSONCapture(t, object), testAsOf), &stdout); errRun != nil {
		t.Fatal(errRun)
	}
	for _, excluded := range []string{secret, "Authorization", "Request-Id", "Safety-Buffering", "route_id", "eligible", "healthy", "approved\""} {
		if strings.Contains(stdout.String(), excluded) {
			t.Fatalf("unapproved source content echoed: %q", excluded)
		}
	}
	out := decodeOutput(t, stdout.Bytes())
	kimi := out.Seats[0]
	if kimi.Provider != "kimi" || kimi.Quota.State != "unknown" || kimi.Quota.Reason != "unsupported_provider" || len(kimi.Quota.Windows) != 0 || kimi.ObservedModel != nil || out.ObservedSeats != 4 || out.RosterCompleteness != "unverified" {
		t.Fatalf("unsupported/missing roster facts invented: %+v", out)
	}
	if out.Seats[1].Provider != "unknown" || out.Seats[1].ObservedModel != nil {
		t.Fatal("arbitrary provider/model was echoed")
	}
}

func TestRunMalformedAndEmptySafety(t *testing.T) {
	for _, input := range []string{"", " ", "null", "{}", "[]", "{", realCaptureFixture + " {}", `{"captured_at":"2026-11-05T10:45:39","seats":[]}`, `{"captured_at":"2026-11-05T10:45:39Z","seats":null}`, `{"captured_at":"2026-11-05T10:45:39Z","seats":[{"auth_index":"private@example.invalid"}]}`, `{"captured_at":"2026-11-05T10:45:39Z","seats":[{"auth_index":"0000000000000001","headers":{"X-Codex-Primary-Used-Percent":"wrong-shape"}}]}`} {
		var stdout bytes.Buffer
		if err := run(cliArgs(writeCapture(t, []byte(input)), testAsOf), &stdout); err == nil || stdout.Len() != 0 {
			t.Fatal("malformed input produced an artifact or success")
		}
	}
	empty := invoke(t, writeCapture(t, []byte(`{"captured_at":"2026-11-05T10:45:39Z","seats":[]}`)), testAsOf)
	if empty.ObservedSeats != 0 || empty.Seats == nil || len(empty.Seats) != 0 || empty.RosterCompleteness != "unverified" {
		t.Fatalf("empty roster became coverage: %+v", empty)
	}
	capture := fixture(t)
	capture.Seats[0].Headers = nil
	out := invoke(t, writeJSONCapture(t, capture), testAsOf)
	if len(out.Seats) != 2 || out.Seats[1].Quota.State != "unknown" || len(out.Seats[1].Quota.Windows) != 0 {
		t.Fatal("missing headers lost seat or fabricated windows")
	}
}

func TestRunRequiresExplicitArgumentsAndSanitizesErrors(t *testing.T) {
	input := writeCapture(t, []byte(realCaptureFixture))
	for _, args := range [][]string{
		nil,
		{"--input", input},
		{"--input", input, "--as-of", testAsOf},
		{"--input", input, "--source-version", testSourceVersion},
		cliArgs(input, "2026-11-05T10:45:39"),
		{"--input", input, "--as-of", testAsOf, "--source-version", "cb337ca"},
		{"--input", input, "--as-of", testAsOf, "--source-version", "SECRET"},
		{"--SECRET", "SECRET"},
		append(cliArgs(input, testAsOf), "SECRET"),
		cliArgs(filepath.Join(t.TempDir(), "SECRET-missing-file"), testAsOf),
	} {
		var stdout bytes.Buffer
		err := run(args, &stdout)
		if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), input) {
			t.Fatalf("missing/invalid args or error echoed input: %v", err)
		}
	}
	if err := run(cliArgs(input, testAsOf), failingWriter{}); err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("stdout failure not returned/sanitized")
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("SECRET") }

func cliArgs(input, asOf string) []string {
	return []string{"--input", input, "--as-of", asOf, "--source-version", testSourceVersion}
}

func writeCapture(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "capture.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeJSONCapture(t *testing.T, input any) string {
	t.Helper()
	raw, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	return writeCapture(t, raw)
}

func fixture(t *testing.T) quotaCapture {
	t.Helper()
	var capture quotaCapture
	if err := json.Unmarshal([]byte(realCaptureFixture), &capture); err != nil {
		t.Fatal(err)
	}
	return capture
}

func invoke(t *testing.T, input, asOf string) normalizedCapture {
	t.Helper()
	var stdout bytes.Buffer
	if err := run(cliArgs(input, asOf), &stdout); err != nil {
		t.Fatal(err)
	}
	return decodeOutput(t, stdout.Bytes())
}

func decodeOutput(t *testing.T, raw []byte) normalizedCapture {
	t.Helper()
	var output normalizedCapture
	if err := json.Unmarshal(raw, &output); err != nil {
		t.Fatal(err)
	}
	return output
}

func findWindow(t *testing.T, seat normalizedSeat, slot string) auth.QuotaWindowView {
	t.Helper()
	for _, window := range seat.Quota.Windows {
		if window.UpstreamWindow == slot {
			return window
		}
	}
	t.Fatalf("missing window %s", slot)
	return auth.QuotaWindowView{}
}

func value(number *float64) float64 {
	if number == nil {
		return math.NaN()
	}
	return *number
}
