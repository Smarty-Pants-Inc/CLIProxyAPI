package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

const (
	producerTestSourceVersion = "cb337ca6ded1729c36f1cc6162e4ce36169f1fec"
	producerTestGatewayID     = "fleet-cliproxyapi-ryzen1"
	producerTestEvaluation    = "2026-11-06T12:01:00Z"
	producerTestAuthA         = "1111111111111111"
	producerTestAuthB         = "2222222222222222"
	producerTestSecret        = "producer-test-do-not-echo-private@example.invalid-token-header-error"
)

type producerTestFiles struct {
	capturePath string
	rosterPath  string
	authPath    string
	sidecarPath string
	captureRaw  []byte
	rosterRaw   []byte
	authRaw     []byte
}

type producerTestSnapshot struct {
	path    string
	raw     []byte
	modTime time.Time
}

// These fixtures are synthetic offline inputs. They do not represent current
// gateway health, live account state, or a capacity/START claim.
func TestProducerSyntheticRunBindsArtifactAndIndependentClocks(t *testing.T) {
	const (
		acquiredA = "2026-11-06T12:00:00.000000001Z"
		acquiredB = "2026-11-06T12:00:20.000000009Z"
		readAt    = "2026-11-06T12:00:45Z"
	)
	seatA := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 900, acquiredA, "25", true)
	seatB := producerTestSeat(producerTestAuthB, "gpt-6-astra", "max", 901, acquiredB, "40", true)
	producerTestMap(seatA, "headers")["X-Private-Test-Header"] = []string{producerTestSecret}
	producerTestMap(seatA, "response_headers_observed_at")["X-Private-Test-Header"] = acquiredA
	seatA["email"], seatA["token"] = producerTestSecret, producerTestSecret

	routeA := producerTestRoute("opaque-consumer-a", producerTestAuthA, "gpt-6-luna", "low")
	routeB := producerTestRoute("opaque-consumer-b", producerTestAuthB, "gpt-6-astra", "max")
	alternateA := producerTestRoute("opaque-unselected-profile", producerTestAuthA, "gpt-6-luna", "max")
	authA := producerTestAuthRow(producerTestAuthA)
	authA["status_message"] = producerTestSecret
	authA["cooldowns"] = []any{producerTestCooldown("model", producerTestSecret)}
	authA["name"] = producerTestSecret
	authB := producerTestAuthRow(producerTestAuthB)
	files := producerTestWriteScenario(t,
		producerTestCapture(seatA, seatB),
		[]map[string]any{routeA, routeB, alternateA},
		[]map[string]any{authA, authB},
		readAt,
	)

	before := producerTestSnapshotInputs(t, files)
	first, err := producerTestRun(t, files, producerTestEvaluation)
	if err != nil {
		t.Fatalf("synthetic producer run failed: %v", err)
	}
	firstSidecar, err := os.ReadFile(files.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := producerTestRun(t, files, producerTestEvaluation)
	if err != nil {
		t.Fatalf("repeat synthetic producer run failed: %v", err)
	}
	repeatedSidecar, err := os.ReadFile(files.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, repeated) || !bytes.Equal(firstSidecar, repeatedSidecar) {
		t.Fatal("same immutable inputs and explicit comparison time produced different bytes")
	}
	producerTestAssertInputsUnchanged(t, before)
	if !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatal("stdout artifact is missing its final newline")
	}

	artifact := producerTestDecodeObject(t, first)
	sidecar := producerTestDecodeObject(t, firstSidecar)
	verification := producerTestObject(t, sidecar["verification"])
	if got := producerTestString(t, sidecar, "artifact_file"); got != "section-2.json" {
		t.Fatalf("artifact_file = %q, want exact caller basename", got)
	}
	artifactDigest := producerTestSHA256(first)
	if got := producerTestString(t, sidecar, "artifact_sha256"); got != artifactDigest {
		t.Fatalf("artifact_sha256 = %q, want stdout digest %q including newline", got, artifactDigest)
	}
	captureDigest := producerTestSHA256(files.captureRaw)
	if got := producerTestString(t, verification, "source_capture_sha256"); got != captureDigest {
		t.Fatalf("source capture digest = %q, want original input-byte digest %q", got, captureDigest)
	}
	if producerTestString(t, verification, "source_commit") != producerTestSourceVersion {
		t.Fatal("sidecar did not bind the explicit source commit")
	}
	if producerTestString(t, verification, "schema_version") != producerTestString(t, artifact, "schema_version") {
		t.Fatal("sidecar schema version does not bind the stdout artifact")
	}
	if producerTestString(t, verification, "capacity_snapshot_id") != producerTestString(t, artifact, "capacity_snapshot_id") {
		t.Fatal("sidecar content ID does not bind the stdout artifact")
	}
	if producerTestString(t, verification, "as_of") != acquiredA {
		t.Fatalf("source as_of = %q, want oldest selected per-header acquisition %q", producerTestString(t, verification, "as_of"), acquiredA)
	}
	if producerTestString(t, artifact, "as_of") != acquiredA || acquiredA == producerTestEvaluation {
		t.Fatalf("artifact source as_of was not kept separate from evaluation time: %q", producerTestString(t, artifact, "as_of"))
	}
	if producerTestString(t, artifact, "captured_at") != "2026-11-06T12:00:59Z" {
		t.Fatal("capture time was not preserved independently")
	}
	if producerTestNumber(t, verification, "observed_seats") != 2 || producerTestNumber(t, artifact, "observed_seats") != 2 {
		t.Fatal("producer did not preserve the selected unique-auth count")
	}
	if !producerTestContainsString(verification, producerTestSHA256(files.rosterRaw)) || !producerTestContainsString(verification, producerTestSHA256(files.authRaw)) {
		t.Fatal("verification does not bind both explicit roster and auth-observation input bytes")
	}

	seats := producerTestArray(t, artifact["seats"])
	if len(seats) != 2 {
		t.Fatalf("normalized seat count = %d, want one seat for each selected auth", len(seats))
	}
	wantAuths := []string{producerTestAuthA, producerTestAuthB}
	wantModels := []string{"gpt-6-luna", "gpt-6-astra"}
	wantEfforts := []string{"low", "max"}
	wantAcquired := []string{acquiredA, acquiredB}
	wantAges := []float64{59.999999999, 39.999999991}
	for index, rawSeat := range seats {
		seat := producerTestObject(t, rawSeat)
		if producerTestString(t, seat, "auth_index") != wantAuths[index] || producerTestString(t, seat, "provider") != "codex" || producerTestString(t, seat, "observed_model") != wantModels[index] {
			t.Fatalf("sorted seat %d does not bind the expected normalized identity: %+v", index, seat)
		}
		quota := producerTestObject(t, seat["quota"])
		primary := producerTestWindow(t, quota, "primary")
		if producerTestString(t, primary, "state") != "known" {
			t.Fatalf("independent fresh account %s lost known primary evidence: %+v", wantAuths[index], primary)
		}
		if got := producerTestNumber(t, primary, "observed_at"); math.Abs(got-producerTestUnix(t, wantAcquired[index])) > 1e-6 {
			t.Fatalf("account %s acquisition = %.9f, want %s", wantAuths[index], got, wantAcquired[index])
		}
		if got := producerTestNumber(t, primary, "age_seconds"); math.Abs(got-wantAges[index]) > 1e-6 {
			t.Fatalf("account %s age = %.9f, want evaluation-time age %.9f", wantAuths[index], got, wantAges[index])
		}
	}
	producerTestAssertWindowStateSummary(t, artifact, verification)

	projection := producerTestOptionalObject(sidecar["route_projection"])
	if len(projection) != 2 {
		t.Fatalf("route projection count = %d, want exactly one explicit consumer route per selected account", len(projection))
	}
	for index, routeID := range []string{"opaque-consumer-a", "opaque-consumer-b"} {
		entry := producerTestObject(t, projection[routeID])
		producerTestExactKeys(t, entry, "projection", []string{"seat_index", "origin_route_id", "origin"})
		if int(producerTestNumber(t, entry, "seat_index")) != index || producerTestString(t, entry, "origin_route_id") != routeID {
			t.Fatalf("route %s does not bind its final sorted seat index and same consumer origin: %+v", routeID, entry)
		}
		origin := producerTestObject(t, entry["origin"])
		producerTestExactKeys(t, origin, "origin", []string{"gateway_id", "provider", "auth_index", "model", "reasoning_effort"})
		if producerTestString(t, origin, "gateway_id") != producerTestGatewayID ||
			producerTestString(t, origin, "provider") != "codex" ||
			producerTestString(t, origin, "auth_index") != wantAuths[index] ||
			producerTestString(t, origin, "model") != wantModels[index] ||
			producerTestString(t, origin, "reasoning_effort") != wantEfforts[index] {
			t.Fatalf("route %s has the wrong explicit full origin tuple: %+v", routeID, origin)
		}
	}
	if _, ok := projection["opaque-unselected-profile"]; ok {
		t.Fatal("one selected auth was fanned out to a sibling model/effort profile")
	}

	health := producerTestObject(t, sidecar["auth_health"])
	for index, authIndex := range wantAuths {
		record := producerTestObject(t, health[authIndex])
		producerTestExactKeys(t, record, "auth health", []string{"gateway_id", "active", "cooldown", "limit_reached", "observed_at"})
		if producerTestString(t, record, "gateway_id") != producerTestGatewayID ||
			!producerTestBool(t, record, "active") ||
			producerTestBool(t, record, "cooldown") ||
			producerTestBool(t, record, "limit_reached") {
			t.Fatalf("synthetic health mapping is not active/no-cooldown/affirmatively-not-limited: %+v", record)
		}
		if producerTestString(t, record, "observed_at") != wantAcquired[index] {
			t.Fatalf("health for %s was restamped to the newer auth-files receipt: %+v", authIndex, record)
		}
	}

	for _, raw := range [][]byte{first, firstSidecar} {
		if bytes.Contains(raw, []byte(producerTestSecret)) || bytes.Contains(raw, []byte("X-Private-Test-Header")) {
			t.Fatal("producer copied a synthetic name, token, raw header, status/error, or model cooldown detail")
		}
	}
}

func TestProducerSelectsNewestAtomicPackByAcquisition(t *testing.T) {
	const (
		olderAt = "2026-11-06T12:00:00.000000001Z"
		newerAt = "2026-11-06T12:00:00.000000002Z"
	)
	older := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 9000000000000, olderAt, "11", true)
	producerTestSetHeader(t, older, "X-Codex-Primary-Reset-At", producerTestUnixText(t, "2026-11-30T00:00:00Z"), olderAt)
	producerTestAddSecondary(t, older, olderAt, "true", "false")
	older["timestamp"], older["created_at_ms"] = "2026-11-06T12:00:50Z", int64(1793966450000)

	newer := producerTestSeat(producerTestAuthA, "gpt-6-astra", "max", 3, newerAt, "44", true)
	producerTestSetHeader(t, newer, "X-Codex-Primary-Reset-At", producerTestUnixText(t, "2026-11-15T00:00:00Z"), newerAt)
	producerTestDeleteHeader(t, newer, "X-Codex-Secondary-Window-Minutes")
	newer["timestamp"], newer["created_at_ms"] = "2026-11-06T11:00:00Z", int64(1793962800000)

	routes := []map[string]any{
		producerTestRoute("old-origin-route", producerTestAuthA, "gpt-6-luna", "low"),
		producerTestRoute("new-origin-route", producerTestAuthA, "gpt-6-astra", "max"),
	}
	files := producerTestWriteScenario(t,
		producerTestCapture(older, newer), routes,
		[]map[string]any{producerTestAuthRow(producerTestAuthA)},
		"2026-11-06T12:00:00.500Z",
	)
	stdout, err := producerTestRun(t, files, "2026-11-06T12:00:01Z")
	if err != nil {
		t.Fatalf("producer failed to select the newest acquired response pack: %v", err)
	}
	artifact := producerTestDecodeObject(t, stdout)
	sidecarRaw, err := os.ReadFile(files.sidecarPath)
	if err != nil {
		t.Fatal(err)
	}
	sidecar := producerTestDecodeObject(t, sidecarRaw)
	seats := producerTestArray(t, artifact["seats"])
	if len(seats) != 1 {
		t.Fatalf("same-auth selection emitted %d seats, want one atomic pack", len(seats))
	}
	seat := producerTestObject(t, seats[0])
	if producerTestString(t, seat, "observed_model") != "gpt-6-astra" {
		t.Fatalf("higher old row id or request/insert time beat newer header acquisition: %+v", seat)
	}
	primary := producerTestWindow(t, producerTestObject(t, seat["quota"]), "primary")
	if math.Abs(producerTestNumber(t, primary, "used_percent")-44) > 1e-9 ||
		math.Abs(producerTestNumber(t, primary, "reset_at")-producerTestUnix(t, "2026-11-15T00:00:00Z")) > 1e-6 ||
		producerTestString(t, primary, "state") != "known" {
		t.Fatalf("selected primary fields were not kept from the newer atomic pack: %+v", primary)
	}
	secondary := producerTestWindow(t, producerTestObject(t, seat["quota"]), "secondary")
	if producerTestString(t, secondary, "reason") != "not_observed" {
		t.Fatalf("older positive secondary leaked into the newer incomplete pack: %+v", secondary)
	}
	verification := producerTestObject(t, sidecar["verification"])
	if producerTestString(t, verification, "as_of") != newerAt {
		t.Fatalf("source as_of included an unselected older pack: %q", producerTestString(t, verification, "as_of"))
	}
	projection := producerTestObject(t, sidecar["route_projection"])
	if len(projection) != 1 {
		t.Fatalf("selected auth projection count = %d, want one", len(projection))
	}
	entry := producerTestObject(t, projection["new-origin-route"])
	origin := producerTestObject(t, entry["origin"])
	if producerTestString(t, origin, "reasoning_effort") != "max" || producerTestString(t, origin, "model") != "gpt-6-astra" {
		t.Fatalf("selected origin did not retain the same row's effort/model: %+v", origin)
	}
}

func TestProducerUsesRowIDOnlyForEqualAcquisition(t *testing.T) {
	const acquired = "2026-11-06T12:00:10.000000001Z"
	lowerID := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 10, acquired, "12", true)
	higherID := producerTestSeat(producerTestAuthA, "gpt-6-astra", "max", 11, acquired, "52", true)
	files := producerTestWriteScenario(t,
		producerTestCapture(lowerID, higherID),
		[]map[string]any{
			producerTestRoute("id-10-route", producerTestAuthA, "gpt-6-luna", "low"),
			producerTestRoute("id-11-route", producerTestAuthA, "gpt-6-astra", "max"),
		},
		[]map[string]any{producerTestAuthRow(producerTestAuthA)},
		"2026-11-06T12:00:15Z",
	)
	stdout, err := producerTestRun(t, files, "2026-11-06T12:00:20Z")
	if err != nil {
		t.Fatalf("equal-acquisition ID tie-break failed: %v", err)
	}
	artifact := producerTestDecodeObject(t, stdout)
	seat := producerTestObject(t, producerTestArray(t, artifact["seats"])[0])
	if producerTestString(t, seat, "observed_model") != "gpt-6-astra" ||
		math.Abs(producerTestNumber(t, producerTestWindow(t, producerTestObject(t, seat["quota"]), "primary"), "used_percent")-52) > 1e-9 {
		t.Fatalf("larger row ID did not break an exactly equal acquisition tie: %+v", seat)
	}
}

func TestProducerRefusesUnorderableOrConflictingDuplicatePacks(t *testing.T) {
	const acquired = "2026-11-06T12:00:00Z"
	t.Run("duplicate_with_unknown_acquisition_does_not_fall_back_to_older_good", func(t *testing.T) {
		older := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 100, acquired, "12", true)
		unknown := producerTestSeat(producerTestAuthA, "gpt-6-astra", "max", 1, acquired, "50", true)
		unknown["response_headers_observed_at"] = nil
		files := producerTestWriteScenario(t,
			producerTestCapture(older, unknown),
			[]map[string]any{
				producerTestRoute("older-route", producerTestAuthA, "gpt-6-luna", "low"),
				producerTestRoute("unknown-route", producerTestAuthA, "gpt-6-astra", "max"),
			},
			[]map[string]any{producerTestAuthRow(producerTestAuthA)},
			"2026-11-06T12:00:10Z",
		)
		producerTestAssertRejected(t, files, producerTestEvaluation)
	})

	t.Run("same_time_same_id_conflicting_origins_refuse", func(t *testing.T) {
		first := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 7, acquired, "12", true)
		conflict := producerTestSeat(producerTestAuthA, "gpt-6-astra", "max", 7, acquired, "50", true)
		files := producerTestWriteScenario(t,
			producerTestCapture(first, conflict),
			[]map[string]any{
				producerTestRoute("first-route", producerTestAuthA, "gpt-6-luna", "low"),
				producerTestRoute("conflict-route", producerTestAuthA, "gpt-6-astra", "max"),
			},
			[]map[string]any{producerTestAuthRow(producerTestAuthA)},
			"2026-11-06T12:00:10Z",
		)
		producerTestAssertRejected(t, files, producerTestEvaluation)
	})
}

func TestProducerUnknownSingletonDoesNotBorrowSiblingAcquisition(t *testing.T) {
	const acquiredB = "2026-11-06T12:00:30Z"
	unknown := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "", "20", true)
	verified := producerTestSeat(producerTestAuthB, "gpt-6-astra", "max", 2, acquiredB, "30", true)
	files := producerTestWriteScenario(t,
		producerTestCapture(unknown, verified),
		[]map[string]any{
			producerTestRoute("unknown-auth-route", producerTestAuthA, "gpt-6-luna", "low"),
			producerTestRoute("verified-auth-route", producerTestAuthB, "gpt-6-astra", "max"),
		},
		[]map[string]any{producerTestAuthRow(producerTestAuthA), producerTestAuthRow(producerTestAuthB)},
		"2026-11-06T12:00:45Z",
	)
	stdout, err := producerTestRun(t, files, producerTestEvaluation)
	if err != nil {
		t.Fatalf("a single unknown-acquisition account should not poison an independently verified account: %v", err)
	}
	artifact := producerTestDecodeObject(t, stdout)
	verification := producerTestObject(t, producerTestDecodeFileObject(t, files.sidecarPath)["verification"])
	if producerTestString(t, verification, "as_of") != acquiredB {
		t.Fatalf("global as_of did not use the oldest available selected acquisition: %+v", verification)
	}
	seats := producerTestArray(t, artifact["seats"])
	if len(seats) != 2 {
		t.Fatalf("seat count = %d, want both independent auths", len(seats))
	}
	unknownSeat := producerTestObject(t, seats[0])
	if producerTestString(t, unknownSeat, "auth_index") != producerTestAuthA {
		t.Fatalf("auth order changed: %+v", seats)
	}
	unknownPrimary := producerTestWindow(t, producerTestObject(t, unknownSeat["quota"]), "primary")
	if producerTestString(t, unknownPrimary, "state") == "known" || producerTestOptionalNumber(unknownPrimary["observed_at"]) != nil || producerTestOptionalNumber(unknownPrimary["age_seconds"]) != nil {
		t.Fatalf("unknown pool borrowed a sibling acquisition: %+v", unknownPrimary)
	}
	verifiedSeat := producerTestObject(t, seats[1])
	if producerTestString(t, producerTestWindow(t, producerTestObject(t, verifiedSeat["quota"]), "primary"), "state") != "known" {
		t.Fatalf("verified independent account lost known evidence: %+v", verifiedSeat)
	}
}

func TestProducerRefusesWhenNoSelectedHeaderAcquisitionExists(t *testing.T) {
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "", "20", true)
	files := producerTestWriteScenario(t,
		producerTestCapture(seat),
		[]map[string]any{producerTestRoute("auth-route", producerTestAuthA, "gpt-6-luna", "low")},
		[]map[string]any{producerTestAuthRow(producerTestAuthA)},
		producerTestEvaluation,
	)
	producerTestAssertRejected(t, files, producerTestEvaluation)
}

func TestProducerHealthRequiresFreshTypedIndependentAuthEvidence(t *testing.T) {
	t.Run("explicit_model_cooldown_is_not_auth_wide", func(t *testing.T) {
		row := producerTestAuthRow(producerTestAuthA)
		row["cooldowns"] = []any{producerTestCooldown("model", "gpt-6-luna")}
		producerTestAssertCooldownValue(t, row, false)
	})
	t.Run("credential_cooldown_is_auth_wide", func(t *testing.T) {
		row := producerTestAuthRow(producerTestAuthA)
		row["cooldowns"] = []any{producerTestCooldown("credential", "")}
		producerTestAssertCooldownValue(t, row, true)
	})
	t.Run("explicit_empty_cooldowns_are_known_false", func(t *testing.T) {
		row := producerTestAuthRow(producerTestAuthA)
		row["cooldowns"] = []any{}
		producerTestAssertCooldownValue(t, row, false)
	})

	for _, tc := range []struct {
		name         string
		unknownField string
		mutate       func(observation map[string]any, authRow map[string]any)
	}{
		{name: "missing_status", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { delete(row, "status") }},
		{name: "untyped_status", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { row["status"] = true }},
		{name: "null_status", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { row["status"] = nil }},
		{name: "missing_disabled", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { delete(row, "disabled") }},
		{name: "untyped_disabled", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { row["disabled"] = "false" }},
		{name: "null_disabled", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { row["disabled"] = nil }},
		{name: "missing_unavailable", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { delete(row, "unavailable") }},
		{name: "null_unavailable", unknownField: "active", mutate: func(_ map[string]any, row map[string]any) { row["unavailable"] = nil }},
		{name: "missing_cooldowns", unknownField: "cooldown", mutate: func(_ map[string]any, row map[string]any) { delete(row, "cooldowns") }},
		{name: "null_cooldowns", unknownField: "cooldown", mutate: func(_ map[string]any, row map[string]any) { row["cooldowns"] = nil }},
		{name: "unknown_cooldown_scope", unknownField: "cooldown", mutate: func(_ map[string]any, row map[string]any) {
			row["cooldowns"] = []any{map[string]any{"scope": "unrecognized"}}
		}},
		{name: "wrong_gateway", mutate: func(observation map[string]any, _ map[string]any) { observation["gateway_id"] = "other-gateway" }},
		{name: "missing_read_receipt", mutate: func(observation map[string]any, _ map[string]any) { delete(observation, "observed_at") }},
		{name: "future_read_receipt", mutate: func(observation map[string]any, _ map[string]any) {
			observation["observed_at"] = "2026-11-06T12:06:00Z"
		}},
		{name: "stale_read_receipt", mutate: func(observation map[string]any, _ map[string]any) {
			observation["observed_at"] = "2026-11-06T11:55:59Z"
		}},
		{name: "wrong_provider", mutate: func(_ map[string]any, row map[string]any) { row["provider"] = "claude" }},
		{name: "duplicate_auth_identity", mutate: func(observation map[string]any, row map[string]any) {
			files := producerTestArrayNoT(observation["files"])
			observation["files"] = append(files, row)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
			authRow := producerTestAuthRow(producerTestAuthA)
			observation := producerTestAuthObservation([]map[string]any{authRow}, "2026-11-06T12:00:45Z")
			tc.mutate(observation, authRow)
			files := producerTestWriteScenarioWithObservation(t,
				producerTestCapture(seat),
				[]map[string]any{producerTestRoute("auth-route", producerTestAuthA, "gpt-6-luna", "low")},
				observation,
			)
			producerTestAssertNoCompleteHealthField(t, files, producerTestAuthA, producerTestEvaluation, tc.unknownField)
		})
	}
}

func TestProducerWindowLimitSignalRequiresAffirmativeFreshMembership(t *testing.T) {
	t.Run("allowed_false_is_limit_reached", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", "false", "2026-11-06T12:00:30Z")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitReached(t, files, producerTestAuthA, true, producerTestEvaluation)
	})
	t.Run("limit_reached_true_is_auth_wide", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestSetHeader(t, seat, "X-Codex-Primary-Limit-Reached", "true", "2026-11-06T12:00:30Z")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitReached(t, files, producerTestAuthA, true, producerTestEvaluation)
	})
	t.Run("all_required_windows_affirmative_false_even_when_quota_exhausted", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "99", true)
		producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "true", "false")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		stdout, err := producerTestRun(t, files, producerTestEvaluation)
		if err != nil {
			t.Fatalf("affirmative per-window signal mapping failed: %v", err)
		}
		sidecar := producerTestDecodeFileObject(t, files.sidecarPath)
		health := producerTestObject(t, sidecar["auth_health"])
		record := producerTestObject(t, health[producerTestAuthA])
		if producerTestBool(t, record, "limit_reached") {
			t.Fatal("healthy Allowed/Limit-Reached flags were overridden by quota percentage")
		}
		artifact := producerTestDecodeObject(t, stdout)
		primary := producerTestWindow(t, producerTestObject(t, producerTestObject(t, producerTestArray(t, artifact["seats"])[0])["quota"]), "primary")
		if producerTestString(t, primary, "state") != "exhausted" {
			t.Fatalf("99%% utilization did not remain independently exhausted: %+v", primary)
		}
	})
	t.Run("missing_required_sibling_signal_is_unknown", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestAddSecondary(t, seat, "2026-11-06T12:00:30Z", "", "")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
	t.Run("aggregate_only_signal_is_not_window_attribution", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", false)
		producerTestSetHeader(t, seat, "X-Codex-Allowed", "true", "2026-11-06T12:00:30Z")
		producerTestSetHeader(t, seat, "X-Codex-Limit-Reached", "false", "2026-11-06T12:00:30Z")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
	t.Run("empty_required_set_is_not_vacuous_false", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestSetHeader(t, seat, "X-Codex-Primary-Window-Minutes", "0", "2026-11-06T12:00:30Z")
		producerTestSetHeader(t, seat, "X-Codex-Secondary-Window-Minutes", "0", "2026-11-06T12:00:30Z")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
	t.Run("absent_secondary_needs_fresh_membership_acquisition", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestDeleteAcquisition(t, seat, "X-Codex-Secondary-Window-Minutes")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
	t.Run("status_flags_without_acquisition_are_not_false", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestDeleteAcquisition(t, seat, "X-Codex-Primary-Allowed")
		producerTestDeleteAcquisition(t, seat, "X-Codex-Primary-Limit-Reached")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
	for _, acquisition := range []struct {
		name string
		at   string
	}{
		{name: "future", at: "2026-11-06T12:01:01Z"},
		{name: "malformed", at: "not-a-timestamp"},
	} {
		t.Run("invalid_flag_acquisition_"+acquisition.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
			producerTestSetHeader(t, seat, "X-Codex-Primary-Allowed", "true", acquisition.at)
			producerTestSetHeader(t, seat, "X-Codex-Primary-Limit-Reached", "false", acquisition.at)
			files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
			producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
		})
	}
	t.Run("percentages_and_credits_without_flags_do_not_imply_false", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "25", false)
		producerTestSetHeader(t, seat, "X-Codex-Credits-Balance", "0", "2026-11-06T12:00:30Z")
		producerTestSetHeader(t, seat, "X-Codex-Credits-Has-Credits", "false", "2026-11-06T12:00:30Z")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
	t.Run("canonical_header_conflict_cannot_be_bypassed", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		producerTestSetHeader(t, seat, "x-codex-primary-allowed", "false", "2026-11-06T12:00:30Z")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z")
		producerTestAssertLimitUnknown(t, files, producerTestAuthA, producerTestEvaluation)
	})
}

func TestProducerFlagAndHealthFreshnessAreInclusiveAt300Seconds(t *testing.T) {
	for _, tc := range []struct {
		name      string
		age       time.Duration
		wantState string
		wantLimit *bool
	}{
		{name: "exactly_300_seconds_is_fresh", age: 300 * time.Second, wantState: "known", wantLimit: producerTestBoolPointer(false)},
		{name: "300_seconds_plus_one_nanosecond_is_unknown", age: 300*time.Second + time.Nanosecond, wantState: "stale"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			eval, err := time.Parse(time.RFC3339Nano, producerTestEvaluation)
			if err != nil {
				t.Fatal(err)
			}
			acquired := eval.Add(-tc.age).UTC().Format(time.RFC3339Nano)
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, acquired, "20", true)
			files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), producerTestEvaluation)
			stdout, runErr := producerTestRun(t, files, producerTestEvaluation)
			if runErr != nil {
				t.Fatalf("freshness boundary run failed: %v", runErr)
			}
			artifact := producerTestDecodeObject(t, stdout)
			primary := producerTestWindow(t, producerTestObject(t, producerTestObject(t, producerTestArray(t, artifact["seats"])[0])["quota"]), "primary")
			if got := producerTestString(t, primary, "state"); got != tc.wantState {
				t.Fatalf("window state = %q, want %q: %+v", got, tc.wantState, primary)
			}
			sidecar := producerTestDecodeFileObject(t, files.sidecarPath)
			record := producerTestOptionalHealth(t, sidecar, producerTestAuthA)
			if tc.wantLimit == nil {
				if record != nil {
					if _, ok := record["limit_reached"].(bool); ok {
						t.Fatalf("stale required-window flag was freshened into a health Boolean: %+v", record)
					}
				}
				return
			}
			if record == nil || producerTestBool(t, record, "limit_reached") != *tc.wantLimit {
				t.Fatalf("inclusive boundary did not retain affirmative health: %+v", record)
			}
			if producerTestString(t, record, "observed_at") != acquired {
				t.Fatalf("health acquisition was not the oldest used flag/membership timestamp: %+v", record)
			}
		})
	}
}

func TestProducerProjectionRequiresOneExactRosterOrigin(t *testing.T) {
	t.Run("explicit_route_id_is_not_parsed", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		route := producerTestRoute("fleet:cpa:misleading:effort=max", producerTestAuthA, "gpt-6-luna", "low")
		files := producerTestSingleAuthScenario(t, seat, producerTestAuthRow(producerTestAuthA), "2026-11-06T12:00:45Z", route)
		stdout, err := producerTestRun(t, files, producerTestEvaluation)
		if err != nil {
			t.Fatalf("explicit full tuple should bind regardless of route-ID spelling: %v", err)
		}
		projection := producerTestObject(t, producerTestDecodeFileObject(t, files.sidecarPath)["route_projection"])
		if _, ok := projection["fleet:cpa:misleading:effort=max"]; !ok {
			t.Fatalf("producer did not use the explicitly supplied route ID: %+v", projection)
		}
		_ = stdout
	})

	for _, tc := range []struct {
		name   string
		mutate func(seat, route, capture map[string]any)
	}{
		{name: "missing_effort_is_not_inferred", mutate: func(seat, _ map[string]any, _ map[string]any) { delete(seat, "reasoning_effort") }},
		{name: "missing_model_has_no_origin", mutate: func(seat, _ map[string]any, _ map[string]any) { delete(seat, "model") }},
		{name: "wrong_gateway_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) { route["gateway_id"] = "other-gateway" }},
		{name: "wrong_provider_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) { route["provider"] = "claude" }},
		{name: "wrong_auth_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) { route["auth_index"] = producerTestAuthB }},
		{name: "wrong_model_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) {
			producerTestMap(route, "model_profile")["model"] = "gpt-6-astra"
		}},
		{name: "wrong_effort_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) {
			producerTestMap(route, "model_profile")["effort"] = "max"
		}},
		{name: "wrong_deployment_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) { route["deployment"] = "cpa-auth:other" }},
		{name: "wrong_limit_scope_does_not_bind", mutate: func(_ map[string]any, route, _ map[string]any) {
			producerTestMap(route, "limit_scope")["scope_id"] = "cpa:other"
		}},
		{name: "missing_gateway_context_does_not_bind", mutate: func(_ map[string]any, _ map[string]any, capture map[string]any) { delete(capture, "gateway_id") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
			route := producerTestRoute("explicit-route", producerTestAuthA, "gpt-6-luna", "low")
			capture := producerTestCapture(seat)
			tc.mutate(seat, route, capture)
			files := producerTestWriteScenarioWithObservation(t, capture, []map[string]any{route}, producerTestAuthObservation([]map[string]any{producerTestAuthRow(producerTestAuthA)}, "2026-11-06T12:00:45Z"))
			producerTestAssertNoProjectionOrReject(t, files, "explicit-route", producerTestEvaluation)
		})
	}

	t.Run("ambiguous_full_identity_is_rejected", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		files := producerTestWriteScenario(t,
			producerTestCapture(seat),
			[]map[string]any{
				producerTestRoute("route-one", producerTestAuthA, "gpt-6-luna", "low"),
				producerTestRoute("route-two", producerTestAuthA, "gpt-6-luna", "low"),
			},
			[]map[string]any{producerTestAuthRow(producerTestAuthA)},
			"2026-11-06T12:00:45Z",
		)
		producerTestAssertRejected(t, files, producerTestEvaluation)
	})

	t.Run("duplicate_route_id_is_not_overwritten", func(t *testing.T) {
		seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
		first := producerTestRoute("same-route-id", producerTestAuthA, "gpt-6-luna", "low")
		conflict := producerTestRoute("same-route-id", producerTestAuthB, "gpt-6-astra", "max")
		files := producerTestWriteScenario(t,
			producerTestCapture(seat), []map[string]any{first, conflict},
			[]map[string]any{producerTestAuthRow(producerTestAuthA)}, "2026-11-06T12:00:45Z",
		)
		producerTestAssertRejected(t, files, producerTestEvaluation)
	})
}

func TestProducerLegacyCLIStillIgnoresUnknownWrongTypedMetadata(t *testing.T) {
	const legacyInput = `{"captured_at":"2026-11-06T12:00:59Z","gateway_id":{"wrong":"type"},"roster":17,"seats":[{"auth_index":"1111111111111111","provider":"codex","model":"gpt-6-luna","headers":{},"id":{"private":true},"reasoning_effort":["not-a-string"],"metadata":"legacy-unknown-private"}]}`
	inputPath := filepath.Join(t.TempDir(), "legacy-capture.json")
	if err := os.WriteFile(inputPath, []byte(legacyInput), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	args := []string{"--input", inputPath, "--as-of", producerTestEvaluation, "--source-version", producerTestSourceVersion}
	if err := run(args, &stdout); err != nil {
		t.Fatalf("legacy CLI rejected unknown producer metadata: %v", err)
	}
	artifact := producerTestDecodeObject(t, stdout.Bytes())
	if producerTestString(t, artifact, "as_of") != producerTestEvaluation {
		t.Fatalf("legacy source as_of changed: %+v", artifact)
	}
	if bytes.Contains(stdout.Bytes(), []byte("legacy-unknown-private")) {
		t.Fatal("legacy output copied unknown metadata")
	}
}

func TestProducerMalformedOrIncompleteOptInWritesNothingAndSanitizesErrors(t *testing.T) {
	for _, tc := range []struct {
		name   string
		modify func(t *testing.T, files producerTestFiles, args []string) []string
	}{
		{name: "missing_roster_option", modify: func(_ *testing.T, _ producerTestFiles, args []string) []string {
			return producerTestRemoveFlag(args, "--roster")
		}},
		{name: "missing_artifact_basename", modify: func(_ *testing.T, _ producerTestFiles, args []string) []string {
			return producerTestRemoveFlag(args, "--artifact-file")
		}},
		{name: "legacy_as_of_forbidden_in_producer_mode", modify: func(_ *testing.T, _ producerTestFiles, args []string) []string {
			return append(args, "--as-of", producerTestEvaluation)
		}},
		{name: "bad_capture_json", modify: func(t *testing.T, files producerTestFiles, args []string) []string {
			if err := os.WriteFile(files.capturePath, []byte("producer-malformed-private-input"), 0o600); err != nil {
				t.Fatal(err)
			}
			return args
		}},
		{name: "bad_roster_json", modify: func(t *testing.T, files producerTestFiles, args []string) []string {
			if err := os.WriteFile(files.rosterPath, []byte("producer-malformed-private-roster"), 0o600); err != nil {
				t.Fatal(err)
			}
			return args
		}},
		{name: "bad_auth_observation_json", modify: func(t *testing.T, files producerTestFiles, args []string) []string {
			if err := os.WriteFile(files.authPath, []byte("producer-malformed-private-auth"), 0o600); err != nil {
				t.Fatal(err)
			}
			return args
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
			files := producerTestWriteScenario(t,
				producerTestCapture(seat),
				[]map[string]any{producerTestRoute("route", producerTestAuthA, "gpt-6-luna", "low")},
				[]map[string]any{producerTestAuthRow(producerTestAuthA)},
				"2026-11-06T12:00:45Z",
			)
			args := producerTestBaseArgs(files, producerTestEvaluation)
			args = tc.modify(t, files, args)
			var stdout bytes.Buffer
			err := run(args, &stdout)
			if err == nil || stdout.Len() != 0 {
				t.Fatalf("invalid producer input produced success/stdout: err=%v stdout=%q", err, stdout.String())
			}
			if strings.Contains(err.Error(), producerTestSecret) || strings.Contains(err.Error(), files.capturePath) || strings.Contains(err.Error(), "producer-malformed-private") {
				t.Fatalf("producer error leaked a path or input value: %v", err)
			}
			producerTestAssertSidecarAbsent(t, files.sidecarPath)
		})
	}

	t.Run("evaluation_time_is_only_a_producer_option", func(t *testing.T) {
		inputPath := filepath.Join(t.TempDir(), "legacy.json")
		if err := os.WriteFile(inputPath, []byte(`{"captured_at":"2026-11-06T12:00:59Z","seats":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		err := run([]string{"--input", inputPath, "--as-of", producerTestEvaluation, "--source-version", producerTestSourceVersion, "--evaluation-time", producerTestEvaluation}, &stdout)
		if err == nil || stdout.Len() != 0 || strings.Contains(err.Error(), inputPath) {
			t.Fatalf("legacy mode accepted producer-only evaluation-time or leaked its path: %v", err)
		}
	})
}

func TestProducerDefaultClockCannotFreshenHistoricalAcquisition(t *testing.T) {
	actualNow := time.Now().UTC().Truncate(time.Second)
	historical, err := time.Parse(time.RFC3339Nano, "2020-01-02T03:04:05.123456789Z")
	if err != nil {
		t.Fatal(err)
	}
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, historical.Format(time.RFC3339Nano), "20", true)
	producerTestSetHeader(t, seat, "X-Codex-Primary-Reset-At", producerTestUnixText(t, historical.Add(30*24*time.Hour).Format(time.RFC3339Nano)), historical.Format(time.RFC3339Nano))
	capture := producerTestCapture(seat)
	capture["captured_at"] = actualNow.Format(time.RFC3339Nano)
	files := producerTestWriteScenario(t,
		capture,
		[]map[string]any{producerTestRoute("historical-route", producerTestAuthA, "gpt-6-luna", "low")},
		[]map[string]any{producerTestAuthRow(producerTestAuthA)},
		actualNow.Format(time.RFC3339Nano),
	)
	stdout, err := producerTestRun(t, files, "")
	if err != nil {
		t.Fatalf("default actual-time path failed: %v", err)
	}
	artifact := producerTestDecodeObject(t, stdout)
	seatOut := producerTestObject(t, producerTestArray(t, artifact["seats"])[0])
	primary := producerTestWindow(t, producerTestObject(t, seatOut["quota"]), "primary")
	if producerTestString(t, primary, "state") != "stale" {
		t.Fatalf("fresh capture/run clock restamped a frozen historical header acquisition: %+v", primary)
	}
	verification := producerTestObject(t, producerTestDecodeFileObject(t, files.sidecarPath)["verification"])
	if producerTestString(t, verification, "as_of") != historical.Format(time.RFC3339Nano) {
		t.Fatalf("default path used run/capture time instead of historical source acquisition: %+v", verification)
	}
}

func producerTestAssertCooldownValue(t *testing.T, authRow map[string]any, want bool) {
	t.Helper()
	seat := producerTestSeat(producerTestAuthA, "gpt-6-luna", "low", 1, "2026-11-06T12:00:30Z", "20", true)
	files := producerTestSingleAuthScenario(t, seat, authRow, "2026-11-06T12:00:45Z")
	stdout, err := producerTestRun(t, files, producerTestEvaluation)
	if err != nil {
		t.Fatalf("cooldown fixture rejected: %v", err)
	}
	if len(stdout) == 0 {
		t.Fatal("producer returned success without a stdout artifact")
	}
	record := producerTestOptionalHealth(t, producerTestDecodeFileObject(t, files.sidecarPath), producerTestAuthA)
	if record == nil || producerTestBool(t, record, "cooldown") != want {
		t.Fatalf("auth-wide cooldown = %v, want %v: %+v", record, want, record)
	}
}

func producerTestAssertLimitReached(t *testing.T, files producerTestFiles, authIndex string, want bool, evaluation string) {
	t.Helper()
	stdout, err := producerTestRun(t, files, evaluation)
	if err != nil {
		t.Fatalf("limit signal fixture rejected: %v", err)
	}
	if len(stdout) == 0 {
		t.Fatal("producer returned success without a stdout artifact")
	}
	record := producerTestOptionalHealth(t, producerTestDecodeFileObject(t, files.sidecarPath), authIndex)
	if record == nil || producerTestBool(t, record, "limit_reached") != want {
		t.Fatalf("limit_reached record = %+v, want %v", record, want)
	}
}

func producerTestAssertLimitUnknown(t *testing.T, files producerTestFiles, authIndex, evaluation string) {
	t.Helper()
	stdout, err := producerTestRun(t, files, evaluation)
	if err != nil {
		producerTestAssertSidecarAbsent(t, files.sidecarPath)
		if len(stdout) != 0 {
			t.Fatalf("invalid limit signal emitted stdout: %q", stdout)
		}
		return
	}
	if len(stdout) == 0 {
		t.Fatal("producer returned success without a stdout artifact")
	}
	record := producerTestOptionalHealth(t, producerTestDecodeFileObject(t, files.sidecarPath), authIndex)
	if record != nil {
		if _, ok := record["limit_reached"].(bool); ok {
			t.Fatalf("incomplete required-window evidence produced limit_reached: %+v", record)
		}
	}
}

func producerTestAssertNoCompleteHealthField(t *testing.T, files producerTestFiles, authIndex, evaluation, unknownField string) {
	t.Helper()
	stdout, err := producerTestRun(t, files, evaluation)
	if err != nil {
		producerTestAssertSidecarAbsent(t, files.sidecarPath)
		if len(stdout) != 0 {
			t.Fatalf("rejected health input emitted stdout: %q", stdout)
		}
		return
	}
	if len(stdout) == 0 {
		t.Fatal("producer returned success without a stdout artifact")
	}
	sidecar := producerTestDecodeFileObject(t, files.sidecarPath)
	record := producerTestOptionalHealth(t, sidecar, authIndex)
	if producerTestHasCompleteHealth(record) {
		t.Fatalf("unknown or stale auth evidence became a complete health record: %+v", record)
	}
	if unknownField != "" && record != nil {
		if _, ok := record[unknownField].(bool); ok {
			t.Fatalf("unknown %s evidence was emitted as a Boolean: %+v", unknownField, record)
		}
	}
}

func producerTestAssertNoProjectionOrReject(t *testing.T, files producerTestFiles, routeID, evaluation string) {
	t.Helper()
	stdout, err := producerTestRun(t, files, evaluation)
	if err != nil {
		producerTestAssertSidecarAbsent(t, files.sidecarPath)
		if len(stdout) != 0 {
			t.Fatalf("rejected origin binding emitted stdout: %q", stdout)
		}
		return
	}
	if len(stdout) == 0 {
		t.Fatal("producer returned success without a stdout artifact")
	}
	projection := producerTestOptionalObject(producerTestDecodeFileObject(t, files.sidecarPath)["route_projection"])
	if _, ok := projection[routeID]; ok {
		t.Fatalf("unqualified or conflicting origin was projected to %q: %+v", routeID, projection[routeID])
	}
	if len(projection) != 0 {
		t.Fatalf("single-seat fixture projected an unexpected route: %+v", projection)
	}
}

func producerTestAssertRejected(t *testing.T, files producerTestFiles, evaluation string) {
	t.Helper()
	stdout, err := producerTestRun(t, files, evaluation)
	if err == nil || len(stdout) != 0 {
		t.Fatalf("ambiguous/unorderable producer input was not rejected before output: err=%v stdout=%q", err, stdout)
	}
	producerTestAssertSidecarAbsent(t, files.sidecarPath)
	if strings.Contains(err.Error(), producerTestSecret) || strings.Contains(err.Error(), files.capturePath) {
		t.Fatalf("rejection leaked an input value: %v", err)
	}
}

func producerTestSingleAuthScenario(t *testing.T, seat, authRow map[string]any, authRead string, routes ...map[string]any) producerTestFiles {
	t.Helper()
	if len(routes) == 0 {
		routes = []map[string]any{producerTestRoute("auth-route", producerTestAuthA, "gpt-6-luna", "low")}
	}
	return producerTestWriteScenario(t, producerTestCapture(seat), routes, []map[string]any{authRow}, authRead)
}

func producerTestWriteScenario(t *testing.T, capture map[string]any, routes, authRows []map[string]any, authRead string) producerTestFiles {
	t.Helper()
	return producerTestWriteScenarioWithObservation(t, capture, routes, producerTestAuthObservation(authRows, authRead))
}

func producerTestWriteScenarioWithObservation(t *testing.T, capture map[string]any, routes []map[string]any, observation map[string]any) producerTestFiles {
	t.Helper()
	return producerTestWriteFiles(t, capture, map[string]any{"routes": producerTestAnyMaps(routes)}, observation)
}

func producerTestWriteFiles(t *testing.T, capture, roster, observation map[string]any) producerTestFiles {
	t.Helper()
	dir := t.TempDir()
	files := producerTestFiles{
		capturePath: filepath.Join(dir, "capture.json"),
		rosterPath:  filepath.Join(dir, "roster.json"),
		authPath:    filepath.Join(dir, "auth-files-observation.json"),
		sidecarPath: filepath.Join(dir, "section-2.provenance.json"),
	}
	var err error
	if files.captureRaw, err = json.Marshal(capture); err != nil {
		t.Fatal(err)
	}
	if files.rosterRaw, err = json.Marshal(roster); err != nil {
		t.Fatal(err)
	}
	if files.authRaw, err = json.Marshal(observation); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct {
		path string
		raw  []byte
	}{{files.capturePath, files.captureRaw}, {files.rosterPath, files.rosterRaw}, {files.authPath, files.authRaw}} {
		if err := os.WriteFile(item.path, item.raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return files
}

func producerTestCapture(seats ...map[string]any) map[string]any {
	return map[string]any{
		"captured_at": "2026-11-06T12:00:59Z",
		"gateway_id":  producerTestGatewayID,
		"source":      producerTestSecret,
		"email":       producerTestSecret,
		"seats":       producerTestAnyMaps(seats),
	}
}

func producerTestSeat(authIndex, model, effort string, id int64, acquiredAt, usedPercent string, includeFlags bool) map[string]any {
	headers := map[string]any{
		"X-Codex-Plan-Type":                []string{"pro"},
		"X-Codex-Active-Limit":             []string{"premium"},
		"X-Codex-Primary-Window-Minutes":   []string{"10080"},
		"X-Codex-Primary-Used-Percent":     []string{usedPercent},
		"X-Codex-Primary-Reset-At":         []string{producerTestUnixTextMust("2026-11-20T00:00:00Z")},
		"X-Codex-Secondary-Window-Minutes": []string{"0"},
	}
	if includeFlags {
		headers["X-Codex-Primary-Allowed"] = []string{"true"}
		headers["X-Codex-Primary-Limit-Reached"] = []string{"false"}
	}
	acquisitions := make(map[string]any, len(headers))
	for name := range headers {
		if acquiredAt != "" {
			acquisitions[name] = acquiredAt
		}
	}
	return map[string]any{
		"id":                           id,
		"auth_index":                   authIndex,
		"provider":                     "codex",
		"model":                        model,
		"reasoning_effort":             effort,
		"timestamp":                    "2026-11-06T11:59:00Z",
		"timestamp_ms":                 int64(1793966340000),
		"created_at_ms":                int64(1793966500000),
		"headers":                      headers,
		"response_headers_observed_at": acquisitions,
	}
}

func producerTestAddSecondary(t *testing.T, seat map[string]any, acquiredAt, allowed, limitReached string) {
	t.Helper()
	producerTestSetHeader(t, seat, "X-Codex-Secondary-Window-Minutes", "300", acquiredAt)
	producerTestSetHeader(t, seat, "X-Codex-Secondary-Used-Percent", "30", acquiredAt)
	producerTestSetHeader(t, seat, "X-Codex-Secondary-Reset-At", producerTestUnixTextMust("2026-11-07T00:00:00Z"), acquiredAt)
	if allowed != "" {
		producerTestSetHeader(t, seat, "X-Codex-Secondary-Allowed", allowed, acquiredAt)
	}
	if limitReached != "" {
		producerTestSetHeader(t, seat, "X-Codex-Secondary-Limit-Reached", limitReached, acquiredAt)
	}
}

func producerTestSetHeader(t *testing.T, seat map[string]any, name, value, acquiredAt string) {
	t.Helper()
	headers := producerTestMap(seat, "headers")
	headers[name] = []string{value}
	acquisitions := producerTestMap(seat, "response_headers_observed_at")
	if acquisitions == nil {
		acquisitions = make(map[string]any)
		seat["response_headers_observed_at"] = acquisitions
	}
	if acquiredAt == "" {
		delete(acquisitions, name)
	} else {
		acquisitions[name] = acquiredAt
	}
}

func producerTestDeleteHeader(t *testing.T, seat map[string]any, name string) {
	t.Helper()
	delete(producerTestMap(seat, "headers"), name)
	producerTestDeleteAcquisition(t, seat, name)
}

func producerTestDeleteAcquisition(t *testing.T, seat map[string]any, name string) {
	t.Helper()
	acquisitions := producerTestMap(seat, "response_headers_observed_at")
	delete(acquisitions, name)
}

func producerTestRoute(routeID, authIndex, model, effort string) map[string]any {
	return map[string]any{
		"route_id":   routeID,
		"gateway_id": producerTestGatewayID,
		"provider":   "codex",
		"auth_index": authIndex,
		"model_profile": map[string]any{
			"model":  model,
			"effort": effort,
		},
		"deployment": "cpa-auth:" + authIndex,
		"limit_scope": map[string]any{
			"scope_id": "cpa:" + authIndex,
		},
	}
}

func producerTestAuthRow(authIndex string) map[string]any {
	return map[string]any{
		"auth_index":  authIndex,
		"provider":    "codex",
		"status":      "active",
		"disabled":    false,
		"unavailable": false,
		"cooldowns":   []any{},
	}
}

func producerTestCooldown(scope, model string) map[string]any {
	return map[string]any{
		"scope":             scope,
		"model_key":         model,
		"reason":            producerTestSecret,
		"retry_at":          "2026-11-06T12:02:00Z",
		"remaining_seconds": 60,
	}
}

func producerTestAuthObservation(authRows []map[string]any, observedAt string) map[string]any {
	return map[string]any{
		"gateway_id":   producerTestGatewayID,
		"observed_at":  observedAt,
		"fixture_note": "synthetic auth-files observation; no live source",
		"files":        producerTestAnyMaps(authRows),
	}
}

func producerTestBaseArgs(files producerTestFiles, evaluation string) []string {
	args := []string{
		"--input", files.capturePath,
		"--source-version", producerTestSourceVersion,
		"--roster", files.rosterPath,
		"--auth-files-observation", files.authPath,
		"--provenance-output", files.sidecarPath,
		"--artifact-file", "section-2.json",
	}
	if evaluation != "" {
		args = append(args, "--evaluation-time", evaluation)
	}
	return args
}

func producerTestRun(t *testing.T, files producerTestFiles, evaluation string) ([]byte, error) {
	t.Helper()
	var stdout bytes.Buffer
	err := run(producerTestBaseArgs(files, evaluation), &stdout)
	return append([]byte(nil), stdout.Bytes()...), err
}

func producerTestSnapshotInputs(t *testing.T, files producerTestFiles) []producerTestSnapshot {
	t.Helper()
	result := make([]producerTestSnapshot, 0, 3)
	for _, path := range []string{files.capturePath, files.rosterPath, files.authPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, producerTestSnapshot{path: path, raw: raw, modTime: info.ModTime()})
	}
	return result
}

func producerTestAssertInputsUnchanged(t *testing.T, snapshots []producerTestSnapshot) {
	t.Helper()
	for _, before := range snapshots {
		after, err := os.ReadFile(before.path)
		if err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(before.path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before.raw, after) || !before.modTime.Equal(info.ModTime()) {
			t.Fatalf("producer changed or restamped immutable input %s", before.path)
		}
	}
}

func producerTestDecodeFileObject(t *testing.T, path string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return producerTestDecodeObject(t, raw)
}

func producerTestDecodeObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("decode JSON object: %v; raw=%q", err, raw)
	}
	return producerTestObject(t, value)
}

func producerTestObject(t *testing.T, value any) map[string]any {
	t.Helper()
	object, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("expected JSON object, got %T (%v)", value, value)
	}
	return object
}

func producerTestOptionalObject(value any) map[string]any {
	if object, ok := value.(map[string]any); ok && object != nil {
		return object
	}
	return map[string]any{}
}

func producerTestArray(t *testing.T, value any) []any {
	t.Helper()
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("expected JSON array, got %T (%v)", value, value)
	}
	return array
}

func producerTestArrayNoT(value any) []any {
	array, _ := value.([]any)
	return array
}

func producerTestMap(parent map[string]any, key string) map[string]any {
	object, _ := parent[key].(map[string]any)
	return object
}

func producerTestAnyMaps(values []map[string]any) []any {
	result := make([]any, len(values))
	for i := range values {
		result[i] = values[i]
	}
	return result
}

func producerTestString(t *testing.T, object map[string]any, key string) string {
	t.Helper()
	value, ok := object[key].(string)
	if !ok {
		t.Fatalf("%s = %T (%v), want string", key, object[key], object[key])
	}
	return value
}

func producerTestBool(t *testing.T, object map[string]any, key string) bool {
	t.Helper()
	value, ok := object[key].(bool)
	if !ok {
		t.Fatalf("%s = %T (%v), want bool", key, object[key], object[key])
	}
	return value
}

func producerTestNumber(t *testing.T, object map[string]any, key string) float64 {
	t.Helper()
	value, ok := object[key].(float64)
	if !ok {
		t.Fatalf("%s = %T (%v), want JSON number", key, object[key], object[key])
	}
	return value
}

func producerTestOptionalNumber(value any) *float64 {
	number, ok := value.(float64)
	if !ok {
		return nil
	}
	return &number
}

func producerTestWindow(t *testing.T, quota map[string]any, windowName string) map[string]any {
	t.Helper()
	for _, raw := range producerTestArray(t, quota["windows"]) {
		window := producerTestObject(t, raw)
		if producerTestString(t, window, "upstream_window") == windowName {
			return window
		}
	}
	t.Fatalf("missing %s window in quota view %+v", windowName, quota)
	return nil
}

func producerTestOptionalHealth(t *testing.T, sidecar map[string]any, authIndex string) map[string]any {
	t.Helper()
	health := producerTestOptionalObject(sidecar["auth_health"])
	value, ok := health[authIndex]
	if !ok {
		return nil
	}
	return producerTestObject(t, value)
}

func producerTestHasCompleteHealth(record map[string]any) bool {
	if record == nil {
		return false
	}
	for _, key := range []string{"active", "cooldown", "limit_reached"} {
		if _, ok := record[key].(bool); !ok {
			return false
		}
	}
	return true
}

func producerTestAssertWindowStateSummary(t *testing.T, artifact, verification map[string]any) {
	t.Helper()
	want := make(map[string]int)
	for _, rawSeat := range producerTestArray(t, artifact["seats"]) {
		seat := producerTestObject(t, rawSeat)
		quota := producerTestObject(t, seat["quota"])
		for _, rawWindow := range producerTestArray(t, quota["windows"]) {
			window := producerTestObject(t, rawWindow)
			want[producerTestString(t, window, "state")]++
		}
	}
	gotRaw := producerTestObject(t, verification["window_states"])
	got := make(map[string]int, len(gotRaw))
	for state, rawCount := range gotRaw {
		count, ok := rawCount.(float64)
		if !ok {
			t.Fatalf("window_states[%q] = %T, want count", state, rawCount)
		}
		if count > 0 {
			got[state] = int(count)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("window-state summary = %v, want counts from normalized stdout %v", got, want)
	}
}

func producerTestExactKeys(t *testing.T, object map[string]any, label string, expected []string) {
	t.Helper()
	got := make([]string, 0, len(object))
	for key := range object {
		got = append(got, key)
	}
	sort.Strings(got)
	sort.Strings(expected)
	if !reflect.DeepEqual(got, expected) {
		t.Fatalf("%s keys = %v, want exact approved keys %v", label, got, expected)
	}
}

func producerTestContainsString(value any, target string) bool {
	switch item := value.(type) {
	case string:
		return item == target
	case map[string]any:
		for _, nested := range item {
			if producerTestContainsString(nested, target) {
				return true
			}
		}
	case []any:
		for _, nested := range item {
			if producerTestContainsString(nested, target) {
				return true
			}
		}
	}
	return false
}

func producerTestSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func producerTestUnix(t *testing.T, stamp string) float64 {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return float64(at.Unix()) + float64(at.Nanosecond())/1e9
}

func producerTestUnixText(t *testing.T, stamp string) string {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%d", at.Unix())
}

func producerTestUnixTextMust(stamp string) string {
	at, err := time.Parse(time.RFC3339Nano, stamp)
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%d", at.Unix())
}

func producerTestBoolPointer(value bool) *bool {
	return &value
}

func producerTestRemoveFlag(args []string, name string) []string {
	result := make([]string, 0, len(args)-2)
	for i := 0; i < len(args); i++ {
		if args[i] == name {
			i++
			continue
		}
		result = append(result, args[i])
	}
	return result
}

func producerTestAssertSidecarAbsent(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed producer input left a sidecar at %s (stat error: %v)", path, err)
	}
}
