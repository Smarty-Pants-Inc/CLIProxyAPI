// Command normalize_quota_capture projects an explicit offline usage-event
// capture into seat/window evidence with optional explicit offline provenance.
// It neither discovers routes nor authorizes dispatch.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const schemaVersion = "seat_quota_windows.v1"

// Only fields needed for this projection are decoded. In particular, seat
// labels, request IDs, source prose, recent events and credentials are excluded.
type quotaCapture struct {
	CapturedAt string        `json:"captured_at"`
	Seats      []captureSeat `json:"seats"`
}

type captureSeat struct {
	AuthIndex                 string            `json:"auth_index"`
	Provider                  string            `json:"provider"`
	Model                     string            `json:"model"`
	Timestamp                 string            `json:"timestamp"`
	TimestampMS               *int64            `json:"timestamp_ms"`
	CreatedAtMS               *int64            `json:"created_at_ms"`
	Headers                   http.Header       `json:"headers"`
	ResponseHeadersObservedAt map[string]string `json:"response_headers_observed_at"`
}

type normalizedCapture struct {
	SchemaVersion       string           `json:"schema_version"`
	CapacitySnapshotID  string           `json:"capacity_snapshot_id,omitempty"`
	SourceCaptureSHA256 string           `json:"source_capture_sha256"`
	SourceVersion       string           `json:"source_version"`
	Source              string           `json:"source"`
	AsOf                string           `json:"as_of"`
	CapturedAt          string           `json:"captured_at"`
	CapturedAtBasis     string           `json:"captured_at_basis"`
	ObservedSeats       int              `json:"observed_seats"`
	RosterCompleteness  string           `json:"roster_completeness"`
	Seats               []normalizedSeat `json:"seats"`
}

type normalizedSeat struct {
	AuthIndex                 string                    `json:"auth_index"`
	Provider                  string                    `json:"provider"`
	ObservedModel             *string                   `json:"observed_model"`
	ObservedModelBasis        string                    `json:"observed_model_basis"`
	QuotaScope                string                    `json:"quota_scope"`
	Health                    string                    `json:"health"`
	CreditsApproval           string                    `json:"credits_approval"`
	CooldownUntil             *float64                  `json:"cooldown_until"`
	NextRetryAt               *float64                  `json:"next_retry_at"`
	Quota                     auth.QuotaWindowsView     `json:"quota"`
	NonAcquisitionDiagnostics nonAcquisitionDiagnostics `json:"non_acquisition_diagnostics"`
	Diagnostics               []string                  `json:"diagnostics,omitempty"`
}

type nonAcquisitionDiagnostics struct {
	RequestTimestamp      *string `json:"request_timestamp"`
	RequestTimestampMS    *int64  `json:"request_timestamp_ms"`
	RequestTimestampBasis string  `json:"request_timestamp_basis"`
	RowInsertTimestampMS  *int64  `json:"row_insert_timestamp_ms"`
	RowInsertBasis        string  `json:"row_insert_timestamp_basis"`
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run is the actual file-to-stdout boundary. All parsing and serialization
// complete before any output; input errors never emit a partial artifact.
func run(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("normalize_quota_capture", flag.ContinueOnError)
	// Flag errors can include arbitrary arguments. Return fixed errors instead.
	flags.SetOutput(io.Discard)
	input := flags.String("input", "", "explicit capture JSON file")
	asOf := flags.String("as-of", "", "comparison clock, RFC3339 with timezone")
	sourceVersion := flags.String("source-version", "", "exact normalizer source commit (40 lowercase hex digits)")
	roster := flags.String("roster", "", "explicit offline route roster JSON file")
	authFiles := flags.String("auth-files-observation", "", "explicit sanitized auth-files observation JSON file")
	provenanceOutput := flags.String("provenance-output", "", "explicit provenance sidecar output file")
	artifactFile := flags.String("artifact-file", "", "exact caller stdout artifact basename")
	evaluationTime := flags.String("evaluation-time", "", "explicit offline replay comparison clock, RFC3339Nano")
	checkpointOut := flags.String("checkpoint-out", "", "explicit next incremental staging checkpoint; enables v2")
	checkpointIn := flags.String("checkpoint-in", "", "explicit prior native checkpoint; omitted only for cursor-zero bootstrap")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return errors.New("invalid arguments: require --input, --as-of and --source-version")
	}
	producerMode, hasAsOf, hasEvaluation, incrementalMode, hasCheckpointIn := false, false, false, false, false
	flags.Visit(func(value *flag.Flag) {
		switch value.Name {
		case "roster", "auth-files-observation", "provenance-output", "artifact-file":
			producerMode = true
		case "checkpoint-in":
			incrementalMode, hasCheckpointIn = true, true
		case "checkpoint-out":
			incrementalMode = true
		case "as-of":
			hasAsOf = true
		case "evaluation-time":
			hasEvaluation = true
		}
	})
	if incrementalMode {
		return runIncremental(incrementalOptions{
			input: *input, sourceVersion: *sourceVersion, roster: *roster, authFiles: *authFiles,
			provenanceOutput: *provenanceOutput, artifactFile: *artifactFile,
			checkpointIn: *checkpointIn, checkpointOut: *checkpointOut,
			evaluationTime: *evaluationTime, replay: hasEvaluation, hasAsOf: hasAsOf, hasCheckpointIn: hasCheckpointIn,
		}, stdout)
	}
	var now time.Time
	if producerMode {
		if *input == "" || !lowerHex(*sourceVersion, 40) || *roster == "" || *authFiles == "" || *provenanceOutput == "" || !validArtifactBasename(*artifactFile) || hasAsOf {
			return errors.New("invalid producer arguments: require input, source-version and all four provenance options; as-of is legacy only")
		}
		now = time.Now().UTC()
		if hasEvaluation {
			parsed, errParse := time.Parse(time.RFC3339Nano, *evaluationTime)
			if errParse != nil || parsed.IsZero() {
				return errors.New("invalid --evaluation-time: require RFC3339 timestamp with timezone")
			}
			now = parsed.UTC()
		}
		if errPath := validateSidecarPath(*provenanceOutput, *input, *roster, *authFiles); errPath != nil {
			return errPath
		}
	} else {
		if hasEvaluation {
			return errors.New("evaluation-time requires producer provenance options")
		}
		if *input == "" || *asOf == "" || !lowerHex(*sourceVersion, 40) {
			return errors.New("require --input, --as-of and --source-version (full 40-digit lowercase commit)")
		}
		parsed, errParse := time.Parse(time.RFC3339Nano, *asOf)
		if errParse != nil || parsed.IsZero() {
			return errors.New("invalid --as-of: require RFC3339 timestamp with timezone")
		}
		now = parsed
	}
	raw, errRead := os.ReadFile(*input)
	if errRead != nil {
		return errors.New("cannot read input capture")
	}
	var capture quotaCapture
	if errDecode := json.Unmarshal(raw, &capture); errDecode != nil || capture.Seats == nil {
		return errors.New("invalid capture: require a JSON object with captured_at and seats array")
	}
	if captured, errCaptured := time.Parse(time.RFC3339Nano, capture.CapturedAt); errCaptured != nil || captured.IsZero() {
		return errors.New("invalid capture: captured_at must be RFC3339 with timezone")
	}
	var producer *producerContext
	if producerMode {
		prepared, errPrepare := prepareProducer(raw, *roster, *authFiles, now, hasEvaluation)
		if errPrepare != nil {
			return errPrepare
		}
		producer = prepared
		capture.Seats = producer.captureSeats()
	}
	captureHash := sha256.Sum256(raw)
	view := normalizedCapture{
		SchemaVersion: schemaVersion, SourceCaptureSHA256: hex.EncodeToString(captureHash[:]),
		SourceVersion: *sourceVersion, Source: "usage_events", AsOf: now.UTC().Format(time.RFC3339Nano),
		CapturedAt: capture.CapturedAt, CapturedAtBasis: "capture_fetch_time_not_acquisition",
		RosterCompleteness: "unverified", Seats: make([]normalizedSeat, 0, len(capture.Seats)),
	}
	if producer != nil {
		view.AsOf = producer.sourceAsOf.UTC().Format(time.RFC3339Nano)
	}
	identities := make(map[string]struct{}, len(capture.Seats))
	for _, seat := range capture.Seats {
		if !lowerHex(seat.AuthIndex, 16) {
			return errors.New("invalid capture: each seat needs a 16-digit lowercase hex auth_index")
		}
		view.Seats = append(view.Seats, normalizeSeat(seat, now))
		identities[seat.AuthIndex] = struct{}{}
	}
	view.ObservedSeats = len(identities)
	sort.SliceStable(view.Seats, func(i, j int) bool {
		a, b := view.Seats[i], view.Seats[j]
		if a.AuthIndex != b.AuthIndex {
			return a.AuthIndex < b.AuthIndex
		}
		if a.Provider != b.Provider {
			return a.Provider < b.Provider
		}
		return modelValue(a.ObservedModel) < modelValue(b.ObservedModel)
	})
	// Bind the artifact to all projected facts, clock and versions. The source
	// capture hash separately identifies the exact original bytes, not its path.
	preimage, errMarshal := json.Marshal(view)
	if errMarshal != nil {
		return errors.New("cannot encode normalized capture")
	}
	snapshotHash := sha256.Sum256(preimage)
	view.CapacitySnapshotID = "sha256:" + hex.EncodeToString(snapshotHash[:])
	output, errOutput := json.MarshalIndent(view, "", "  ")
	if errOutput != nil {
		return errors.New("cannot encode normalized capture")
	}
	output = append(output, '\n')
	if producer != nil {
		sidecar, errSidecar := producer.provenance(view, output, *artifactFile, now)
		if errSidecar != nil {
			return errSidecar
		}
		if errWrite := os.WriteFile(*provenanceOutput, sidecar, 0600); errWrite != nil {
			return errors.New("cannot write provenance sidecar")
		}
	}
	if n, errWrite := stdout.Write(output); errWrite != nil || n != len(output) {
		return errors.New("cannot write normalized capture")
	}
	return nil
}

func normalizeSeat(seat captureSeat, now time.Time) normalizedSeat {
	view := normalizedSeat{
		AuthIndex: seat.AuthIndex, Provider: "unknown", ObservedModelBasis: "usage_event_request_model_not_quota_scope",
		QuotaScope: "unverified", Health: "unknown", CreditsApproval: "unverified",
		NonAcquisitionDiagnostics: nonAcquisitionDiagnostics{
			RequestTimestampMS: seat.TimestampMS, RequestTimestampBasis: "request_started_not_acquisition",
			RowInsertTimestampMS: seat.CreatedAtMS, RowInsertBasis: "row_inserted_not_acquisition",
		},
	}
	switch seat.Provider {
	case "claude", "codex", "kimi":
		view.Provider = seat.Provider
	default:
		view.Diagnostics = append(view.Diagnostics, "unrecognized_provider")
	}
	if knownObservedModel(view.Provider, seat.Model) {
		model := seat.Model
		view.ObservedModel = &model
	} else {
		view.Diagnostics = append(view.Diagnostics, "unrecognized_observed_model")
	}
	if seat.Timestamp != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, seat.Timestamp); err == nil {
			stamp := parsed.UTC().Format(time.RFC3339Nano)
			view.NonAcquisitionDiagnostics.RequestTimestamp = &stamp
		} else {
			view.Diagnostics = append(view.Diagnostics, "invalid_request_timestamp")
		}
	}
	// Only the wire's explicitly supplied per-header acquisition map is trusted.
	// Capture, request and row-insert timestamps are never fallback acquisitions.
	acquiredAt := make(map[string]time.Time, len(seat.ResponseHeadersObservedAt))
	invalidAcquisition := false
	for key, value := range seat.ResponseHeadersObservedAt {
		stamp, err := time.Parse(time.RFC3339Nano, value)
		if key == "" || http.CanonicalHeaderKey(key) != key || err != nil || stamp.IsZero() {
			invalidAcquisition = true
			continue
		}
		acquiredAt[key] = stamp
	}
	if invalidAcquisition {
		view.Diagnostics = append(view.Diagnostics, "invalid_acquisition_timestamp_map")
	}
	view.Quota = auth.NormalizeQuotaHeaderWindows(view.Provider, seat.Headers, acquiredAt, now, auth.QuotaWindowProvenance{
		Source: "usage_events", TimestampBasis: "unknown",
	})
	return view
}

func lowerHex(value string, digits int) bool {
	if len(value) != digits {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func knownObservedModel(provider, model string) bool {
	switch provider {
	case "claude":
		return model == "claude-opus-5-5" || model == "claude-fable-5-1"
	case "codex":
		return model == "gpt-6.1-sol" || model == "gpt-6-luna" || model == "gpt-6-astra"
	default:
		return false
	}
}

func modelValue(model *string) string {
	if model == nil {
		return ""
	}
	return *model
}
