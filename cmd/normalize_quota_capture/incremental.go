package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const (
	incrementalSchema = "seat_quota_windows.v2"
	deltaSchema       = "seat_quota_delta.v1"
	checkpointSchema  = "seat_quota_checkpoint.v1"
	provenanceSchema  = "seat_quota_provenance.v2"
	maxRetainedPack   = 64 * 1024
)

type incrementalOptions struct {
	input, sourceVersion, roster, authFiles, provenanceOutput, artifactFile string
	checkpointIn, checkpointOut, evaluationTime                             string
	replay, hasAsOf, hasCheckpointIn                                        bool
}

// The SQL TEXT columns are strings, not JSON objects at this outer boundary.
// Only the native decoder below examines their contents. Failure/status fields
// are deliberately irrelevant to quota observation presence and ordering.
type quotaDeltaRow struct {
	ID                  *int64  `json:"id"`
	Provider            string  `json:"provider"`
	AuthIndex           string  `json:"auth_index"`
	Model               string  `json:"model"`
	ReasoningEffort     *string `json:"reasoning_effort"`
	QuotaJSON           *string `json:"quota_json"`
	QuotaObservedAtJSON *string `json:"quota_observed_at_json"`
	Timestamp           *string `json:"timestamp"`
	TimestampMS         *int64  `json:"timestamp_ms"`
	CreatedAtMS         *int64  `json:"created_at_ms"`
}

type quotaDelta struct {
	SchemaVersion string          `json:"schema_version"`
	GatewayID     string          `json:"gateway_id"`
	CapturedAt    string          `json:"captured_at"`
	AfterID       string          `json:"after_id"`
	ThroughID     string          `json:"through_id"`
	CaughtUp      *bool           `json:"caught_up"`
	Rows          []quotaDeltaRow `json:"rows"`
}

// A retained pack is an atomic, filtered transport object, not parsed windows.
// RawMessage preserves malformed present values and null/missing distinctions.
// Malformed text/oversize objects are represented by a digest-only marker.
type incrementalPack struct {
	ID                        int64                      `json:"id"`
	Origin                    producerOrigin             `json:"origin"`
	Headers                   map[string]json.RawMessage `json:"headers"`
	ResponseHeadersObservedAt map[string]json.RawMessage `json:"response_headers_observed_at"`
	TransportSHA256           string                     `json:"transport_sha256"`
	Marker                    string                     `json:"marker,omitempty"`
	Timestamp                 *string                    `json:"timestamp"`
	TimestampMS               *int64                     `json:"timestamp_ms"`
	CreatedAtMS               *int64                     `json:"created_at_ms"`
}

type incrementalAuthState struct {
	AuthIndex       string           `json:"auth_index"`
	Anchor          *incrementalPack `json:"anchor"`
	Uncertain       *incrementalPack `json:"uncertain"`
	LastUncertainID int64            `json:"last_uncertain_id"`
	Ceiling         *string          `json:"acquisition_ceiling"`
	Unbounded       bool             `json:"unbounded"`
	RecoveryAfter   *string          `json:"recovery_after"`
}

type quotaCheckpoint struct {
	SchemaVersion string                 `json:"schema_version"`
	Source        string                 `json:"source"`
	GatewayID     string                 `json:"gateway_id"`
	RosterSHA256  string                 `json:"roster_sha256"`
	ThroughID     string                 `json:"through_id"`
	Auths         []incrementalAuthState `json:"auths"`
}

type incrementalHealthSignals struct {
	Status             string             `json:"status"`
	SourceObservedAt   *string            `json:"source_observed_at"`
	Active             *bool              `json:"active"`
	ActiveObservedAt   *string            `json:"active_observed_at"`
	Cooldown           *bool              `json:"cooldown"`
	CooldownObservedAt *string            `json:"cooldown_observed_at"`
	LimitReached       *bool              `json:"limit_reached"`
	LimitUsedKeys      []string           `json:"limit_used_keys"`
	LimitAcquiredAt    map[string]*string `json:"limit_acquired_at"`
}

type incrementalSignals struct {
	CurrentPack     *incrementalPack         `json:"current_pack"`
	RetainedAnchor  *incrementalPack         `json:"retained_anchor"`
	UsedQuotaKeys   []string                 `json:"used_quota_keys"`
	QuotaAcquiredAt map[string]*string       `json:"quota_acquired_at"`
	QuotaObservedAt *string                  `json:"quota_observed_at"`
	Health          incrementalHealthSignals `json:"health"`
	ObservedAt      *string                  `json:"observed_at"`
}

type incrementalAuthStatus struct {
	AuthIndex       string  `json:"auth_index"`
	Provider        string  `json:"provider"`
	EvidenceStatus  string  `json:"evidence_status"`
	EffectiveStatus string  `json:"effective_status"`
	HealthStatus    string  `json:"health_status"`
	ObservedAt      *string `json:"observed_at"`
}

type incrementalSeat struct {
	normalizedSeat
	EvidenceStatus string  `json:"evidence_status"`
	ObservedAt     *string `json:"observed_at"`
}

type incrementalView struct {
	SchemaVersion              string                        `json:"schema_version"`
	CapacitySnapshotID         string                        `json:"capacity_snapshot_id,omitempty"`
	SourceCaptureSHA256        string                        `json:"source_capture_sha256"`
	SourceVersion              string                        `json:"source_version"`
	Source                     string                        `json:"source"`
	GatewayID                  string                        `json:"gateway_id"`
	AsOf                       *string                       `json:"as_of"`
	CapturedAt                 string                        `json:"captured_at"`
	CapturedAtBasis            string                        `json:"captured_at_basis"`
	ObservedSeats              int                           `json:"observed_seats"`
	RosterCompleteness         string                        `json:"roster_completeness"`
	SourceStatus               string                        `json:"source_status"`
	AfterID                    string                        `json:"after_id"`
	ThroughID                  string                        `json:"through_id"`
	CaughtUp                   bool                          `json:"caught_up"`
	PriorCheckpointSHA256      *string                       `json:"prior_checkpoint_sha256"`
	NextCheckpointSHA256       string                        `json:"next_checkpoint_sha256"`
	RosterSHA256               string                        `json:"roster_sha256"`
	AuthFilesObservationSHA256 string                        `json:"auth_files_observation_sha256"`
	Seats                      []incrementalSeat             `json:"seats"`
	AuthStatuses               []incrementalAuthStatus       `json:"auth_statuses"`
	Signals                    map[string]incrementalSignals `json:"signals"`
}

type incrementalInputs struct {
	routes       map[producerOrigin]string
	auths        []string
	authFiles    map[string]producerAuthFile
	receipt      *string
	validReceipt time.Time
	rosterHash   string
	authHash     string
}

func runIncremental(options incrementalOptions, stdout io.Writer) error {
	if options.input == "" || !lowerHex(options.sourceVersion, 40) || options.roster == "" || options.authFiles == "" || options.provenanceOutput == "" || !validArtifactBasename(options.artifactFile) || options.checkpointOut == "" || options.hasAsOf || (options.hasCheckpointIn && options.checkpointIn == "") {
		return errors.New("invalid incremental arguments: require checkpoint-out and all producer options; as-of is legacy only")
	}
	now := time.Now().UTC()
	if options.replay {
		parsed, errParse := time.Parse(time.RFC3339Nano, options.evaluationTime)
		if errParse != nil || parsed.IsZero() {
			return errors.New("invalid --evaluation-time: require RFC3339 timestamp with timezone")
		}
		now = parsed.UTC()
	}
	if errPaths := incrementalPaths(options, stdout); errPaths != nil {
		return errPaths
	}
	raw, errRead := os.ReadFile(options.input)
	if errRead != nil {
		return errors.New("cannot read incremental delta")
	}
	var delta quotaDelta
	if errDecode := json.Unmarshal(raw, &delta); errDecode != nil || delta.SchemaVersion != deltaSchema || delta.GatewayID != producerGateway || delta.Rows == nil || delta.CaughtUp == nil || parseNativeTime(delta.CapturedAt).IsZero() {
		return errors.New("invalid incremental delta envelope")
	}
	after, validAfter := decimalCursor(delta.AfterID)
	through, validThrough := decimalCursor(delta.ThroughID)
	if !validAfter || !validThrough || through < after {
		return errors.New("invalid incremental cursor")
	}
	inputs, errInputs := readIncrementalInputs(options.roster, options.authFiles, now)
	if errInputs != nil {
		return errInputs
	}
	checkpoint, priorHash, errCheckpoint := readQuotaCheckpoint(options.checkpointIn, inputs, after)
	if errCheckpoint != nil {
		return errCheckpoint
	}
	states := make(map[string]*incrementalAuthState, len(checkpoint.Auths))
	for index := range checkpoint.Auths {
		state := &checkpoint.Auths[index]
		states[state.AuthIndex] = state
	}
	lastID := after
	for _, row := range delta.Rows {
		if row.ID == nil || *row.ID <= lastID || *row.ID > through || row.Provider != "codex" || states[row.AuthIndex] == nil || len(row.Model) > 256 || (row.ReasoningEffort != nil && len(*row.ReasoningEffort) > 32) {
			return errors.New("invalid incremental row identity or order")
		}
		lastID = *row.ID
		pack, present := decodeIncrementalPack(row)
		if present {
			reduceIncrementalPack(states[row.AuthIndex], pack, now)
		}
	}
	if !*delta.CaughtUp && (len(delta.Rows) == 0 || lastID != through) {
		return errors.New("invalid incomplete incremental page cursor")
	}
	// F6: every candidate above used checkpoint-IN's receipt. A new U has
	// already invalidated it. Only now may this post-read GET bound a future
	// candidate; health alone never clears uncertainty or slides a bound.
	for index := range checkpoint.Auths {
		state := &checkpoint.Auths[index]
		if state.Uncertain != nil && state.Unbounded && state.RecoveryAfter == nil && !inputs.validReceipt.IsZero() {
			state.RecoveryAfter = timeText(inputs.validReceipt)
		}
	}
	checkpoint.ThroughID = delta.ThroughID
	checkpointBytes, errEncode := marshalIncremental(checkpoint)
	if errEncode != nil {
		return errEncode
	}
	view, projection, health := buildIncrementalView(checkpoint, inputs, delta, raw, priorHash, bytesSHA256(checkpointBytes), options.sourceVersion, now)
	preimage, errPreimage := json.Marshal(view)
	if errPreimage != nil {
		return errors.New("cannot encode incremental artifact")
	}
	view.CapacitySnapshotID = "sha256:" + bytesSHA256(preimage)
	output, errOutput := marshalIncremental(view)
	if errOutput != nil {
		return errOutput
	}
	sidecar, errSidecar := incrementalProvenance(view, projection, health, output, options, now)
	if errSidecar != nil {
		return errSidecar
	}
	// These are staging files, not a publication transaction. Any error makes
	// the entire generation unusable, including files already written.
	if errWrite := os.WriteFile(options.checkpointOut, checkpointBytes, 0600); errWrite != nil {
		return errors.New("cannot write incremental checkpoint")
	}
	if errWrite := os.WriteFile(options.provenanceOutput, sidecar, 0600); errWrite != nil {
		return errors.New("cannot write provenance sidecar")
	}
	if n, errWrite := stdout.Write(output); errWrite != nil || n != len(output) {
		return errors.New("cannot write normalized capture")
	}
	return nil
}

func decimalCursor(value string) (int64, bool) {
	if value == "" || (len(value) > 1 && value[0] == '0') {
		return 0, false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return 0, false
		}
	}
	id, errParse := strconv.ParseInt(value, 10, 64)
	return id, errParse == nil
}

func parseNativeTime(value string) time.Time {
	at, errParse := time.Parse(time.RFC3339Nano, value)
	if errParse != nil || at.IsZero() {
		return time.Time{}
	}
	return at
}

func timeText(at time.Time) *string {
	if at.IsZero() {
		return nil
	}
	value := at.UTC().Format(time.RFC3339Nano)
	return &value
}

func optionalTime(value *string) time.Time {
	if value == nil {
		return time.Time{}
	}
	return parseNativeTime(*value)
}

func marshalIncremental(value any) ([]byte, error) {
	raw, errMarshal := json.MarshalIndent(value, "", "  ")
	if errMarshal != nil {
		return nil, errors.New("cannot encode incremental output")
	}
	return append(raw, '\n'), nil
}

func readIncrementalInputs(rosterPath, authPath string, now time.Time) (*incrementalInputs, error) {
	rosterRaw, errRoster := os.ReadFile(rosterPath)
	if errRoster != nil {
		return nil, errors.New("cannot read producer roster")
	}
	var roster struct {
		Routes []producerRoute `json:"routes"`
	}
	if errDecode := json.Unmarshal(rosterRaw, &roster); errDecode != nil || roster.Routes == nil {
		return nil, errors.New("invalid producer roster: require routes array")
	}
	inputs := &incrementalInputs{routes: make(map[producerOrigin]string), authFiles: make(map[string]producerAuthFile), rosterHash: bytesSHA256(rosterRaw)}
	auths, routeIDs := make(map[string]bool), make(map[string]bool)
	for _, route := range roster.Routes {
		if route.RouteID == "" || strings.TrimSpace(route.RouteID) != route.RouteID || routeIDs[route.RouteID] {
			return nil, errors.New("invalid or duplicate explicit roster route")
		}
		routeIDs[route.RouteID] = true
		if route.GatewayID != producerGateway || route.Provider != "codex" {
			continue
		}
		if !lowerHex(route.AuthIndex, 16) || route.Deployment != "cpa-auth:"+route.AuthIndex || route.LimitScope.ScopeID != "cpa:"+route.AuthIndex {
			return nil, errors.New("invalid explicit roster deployment or scope")
		}
		origin := producerOrigin{producerGateway, "codex", route.AuthIndex, route.ModelProfile.Model, route.ModelProfile.Effort}
		if _, exists := inputs.routes[origin]; exists {
			return nil, errors.New("ambiguous explicit roster origin")
		}
		inputs.routes[origin], auths[route.AuthIndex] = route.RouteID, true
	}
	for identity := range auths {
		inputs.auths = append(inputs.auths, identity)
	}
	sort.Strings(inputs.auths)
	authRaw, errAuth := os.ReadFile(authPath)
	if errAuth != nil {
		return nil, errors.New("cannot read sanitized auth-files observation")
	}
	var observation producerAuthObservation
	if errDecode := json.Unmarshal(authRaw, &observation); errDecode != nil || observation.Files == nil {
		return nil, errors.New("invalid auth-files observation: require files array")
	}
	for _, file := range observation.Files {
		if !lowerHex(file.AuthIndex, 16) {
			return nil, errors.New("invalid auth-files observation identity")
		}
		if _, exists := inputs.authFiles[file.AuthIndex]; exists {
			return nil, errors.New("duplicate auth-files observation identity")
		}
		if auths[file.AuthIndex] && file.Provider != "codex" {
			return nil, errors.New("conflicting auth-files observation provider")
		}
		inputs.authFiles[file.AuthIndex] = file
	}
	at := parseNativeTime(observation.ObservedAt)
	if observation.GatewayID == producerGateway && !at.IsZero() {
		inputs.receipt = &observation.ObservedAt // Original spelling, not a float/UTC reconstruction.
		if freshAcquisition(at, now) {
			inputs.validReceipt = at
		}
	}
	inputs.authHash = bytesSHA256(authRaw)
	return inputs, nil
}

func readQuotaCheckpoint(path string, inputs *incrementalInputs, after int64) (quotaCheckpoint, *string, error) {
	checkpoint := quotaCheckpoint{SchemaVersion: checkpointSchema, Source: "usage_events", GatewayID: producerGateway, RosterSHA256: inputs.rosterHash, ThroughID: "0", Auths: make([]incrementalAuthState, len(inputs.auths))}
	for index, identity := range inputs.auths {
		checkpoint.Auths[index].AuthIndex = identity
	}
	if path == "" {
		if after != 0 {
			return checkpoint, nil, errors.New("incremental bootstrap requires cursor zero or a matching native checkpoint")
		}
		return checkpoint, nil, nil
	}
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return checkpoint, nil, errors.New("cannot read prior native checkpoint")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var restored quotaCheckpoint
	errDecode := decoder.Decode(&restored)
	checkpoint = restored // Never let missing fields inherit bootstrap defaults.
	var extra any
	errEnd := decoder.Decode(&extra)
	cursor, validCursor := decimalCursor(checkpoint.ThroughID)
	if errDecode != nil || errEnd != io.EOF || checkpoint.SchemaVersion != checkpointSchema || checkpoint.Source != "usage_events" || checkpoint.GatewayID != producerGateway || checkpoint.RosterSHA256 != inputs.rosterHash || !validCursor || cursor != after || len(checkpoint.Auths) != len(inputs.auths) {
		return checkpoint, nil, errors.New("invalid or mismatched native checkpoint")
	}
	for index, state := range checkpoint.Auths {
		if state.AuthIndex != inputs.auths[index] || state.LastUncertainID < 0 || state.LastUncertainID > cursor || (state.Ceiling != nil && (len(*state.Ceiling) > 64 || optionalTime(state.Ceiling).IsZero())) || (state.RecoveryAfter != nil && (len(*state.RecoveryAfter) > 64 || optionalTime(state.RecoveryAfter).IsZero())) {
			return checkpoint, nil, errors.New("invalid native checkpoint state")
		}
		for _, pack := range []*incrementalPack{state.Anchor, state.Uncertain} {
			if pack != nil && !validCheckpointPack(pack, state.AuthIndex, cursor) {
				return checkpoint, nil, errors.New("invalid native checkpoint pack")
			}
		}
		if state.Uncertain == nil {
			if state.LastUncertainID != 0 || state.Ceiling != nil || state.Unbounded || state.RecoveryAfter != nil {
				return checkpoint, nil, errors.New("invalid native checkpoint uncertainty")
			}
		} else if state.LastUncertainID != state.Uncertain.ID || (!state.Unbounded && state.RecoveryAfter != nil) {
			return checkpoint, nil, errors.New("invalid native checkpoint uncertainty")
		}
		if state.Anchor != nil {
			// Ignore future-relative-to-this-evaluation only for structural
			// validation. The SDK still refuses future evidence at evaluation.
			_, _, complete := packInterval(state.Anchor, time.Time{})
			if !complete {
				return checkpoint, nil, errors.New("invalid native checkpoint anchor")
			}
		}
	}
	hash := bytesSHA256(raw)
	return checkpoint, &hash, nil
}

func validCheckpointPack(pack *incrementalPack, identity string, cursor int64) bool {
	if pack.ID <= 0 || pack.ID > cursor || pack.Origin.GatewayID != producerGateway || pack.Origin.Provider != "codex" || pack.Origin.AuthIndex != identity || len(pack.Origin.Model) > 256 || len(pack.Origin.ReasoningEffort) > 32 || !lowerHex(pack.TransportSHA256, 64) {
		return false
	}
	encoded, errMarshal := json.MarshalIndent(pack, "      ", "  ")
	if errMarshal != nil || len(encoded) > maxRetainedPack {
		return false
	}
	switch pack.Marker {
	case "", "malformed_quota_text", "malformed_acquisition_map", "pack_too_large":
	default:
		return false
	}
	for key := range pack.Headers {
		if !retainedQuotaKey(key) {
			return false
		}
	}
	for key := range pack.ResponseHeadersObservedAt {
		if _, exists := pack.Headers[key]; !exists {
			return false
		}
	}
	return pack.Marker != "" || len(pack.Headers) > 0
}

func retainedQuotaKey(key string) bool {
	name := strings.ToLower(strings.TrimSpace(key))
	return strings.HasPrefix(name, "x-codex-") && name != "x-codex-turn-state"
}

func decodeIncrementalPack(row quotaDeltaRow) (*incrementalPack, bool) {
	transport := struct {
		Quota *string `json:"quota_json"`
		Times *string `json:"quota_observed_at_json"`
	}{row.QuotaJSON, row.QuotaObservedAtJSON}
	encoded, _ := json.Marshal(transport)
	pack := &incrementalPack{
		ID: *row.ID, Origin: producerOrigin{GatewayID: producerGateway, Provider: "codex", AuthIndex: row.AuthIndex, Model: row.Model},
		TransportSHA256: bytesSHA256(encoded), TimestampMS: row.TimestampMS, CreatedAtMS: row.CreatedAtMS,
	}
	if row.ReasoningEffort != nil {
		pack.Origin.ReasoningEffort = *row.ReasoningEffort
	}
	if row.Timestamp != nil && len(*row.Timestamp) <= 128 && !parseNativeTime(*row.Timestamp).IsZero() {
		pack.Timestamp = row.Timestamp
	}
	var headers map[string]json.RawMessage
	if row.QuotaJSON != nil {
		if errDecode := json.Unmarshal([]byte(*row.QuotaJSON), &headers); errDecode != nil {
			pack.Marker = "malformed_quota_text"
			return pack, true
		}
	}
	pack.Headers = make(map[string]json.RawMessage)
	for key, value := range headers {
		if retainedQuotaKey(key) {
			pack.Headers[key] = value
		}
	}
	if len(pack.Headers) == 0 {
		return nil, false // F1: proven absence, including null/empty/transport-only.
	}
	var clocks map[string]json.RawMessage
	if row.QuotaObservedAtJSON != nil {
		if errDecode := json.Unmarshal([]byte(*row.QuotaObservedAtJSON), &clocks); errDecode != nil {
			pack.Marker = "malformed_acquisition_map"
			return boundedIncrementalPack(pack), true
		}
	}
	if clocks != nil {
		pack.ResponseHeadersObservedAt = make(map[string]json.RawMessage)
		for key := range pack.Headers {
			if value, exists := clocks[key]; exists {
				pack.ResponseHeadersObservedAt[key] = value
			}
		}
	}
	return boundedIncrementalPack(pack), true
}

func boundedIncrementalPack(pack *incrementalPack) *incrementalPack {
	// Packs occur three levels below either output root. Include that native
	// indentation in the bound, not only a smaller compact representation.
	encoded, errMarshal := json.MarshalIndent(pack, "      ", "  ")
	if errMarshal != nil || len(encoded) > maxRetainedPack {
		pack.Headers, pack.ResponseHeadersObservedAt = nil, nil
		pack.Marker = "pack_too_large"
	}
	return pack
}

func rawAcquisition(pack *incrementalPack, key string) (*string, time.Time) {
	var value string
	if pack == nil || key == "" || key != http.CanonicalHeaderKey(key) || json.Unmarshal(pack.ResponseHeadersObservedAt[key], &value) != nil {
		return nil, time.Time{}
	}
	at := parseNativeTime(value)
	if at.IsZero() {
		return nil, time.Time{}
	}
	return &value, at
}

// A zero now is structural validation only. Otherwise future values are not
// included in the ceiling: an arbitrary future stamp cannot poison recovery.
func packInterval(pack *incrementalPack, now time.Time) (time.Time, time.Time, bool) {
	var low, high time.Time
	if pack == nil {
		return low, high, false
	}
	complete := pack.Marker == "" && len(pack.Headers) > 0
	for key := range pack.Headers {
		_, at := rawAcquisition(pack, key)
		if at.IsZero() || (!now.IsZero() && at.After(now)) {
			complete = false
			continue
		}
		low = oldestTime(low, at)
		if at.After(high) {
			high = at
		}
	}
	return low, high, complete && !low.IsZero()
}

func reduceIncrementalPack(state *incrementalAuthState, candidate *incrementalPack, now time.Time) {
	low, high, complete := packInterval(candidate, now)
	if !complete {
		markIncrementalUncertain(state, candidate, high, true, now)
		return
	}
	if state.Uncertain != nil {
		ceiling := optionalTime(state.Ceiling)
		bound := optionalTime(state.RecoveryAfter)
		if candidate.ID > state.LastUncertainID && low.After(ceiling) && freshAcquisition(low, now) && (!state.Unbounded || (!bound.IsZero() && low.After(bound))) {
			state.Anchor = candidate
			state.Uncertain, state.Ceiling, state.RecoveryAfter = nil, nil, nil
			state.LastUncertainID, state.Unbounded = 0, false
		} else if high.After(ceiling) {
			state.Ceiling = timeText(high)
		}
		return
	}
	if state.Anchor == nil {
		state.Anchor = candidate
		return
	}
	oldLow, oldHigh, oldComplete := packInterval(state.Anchor, now)
	if !oldComplete {
		markIncrementalUncertain(state, candidate, high, true, now)
		return
	}
	// Equal coherent acquisitions retain the legacy nanosecond/ID tie-break.
	if low.Equal(high) && oldLow.Equal(oldHigh) && low.Equal(oldLow) {
		if candidate.ID > state.Anchor.ID {
			state.Anchor = candidate
		}
		return
	}
	if sameIncrementalEvidence(state.Anchor, candidate) {
		if candidate.ID > state.Anchor.ID {
			state.Anchor = candidate
		}
		return
	}
	if low.After(oldHigh) {
		state.Anchor = candidate
	} else if !high.Before(oldLow) {
		markIncrementalUncertain(state, candidate, high, false, now)
	}
}

func sameIncrementalEvidence(a, b *incrementalPack) bool {
	return a.Origin == b.Origin && sameRawFields(a.Headers, b.Headers) && sameRawFields(a.ResponseHeadersObservedAt, b.ResponseHeadersObservedAt) && a.Marker == b.Marker
}

func sameRawFields(a, b map[string]json.RawMessage) bool {
	if len(a) != len(b) {
		return false
	}
	for key, raw := range a {
		other, exists := b[key]
		if !exists {
			return false
		}
		// Whitespace in SQL JSON is not an acquisition fact. UseNumber avoids
		// collapsing distinct large malformed numeric values through float64.
		var left, right any
		leftDecoder, rightDecoder := json.NewDecoder(bytes.NewReader(raw)), json.NewDecoder(bytes.NewReader(other))
		leftDecoder.UseNumber()
		rightDecoder.UseNumber()
		if leftDecoder.Decode(&left) != nil || rightDecoder.Decode(&right) != nil || !reflect.DeepEqual(left, right) {
			return false
		}
	}
	return true
}

func markIncrementalUncertain(state *incrementalAuthState, candidate *incrementalPack, high time.Time, unbounded bool, now time.Time) {
	ceiling := optionalTime(state.Ceiling)
	_, anchorHigh, _ := packInterval(state.Anchor, now)
	if anchorHigh.After(ceiling) {
		ceiling = anchorHigh
	}
	if high.After(ceiling) {
		ceiling = high
	}
	state.Ceiling = timeText(ceiling)
	state.Uncertain, state.LastUncertainID = candidate, candidate.ID
	if unbounded {
		// NEW U invalidates the old receipt immediately, even if a later P in
		// this same page would have qualified against that superseded bound.
		state.Unbounded, state.RecoveryAfter = true, nil
	}
}

func packCaptureSeat(pack *incrementalPack) (captureSeat, bool) {
	seat := captureSeat{AuthIndex: pack.Origin.AuthIndex, Provider: "codex", Model: pack.Origin.Model, Headers: make(http.Header), ResponseHeadersObservedAt: make(map[string]string), TimestampMS: pack.TimestampMS, CreatedAtMS: pack.CreatedAtMS}
	if pack.Timestamp != nil {
		seat.Timestamp = *pack.Timestamp
	}
	validShape := pack.Marker == ""
	for key, raw := range pack.Headers {
		var values []string
		if errDecode := json.Unmarshal(raw, &values); errDecode != nil || len(values) == 0 {
			validShape = false
		} else {
			seat.Headers[key] = values
		}
		if text, _ := rawAcquisition(pack, key); text != nil {
			seat.ResponseHeadersObservedAt[key] = *text
		}
	}
	return seat, validShape
}

func buildIncrementalView(checkpoint quotaCheckpoint, inputs *incrementalInputs, delta quotaDelta, raw []byte, priorHash *string, nextHash, sourceVersion string, now time.Time) (incrementalView, map[string]producerProjection, map[string]producerHealth) {
	view := incrementalView{
		SchemaVersion: incrementalSchema, SourceCaptureSHA256: bytesSHA256(raw), SourceVersion: sourceVersion,
		Source: "usage_events", GatewayID: producerGateway, CapturedAt: delta.CapturedAt,
		CapturedAtBasis: "sqlite_read_receipt_not_acquisition", RosterCompleteness: "configured_scope_only",
		SourceStatus: "caught_up", AfterID: delta.AfterID, ThroughID: delta.ThroughID, CaughtUp: *delta.CaughtUp,
		PriorCheckpointSHA256: priorHash, NextCheckpointSHA256: nextHash, RosterSHA256: inputs.rosterHash,
		AuthFilesObservationSHA256: inputs.authHash, Seats: make([]incrementalSeat, 0),
		AuthStatuses: make([]incrementalAuthStatus, 0, len(checkpoint.Auths)), Signals: make(map[string]incrementalSignals),
	}
	if !view.CaughtUp {
		view.SourceStatus = "source_catching_up"
	}
	projection, health := make(map[string]producerProjection), make(map[string]producerHealth)
	allAcquired := len(checkpoint.Auths) > 0 && view.CaughtUp
	var oldest time.Time
	for _, state := range checkpoint.Auths {
		status := "unobserved"
		pack := state.Anchor
		if pack != nil {
			status = "selected"
		}
		if state.Uncertain != nil {
			status, pack = "uncertain", state.Uncertain
		}
		effective := status
		if !view.CaughtUp {
			effective = "source_catching_up"
		}
		signals := incrementalSignals{CurrentPack: pack, UsedQuotaKeys: make([]string, 0), QuotaAcquiredAt: make(map[string]*string)}
		if status == "uncertain" {
			signals.RetainedAnchor = state.Anchor
		}
		var capture captureSeat
		var seat normalizedSeat
		if pack != nil {
			var validShape bool
			capture, validShape = packCaptureSeat(pack)
			seat = normalizeSeat(capture, now)
			if effective != "selected" || !validShape {
				seat.Quota = auth.NormalizeQuotaHeaderWindows("codex", nil, nil, now, auth.QuotaWindowProvenance{Source: "usage_events", TimestampBasis: "unknown"})
				seat.Quota.Reason = "uncertain_source_evidence"
				if effective == "source_catching_up" {
					seat.Quota.Reason = "source_catching_up"
				}
			}
			for key := range pack.Headers {
				signals.UsedQuotaKeys = append(signals.UsedQuotaKeys, key)
				text, at := rawAcquisition(pack, key)
				if at.After(now) {
					text = nil
				}
				signals.QuotaAcquiredAt[key] = text
			}
			sort.Strings(signals.UsedQuotaKeys)
			low, _, complete := packInterval(pack, now)
			if effective == "selected" && complete {
				signals.QuotaObservedAt = timeText(low)
				oldest = oldestTime(oldest, low)
			} else {
				allAcquired = false
			}
		} else {
			allAcquired = false
		}
		healthSignals, record := incrementalHealth(state.AuthIndex, inputs, capture, seat.Quota, effective == "selected", now)
		signals.Health = healthSignals
		if record != nil {
			health[state.AuthIndex] = *record
		}
		if signals.QuotaObservedAt != nil && healthSignals.Status == "complete" {
			signals.ObservedAt = timeText(oldestTime(optionalTime(signals.QuotaObservedAt), parseNativeTime(record.ObservedAt)))
		}
		view.AuthStatuses = append(view.AuthStatuses, incrementalAuthStatus{state.AuthIndex, "codex", status, effective, healthSignals.Status, signals.ObservedAt})
		view.Signals[state.AuthIndex] = signals
		if pack == nil {
			continue // Configured coverage is not a fabricated observed seat.
		}
		index := len(view.Seats)
		view.Seats = append(view.Seats, incrementalSeat{seat, effective, signals.ObservedAt})
		if effective == "selected" && seat.ObservedModel != nil && qualifiedEffort(&pack.Origin.ReasoningEffort) {
			if routeID, exists := inputs.routes[pack.Origin]; exists {
				projection[routeID] = producerProjection{index, routeID, pack.Origin}
			}
		}
	}
	view.ObservedSeats = len(view.Seats)
	if allAcquired {
		view.AsOf = timeText(oldest)
	}
	return view, projection, health
}

func incrementalHealth(identity string, inputs *incrementalInputs, capture captureSeat, quota auth.QuotaWindowsView, quotaSelected bool, now time.Time) (incrementalHealthSignals, *producerHealth) {
	signals := incrementalHealthSignals{Status: "unavailable", SourceObservedAt: inputs.receipt, LimitUsedKeys: make([]string, 0), LimitAcquiredAt: make(map[string]*string)}
	file, exists := inputs.authFiles[identity]
	if !exists || file.Provider != "codex" || inputs.validReceipt.IsZero() {
		return signals, nil
	}
	signals.Active, signals.Cooldown = authFileActive(file), authFileCooldown(file.Cooldowns)
	if signals.Active != nil {
		signals.ActiveObservedAt = inputs.receipt
	}
	if signals.Cooldown != nil {
		signals.CooldownObservedAt = inputs.receipt
	}
	var limitAt time.Time
	if quotaSelected {
		var keys []string
		signals.LimitReached, limitAt, keys = producerLimitReachedEvidence(capture, quota, now)
		for _, key := range keys {
			signals.LimitUsedKeys = append(signals.LimitUsedKeys, key)
			text := capture.ResponseHeadersObservedAt[key]
			signals.LimitAcquiredAt[key] = &text
		}
	}
	if signals.Active == nil && signals.Cooldown == nil && signals.LimitReached == nil {
		return signals, nil
	}
	signals.Status = "partial"
	if signals.Active != nil && signals.Cooldown != nil && signals.LimitReached != nil {
		signals.Status = "complete"
	}
	at := inputs.validReceipt
	if signals.LimitReached != nil {
		at = oldestTime(at, limitAt)
	}
	return signals, &producerHealth{GatewayID: producerGateway, Active: signals.Active, Cooldown: signals.Cooldown, LimitReached: signals.LimitReached, ObservedAt: at.UTC().Format(time.RFC3339Nano)}
}

func incrementalProvenance(view incrementalView, projection map[string]producerProjection, health map[string]producerHealth, output []byte, options incrementalOptions, now time.Time) ([]byte, error) {
	providers, windows := make(map[string]int), make(map[string]int)
	for _, seat := range view.Seats {
		providers[seat.Provider]++
		for _, window := range seat.Quota.Windows {
			windows[window.State]++
		}
	}
	basis := "actual_utc"
	if options.replay {
		basis = "explicit_offline_replay"
	}
	verification := map[string]any{
		"source_commit": view.SourceVersion, "as_of": view.AsOf, "schema_version": view.SchemaVersion,
		"capacity_snapshot_id": view.CapacitySnapshotID, "artifact_sha256": bytesSHA256(output),
		"source_capture_sha256": view.SourceCaptureSHA256, "roster_sha256": view.RosterSHA256,
		"auth_files_observation_sha256": view.AuthFilesObservationSHA256,
		"prior_checkpoint_sha256":       view.PriorCheckpointSHA256, "next_checkpoint_sha256": view.NextCheckpointSHA256,
		"observed_seats": view.ObservedSeats, "observed_by_provider": providers, "window_states": windows,
		"evaluated_at": now.UTC().Format(time.RFC3339Nano), "evaluation_time_basis": basis,
	}
	sidecar := struct {
		SchemaVersion   string                        `json:"schema_version"`
		ArtifactFile    string                        `json:"artifact_file"`
		ArtifactSHA256  string                        `json:"artifact_sha256"`
		Verification    map[string]any                `json:"verification"`
		RouteProjection map[string]producerProjection `json:"route_projection"`
		AuthHealth      map[string]producerHealth     `json:"auth_health"`
		AuthStatuses    []incrementalAuthStatus       `json:"auth_statuses"`
		Signals         map[string]incrementalSignals `json:"signals"`
	}{provenanceSchema, options.artifactFile, bytesSHA256(output), verification, projection, health, view.AuthStatuses, view.Signals}
	return marshalIncremental(sidecar)
}

// Resolve existing ancestors too: two not-yet-created outputs under symlinked
// directories may alias even though neither can be passed to os.SameFile yet.
func incrementalPathIdentity(path string) (string, error) {
	absolute, errAbs := filepath.Abs(path)
	if errAbs != nil {
		return "", errAbs
	}
	resolved, errResolve := filepath.EvalSymlinks(absolute)
	if errResolve == nil {
		return resolved, nil
	}
	if !errors.Is(errResolve, os.ErrNotExist) {
		return "", errResolve
	}
	if info, errStat := os.Lstat(absolute); errStat == nil && info.Mode()&os.ModeSymlink != 0 {
		target, errLink := os.Readlink(absolute)
		if errLink != nil {
			return "", errLink
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(filepath.Dir(absolute), target)
		}
		return incrementalPathIdentity(target)
	}
	parent := filepath.Dir(absolute)
	if parent == absolute {
		return "", errResolve
	}
	resolvedParent, errParent := incrementalPathIdentity(parent)
	if errParent != nil {
		return "", errParent
	}
	return filepath.Join(resolvedParent, filepath.Base(absolute)), nil
}

func incrementalPaths(options incrementalOptions, stdout io.Writer) error {
	inputs := []string{options.input, options.roster, options.authFiles}
	if options.checkpointIn != "" {
		inputs = append(inputs, options.checkpointIn)
	}
	outputs := []string{options.checkpointOut, options.provenanceOutput, filepath.Join(filepath.Dir(options.provenanceOutput), options.artifactFile)}
	paths := append(append([]string{}, inputs...), outputs...)
	identities := make([]string, len(paths))
	infos := make([]os.FileInfo, len(paths))
	for index, path := range paths {
		identity, errPath := incrementalPathIdentity(path)
		if errPath != nil {
			return errors.New("invalid incremental staging path")
		}
		identities[index] = identity
		infos[index], _ = os.Stat(path)
	}
	for index := len(inputs); index < len(paths); index++ {
		for prior := 0; prior < index; prior++ {
			if identities[index] == identities[prior] || (infos[index] != nil && infos[prior] != nil && os.SameFile(infos[index], infos[prior])) {
				return errors.New("incremental outputs must not alias inputs or each other")
			}
		}
	}
	if file, ok := stdout.(*os.File); ok {
		info, errStat := file.Stat()
		if errStat != nil {
			return errors.New("cannot inspect incremental stdout")
		}
		for index, other := range infos {
			// The declared artifact path itself is allowed to be stdout.
			if index != len(paths)-1 && other != nil && os.SameFile(info, other) {
				return errors.New("incremental stdout must not alias an input or staging output")
			}
		}
	}
	return nil
}
