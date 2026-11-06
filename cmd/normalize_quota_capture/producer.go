package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const producerGateway = "fleet-cliproxyapi-ryzen1"

// Producer-only metadata must not narrow the legacy decoder's acceptance of
// ignored fields. Each selected row keeps its headers, acquisitions and origin.
type producerSeat struct {
	captureSeat
	ID              *int64  `json:"id"`
	ReasoningEffort *string `json:"reasoning_effort"`
}

type producerOrigin struct {
	GatewayID       string `json:"gateway_id"`
	Provider        string `json:"provider"`
	AuthIndex       string `json:"auth_index"`
	Model           string `json:"model"`
	ReasoningEffort string `json:"reasoning_effort"`
}

type producerProjection struct {
	SeatIndex     int            `json:"seat_index"`
	OriginRouteID string         `json:"origin_route_id"`
	Origin        producerOrigin `json:"origin"`
}

type producerRoute struct {
	RouteID      string `json:"route_id"`
	GatewayID    string `json:"gateway_id"`
	Provider     string `json:"provider"`
	AuthIndex    string `json:"auth_index"`
	Deployment   string `json:"deployment"`
	ModelProfile struct {
		Model  string `json:"model"`
		Effort string `json:"effort"`
	} `json:"model_profile"`
	LimitScope struct {
		ScopeID string `json:"scope_id"`
	} `json:"limit_scope"`
}

type producerAuthFile struct {
	AuthIndex   string          `json:"auth_index"`
	Provider    string          `json:"provider"`
	Status      json.RawMessage `json:"status"`
	Disabled    json.RawMessage `json:"disabled"`
	Unavailable json.RawMessage `json:"unavailable"`
	Cooldowns   json.RawMessage `json:"cooldowns"`
}

type producerAuthObservation struct {
	GatewayID  string             `json:"gateway_id"`
	ObservedAt string             `json:"observed_at"`
	Files      []producerAuthFile `json:"files"`
}

type producerHealth struct {
	GatewayID    string `json:"gateway_id"`
	Active       *bool  `json:"active,omitempty"`
	Cooldown     *bool  `json:"cooldown,omitempty"`
	LimitReached *bool  `json:"limit_reached,omitempty"`
	ObservedAt   string `json:"observed_at"`
}

type producerVerification struct {
	SourceCommit               string         `json:"source_commit"`
	AsOf                       string         `json:"as_of"`
	SchemaVersion              string         `json:"schema_version"`
	CapacitySnapshotID         string         `json:"capacity_snapshot_id"`
	ArtifactSHA256             string         `json:"artifact_sha256"`
	SourceCaptureSHA256        string         `json:"source_capture_sha256"`
	RosterSHA256               string         `json:"roster_sha256"`
	AuthFilesObservationSHA256 string         `json:"auth_files_observation_sha256"`
	ObservedSeats              int            `json:"observed_seats"`
	ObservedByProvider         map[string]int `json:"observed_by_provider"`
	WindowStates               map[string]int `json:"window_states"`
	EvaluatedAt                string         `json:"evaluated_at"`
	EvaluationTimeBasis        string         `json:"evaluation_time_basis"`
}

type producerContext struct {
	selected       map[string]producerSeat
	routes         map[producerOrigin]string
	authFiles      map[string]producerAuthFile
	authObservedAt time.Time
	sourceAsOf     time.Time
	rosterHash     string
	authFilesHash  string
	replay         bool
}

func validArtifactBasename(name string) bool {
	return name != "" && name != "." && name != ".." && filepath.Base(name) == name && !strings.ContainsAny(name, "/\\")
}

// A named sidecar must not overwrite any immutable input, including a supplied
// symlink/hardlink alias. No alternate artifact storage is created here.
func validateSidecarPath(output string, inputs ...string) error {
	outPath, errAbs := filepath.Abs(output)
	if errAbs != nil {
		return errors.New("invalid provenance output path")
	}
	outInfo, _ := os.Stat(output)
	for _, input := range inputs {
		inputPath, errInput := filepath.Abs(input)
		if errInput != nil || outPath == inputPath {
			return errors.New("provenance output must not overwrite an input")
		}
		inputInfo, errStat := os.Stat(input)
		if errStat == nil && outInfo != nil && os.SameFile(outInfo, inputInfo) {
			return errors.New("provenance output must not overwrite an input")
		}
	}
	return nil
}

func prepareProducer(raw []byte, rosterPath, authPath string, now time.Time, replay bool) (*producerContext, error) {
	var capture struct {
		GatewayID string         `json:"gateway_id"`
		Seats     []producerSeat `json:"seats"`
	}
	if errDecode := json.Unmarshal(raw, &capture); errDecode != nil || capture.GatewayID != producerGateway || capture.Seats == nil {
		return nil, errors.New("invalid producer capture: require fixed gateway and typed source rows")
	}
	selected, errSelect := selectProducerRows(capture.Seats)
	if errSelect != nil {
		return nil, errSelect
	}
	context := &producerContext{selected: selected, replay: replay}
	for _, row := range context.selected {
		for key, values := range row.Headers {
			if len(values) > 0 {
				context.sourceAsOf = oldestTime(context.sourceAsOf, headerAcquisition(row.captureSeat, key))
			}
		}
	}
	if context.sourceAsOf.IsZero() {
		return nil, errors.New("producer capture has no source header acquisition")
	}
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
	context.routes = make(map[producerOrigin]string)
	routeIDs := make(map[string]bool)
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
		origin := producerOrigin{route.GatewayID, route.Provider, route.AuthIndex, route.ModelProfile.Model, route.ModelProfile.Effort}
		if _, exists := context.routes[origin]; exists {
			return nil, errors.New("ambiguous explicit roster origin")
		}
		context.routes[origin] = route.RouteID
	}
	authRaw, errAuth := os.ReadFile(authPath)
	if errAuth != nil {
		return nil, errors.New("cannot read sanitized auth-files observation")
	}
	var observation producerAuthObservation
	if errDecode := json.Unmarshal(authRaw, &observation); errDecode != nil || observation.Files == nil {
		return nil, errors.New("invalid auth-files observation: require files array")
	}
	context.authFiles = make(map[string]producerAuthFile)
	for _, file := range observation.Files {
		if !lowerHex(file.AuthIndex, 16) {
			return nil, errors.New("invalid auth-files observation identity")
		}
		if _, exists := context.authFiles[file.AuthIndex]; exists {
			return nil, errors.New("duplicate auth-files observation identity")
		}
		if row, exists := context.selected[file.AuthIndex]; exists && file.Provider != row.Provider {
			return nil, errors.New("conflicting auth-files observation provider")
		}
		context.authFiles[file.AuthIndex] = file
	}
	if acquired, errParse := time.Parse(time.RFC3339Nano, observation.ObservedAt); errParse == nil && observation.GatewayID == producerGateway && freshAcquisition(acquired, now) {
		context.authObservedAt = acquired
	}
	context.rosterHash, context.authFilesHash = bytesSHA256(rosterRaw), bytesSHA256(authRaw)
	return context, nil
}

func selectProducerRows(rows []producerSeat) (map[string]producerSeat, error) {
	type observation struct {
		row      producerSeat
		at       time.Time
		coherent bool
	}
	groups := make(map[string][]observation)
	for _, row := range rows {
		if !lowerHex(row.AuthIndex, 16) || (row.ID != nil && *row.ID < 0) {
			return nil, errors.New("invalid producer capture identity")
		}
		at, coherent := responsePackAcquisition(row.captureSeat)
		groups[row.AuthIndex] = append(groups[row.AuthIndex], observation{row, at, coherent})
	}
	selected := make(map[string]producerSeat, len(groups))
	for identity, group := range groups {
		if len(group) > 1 {
			for _, source := range group {
				if source.row.Provider != "codex" {
					return nil, errors.New("unsupported duplicate source identity")
				}
				if !source.coherent {
					return nil, errors.New("unorderable duplicate source observations")
				}
			}
			// Check equal-time/equal-ID conflicts even among superseded rows,
			// so acceptance does not depend on the capture's input ordering.
			sort.SliceStable(group, func(i, j int) bool {
				if !group[i].at.Equal(group[j].at) {
					return group[i].at.Before(group[j].at)
				}
				a, b := group[i].row.ID, group[j].row.ID
				if a == nil || b == nil {
					return a == nil && b != nil
				}
				return *a < *b
			})
			for index := 1; index < len(group); index++ {
				previous, current := group[index-1], group[index]
				if previous.at.Equal(current.at) && !reflect.DeepEqual(previous.row, current.row) {
					a, b := previous.row.ID, current.row.ID
					if a == nil || b == nil || *a == *b {
						return nil, errors.New("conflicting equal-acquisition source observations")
					}
				}
			}
		}
		selected[identity] = group[len(group)-1].row
	}
	return selected, nil
}

func (context *producerContext) captureSeats() []captureSeat {
	seats := make([]captureSeat, 0, len(context.selected))
	for _, row := range context.selected {
		seats = append(seats, row.captureSeat)
	}
	return seats
}

// Ordering is independent of numeric quota validity and freshness. An invalid
// newer response must not cause selection of an older positive response. Mixed
// or missing acquisitions cannot order duplicate atomic response packs.
func responsePackAcquisition(row captureSeat) (time.Time, bool) {
	var acquired time.Time
	for key, values := range row.Headers {
		if len(values) == 0 {
			continue
		}
		at := headerAcquisition(row, key)
		if at.IsZero() || (!acquired.IsZero() && !at.Equal(acquired)) {
			return time.Time{}, false
		}
		acquired = at
	}
	return acquired, !acquired.IsZero()
}

func headerAcquisition(row captureSeat, key string) time.Time {
	key = http.CanonicalHeaderKey(strings.TrimSpace(key))
	if key == "" {
		return time.Time{}
	}
	at, errParse := time.Parse(time.RFC3339Nano, row.ResponseHeadersObservedAt[key])
	if errParse != nil {
		return time.Time{}
	}
	return at
}

func oldestTime(a, b time.Time) time.Time {
	if a.IsZero() || (!b.IsZero() && b.Before(a)) {
		return b
	}
	return a
}

func freshAcquisition(at, now time.Time) bool {
	return !at.IsZero() && !at.After(now) && now.Sub(at) <= 300*time.Second
}

func qualifiedEffort(effort *string) bool {
	if effort == nil {
		return false
	}
	switch *effort {
	case "none", "minimal", "low", "medium", "high", "xhigh", "max":
		return true
	default:
		return false
	}
}

func (context *producerContext) provenance(view normalizedCapture, output []byte, artifactFile string, now time.Time) ([]byte, error) {
	artifactHash := bytesSHA256(output)
	verification := producerVerification{
		SourceCommit: view.SourceVersion, AsOf: view.AsOf, SchemaVersion: view.SchemaVersion,
		CapacitySnapshotID: view.CapacitySnapshotID, ArtifactSHA256: artifactHash, SourceCaptureSHA256: view.SourceCaptureSHA256,
		RosterSHA256: context.rosterHash, AuthFilesObservationSHA256: context.authFilesHash,
		ObservedSeats: len(view.Seats), ObservedByProvider: make(map[string]int), WindowStates: make(map[string]int),
		EvaluatedAt: now.UTC().Format(time.RFC3339Nano), EvaluationTimeBasis: "actual_utc",
	}
	if context.replay {
		verification.EvaluationTimeBasis = "explicit_offline_replay"
	}
	projection := make(map[string]producerProjection)
	health := make(map[string]producerHealth)
	for index, seat := range view.Seats {
		row, exists := context.selected[seat.AuthIndex]
		if !exists {
			return nil, errors.New("normalized seat lost source binding")
		}
		verification.ObservedByProvider[seat.Provider]++
		for _, window := range seat.Quota.Windows {
			verification.WindowStates[window.State]++
		}
		if seat.Provider != "codex" || row.Provider != seat.Provider {
			continue
		}
		if qualifiedEffort(row.ReasoningEffort) && seat.ObservedModel != nil {
			if *seat.ObservedModel != row.Model {
				return nil, errors.New("normalized seat conflicts with source origin")
			}
			origin := producerOrigin{producerGateway, row.Provider, row.AuthIndex, row.Model, *row.ReasoningEffort}
			if routeID, exists := context.routes[origin]; exists {
				projection[routeID] = producerProjection{SeatIndex: index, OriginRouteID: routeID, Origin: origin}
			}
		}
		file, exists := context.authFiles[seat.AuthIndex]
		if !exists || file.Provider != "codex" || context.authObservedAt.IsZero() {
			continue
		}
		active, cooldown := authFileActive(file), authFileCooldown(file.Cooldowns)
		limit, limitAt := producerLimitReached(row.captureSeat, seat.Quota, now)
		if active == nil && cooldown == nil && limit == nil {
			continue
		}
		observed := context.authObservedAt
		if limit != nil {
			observed = oldestTime(observed, limitAt)
		}
		health[seat.AuthIndex] = producerHealth{GatewayID: producerGateway, Active: active, Cooldown: cooldown, LimitReached: limit, ObservedAt: observed.UTC().Format(time.RFC3339Nano)}
	}
	sidecar := struct {
		ArtifactFile    string                        `json:"artifact_file"`
		ArtifactSHA256  string                        `json:"artifact_sha256"`
		Verification    producerVerification          `json:"verification"`
		RouteProjection map[string]producerProjection `json:"route_projection"`
		AuthHealth      map[string]producerHealth     `json:"auth_health"`
	}{artifactFile, artifactHash, verification, projection, health}
	encoded, errMarshal := json.MarshalIndent(sidecar, "", "  ")
	if errMarshal != nil {
		return nil, errors.New("cannot encode provenance sidecar")
	}
	return append(encoded, '\n'), nil
}

func bytesSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func authFileActive(file producerAuthFile) *bool {
	var status *string
	if errDecode := json.Unmarshal(file.Status, &status); errDecode != nil || status == nil || *status == "" {
		return nil
	}
	disabled, unavailable := explicitBool(file.Disabled), explicitBool(file.Unavailable)
	if disabled == nil || unavailable == nil {
		return nil
	}
	value := *status == "active" && !*disabled && !*unavailable
	return &value
}

func explicitBool(raw json.RawMessage) *bool {
	var value *bool
	if errDecode := json.Unmarshal(raw, &value); errDecode != nil {
		return nil
	}
	return value
}

func authFileCooldown(raw json.RawMessage) *bool {
	var entries []json.RawMessage
	if errDecode := json.Unmarshal(raw, &entries); errDecode != nil || entries == nil {
		return nil
	}
	unknown := false
	for _, entry := range entries {
		var scope struct {
			Scope string `json:"scope"`
		}
		if errDecode := json.Unmarshal(entry, &scope); errDecode != nil {
			unknown = true
			continue
		}
		switch scope.Scope {
		case "credential":
			value := true
			return &value
		case "model":
		default:
			unknown = true
		}
	}
	if unknown {
		return nil
	}
	value := false
	return &value
}

// Only approved default-window booleans contribute to auth-wide health. Numeric
// exhaustion, credits, aggregate and opaque namespace signals cannot grant it.
// Native LimitSignals and window classification retain native conflict refusal.
func producerLimitReached(row captureSeat, quota auth.QuotaWindowsView, now time.Time) (*bool, time.Time) {
	value, at, _ := producerLimitReachedEvidence(row, quota, now)
	return value, at
}

// The additional keys expose exactly the flag/membership clocks used by v2;
// the v1 policy and its timestamps remain unchanged.
func producerLimitReachedEvidence(row captureSeat, quota auth.QuotaWindowsView, now time.Time) (*bool, time.Time, []string) {
	windows := make(map[string]auth.QuotaWindowView)
	for _, window := range quota.Windows {
		if window.LimitKey == "x-codex" {
			windows[window.UpstreamWindow] = window
		}
	}
	var rejectedAt, affirmativeAt time.Time
	var rejectedKeys, affirmativeKeys []string
	required, allAffirmative := 0, true
	for _, slot := range []string{"primary", "secondary"} {
		window, exists := windows[slot]
		prefix := "X-Codex-" + slot + "-"
		if exists && window.State == "not_applicable" && window.Reason == "upstream_absent" && window.TimestampBasis == "header_acquisition" {
			at := headerAcquisition(row, prefix+"Window-Minutes")
			if freshAcquisition(at, now) {
				affirmativeAt = oldestTime(affirmativeAt, at)
				affirmativeKeys = append(affirmativeKeys, http.CanonicalHeaderKey(prefix+"Window-Minutes"))
				continue
			}
		}
		required++
		positive, valid := false, exists
		for _, suffix := range []string{"Allowed", "Limit-Reached"} {
			key := http.CanonicalHeaderKey(prefix + suffix)
			raw, present := quota.LimitSignals[key]
			if !present {
				continue
			}
			at := headerAcquisition(row, key)
			value := strings.ToLower(strings.TrimSpace(raw))
			if (value != "true" && value != "false") || !freshAcquisition(at, now) {
				valid = false
				continue
			}
			rejected := (suffix == "Allowed" && value == "false") || (suffix == "Limit-Reached" && value == "true")
			if rejected {
				rejectedAt = oldestTime(rejectedAt, at)
				rejectedKeys = append(rejectedKeys, key)
			} else {
				positive = true
				affirmativeAt = oldestTime(affirmativeAt, at)
				affirmativeKeys = append(affirmativeKeys, key)
			}
		}
		allAffirmative = allAffirmative && valid && positive
	}
	if !rejectedAt.IsZero() {
		value := true
		sort.Strings(rejectedKeys)
		return &value, rejectedAt, rejectedKeys
	}
	if required > 0 && allAffirmative && !affirmativeAt.IsZero() {
		value := false
		sort.Strings(affirmativeKeys)
		return &value, affirmativeAt, affirmativeKeys
	}
	return nil, time.Time{}, nil
}
