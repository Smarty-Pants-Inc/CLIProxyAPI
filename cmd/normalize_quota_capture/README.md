# Offline quota capture normalization

This command reads one explicitly named, redacted `usage_events` capture and
writes one JSON seat/window artifact to stdout. It reuses the pure SDK
`auth.NormalizeQuotaHeaderWindows` parser, the existing content-ID serialization,
and standard Go JSON for an optional provenance sidecar. This is not a new
service, quota parser, credential loader, scheduler or capacity aggregator. It
never reads a database, live gateway, credential material or runtime configuration,
fetches providers, dispatches requests, or claims live capacity/START permission.
Producer mode reads only explicitly supplied sanitized offline files.

```sh
normalize_quota_capture \
  --input quota-capture-2026-11-05T104539Z.json \
  --as-of 2026-11-05T10:45:39Z \
  --source-version FULL_40_DIGIT_LOWERCASE_SOURCE_COMMIT > seat-windows.json
```

In legacy mode all three flags are mandatory. `--as-of` accepts RFC3339 with a
timezone and optional nanoseconds; it is the comparison clock, not an observation
timestamp. Without the provenance options, the original behavior and output
bytes are unchanged, including acceptance of ignored unknown producer metadata.
`--source-version` must be the exact full commit of the normalizer source used to
build the command. This is an explicit caller assertion: the offline command
validates its form but does not query Git or infer a version. The caller must
pin the actual candidate, including the SDK parser; do not label dirty source as
a clean commit. Input/argument errors produce no JSON and a fixed, non-sensitive
error on stderr. A stdout transport error may leave partial output and is an
error, not a usable artifact. Legacy mode writes only stdout; the shell redirect
above belongs to the caller. The existing two-argument `run(args, stdout) error`
boundary remains unchanged; `main` prints its fixed error to stderr and exits 1.

## Input and acquisition provenance

The supplied shape is a JSON object with `captured_at` (RFC3339 with timezone)
and `seats` (array). Each seat has a 16-digit lowercase hex `auth_index`,
`provider`, exact request `model`, and raw `headers: {"Canonical-Header":["value"]}`.
Missing/malformed identities reject the capture rather than inventing IDs.
In legacy mode, empty `seats: []` is an explicit zero-observation artifact with
unverified roster completeness. Producer mode cannot emit without a source
acquisition. Absent/null seats or malformed JSON are errors. Missing/empty
headers retain the seat as unknown, never free capacity.

The historical 2026-11-05 capture has **no acquisition timestamps**. Its windows
remain **unknown/unverified**, even when numeric utilization, headroom and
absolute resets are valid. Codex primary in this capture is weekly because its
reported duration is 10080 minutes, not because it is called primary. A
zero-minute secondary is not five-hour free capacity; without acquisition
provenance even that absence observation is unverified.

A newer usage-event wire may supply, on each seat, the optional map:

```json
"response_headers_observed_at": {
  "Anthropic-Ratelimit-Unified-7d-Utilization": "2026-11-05T10:44:39.123456789Z",
  "Anthropic-Ratelimit-Unified-7d-Reset": "2026-11-05T10:44:39.123456789Z",
  "Anthropic-Ratelimit-Unified-7d-Status": "2026-11-05T10:44:39.123456789Z"
}
```

Only actually supplied, nonzero RFC3339Nano times under canonical header keys
are passed as acquisition evidence. Bad entries are ignored and diagnosed with
a fixed code. Missing/empty maps stay unknown. The SDK requires coherent
per-header provenance for each window and labels verified timing
`header_acquisition`; a label alone cannot verify an observation. The parser
owns freshness (<=300 seconds), future/reset checks, all five window states,
relative-reset diagnostics, credit facts and malformed-sibling isolation. The
adapter neither duplicates those rules nor supplies a fallback timestamp.

`captured_at` is retained exactly and labelled `capture_fetch_time_not_acquisition`.
Request `timestamp`/`timestamp_ms` and row `created_at_ms` survive only in
`non_acquisition_diagnostics`, respectively labelled
`request_started_not_acquisition` and `row_inserted_not_acquisition`. A valid
request timestamp is rendered as the same instant in UTC; an invalid string is
not echoed. None of these fields establishes freshness. There is no wall-clock
read in legacy mode, replay restamp or timestamp derived by subtracting relative
resets. Producer mode's separate evaluation clock is described below.

## Opt-in offline producer

```sh
normalize_quota_capture \
  --input paired-quota-capture.json \
  --source-version FULL_40_DIGIT_LOWERCASE_SOURCE_COMMIT \
  --roster ROSTER.json \
  --auth-files-observation sanitized-auth-files.json \
  --provenance-output section-2.provenance.json \
  --artifact-file section-2.json > section-2.json
```

All four provenance options are required together, with `--input` and
`--source-version`. `--artifact-file` is the **exact basename** of the caller's
stdout artifact, not another output location. `--as-of` is rejected in producer
mode. Optional `--evaluation-time RFC3339Nano` is an explicit, labelled **offline
replay comparison clock**, valid only in producer mode; otherwise comparison uses
actual UTC time. Replay is not a live freshness claim.

### Explicit inputs and atomic selection

The producer capture uses the core shape above, plus root
`"gateway_id":"fleet-cliproxyapi-ryzen1"` (required). Each row may carry a numeric
integer `id` and an exact string `reasoning_effort`, alongside the same row's
`model`, `headers` and `response_headers_observed_at`. Producer metadata is decoded
only in opt-in mode. No request model or effort is inferred from a route ID.

Before final SDK normalization, same-auth Codex rows are reduced to one atomic
response pack. Every present header in a duplicated pack must have the same
valid per-header acquisition instant; missing/mixed acquisitions refuse the
ambiguous pool. The newest acquisition wins, at nanosecond precision; row ID is
only an equal-acquisition tie-break. Equal-time conflicting rows without distinct
IDs refuse. Quota/reset values, request/insert timestamps, and ID magnitude do
not outrank acquisition. A newer invalid/exhausted pack is never replaced by an
older positive pack. No header/origin fields are merged across rows. Unsupported
provider duplicates or cross-provider identity conflicts refuse rather than
violating the consumer's one-seat-per-auth invariant. Unique non-Codex rows retain
the legacy evidence projection but never gain a Codex route binding.

A singleton with missing/partial acquisition remains unverified; it cannot borrow
a sibling's stamp. **Source `as_of` is the minimum/oldest valid acquisition among
selected source headers**, never the maximum, request/insert time, `captured_at`,
run time or evaluation override. If no selected source header has an acquisition,
producer mode refuses to emit. Each window still uses its own original map and
is normalized against the separate actual/explicit evaluation clock, not source
`as_of`. Thus old signals stay stale even when a capture or replay clock is newer.

The roster is an object with an explicit `routes` array. Its relevant row shape is:

```json
{
  "route_id": "fleet:cpa:6e912530b1784ac7:gpt-6-luna:effort=low",
  "gateway_id": "fleet-cliproxyapi-ryzen1",
  "provider": "codex",
  "auth_index": "6e912530b1784ac7",
  "model_profile": {"model": "gpt-6-luna", "effort": "low"},
  "deployment": "cpa-auth:6e912530b1784ac7",
  "limit_scope": {"scope_id": "cpa:6e912530b1784ac7"}
}
```

Join gateway/provider/auth/exact model/exact effort to exactly one supplied route,
including the explicit deployment and scope checks. Missing/unqualified model or
effort leaves no projection. Duplicate route IDs, ambiguous identities or malformed
explicit bindings reject; there is no first-match fallback, alias, wildcard,
route-ID parsing or broader fan-out. Final `seat_index` refers to the sorted,
normalized selected row with matching provider/auth/observed model. Default
primary+secondary are one account pool; opaque namespaces do not establish model
applicability or multiply the pool by model/effort.

### Independent auth health

Supply an explicit wrapper, never credential files. This example is **synthetic**:

```json
{
  "gateway_id": "fleet-cliproxyapi-ryzen1",
  "observed_at": "2026-11-06T11:33:52.196199291Z",
  "files": [{
    "auth_index": "6e912530b1784ac7",
    "provider": "codex",
    "status": "active",
    "disabled": false,
    "unavailable": false,
    "cooldowns": []
  }]
}
```

`observed_at` is the actual source auth-files read receipt, not roster generation
or quota time. A fixed matching gateway and a valid receipt with inclusive
`0 <= evaluation - acquisition <= 300 seconds` are required to supply current
health. Wrong/missing gateway or missing/invalid/future/stale receipt cannot do
so. An explicit empty/unavailable wrapper (`files: []`, missing receipt) is valid:
quota and route projection may still be emitted, with empty/unknown health.
Duplicate auth identities or a provider conflicting with the selected source
reject rather than first-match.

Active is true only with explicitly typed `status == "active"`, `disabled == false`
and `unavailable == false`. Other explicit states are non-active; missing, null
or untyped flags stay unknown. Cooldowns are credential/auth-wide only: explicit
`[]` means false; an entry with `scope: "credential"` means true. Known
`scope: "model"` entries do not become credential gates. Missing/null lists or
unknown entry scope cannot grant false. Model keys and errors are never emitted.

Native auth-files rows have **no auth-wide `limit_reached` Boolean**. The approved
producer-only policy uses native SDK `Quota.LimitSignals` and default-window
classification, with the original per-header acquisition map:

- True if any fresh required-window signal has `Limit-Reached=true` or
  `Allowed=false`.
- False only if **every** required window affirmatively supplies fresh
  `Allowed=true` or `Limit-Reached=false`, without an invalid/stale present status
  counterpart. Missing signals are unknown, never false.
- Primary and secondary are required except genuinely fresh native
  `not_applicable/upstream_absent` evidence. Any absence used to exclude a sibling
  contributes its acquisition. An empty required set is unknown, not vacuous false.
- Each used flag has its own inclusive 0..300-second acquisition check. Global
  or namespaced signals cannot grant this default auth-wide false. Percentages,
  credits, resets, absence alone and quota `state == "exhausted"` are not Boolean
  health evidence: 98% local exhaustion is distinct from provider refusal.
  Native header-conflict handling is not bypassed.

Partial health fields are omitted when unknown. A complete admission record
requires all three typed booleans, not omitted defaults. Health `observed_at` is
independently the **oldest auth-files receipt and flag/membership acquisition
actually used**, never restamped as source `as_of`, evaluation time or now.
Historical roster health is ignored. Frozen real examples missing flags remain
unknown/HOLD even if quota numbers exist.

### Existing sidecar slots, exact schema

The sidecar has these fields (hashes and counts below are schematic):

```json
{
  "artifact_file": "section-2.json",
  "artifact_sha256": "LOWERCASE_SHA256",
  "verification": {
    "source_commit": "FULL_40_DIGIT_LOWERCASE_SOURCE_COMMIT",
    "as_of": "OLDEST_SELECTED_HEADER_ACQUISITION",
    "schema_version": "seat_quota_windows.v1",
    "capacity_snapshot_id": "sha256:CONTENT_ID",
    "artifact_sha256": "LOWERCASE_SHA256",
    "source_capture_sha256": "ORIGINAL_CAPTURE_BYTES_SHA256",
    "roster_sha256": "ORIGINAL_ROSTER_BYTES_SHA256",
    "auth_files_observation_sha256": "ORIGINAL_AUTH_OBSERVATION_BYTES_SHA256",
    "observed_seats": 1,
    "observed_by_provider": {"codex": 1},
    "window_states": {"known": 1, "not_applicable": 1},
    "evaluated_at": "SEPARATE_COMPARISON_CLOCK",
    "evaluation_time_basis": "actual_utc"
  },
  "route_projection": {
    "fleet:cpa:6e912530b1784ac7:gpt-6-luna:effort=low": {
      "seat_index": 0,
      "origin_route_id": "fleet:cpa:6e912530b1784ac7:gpt-6-luna:effort=low",
      "origin": {
        "gateway_id": "fleet-cliproxyapi-ryzen1",
        "provider": "codex",
        "auth_index": "6e912530b1784ac7",
        "model": "gpt-6-luna",
        "reasoning_effort": "low"
      }
    }
  },
  "auth_health": {
    "6e912530b1784ac7": {
      "gateway_id": "fleet-cliproxyapi-ryzen1",
      "active": true,
      "cooldown": false,
      "limit_reached": false,
      "observed_at": "OLDEST_HEALTH_EVIDENCE_USED"
    }
  }
}
```

Projection objects have **exactly** `seat_index`, `origin_route_id`, `origin`;
origin objects have **exactly** `gateway_id`, `provider`, `auth_index`, `model`,
`reasoning_effort`. Consumer route equals origin route. No extra diagnostics,
deployment or scope fields are inserted into these minimal objects. Missing
projection/health are empty maps. `verification.observed_seats == len(seats)`;
window-state counts and normalized provider counts cover exactly those seats.
Explicit replay sets `evaluation_time_basis: "explicit_offline_replay"`.

The artifact digest hashes **exact stdout bytes, including its final newline**.
Capture/roster/auth-input digests hash each original immutable file, not a
re-encoded or filtered copy. Existing snapshot content-ID generation is reused.
All input validation and both JSON serializations finish before sidecar/stdout
writes. The only producer file write is the explicitly named sidecar; it cannot
overwrite an input or an existing input hardlink/symlink alias. Input errors emit
neither output. Transport/write failure is an error and any partial/mismatched
pair is unusable. Paths, source names/emails, status prose, credentials, raw
headers and error bodies are not copied into the sidecar. Inputs are not mutated.

This is offline source evidence only, not a live gateway/deployment, known
capacity, complete roster, spending approval or START claim. Admission remains
with the consumer and its independent policy/health/equivalence/grant checks.

## Output contract: `seat_quota_windows.v1`

- `schema_version`, `as_of` (UTC RFC3339Nano), `source_version`, and fixed
  `source: "usage_events"` identify interpretation and provenance. Legacy `as_of`
  is the caller comparison clock; producer `as_of` is oldest source acquisition.
- `source_capture_sha256` is lowercase SHA256 of the exact input bytes, including
  whitespace. File paths do not enter output or identity.
- `capacity_snapshot_id` is `sha256:` followed by SHA256 of the compact Go JSON
  encoding of the complete normalized envelope **with that ID field omitted**.
  It binds schema, capture hash, code version, source `as_of` and projected facts
  (including SDK window ages at the comparison clock). The final artifact is
  indented JSON with a trailing newline. Identical bytes and args yield identical
  stdout in legacy mode or with an explicit producer replay clock. Producer mode's
  default real evaluation time is not a deterministic replay. Neither clock nor
  version changes restamp acquisition times.
- `observed_seats` counts distinct observed `auth_index` values only;
  `roster_completeness` is always `unverified`. The supplied 62 observed seats
  do not prove 64-seat coverage. No absent identities or roster rows are added.
- `seats` are sorted by `auth_index`, then provider and exact observed model,
  preserving input order on ties. Each row retains its own SDK `quota` result;
  legacy observations are not reduced. Producer selection is described above;
  neither mode merges header packs. SDK window timestamps/ages/durations/reset values
  use seconds, percentages use 0..100 and absent numbers are JSON null.
- `observed_model` is the exact allowlisted usage-event request model, explicitly
  labelled `usage_event_request_model_not_quota_scope`. It does not assert that
  an account-wide or opaque limit namespace applies to that model.
- `quota_scope: "unverified"`, `health: "unknown"` and
  `credits_approval: "unverified"` remain independent of provider credit facts.
  `cooldown_until` and `next_retry_at` are null: this capture does not supply
  verified scoped retry/health state. HTTP success/failure is not health proof.

In the normalized artifact, only `auth_index` and the provider/model allowlist
below are emitted from identity fields. Producer sidecar identity fields are
limited to the explicit binding schema above. Other strings/unknown fields,
capture source prose, seat names/emails,
request IDs, tokens, recent history and raw headers are not copied. Provider
quota facts come only from the SDK's bounded quota projection.

| Provider | Exact observed-model values allowed by this capture adapter |
| --- | --- |
| `claude` | `claude-opus-5-5`, `claude-fable-5-1` |
| `codex` | `gpt-6.1-sol`, `gpt-6-luna`, `gpt-6-astra` |
| `kimi` | No qualified model/window parser; explicitly `unknown/unsupported_provider` |

An unrecognized provider is emitted as `unknown`, not its arbitrary source
string. An unrecognized model is null with a fixed diagnostic, never mapped to
an equivalent model. Extending this capture-specific allowlist is a separate
source change, not dynamic route discovery.

## Route and admission boundary

Legacy output remains **seat/window evidence only**, with no inferred route
mapping. Producer mode adds only exact supplied origin bindings and justified
independent health in existing sidecar slots. Neither mode implements the reader,
route eligibility, aggregate headroom, cost, equivalence policy or START grant,
nor changes CPA's selectors. No absent roster seats are fabricated.

## Validation ownership

`main_test.go` exercises the real `run(args, stdout)` boundary with disk inputs
and a file-backed stdout, reduced real Claude/Codex rows, repeat-byte equality,
content IDs, no input mutation/restamp, missing and explicit acquisition maps,
300-second/nanosecond boundaries, malformed siblings, no secret echo, malformed
inputs/arguments and empty/unsupported evidence. Synthetic acquisition times in
tests are labelled test provenance, not recovered historical evidence. Keep
reason: data safety and the acquisition-provenance trust boundary.

`producer_test.go` is separately owned by the test sibling. Producer acceptance
covers the real `run(args, stdout)` seam, atomic newest-row selection, exact
origin/effort binding, two clocks, independent partial health, exact sidecar
hashes/counts, input immutability and unchanged legacy metadata acceptance.
Synthetic health/acquisition fixtures must be labelled synthetic, not live proof.

The source implementation task runs only gofmt on its own Go files and
`git diff --check`, not tests/builds. The parent owns all test/build execution
after sibling source writers are terminal:

```sh
go test ./cmd/normalize_quota_capture
go build -o test-output ./cmd/server && rm test-output
```

A full supplied-capture CLI run is additional parent evidence; fixture tests do
not establish live freshness, roster coverage or route eligibility. No network,
gateway or credential operation is needed for this command's runtime.
