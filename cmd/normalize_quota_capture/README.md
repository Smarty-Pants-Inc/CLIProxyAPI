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

Native auth-files rows have **no auth-wide `limit_reached` Boolean**. Both
producer versions use native SDK `Quota.LimitSignals`, default-window membership
and the original per-header acquisition map. Existing explicit-only results
retain their flag precedence and omit the optional fallback basis:

- True if any fresh required-window signal has `Limit-Reached=true` or
  `Allowed=false`. Explicit refusal wins over affirmative siblings.
- With flags on every required window, false requires fresh `Allowed=true` or
  `Limit-Reached=false` on **every** required window, without an invalid/stale
  present status counterpart. Numeric quota classification does not replace
  this explicit-only policy.
- Primary and secondary are required except genuinely fresh native
  `not_applicable/upstream_absent` duration-zero membership. Any absence used to
  exclude a sibling contributes its acquisition. Missing, unknown or stale
  membership does not exclude a window. An empty required set is unknown, not
  vacuous false.

For a required window with **neither explicit flag present**, the approved
missing-flag fallback is:

- False only if a fresh auth-files receipt proves typed active, not disabled,
  not unavailable and no quota cooldown, **and every required window** supplies
  fresh native `used_percent < 100`. In a mixed explicit/missing-flag pack, the
  explicit windows must still have valid affirmative flags as well as fresh
  below-100 percentages; missing sibling flags are not implicitly affirmative.
- True if any required window has fresh native `used_percent >= 100` while the
  missing-flag fallback participates, or a fresh matching auth-files read has
  a known quota cooldown. These are independent vetoes: missing other evidence
  cannot grant false. An auth quota-cooldown veto also survives uncertain,
  catching-up or absent quota, and can veto otherwise affirmative flags.
- Otherwise unknown/HOLD. A present malformed, stale or unclocked flag is **not
  absent** and cannot be replaced by a percentage to grant false. Native header
  conflicts are never bypassed. No retained hidden anchor or old health file is
  used as a substitute.

Quota-cooldown evidence reads the raw typed `reason` separately from the existing
credential-vs-model `cooldown` Boolean. Exact exporter reasons `quota` and
`credential_quota` veto even if scope is unknown. Explicit `[]` proves no quota
cooldown. Known credential/model scope with a known nonquota reason
(`cloudflare_challenge`, `invalid_grant`, `unauthorized`, `payment_required`,
`not_found`, `model_not_supported`, `transient_error`) does not become a quota
veto. Missing/null/malformed lists or missing/unknown scope or reason cannot
prove no quota cooldown. There is no invented `usage` reason or coercion of
strings/numbers to typed evidence. Known model nonquota entries remain non-global
for the independent `cooldown` Boolean.

Each used flag, percentage and exclusion membership has its **own** inclusive
`0 <= evaluation - acquisition <= 300 seconds` check; the auth-files receipt is
checked independently. No reset, row, request, collection or evaluation time
supplies a missing acquisition. The SDK's public
`auth.ParseCodexQuotaUsedPercent` reuses its existing finite nonnegative decimal
grammar, including valid values above 100 for a veto. Normalized windows still
cap their numeric percentages at 100 and retain their existing exhaustion
threshold: **99 is below 100 for this fallback predicate**, even when the SDK
window independently classifies it as exhausted. Global/opaque namespace flags,
credits, resets and absence alone do not grant the fallback.

Fallback-derived true/false results carry
`"limit_reached_basis":"fallback:auth-files+used_percent"` in `auth_health` and
v2 health signals. Unknown results may omit it; explicit-only results omit it.
A cooldown-only true uses its actual auth-files receipt and no fabricated
percentage key. A fresh percentage veto can remain partial when auth-files is
unavailable; it cannot complete admission health or promote its clock.

Partial health fields are omitted when unknown. A complete admission record
requires all three typed booleans, not omitted defaults. Health `observed_at` is
independently the **oldest auth-files receipt and flag/percentage/membership
acquisition actually used**, never restamped as source `as_of`, evaluation time
or now. Historical roster health is ignored. Historical captures without the
required fresh independent evidence remain unknown/HOLD; replay does not invent
that evidence.

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

The health object may additionally contain the optional `limit_reached_basis`
marker described above; it is omitted for explicit-only results.

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

## Opt-in checkpointed native producer: v2

The sections above describe **unchanged v1**. Only `--checkpoint-out NEXT.json`
opts into the separate v2 decoder/reducer below. `--checkpoint-in PREVIOUS.json`
is optional only for an explicit cursor-zero first bootstrap; it is not a
legacy-capture seed. A lone checkpoint-in, missing producer options, `--as-of`,
nonzero bootstrap cursor without a native checkpoint, or mismatched checkpoint
refuses. There is no fallback to v1 after a v2 error.

```sh
# First bounded page, after_id MUST be "0". Paths are caller-owned staging paths.
normalize_quota_capture \
  --input generation-001/delta.json \
  --source-version FULL_40_DIGIT_LOWERCASE_SOURCE_COMMIT \
  --roster ROSTER.json \
  --auth-files-observation generation-001/auth-files.json \
  --checkpoint-out generation-001/next.json \
  --provenance-output generation-001/section-2.provenance.json \
  --artifact-file section-2.json > generation-001/section-2.json

# Next ordinary invocation, only after the wrapper accepted the prior generation.
normalize_quota_capture \
  --input generation-002/delta.json \
  --source-version FULL_40_DIGIT_LOWERCASE_SOURCE_COMMIT \
  --roster ROSTER.json \
  --auth-files-observation generation-002/auth-files.json \
  --checkpoint-in generation-001/next.json \
  --checkpoint-out generation-002/next.json \
  --provenance-output generation-002/section-2.provenance.json \
  --artifact-file section-2.json > generation-002/section-2.json
```

`--evaluation-time RFC3339Nano` remains an explicitly labelled offline replay
clock; without it evaluation uses actual UTC. It never acquires quota. The
native gateway/origin stays **`fleet-cliproxyapi-ryzen1`**, including roster joins.
A publisher's `ryzen1-cpa` scope is wrapper configuration, not a native gateway
alias, org mapping, model equivalence or eligibility decision.

### Exact delta input: `seat_quota_delta.v1`

This synthetic example demonstrates the **outer wire**, not current capacity:

```json
{
  "schema_version": "seat_quota_delta.v1",
  "gateway_id": "fleet-cliproxyapi-ryzen1",
  "captured_at": "2026-11-06T12:00:29Z",
  "after_id": "0",
  "through_id": "100",
  "caught_up": true,
  "rows": [{
    "id": 100,
    "provider": "codex",
    "auth_index": "1111111111111111",
    "model": "gpt-6-luna",
    "reasoning_effort": "low",
    "quota_json": "{\"X-Codex-Primary-Used-Percent\":[\"20\"]}",
    "quota_observed_at_json": "{\"X-Codex-Primary-Used-Percent\":\"2026-11-06T12:00:00.123456789Z\"}",
    "timestamp": "2026-11-06T11:59:00Z",
    "timestamp_ms": 1793966340000,
    "created_at_ms": 1793966410000
  }]
}
```

The exact outer fields are `schema_version`, `gateway_id`, `captured_at`,
`after_id`, `through_id`, `caught_up`, `rows`. `rows` must be an array (including
`[]`), and caught_up must be a Boolean. Each row has the fields illustrated;
`quota_json` and `quota_observed_at_json` are **original SQLite TEXT strings or
JSON null**, NOT decoded JSON objects. Preserve their text unchanged in the
wrapper. Nullable timestamp/model/effort columns may be absent/null; missing
model/effort never obtains a route. Optional failure/status/other row fields are
ignored, not filters or health facts. Model strings over 256 bytes and effort
strings over 32 bytes are unusable outer identities and refuse.

Both cursors are canonical nonnegative signed-int64 decimal **strings** (`0` or
`[1-9][0-9]*`, maximum `9223372036854775807`). Row `id` is a required positive
int64 JSON **integer**, strictly ascending, greater than after_id and at most
through_id; no duplicates/conflicting ID reuse are accepted. Read row IDs with
an int64-capable decoder; do not round them through JavaScript Number.
Row-ID gaps are valid. `after_id` must equal checkpoint-IN's `through_id`. For
`caught_up=false`, `through_id` must strictly advance beyond `after_id`; `rows`
may be empty, and any selected rows may end below `through_id`, because the
cursor follows raw-page progress, not only selected Codex rows. For
`caught_up=true`, `through_id` may include gaps in the exhausted raw range, and
`rows` may also be empty. A missing/malformed checkpoint is an error, never a
reset to empty state.

The wrapper owns one SQLite read transaction: read the global maximum ID H and
fetch one bounded raw `usage_events` page ordered by primary key from that same
snapshot. Derive `through_id` and `caught_up` from all raw page rows and H, then
filter fetched rows in application code to `origin IS NULL`, provider `codex`
and the configured auth scope. Only the initial cold bootstrap may use a SQL
lower bound above zero while wire `after_id` remains `"0"`; subsequent pages
resume from the checkpoint cursor. Do not push the application scope or
value/clock/status/429 filters into SQL, and do not select only the highest ID
per auth. Close SQLite before HTTP/CLI work. `captured_at` is the completed
SQLite read receipt, diagnostic only. Then perform a fresh auth-files GET and
supply its sanitized source receipt. On GET failure supply exactly the
unavailable shape `{"gateway_id":"fleet-cliproxyapi-ryzen1","files":[]}` without a
fabricated receipt. Never reuse the last successful health file as this tick's
observation. The native command itself does not query SQLite or perform/verify
the GET.

Only auths configured by matching Codex roster rows participate. An out-of-scope
row/provider, invalid source/cursor/identity, malformed outer SQL-column type or
malformed roster/health wrapper is a sanitized whole-run error. Malformed quota
or acquisition **TEXT contents** for a valid scoped identity instead become
explicit unknown evidence; the affected auth is not dropped.

### Bounded reducer and restart semantics

The native command retains one ordered whole-pack anchor, at most one uncertain
representative and fixed uncertainty scalars per distinct configured auth. It
keeps no losing history, per-model state, downstream partitions or publication
counter. Each serialized retained pack (including its native output indentation)
is at most **64 KiB**. A larger
pack is a digest-only `pack_too_large` unknown, never a truncated positive. Size
is checked after removing transport/non-Codex keys; an ordinary header-less row
is still a no-observation even if its unused clock column is malformed/large.

Presence is determined before value validation: retain all `x-codex-*` names
except `X-Codex-Turn-State`, including opaque namespaces, malformed values,
empty arrays and nulls. This broad namespace is intentional in this paired
scope; distinguishing nonquota safety-buffering names is deferred (F1.a).
Request-ID headers and other-provider/nonquota namespaces are stripped. A
successfully decoded absent/null/empty/transport-only pack is **no quota
observation (F1)**: it advances only traversal, never quota origin/clocks,
uncertainty, recovery, health or observed-seat coverage. Undecodable text/shapes
cannot prove absence and become unknown. Quota-bearing failed/429 rows still
participate.

Selection precedes SDK quota-value/window parsing. A newer fully clocked
malformed/depleted pack displaces an older positive; a higher-ID older positive
cannot restore it. Coherent acquisitions compare at `time.Time` nanosecond
precision with ID only for an equal acquisition. For independently clocked
packs, only strictly disjoint intervals establish whole-pack order; identical
quota/origin/clock values are duplicates, while nonidentical overlapping
intervals become unknown. No per-window selection, field merge, maximum-clock
winner or clock equalization is performed. Separately coherent SDK windows keep
their own clocks; mixed clocks within one window remain SDK unknown. Valid
header arrays pass to the SDK unchanged. Non-array/null/empty-array header
shapes cannot yield a positive normalized pack. Raw values remain in signals.

Quota-bearing missing/invalid/future clocks set uncertainty and hide the anchor.
A fixed scalar retains the greatest valid nonfuture competitor acquisition;
invalid/future stamps do not poison it. Complete-overlap uncertainty recovers
only with a newly delivered fully clocked pack whose oldest acquisition is
strictly after the entire competitor ceiling and is fresh (`0 <= age <= 300s`).
Unbounded/missing-time uncertainty additionally requires ID > last_uncertain_id
and oldest acquisition strictly after its stored `recovery_after` receipt.

**F3/F6 order:** evaluate this page against checkpoint-IN first. A NEW missing/
invalid/future-clock U immediately invalidates its old receipt, so neither
`P101 -> U102` nor `U102 -> P103` in that page can use the superseded bound. Only
AFTER reduction can this tick's valid post-read source auth receipt establish a
bound for new/still-unbounded U whose bound is absent. An established bound never
slides without a new U. No-quota E, no rows, health-only success, reset passage or
clock passage cannot clear uncertainty. Actual post-bound quota (positive,
depleted or malformed) may recover; the SDK decides its numeric state.

This uses the existing source causal order (header acquisition before insertion,
completed read before GET) and same-gateway wall-clock contract. Serialized Go
clocks are **not** process-monotonic proofs; future and inclusive 300-second
guards remain. Clock steps, installed gateway behavior and live incidence have
not been measured here. There is no new clock monitor/permission gate.

### Exact checkpoint wire: `seat_quota_checkpoint.v1`

All checkpoint fields are emitted, including nulls:

- Root: `schema_version`, fixed `source: "usage_events"`, fixed `gateway_id`,
  `roster_sha256` (exact original roster bytes), `through_id` (decimal string),
  `auths` (array sorted by auth_index, exactly one entry per configured auth).
- Each auth: `auth_index`, `anchor: pack|null`, `uncertain: pack|null`,
  `last_uncertain_id` (int64 integer, zero without uncertainty),
  `acquisition_ceiling: RFC3339Nano|null`, `unbounded: bool`,
  `recovery_after: RFC3339Nano|null`. These fixed scalars use UTC canonical
  spellings; the original independent acquisition strings live in the packs.
- Each pack: `id` (int64 integer), `origin` (EXACT existing five-field object),
  `headers: object|null`, `response_headers_observed_at: object|null`,
  `transport_sha256`, optional `marker`, `timestamp: string|null`,
  `timestamp_ms: int64|null`, `created_at_ms: int64|null`.
- `headers` retains original Codex names and raw JSON values (normally string
  arrays). The matching map retains original values, including nulls, invalid
  entries, spelling, zone and nanoseconds. A missing map key stays absent; a
  present null stays null. SQL NULL/decoded JSON null maps both render as null;
  the transport digest still distinguishes their original column bytes. Only
  clock keys corresponding to retained headers survive. Validated acquisition
  requires the canonical header name and its actual valid timestamp, never a
  request/capture/evaluation fallback.
- `transport_sha256` hashes compact Go JSON of the two-field object
  `{"quota_json":TEXT_OR_NULL,"quota_observed_at_json":TEXT_OR_NULL}` before
  filtering. It is not a parsed-value or timestamp digest. Malformed raw text is
  not echoed: markers are `malformed_quota_text`, `malformed_acquisition_map`, or
  `pack_too_large`. A malformed map may retain its quota headers with a null map.
- Request timestamp diagnostics retain only valid strings of at most 128 bytes;
  they never acquire quota. A marker retains its ID/origin/digest, not a positive
  truncation. There are no evaluation ages, health snapshots, output hashes,
  downstream `source_sequence` or publication ledger in NEXT.

Checkpoint-IN must have this native schema, exact gateway/source/roster hash,
configured identity set and cursor. It is immutable. A legacy capture, arbitrary
snapshot, missing prior file or changed roster cannot masquerade as cold
recovery. Serialize NEXT first (indented JSON plus newline), hash those exact
bytes, then serialize stdout and sidecar: NEXT contains neither digest, avoiding
a circular hash.

### Exact stdout and provenance v2 wire

Stdout root fields are:

```text
schema_version = seat_quota_windows.v2
capacity_snapshot_id = sha256:<content ID>
source_capture_sha256, source_version, source = usage_events, gateway_id
as_of: RFC3339Nano|null
captured_at, captured_at_basis = sqlite_read_receipt_not_acquisition
observed_seats, roster_completeness = configured_scope_only
source_status = caught_up|source_catching_up
after_id, through_id: canonical decimal strings; caught_up: bool
prior_checkpoint_sha256: lowercase SHA256|null
next_checkpoint_sha256, roster_sha256, auth_files_observation_sha256
seats: array; auth_statuses: array; signals: object keyed by auth_index
```

The core normalized seat/SDK fields retain their v1 shapes. Each observed seat
adds `evidence_status` (effective status below) and `observed_at: string|null`.
Configured-but-unobserved coverage is **not** added to seats or observed_seats.
Uncertain/catching-up rows have empty unknown window projections; retained
positive raw diagnostics are never their current normalized quota. Selected
SDK-unknown windows may retain numeric diagnostics and independently valid siblings.

Each `auth_statuses` entry has EXACT fields `auth_index`, `provider: "codex"`,
`evidence_status: selected|uncertain|unobserved`,
`effective_status: selected|uncertain|unobserved|source_catching_up`,
`health_status: complete|partial|unavailable`, `observed_at: string|null`.
The array covers all configured auths in sorted order. caught_up=false forces
all effective statuses/source quota to unknown, even if an anchor is selected.

Each `signals[auth_index]` has EXACT fields:

```text
current_pack: pack|null
retained_anchor: pack|null
used_quota_keys: sorted array of original retained header names
quota_acquired_at: object of key -> original validated timestamp string|null
quota_observed_at: RFC3339Nano|null
health: object (below)
observed_at: RFC3339Nano|null
```

A selected current pack is the anchor; uncertain current pack is its uncertain
representative, with the hidden ordered anchor exported separately. Unobserved
has both null. used_quota_keys reflects the whole pack used for native
selection/uncertainty, including opaque or malformed present quota, not just
SDK numeric fields. Missing/invalid/future acquisition validates to null in
quota_acquired_at; raw evidence is still lossless in current_pack.
quota_observed_at is the oldest whole selected quota acquisition only when
complete/caught up. No timestamp is reconstructed from SDK float seconds.

The required `health` fields are `status`, `source_observed_at: string|null`,
`active: bool|null`, `active_observed_at: string|null`, `cooldown: bool|null`,
`cooldown_observed_at: string|null`, `limit_reached: bool|null`,
`limit_used_keys: sorted string[]`,
`limit_acquired_at: object of key -> original string|null`. Optional
`limit_reached_basis` is exactly `fallback:auth-files+used_percent` for a fallback
result and is omitted for explicit-only results. Original valid source receipt
strings are retained even if stale; only fresh typed evidence supplies auth
facts. The native helper records exactly the flag, used-percent and exclusion
membership keys actually used, with their original independent acquisition
strings. A cooldown-only true has empty limit_used_keys/limit_acquired_at and
uses the source auth receipt, not a fabricated percentage clock.

Model cooldown is not widened to credential cooldown. Uncertain/catching-up
quota cannot grant `limit_reached=false` or supply fallback percentages. A fresh
independent quota-cooldown true may survive it. Failed GET never reuses previous
health or fabricates false; independent active/cooldown facts become unavailable,
while a fresh selected percentage veto may remain partial. Partial independent
auth facts survive when the current GET actually supplies them.

Authoritative publication `observed_at` (in signals/status/seat) is the oldest
actually used native quota PLUS independent health acquisition, or null unless
quota clocks and all three typed health booleans are complete. Global `as_of`
is the oldest required selected quota acquisition only when **all configured
auths** are complete/caught up; otherwise null. A global null does not erase an
independently complete auth's clock. SDK per-window float observations/ages are
diagnostics, not authoritative publication clocks. No collection/evaluation/
request/insert time becomes SourceClock.

The sidecar has EXACT root fields `schema_version: seat_quota_provenance.v2`,
`artifact_file`, `artifact_sha256`, `verification`, `route_projection`,
`auth_health`, `auth_statuses`, `signals`. The last two exactly mirror stdout.
`route_projection`/`origin` retain their existing EXACT v1 shapes. Partial
`auth_health` retains its v1 shape plus the optional fallback basis above, not
a new consumer schema. Only selected/caught-up
same-row gateway/provider/auth/allowlisted-model/qualified-effort tuples with one
exact supplied roster match gain projection. No model fanout or unobserved seat
projection is invented. Health may independently be partial for any configured
auth; unknown fields remain omitted in auth_health, not defaulted.

`verification` has EXACT fields `source_commit`, nullable `as_of`, `schema_version`
(the stdout schema), `capacity_snapshot_id`, `artifact_sha256`,
`source_capture_sha256`, `roster_sha256`, `auth_files_observation_sha256`,
nullable `prior_checkpoint_sha256`, `next_checkpoint_sha256`, `observed_seats`,
`observed_by_provider`, `window_states`, `evaluated_at`, `evaluation_time_basis`.
Counts cover exactly the observed normalized seats/windows. Evaluation basis is
`actual_utc` or `explicit_offline_replay`. Every SHA256 is unprefixed lowercase
hex except the explicitly prefixed capacity_snapshot_id.

source_capture_sha256 hashes **this exact delta input**, not all history. Prior/
next checkpoint hashes bind retained evidence; roster/auth hashes bind their
exact files. capacity_snapshot_id uses the existing compact-Go-JSON preimage
rule with its own field omitted, over the complete v2 envelope. artifact_sha256
binds exact stdout bytes INCLUDING newline. Per-auth uncertainty, health, raw
clocks and checkpoint state therefore affect provenance/identity, not arbitrary
capture-file mtime. This dated artifact ID is not the wrapper's semantic
observed_version or durable publication sequence.

### Staging/failure and downstream limits

All parsing/reduction/serialization completes before any output. Write order is
NEXT checkpoint, sidecar, stdout. Each named output must be distinct from every
input and from each other, including existing hardlinks/symlinks and symlinked
parents; the declared artifact path is its basename in the sidecar's directory.
A file-backed stdout is also checked against input/checkpoint/sidecar aliases.
The caller must not open/truncate an input as stdout before invoking the command.
Outputs are caller-owned **staging** paths only; the command never replaces
latest, edits checkpoint-IN, allocates a sequence or publishes to a remote DB.

Any short stdout, write/parse/checkpoint/sidecar error is failure, not a valid
result. A failed generation may leave staged checkpoint/sidecar/partial stdout
bytes. Do NOT adopt that NEXT cursor or advertise any subset as successful.
The wrapper owns promotion of cursor/state/publication identity together,
reconciliation of ambiguous remote publication, unknown invalidation of its
previous exact scope/window/reset partitions, and externally visible failure.
Do not fall back to last-positive-as-current. Individual file writes/native
success do not prove local multi-file or remote transaction atomicity.

The wrapper alone owns durable canonical decimal BIGINT source_sequence and
semantic observed_version within each exact downstream partition. Neither SQL
row ID, acquisition, native artifact hash nor elapsed time substitutes for it.
Age-only reevaluation may remain reader-derived; actual changed uncertainty or
persisted independent health evidence must not reuse an old publication identity.
No new Go downstream ledger/partition invalidation policy is included.

Cold bootstrap scans cursor-zero bounded pages and stays source_catching_up until
complete. Page sizing, backlog volume, tick budget and matching native seeds are
wrapper/Main decisions. F2 per-window fallback, F4 freshness-seek bootstrap,
F1.a narrower header-name recognition, multi-provider coverage and other GOLD
follow-ups are explicitly not implemented. No tests here prove installed binary,
live clock behavior, capacity, throughput, wrapper publication or START.

## Validation ownership

`main_test.go` exercises the real `run(args, stdout)` boundary with disk inputs
and a file-backed stdout, reduced real Claude/Codex rows, repeat-byte equality,
content IDs, no input mutation/restamp, missing and explicit acquisition maps,
300-second/nanosecond boundaries, malformed siblings, no secret echo, malformed
inputs/arguments and empty/unsupported evidence. Synthetic acquisition times in
tests are labelled test provenance, not recovered historical evidence. Keep
reason: data safety and the acquisition-provenance trust boundary.

`producer_test.go` retains existing v1 producer acceptance through the real
`run(args, stdout)` seam, atomic newest-row selection, exact
origin/effort binding, two clocks, independent partial health, exact sidecar
hashes/counts, input immutability and unchanged legacy metadata acceptance.
Synthetic health/acquisition fixtures must be labelled synthetic, not live proof.

`incremental_test.go` authors file-backed CLI/checkpoint reload sequences for
F1/F3/F6, newer depleted/malformed versus late old positives, original nullable
independent clocks, SDK coherence and 300-second/nanosecond freshness, partial
typed health/failed GET, bounded losing/uncertain pages, catching-up unknown,
SQL TEXT/outer/source/cursor/roster/checkpoint refusals, aliases, short stdout and
staging-write errors. Fixed v1 wire templates also guard unflagged stdout and
sidecar bytes and legacy refusals. These new tests are **authored, not run** by
the source task. Link-dependent subcases explicitly skip only when that platform
cannot create the required hardlink/symlink; they do not prove alias coverage on
such a platform. Main owns execution and independent review on the frozen bytes.

The fallback source implementation task runs only gofmt on its own Go files
and source diff/whitespace inspection, not tests, builds, syntax/import checks or
runtime probes. The separate test author owns fallback regression tests and
native percent-parser coverage. The parent owns all test/build execution after
source writers are terminal:

```sh
go test ./cmd/normalize_quota_capture
go build -o test-output ./cmd/server && rm test-output
```

A full supplied-capture CLI run is additional parent evidence; fixture tests do
not establish live freshness, roster coverage or route eligibility. No network,
gateway or credential operation is needed for this command's runtime.
