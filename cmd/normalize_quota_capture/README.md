# Offline quota capture normalization

This command reads one explicitly named, redacted `usage_events` capture and
writes one JSON seat/window artifact to stdout. It reuses the pure SDK
`auth.NormalizeQuotaHeaderWindows` parser. It does not read a database, gateway,
credentials, auth files or runtime configuration; fetch providers; persist state;
select routes; or aggregate capacity.

```sh
normalize_quota_capture \
  --input quota-capture-2026-11-05T104539Z.json \
  --as-of 2026-11-05T10:45:39Z \
  --source-version FULL_40_DIGIT_LOWERCASE_SOURCE_COMMIT > seat-windows.json
```

All three flags are mandatory. `--as-of` accepts RFC3339 with a timezone and
optional nanoseconds; it is the comparison clock, not an observation timestamp.
`--source-version` must be the exact full commit of the normalizer source used to
build the command. This is an explicit caller assertion: the offline command
validates its form but does not query Git or infer a version. The caller must
pin the actual candidate, including the SDK parser; do not label dirty source as
a clean commit. Input/argument errors produce no JSON and a fixed, non-sensitive
error on stderr. A stdout transport error may leave partial output and is an
error, not a usable artifact. Only stdout is written; the shell redirect above
belongs to the caller.

## Input and acquisition provenance

The supplied shape is a JSON object with `captured_at` (RFC3339 with timezone)
and `seats` (array). Each seat has a 16-digit lowercase hex `auth_index`,
`provider`, exact request `model`, and raw `headers: {"Canonical-Header":["value"]}`.
Missing/malformed identities reject the capture rather than inventing IDs.
Empty `seats: []` is an explicit zero-observation artifact with unverified roster
completeness; absent/null seats or malformed JSON are errors. Missing/empty
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
read, replay restamp or timestamp derived by subtracting relative resets.

## Output contract: `seat_quota_windows.v1`

- `schema_version`, explicit `as_of` (UTC RFC3339Nano), `source_version`, and fixed
  `source: "usage_events"` identify interpretation and provenance.
- `source_capture_sha256` is lowercase SHA256 of the exact input bytes, including
  whitespace. File paths do not enter output or identity.
- `capacity_snapshot_id` is `sha256:` followed by SHA256 of the compact Go JSON
  encoding of the complete normalized envelope **with that ID field omitted**.
  It binds schema, capture hash, code version, comparison clock and projected
  facts. The final artifact is indented JSON with a trailing newline. Identical
  bytes and args yield identical stdout; changing the clock/version changes the
  artifact ID, not acquisition times.
- `observed_seats` counts distinct observed `auth_index` values only;
  `roster_completeness` is always `unverified`. The supplied 62 observed seats
  do not prove 64-seat coverage. No absent identities or roster rows are added.
- `seats` are sorted by `auth_index`, then provider and exact observed model,
  preserving input order on ties. Each row retains its own SDK `quota` result;
  observations are not merged. SDK window timestamps/ages/durations/reset values
  use seconds, percentages use 0..100 and absent numbers are JSON null.
- `observed_model` is the exact allowlisted usage-event request model, explicitly
  labelled `usage_event_request_model_not_quota_scope`. It does not assert that
  an account-wide or opaque limit namespace applies to that model.
- `quota_scope: "unverified"`, `health: "unknown"` and
  `credits_approval: "unverified"` remain independent of provider credit facts.
  `cooldown_until` and `next_retry_at` are null: this capture does not supply
  verified scoped retry/health state. HTTP success/failure is not health proof.

Only `auth_index` and the provider/model allowlist below are emitted from identity
fields. Other strings/unknown fields, capture source prose, seat names/emails,
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

## Route adapter blocked on owner input

This is a **seat/window evidence artifact only**. Owner-provided route-policy
mapping, effective model/reasoning equivalence, tariff provenance, scoped health
and complete roster evidence are missing. A route adapter cannot safely infer
route IDs, eligibility, aggregate headroom or cost from these rows. That adapter
and aggregation remain blocked on those owner inputs; this command does not
implement them or change CPA's selectors.

## Validation ownership

`main_test.go` exercises the real `run(args, stdout)` boundary with disk inputs
and a file-backed stdout, reduced real Claude/Codex rows, repeat-byte equality,
content IDs, no input mutation/restamp, missing and explicit acquisition maps,
300-second/nanosecond boundaries, malformed siblings, no secret echo, malformed
inputs/arguments and empty/unsupported evidence. Synthetic acquisition times in
tests are labelled test provenance, not recovered historical evidence. Keep
reason: data safety and the acquisition-provenance trust boundary.

The parent owns test/build execution after sibling source writers are terminal:

```sh
go test ./cmd/normalize_quota_capture
go build -o test-output ./cmd/server && rm test-output
```

A full supplied-capture CLI run is additional parent evidence; fixture tests do
not establish live freshness, roster coverage or route eligibility. No network,
gateway or credential operation is needed for this command's runtime.
