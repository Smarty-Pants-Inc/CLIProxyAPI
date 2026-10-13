# Auth metadata concurrency (smarty-dev#7671)

Each `sdk/cliproxy/auth.Auth` owns its metadata RWMutex. After publication, use
`MetadataString`, `MetadataBool`, `MetadataValue`, `SetMetadata`, `WithMetadata`,
or `CloneMetadata`; do not copy an Auth by value. `Clone` creates a fresh mutex
and takes a read-locked metadata snapshot. Pointer JSON serialization snapshots
metadata too. Existing manager synchronization still owns the other Auth fields.

`WithMetadata` callbacks must not retain the map or recursively call metadata
methods on the same credential. Nested map/slice values are immutable snapshots:
replace them rather than mutate them. Claude device pool accessors defensively
copy slices on both reads and writes.

The Claude helpers now accept `*Auth` rather than `*map[string]any`. This avoids
an owner lookup/global map-lock registry, and makes all providers use the same
credential-owned lock. The legacy `EnsureDeviceIDPool(map[string]any)` helper is
only for standalone maps; its separate mutex is **not** an Auth metadata lock.
The module's remaining calls to that helper are its standalone-map tests.

## Acceptance checks

- Shared selector weight and websocket readers, classification string and nested
  token readers, conductor error rules (both spellings), usage email and both
  project keys, and Auth clone run concurrently with the real metadata merge
  writer on ONE Auth (eight readers per regression).
- These exact regression files compile on base
  `e999c3259e991a8a7b65117f710d355a2e831572`; ten individually isolated probes
  report data races there. Classification-token and clone also reproduced fatal
  concurrent-map failures. The usage-email fixture uses immutable API-key
  classification so its email fallback, not just classification, is exercised.
- Accessor tests cover nil receivers/maps, type semantics, nil entries, independent
  snapshots, atomic initialization/read-modify-write, concurrent JSON encoding,
  and clone field preservation. Claude helpers are also mixed with Auth-native
  readers/writers on a single initially empty credential.
- Build, vet (including copylocks), and the requested three-run race suite are
  the final gates. Persistence, plugins, API websocket adapters, and SDK service
  changes additionally receive their package tests.

## Validation outcome

Build and vet pass. All new regressions pass with `-race -count=3`, as do the
complete auth, Claude, and executor-helper packages. The complete executor suite
passes with `-race -count=1`. Its requested `-count=3` run completes but fails the
pre-existing `TestAntigravityAuthHasCreditsRequiredHomeBalanceUsesKV` on repeats:
`KVGet count = 0, want 1`. The identical test fails on the base commit with
`-race -count=3` too (cached global Home credit state). That unrelated cache-test
failure is not changed in this metadata patch.

The repeated suite also exposed a pre-existing xAI websocket test that leaked its
persistent session/response-ID state between iterations, then hung. That failure
was reproduced on base. Test-only session cleanup now lets all three iterations
complete without changing websocket runtime behavior.

## Intentionally retained direct accesses

The audit includes `.Metadata[`, `Metadata =`, nil/length checks, map iterations,
and whole-map arguments in `internal/`, `sdk/`, and `cmd/`. Direct accesses that
remain are not accesses to a concurrently published credential:

| Location | Reason |
| --- | --- |
| `sdk/cliproxy/auth/metadata.go` | The owning lock implementation itself; every access is locked. |
| `sdk/cliproxy/auth/metadata_merge.go` | Writes to the newly cloned, unpublished `merged` result. Shared merge inputs are read-locked snapshots. |
| `sdk/cliproxy/auth/key_policy.go` | Initial nested-secret JSON copy on the unpublished selected clone, and serialization of the private clone returned by `Manager.GetByID`. Published selected reads use accessors. |
| `internal/runtime/executor/codex_executor_auth.go`, `xai_executor_auth.go`, `kimi_executor.go` | Refresh first clones the input and then builds an unpublished candidate, including attributes/storage; credential reads outside refresh use accessors. |
| `internal/runtime/executor/antigravity_executor_auth.go` | Preparation and refresh mutate private clones. Every production call of `refreshToken` passes `auth.Clone()`; `ensureAntigravityProjectID` is called only from that private refresh path. Request-time readers use accessors/snapshots. |
| `internal/runtime/executor/devin_executor.go` | Refresh writes only to its newly cloned `updated` candidate. |
| `sdk/auth/filestore.go` (file parsing), `internal/watcher/synthesizer/file.go`, `internal/watcher/synthesizer/config.go` | File/plugin/config construction before registration/publication. Save paths now lock normalization, use locked setters, and pass independent metadata snapshots to storage/JSON. |
| `sdk/auth/manager.go` | Legacy migration metadata comes from a store's private file-parsing result, before publication. |
| `internal/pluginhost/quota_provider.go` | Auth lookup returns a private `Manager.List` clone or a newly parsed physical file; the map is passed to a request-local quota operation. |
| `internal/api/handlers/management/{auth_files.go,auth_files_fields.go,api_tools.go,plugin_quota.go}` | Deprecated endpoints intentionally unchanged. They operate on private `Manager.List`/`GetByID` clones, parsed files, or unpublished update candidates, not the live credential. |
| `cmd/fetch_{antigravity,codex,devin}_models/main.go` | Standalone, single-owner CLI discovery/refresh credentials, not gateway in-flight credentials. |
| `*_test.go` | Fixture construction before goroutines, reads after joining workers, or private clone assertions. Concurrent writer regressions use the production merge helper, Claude helpers, or Auth methods. |

Other `Metadata` fields belong to request/options, plugin DTOs, OAuth sessions,
token storage, or session-tree structures, **not** `cliproxyauth.Auth`; they do
not acquire an Auth lock. Existing raw-map utility functions still accept private
maps, but shared Auth callers now supply `CloneMetadata()` snapshots.

No upstream payload semantics, public configuration keys, registrations, or Home
wire schema changed. Home dispatch decoding and test fixtures clone Auth records
rather than copy their mutexes by value.
