# Full-config save source fence

`LoadConfig`, `LoadConfigOptional` (when bytes were read), and `ParseConfigBytes`
record SHA-256 of their exact source bytes in private value metadata. The metadata
is not YAML or JSON. Value copies and `CloneForRuntime` preserve their own revision;
a successful save advances only the supplied snapshot, not its copies.

`SaveConfigPreserveComments` requires tracked provenance and matching destination
bytes. Missing files, changed source bytes, and untracked/nil configs return
`ErrStaleConfig` without changing disk. The SDK exports the same sentinel. Use
`errors.Is(err, config.ErrStaleConfig)`, reload, then reapply the intended mutation;
do not retry the same stale snapshot. A manually constructed config, a YAML/JSON
round trip, and optional missing-file standby are untracked and cannot full-save.
A parsed config can save only onto a file containing its exact input bytes.
Comments and whitespace are part of the revision, so their changes also conflict.
This is a content revision, not a monotonic history: an exact byte-for-byte revert
matches again.

Plaintext management keys are hashed in memory during load. Their nested hash
persistence is conditional on the exact original source revision and fails on a
completed concurrent update, including key rotation. A successful load binds the
exact emitted bytes, never a reread of possibly newer, unrelated contents. Hash
persistence errors now fail load instead of being ignored. Parsing bytes does not
persist its in-memory hash.

The package serializes its full and nested-scalar file saves with a process-local
mutex and validates again after rendering, before truncation. This prevents a
known stale full snapshot from overwriting a raw external rewrite or nested-scalar
update that completed before full save, and allows ordinary uncontended saves and
updates that happened before load.

Management full-save paths return HTTP 409 for this sentinel. They do not
roll back mutations already made to the handler's runtime config. Plugin install
and delete can also have changed plugin files before the config save conflicts.
A conflict guarantees refusal of that config save, not rollback of the complete
management operation. Raw YAML upload remains an authoritative unfenced write.

## Explicit cuts from smarty-dev#3101

This is a stale-full-save fence, **not** the universal configuration transaction
redesign and **not** closure of #3101. These remain unclosed:

- A cross-process lock/transaction boundary. The mutex is process-local only.
- Full management mutation locking, including mutable runtime config access.
- The late validation/publication window and coordination with **all external
  writers**. An uncooperative writer can write after the final checksum and before
  or during publication. A final checksum alone cannot solve that race.
- Atomic publication, crash safety, and partial-write rollback. Existing in-place
  writes remain; a failed write does not advance the supplied snapshot's metadata.
- Body-based management key deletion and associated logging concerns.

Tests use only synthetic fixtures. Subprocess raw and nested-scalar writers have a
completion barrier before full save. Unix FIFO tests gate hash persistence while a
completed raw rewrite replaces the original source, with no timing assumptions.
These tests do not claim safety for the unclosed late-publication race.
