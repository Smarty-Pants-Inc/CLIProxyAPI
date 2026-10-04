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

## Shared publication boundary

All in-repo file-backed config writers (full/SDK saves, raw YAML upload, nested
scalar persistence and load-time management-key hashing) publish under an
exclusive flock on `<canonical-config-path>.lock`. Canonicalization resolves
symlinks, including parent directories, before selecting the sibling lock. This
is the same lock name and protocol as the operator `cmd/config-publish` path in
sibling PR #51. Never lock the config inode: atomic rename replaces that inode.
Never unlink or replace the lock file while writers may be running.

Revision-checked writers re-read and compare the expected bytes inside the
lock, then write an owner-private (`0600`) staging file in the same directory,
fsync it, close it, rename it over the destination and fsync the directory before
releasing the lock. There is no unlocked final-check/publication gap for
cooperating writers. The directory must be writable. Single-file bind mounts or
other non-renameable destinations fail; there is no in-place/truncating fallback.
The watcher watches the canonical parent directory, not the replaceable config
inode. It retains the triggering hash after runtime apply instead of marking a
later reread of disk observed; a newer publication remains eligible for reload.
Failed private staging files may remain for diagnosis. A failure after rename
(such as directory fsync failure) can mean bytes were published; reload before
retrying. Windows publication is refused pending durable native hosted validation.

External writer contract: take the same canonical sibling exclusive flock
before reading the current revision and hold it through publication and directory
fsync. Use a source-snapshot CAS when replacing an edited snapshot. Direct editor,
`cp`, or `sed -i` writes to the live file without the lock are unsupported; an
advisory lock cannot protect against writers that ignore it. The #51 publisher is
not included or claimed merged by this PR.

Plaintext management keys are hashed in memory during load. Their nested hash
persistence is conditional on the exact original source revision under this same
boundary, including key rotation. A successful load binds the exact emitted bytes,
never a reread of possibly newer, unrelated contents. Hash persistence errors fail
load. Parsing bytes does not persist its in-memory hash.

Raw YAML upload remains an authoritative replacement, not a source-snapshot
CAS, but uses the same publication lock and atomic replacement. It must not be
used to publish stale operator snapshots as if they were current. Full management
save paths return a fixed secret-free HTTP 409 for `ErrStaleConfig`. They do not
roll back mutations already made to handler memory. Plugin install/delete can
also have changed plugin files before a config conflict. Refusal of a config save
is not complete-operation rollback.

## Remaining scope of smarty-dev#3101

This closes the cooperating-writer late-publication revocation race, not the
universal configuration transaction redesign or #3101. Full management mutation
locking, mutable runtime-config access, complete-operation rollback, body-based
management-key deletion/logging concerns and non-file storage coordination remain
separate work. Advisory locking requires every external writer to cooperate.

The permanent real two-process regression gates the saver's exact final source
read before publication. A child attempts the same flock and completes client-key
removal or management-key rotation. It cannot complete inside the saver's locked
interval, and its newer bytes remain intact. With the old unlocked writer the
child completes first and the saver restores revoked credentials (RED). Repeated
uncontended full saves provide the successful-publication counterexample.
