# Legacy signed compaction: 409 investigation and recovery design

## Decision

Do not change unknown-signer routing in this patch. A safe live-session recovery
is not a small gateway-only change. The state location fix does not recover signer
provenance; moving to a fresh state directory can also expose the same 409.

## Why the incident happens

`SessionAffinitySelector.prepareCompactionAffinity` in
`sdk/cliproxy/auth/compaction_affinity.go` collects a digest key for **every**
signed compaction block and looks up its protected producing-account binding.
`RecordCompactionOutput` records this evidence only when this gateway actually
observes a successful output from a selected auth, and persists it when a state
path exists. Builds before persistence/recording, compactions performed elsewhere,
or absent/unwritten state leave no such record. Replay then returns HTTP 409
`compaction_affinity_missing` before selecting or calling an upstream account.
Signer loss through expiration or eviction is deliberately treated the same way.

The block is opaque. Neither a current session ID, prompt-cache key, approximate
trajectory match, newly established routing binding, nor a client's account pin
proves which account signed it. A legacy marker cannot be inferred from absence
of a record: an imported/cross-account block is indistinguishable. Even one current
credential is not proof that it produced an old block. Trying accounts until one
accepts it would send protected context to unrelated accounts and violate the
cross-account guarantee. Mixed known/unknown blocks must not bypass that guarantee.

Existing regression tests explicitly enforce this boundary:
`TestCompactionAffinityColdBlockRequiresRecompaction`,
`TestCompactionAffinityLostSignerCannotUseNewSessionBinding`,
`TestCompactionAffinityEveryBlockConstrainsSigner`, and
`TestCompactionAffinityDigestSurvivesIdentityAndModelChange`.

## Minimal safe behavior (requires coordinated client recovery)

Keep the fail-closed gateway check. A client that retained the pre-compaction
transcript should treat this specific 409 as a recoverable conversation event,
not a dead session: discard only the untrusted signed artifact, rebuild input from
that retained transcript, and recompact on an explicitly selected live account.
The gateway then records the newly observed output before replay; account failover
must remain disabled for protected blocks. Recovery must not silently discard
conversation history, loop retries, replay side-effecting tool calls, or send an
unknown signed block to any account. If the transcript is unavailable, require
explicit user recovery rather than guessing or fabricating signer evidence.

For state that *does* contain recorded signer evidence, an authorized operator
may copy a vetted, intact legacy state snapshot to the new directory while the
process is stopped, preserving auth IDs, digest bindings, and protection metadata.
No automatic legacy-state read/write or migration is added: this patch must never
write in auth-dir and cannot certify provenance in a state file that never recorded
those blocks. A missing state snapshot cannot be reconstructed from mutable aliases.

## Risks and gates before a separate recovery change

Client transcript retention and retry semantics must be specified and tested end
to end (HTTP, streaming, bootstrap retries, and duplex sockets). Test a legacy
unknown block continuing through transcript-based recompaction; known blocks stay
on their producing account across restart/identity changes; mixed-signers, imported
unknown blocks, conflicting pins, unavailable signers, and persistence failures
remain fail-closed. Test retention loss, no tool re-execution, no retry loop, and
operator migration rollback. No install, live-gateway mutation, or unsafe fallback
is part of this change.
