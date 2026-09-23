# Smarty upstream sync and Codex model-integrity maintenance

## Sync record

- Fork: `Smarty-Pants-Inc/CLIProxyAPI`
- Upstream: `router-for-me/CLIProxyAPI`
- Initial sync route: GitHub `POST /repos/Smarty-Pants-Inc/CLIProxyAPI/merge-upstream` with `branch=main`, via the approved credential wrapper. This was not a branch-protected route.
- Initial synced base: `a5ab69521f7b4e0f244836d0419da8fcd89408ea`
- Base tree: `881cdf33de6e13ba4a38c5de9038ce9716a014c0`
- Base parent: `29bdd856c073fee62df7da50192c076569b5585c`
- Sync receipt under the enclosing Smarty Dev root: `.local/model-integrity-sync-20260921/FORK-SYNC-RECEIPT.json`
- Receipt SHA256: `d286c1815c2c1bfeba7f63533ecbad2dccea9f0891a7dd0259c4899e886ac4c4`

Never force-push, reset a shared branch, or import the preserved investigation worktree wholesale. Future upstream updates must preserve this fork's model-integrity changes through review and the normal repository landing route. Do not describe an unprotected route as protected or change protections as an update side effect.

## Patch invariant

The Codex Responses executor must validate authoritative upstream `response.model` against the effective upstream request model before downstream exposure. A mismatch or missing model at terminal completion returns `model_mismatch`; no force-map or alias rewrite may turn it into success. Buffer unverified stream output within the existing bounds. Neither terminal failure nor budget exhaustion may release unverified text, tool calls, or observer payloads. Credential-only retry must keep the requested model unchanged and release attempt resources without closing the downstream socket prematurely.

Coverage is limited to ordinary Codex Responses HTTP and WebSocket paths, streaming and non-streaming. It excludes `/responses/compact`, Codex image-generation paths, and protocols without authoritative Codex `response.model`.

## Accepted delivery — 2026-09-21

[PR #2](https://github.com/Smarty-Pants-Inc/CLIProxyAPI/pull/2) landed through normal reviewed GitHub squash merge, not a branch-protected merge:

- Landed commit: `dbddedb8bdf1f98ab5e8f28d6767591de9029a4b`
- Landed tree: `e825c151bebf5be2f34b7d601d06c444072c53d0`
- Independent source review closed the output/observer exposure, bootstrap failure/budget, session cleanup, and retry-disconnect findings. CI separately accepted the artifact definition and hosted placement.
- Exact landed artifact: [CI run 35566929105](https://github.com/Smarty-Pants-Inc/CLIProxyAPI/actions/runs/35566929105), attempt 1, job `106230525406`, artifact `10624269038`.
- Build: Go 1.26.8, Linux amd64, CGO disabled, explicit clean landed checkout cwd, embedded commit/build time, no catalog refresh. CI retained tool identity, command, source/tree/definition, clean post-build state, and successful build/help/receipt exits.
- Binary SHA256: `2c1098d4a1b151ec8ddb5c8fab01a7020460317296b04fbaadb828c41f3e72d8`

The same tested artifact was installed at `/usr/local/bin/cliproxyapi` through `cliproxyapi.service`. Its version was `smarty-model-integrity`, embedded commit matched the landed commit, and build time was `2026-09-21T06:05:26Z`. At delivery, staged, installed, and running-process digests matched; PID `4065315` was active. The authenticated catalog returned HTTP 200 with 55 models including `gpt-6-astra`; anonymous access returned HTTP 401. These are dated observations, not a claim about future process state.

### Proof and limits

Before activation and again afterward, isolated instances of the staged/installed executable passed six synthetic upstream cases: same-model, mismatched-model, and missing-model responses in both HTTP modes. Same-model responses preserved text and tool payloads. Mismatch/missing responses returned HTTP 502 with `model_mismatch` and no forbidden text, tool-name, call-ID, or argument markers in retained raw responses.

These were executable HTTP proofs, not failure injection into production upstreams. The shared gateway's identity and catalog were verified separately. Changed WebSocket paths had targeted executor tests and independent source review, including observer suppression and same-session retry without a disconnect notification; executable WebSocket and live-provider mismatch proofs were not claimed.

Configuration and credentials were unchanged. The previous 7.3.9 artifact was retained at `/usr/local/bin/cliproxyapi.bak.20260921T060942Z`, SHA256 `f85478b2acde6e6be727b84b0e98db89cf9ac5e67ed49831a7fe11d57f690b44`.

Private delivery evidence: `/home/paul/.local/share/cliproxyapi-model-integrity/pr2-stage/DELIVERY.md`; its `run-35566929105-attempt-1/` directory contains `CI-RECEIPT.json`, raw pre/post-activation proofs, provenance, and activation evidence.

### Superseded evidence

PR #1 and its `434f0ff4` follow-up are not the accepted release proof. The first candidate leaked a mismatched HTTP streaming completion and was rolled back. An earlier combined executor test exceeded 600 seconds; local checks were not CI qualification. The initial claimed post-merge build did not change into its detached landed checkout. Those build claims and binaries must not be reused as exact-landed artifact evidence. PR #2 and the CI receipt above supersede them.

## Claude Messages identity guard — 2026-09-23

The shared Claude executor also validates successful Messages responses before
response logging, usage observation, tool-name restoration, replay caching, or
translation. This covers API-key and OAuth credentials, native Messages output,
and output translated from Claude. It does not change the Codex guards above.

- Compare JSON `model` or SSE `message_start.message.model` with `model` in the
  **final outbound request body**. Existing routing aliases, thinking-suffix
  removal, provider normalization, and payload rules run before this boundary.
  Response alias restoration cannot make a mismatch pass. No new substitution,
  fuzzy matching, or model fallback is introduced.
- A missing, non-string, or different model fails with `model_mismatch`. The
  request-scoped error prevents ordinary credential/model rotation and avoids
  penalizing credentials for an identity failure. Error text contains no
  unverified upstream values.
- Withhold SSE output, including ping events, until identity is verified. Reject
  content before identity, missing identity at EOF, and a repeated message start.
  The pre-identity buffer and scanner use the existing 50 MB bound. Keep the
  streaming goroutine, cancellation, and response-body cleanup paths; do not add
  network deadlines or wait for the whole verified response before streaming.
- Model identity is the upstream's declaration, not proof of the model's weights.
  A later protocol failure cannot retract content already released under a valid
  initial identity. Other provider executors and token-count endpoints are not
  covered by this patch. Existing routing policy is not redefined.

Targeted regressions are `TestClaudeModelJSONIdentity`,
`TestClaudeModelStreamIdentity`, and `TestClaudeMessagesModelIntegrity`. They cover
native and translated responses in both HTTP modes, synthetic API-key and OAuth
credentials, exact/wrong/missing identity, pre-identity content, normalization and
thinking suffixes, malformed/bounded input, and existing OAuth cancellation.
The hosted PR job runs these and the three retained Codex executor regressions,
then the unchanged required build. Test-name assertions reject empty selection.
The main-only exact-landed artifact job is unchanged.

Activation still requires an exact reviewed landed artifact and both six-case
executable proofs (Messages and Responses), with exact-model text/tool positives
and wrong/missing-model negatives that release no text/tool markers. Keep the
installed Messages failure baseline; never overwrite it with candidate results.
These synthetic loopback fixtures use temporary configuration and credentials,
not real model inference. Startup can fetch public version metadata, so this is
not an OS-network-isolation claim. Test source and a green build alone are not
activation evidence. Runtime staging and activation stay with the service owner.

## Future updates and verification

1. Review upstream changes against the fork's current landed source. Preserve the authority fences, bounded buffering, observer behavior, error classification, and retry cleanup. Keep unrelated investigation changes separate.
2. Format changed Go files and run targeted helper/executor regressions for changed paths. Include `TestCodexHTTPModelIntegrityTerminal`, `TestCodexUnverifiedFailureDoesNotFlush`, and `TestCodexWebsocketModelFailureReleasesSession` when these guards change. Follow product-required checks; do not use a broad local build/test command as release evidence.
3. Follow the enclosing Smarty Dev `smarty-ci` skill for placement and admission. Dev1 is not a build host. Preserve existing hosted PR checks. A passing PR build that refreshes floating catalogs and deletes its output is not an exact-source release artifact.
4. After reviewed landing, use the admitted main-only, input-free artifact job in `.github/workflows/pr-test-build.yml`. Revalidate exact source and definition before its single authorized dispatch. Do not infer new hosted placement or deployment permission from the existence of that job.
5. Stage the exact landed artifact separately; verify provenance and digest. Run executable same/mismatch/missing text-and-tool proofs before activation. Promote those same bytes only through the authorized service-owner path, preserve compatible rollback, and verify the actual running executable, catalog, and required behavior. A build or open PR is not rollout.
