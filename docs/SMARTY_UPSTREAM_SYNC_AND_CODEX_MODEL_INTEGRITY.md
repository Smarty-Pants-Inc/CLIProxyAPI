# Smarty upstream sync and Codex model-integrity maintenance

## Sync record

- Fork: `Smarty-Pants-Inc/CLIProxyAPI`
- Upstream: `router-for-me/CLIProxyAPI`
- Protected sync route: GitHub `POST /repos/Smarty-Pants-Inc/CLIProxyAPI/merge-upstream` with `branch=main`, via the approved credential wrapper.
- Current synced base: `origin/main` / `a5ab69521f7b4e0f244836d0419da8fcd89408ea`
- Base tree: `881cdf33de6e13ba4a38c5de9038ce9716a014c0`
- Base parent: `29bdd856c073fee62df7da50192c076569b5585c`
- Receipt: `.local/model-integrity-sync-20260921/FORK-SYNC-RECEIPT.json`
- Receipt SHA256: `d286c1815c2c1bfeba7f63533ecbad2dccea9f0891a7dd0259c4899e886ac4c4`
- Historical divergence evidence: `/home/paul/Projects/smarty-dev/.local/model-integrity-sync-20260921/DIVERGENCE-HANDOFF.md`
- Sync authority addendum: `.local/model-integrity-sync-20260921/SYNC-AUTHORITY-ADDENDUM.md`

Reapply work only after refreshing `origin/main` through the protected fork-sync route. Never force-push, reset a shared branch, or merge the preserved investigation worktree wholesale.

## Patch invariant

The Codex Responses executor must validate the authoritative upstream `response.model` against the effective upstream request model before translating or exposing a response. A mismatch or missing model at terminal completion returns `model_mismatch`; no force-map or alias rewrite may turn it into success. A stream must validate its first authoritative model before releasing bootstrap-buffered output. Retry remains eligible for another credential for the same requested model and must not expose the failed attempt.

The guard covers only ordinary Codex Responses HTTP and WebSocket response paths, both streaming and non-streaming. It does not cover `/responses/compact`, Codex image-generation paths, or protocols that do not provide the authoritative Codex `response.model` field.

## Tests and reapply

Offline fixtures cover same-model success, mismatch, missing terminal model, and alias mismatch. Run:

```text
gofmt -w internal/runtime/executor/helps/codex_model_integrity.go \
  internal/runtime/executor/helps/codex_model_integrity_test.go \
  internal/runtime/executor/helps/response_model.go \
  internal/runtime/executor/codex_executor_execute.go \
  internal/runtime/executor/codex_executor_stream.go \
  internal/runtime/executor/codex_websockets_execute.go \
  internal/runtime/executor/codex_websockets_stream.go
go test ./internal/runtime/executor/helps ./internal/runtime/executor
go build -o test-output ./cmd/server && rm test-output
```

Local verification evidence for patch commit `434f0ff405fee56708016d545fa3631a1bbaab6b` (tree `78d786baecd728a9c50647470dc988dbef496810`):

- Go: `/home/paul/.local/share/smarty-dev/go/1.26.8/bin/go`; SHA256 `d9a2fa19c7ef8b57f420012c21f49f235c46f08a68c12077d9c753dbb6ccdc34`.
- gofmt: `/home/paul/.local/share/smarty-dev/go/1.26.8/bin/gofmt`; SHA256 `b233484fae3a686bd1394f01535477992dbe574b31628b79f58dc272f3c4c597`.
- The earlier combined `go test ./internal/runtime/executor/helps ./internal/runtime/executor` attempt exceeded the 600-second tool timeout after the helper package passed; no test process remained.
- `go test ./internal/runtime/executor/helps`: passed.
- The initial focused WebSocket run exposed legacy offline fixtures without `response.model`; it failed with the intended `model_mismatch` and produced fixture goroutine panics. Those fixtures were updated only where the tests intended same-model behavior.
- Focused duplex rerun: passed with `-run 'TestCodexDuplex(InitialFailure|RejectedCreateMetadata|LaterInvalidSignatureClearsReplay|AutomaticSuccessorMetadata|SteeringLifecycle|AppendInheritsContextAndInstructions|StandaloneCreateDoesNotInheritParentID|QueuedCreateDoesNotBlockSubsequentSteer)$' -count=1 -timeout=3m`.
- `git diff --check`: passed.
- `go build -o /tmp/cliproxyapi-model-guard ./cmd/server`: passed.

The supplied official Go SHA did not match the installed tool binaries above. These are local offline checks only, not CI-host qualification. Before landing, inspect the exact diff and run the product's protected checks on the final synced commit. PR creation and protected landing remain integration-owner work.
