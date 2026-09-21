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

Before landing, inspect the exact diff and run the product's protected checks on the final synced commit. Current patch/PR placeholders: `PATCH_COMMIT=<set after local commit>`, `PR=<set by integration owner>`. Integration owns protected landing and must verify the final tree against the sync receipt.
