# CLIProxyAPI #50 — Astra round 1 repair

Reviewed starting head: `4702c62027f86b3097b1c8c8113b8269554dc7d3`. First parent: `6efd8189460b10770ea0383139d69c51d4339323`. Branch: `sync/upstream-v8.0.12`.

**All twelve P2 findings repaired.** No upstream feature was removed: remote TUI, custom patch bridging, source configuration-update intent, v8 plugins, Home capabilities, and forced shutdown after deadline remain supported. No push, GitHub interaction, credential access, agent spawning, rebase, stash, force operation, or git identity configuration was used.

## Evidence conventions

Kept evidence directory (`OUT` below): `/srv/scratch/paul/tasks/direct/fr-cpa50r1/artifacts`.
Toolchain: `/home/paul/.local/share/go/bin/go`, `go1.27.1 linux/amd64`. Commands used this directory on `PATH`. Dependency metadata was initially checked offline; missing public Go dependency metadata was downloaded through the Go module proxy, then final checks ran with `GOPROXY=off`.

The initial, pre-repair RED command was:

```sh
go test ./internal/tui ./internal/api ./internal/config ./internal/runtime/executor ./internal/translator/common ./sdk/cliproxy/auth \
  -run 'TestRound1|TestHomeDispatchConfigurationUpdateCapabilityAndLegacyFallback' -count=1
```

Exit **1**, `red-main.log`. Initial nonstreaming normalizer fixtures had incomplete response events; those fixtures were corrected, and genuine production-path RED was obtained for both execution modes using the original-code overlay below. Fixture compilation failures are not counted as RED evidence.

For the strengthened replay, normalizer, Kimi, and dispatcher probes, original production files from the reviewed starting head were supplied with Go's `-overlay`; the checkout/branch was never switched. The original registry overlay adds only an update-only `RequestThinkingChanged` compatibility shim so new helper callers can compile against its old behavior. Original files and the reproducible overlay are kept in `OUT/red-overlay/`.

```sh
go test -overlay "$OUT/red-overlay/overlay.json" ./internal/runtime/executor ./internal/runtime/executor/helps \
  -run 'TestRound1CodexServerWorkBeforeIdentity|TestRound1NormalizerOwnsEffort|TestRound1KimiPatchSSEBoundary|TestRound1DispatcherRetainedLimits' \
  -count=1 -timeout=120s
```

Exit **1**, `red-extended.log`. This was executed before adding the separate Home entry to the saved overlay; adding that entry does not change these four probes.

The consolidated GREEN command was:

```sh
go test ./internal/tui ./internal/api ./internal/config ./internal/runtime/executor ./internal/runtime/executor/helps \
  ./internal/translator/common ./sdk/cliproxy/auth \
  -run 'TestRound1|TestHomeDispatchConfigurationUpdateCapabilityAndLegacyFallback|TestServerStop' -count=1 -timeout=120s
```

Exit **0**, all seven packages passed (`green-final-ledger.log`, `green-final-ledger.exit`). After retaining upstream high-intent source recovery, the normalizer probe was rerun, exit **0** (`green-normalizer-final.log`). The final extra CLI validation was followed by the complete TUI package, exit **0** (`tui-final-package.log`).

## Findings

### 1. Bootstrap silent EOF loses the request-stop marker

- **Cause:** the bootstrap empty-buffer branch returned nil error even after upstream server-tool work had closed `replaySafe`.
- **Fix:** `internal/runtime/executor/codex_executor_stream.go:353` allows silent empty EOF only while replay is safe. Unsafe EOF now takes the incomplete-stream error path and its existing named-error defer supplies the non-replayable/request-stop marker.
- **RED:** initial command above, exit **1**, reported retryable `empty_stream` without the marker for work-before-identity with and without a subsequent matching handshake. The strengthened overlay command, exit **1**, observed **three upstream dispatches** in each ordering (`red-extended.log`).
- **GREEN:** consolidated command, exit **0**. `TestRound1CodexServerWorkBeforeIdentity` runs `Manager.ExecuteStream`, enables retries, provides three selectable credentials, and asserts a request-stop error and **exactly one upstream dispatch** for both orderings. Upstream safe-empty retry behavior remains intact.

### 2. Remote TUI exposes the management key over implicit plaintext HTTP

- **Cause:** schemeless remote addresses selected HTTP; credentials were attached without destination or redirect validation.
- **Fix:** `internal/tui/client.go:33-47,68-72` defaults remote addresses to HTTPS and validates before attaching credentials. `internal/tui/url_security.go:11-54` permits local loopback HTTP, rejects remote plaintext/malformed URLs, HTTPS downgrades, and cross-origin redirects. `internal/tui/app.go:500-507` validates the actual CLI-selected destination before terminal startup. The existing remote TUI CLI flag remains registered and functional.
- **RED:** initial command, exit **1**: remote address had an HTTP default, the mock transport received the plaintext credential, and the redirect guard was absent (`red-main.log`). A real pre-validation built CLI invoked with `--config <owned-scratch-config> --tui --management-base-url http://192.0.2.1:8317 --local-model` exited **0** but reached TTY startup instead of rejecting the address; the `grep -F 'HTTPS is required'` acceptance assertion exited **1** (`red-cli-tui.log`).
- **GREEN:** consolidated transport probe, exit **0**: HTTPS default, pre-dial plaintext rejection, actual TLS-to-HTTP redirect rejection, and authenticated loopback access. The same real CLI command on the rebuilt artifact exits **0** under the existing main error-reporting contract and prints `TUI error: HTTPS is required for remote destinations`; the rejection assertion exits **0** (`green-cli-tui.log`). CLI help also exits **0** and lists `-management-base-url` (`cli-help.log`). No real administrative credential was used.

### 3. Remote OAuth response invokes unrestricted local OS handlers

- **Cause:** the shared browser launcher accepted arbitrary response strings as OS-handler targets.
- **Fix:** `internal/tui/browser.go:11-20` parses and validates before any `exec.Command` call, using `internal/tui/url_security.go:20-32`. Absolute, non-opaque HTTPS with host is accepted; HTTP is restricted to loopback. File/custom schemes, paths, option-like values, userinfo, missing hosts, and fragments are rejected.
- **RED:** initial command, exit **1**. `TestRound1BrowserRejectsUnsafeTargets` reached OS executable lookup instead of the validation boundary for all seven unsafe targets (`red-main.log`). An empty test-owned `PATH` prevented any OS launcher from executing, including on RED.
- **GREEN:** consolidated command, exit **0**; every unsafe target returns `unsafe browser URL` before OS launch. Necessary loopback flows and remote HTTPS browser links are retained.

### 4. Source effort replay undoes the request normalizer

- **Cause:** ordinary unnormalized Responses effort was treated as explicit update intent, while provenance tracked only configuration-update items and both Claude modes discarded that provenance.
- **Fix:** `internal/thinking/apply.go:240` recovers explicit update intent separately. `sdk/translator/registry.go:141-190` detects normalizer edits/deletions to reasoning, effort, thinking, and updates from a copied pre-normalization snapshot. `sdk/translator/pipeline.go:16` documents that provenance. `internal/runtime/executor/claude_executor_execute.go:85,91` and `claude_executor_stream.go:88,94` carry it to thinking; `internal/runtime/executor/helps/codex_multi_agent_v2.go:135-137,148,181-187` also carries it across manual compatibility conversion. Existing Codex preparation already consumes the flag. Source max/xhigh semantic recovery remains allowed when no normalizer overrode it; native update-capable passthrough and explicit model suffix priority remain unchanged.
- **RED:** overlay command, exit **1**, observed source `high` overriding lowered/deleted effort and disabled thinking in **both real Claude execution modes**, and source `high` reappearing for a user-defined, update-unsupported Codex model in both modes (`red-extended.log`).
- **GREEN:** consolidated command and final normalizer rerun, both exit **0**. Tests inspect real upstream HTTP bodies for lowering, deletion, and disabling, including compatibility-mode Claude. Full `internal/thinking`, helper, translator, and SDK-translator packages also pass, exit **0** (`targeted-packages.log`), including upstream max/xhigh source-intent cases. Compute caps are not bypassed and upstream source recovery is not dropped.

### 5. Custom apply_patch stays enabled on a no-tools turn

- **Cause:** conversion declared custom patch tools but treated `tool_choice:none` as omission, which does not prohibit tools.
- **Fix:** `internal/translator/claude/openai/responses/claude_openai-responses_request.go:594` emits supported Claude `{"type":"none"}` while retaining declarations and history.
- **RED:** initial command, exit **1**, showed enabled patch declarations and no explicit no-tools choice in the actual HTTP body for both Claude modes (`red-main.log`).
- **GREEN:** consolidated command, exit **0**. `TestRound1ClaudePatchNone` executes streaming and nonstreaming Claude requests and inspects upstream bodies. Custom patch support, paired response restoration, and historical pairing remain intact.

### 6. Fragmented patch streaming has quadratic accumulation and no bound

- **Cause:** per-delta string concatenation and repeated snapshot decoding; unbounded cumulative event retention and call records in common and dispatcher bridges.
- **Fix:** `internal/translator/common/apply_patch_responses.go:116-119,201,371-379,432-439,646-648` uses builders, cached decoded snapshots, and compares only newly decoded input rather than the full prefix per delta. `internal/translator/common/apply_patch_limits.go:6-23` bounds each response to **16 MiB cumulative event bytes, 131072 accepted events, 1024 records** before buffering. `internal/runtime/executor/helps/apply_patch_responses.go:37-38,46,143-146,162-179,256,455-461` independently protects pre-restoration snapshots/dispatcher buffering and uses a builder. Existing terminal translation-failure behavior is reused; no post-connect network timeout was added.
- **RED:** initial common-bridge command, exit **1**, accepted input exceeding 16 MiB. The original-code overlay, exit **1**, accepted oversized input on the **real Kimi SSE executor** without error/failure event and allowed all dispatcher bytes/events/records probes (`red-extended.log`).
- **GREEN:** consolidated command, exit **0**: a **1 MiB valid input fragmented into 16-byte SSE deltas** completes on Kimi; oversized input fails with exactly one response failure and no response completion. Dispatcher probes enforce all three limits. Common bridge fragmented-valid and retained-input checks also pass. Patch and namespace support are preserved.

### 7. Eight nested Go plugins were not migrated with their SDK imports

- **Cause:** nested module identities, requirements, and local replacements still referenced v7 while source imports referenced v8.
- **Fix:** `examples/plugin/{simple,claude-web-search-router,codex-service-tier,frontend-auth-exclusive,host-callback-auth-files,host-model-callback,request-lifecycle,scheduler}/go/go.mod`, lines **1,6 (or 5), final replace line**, now consistently identify/require/replace v8 against `../../../..`. All eight underwent `go mod tidy`; `claude-web-search-router/go/go.sum` changed where needed. `examples/plugin/README.md:133` and `README_CN.md:122` reference the v8 SDK. Internal registry imports now satisfy Go's internal-package boundary.
- **RED command:** for each named plugin, `(cd examples/plugin/$p/go && go build -buildmode=c-shared -o "$OUT/red-$p.so" .)`. All **eight exit 1** (`red-plugin-*.log`); seven identify missing v8 modules, while service-tier also exposes stale dependency metadata in the offline graph.
- **GREEN command:** `(cd examples/plugin/$p/go && go build -buildmode=c-shared -o "$OUT/green-$p.so" .)`, matching the documented `examples/plugin/Makefile:38-39` nested build entrypoint. All **eight exit 0**, final offline rebuilds recorded in `green-plugins.exit` and `green-plugin-*.log`; built `.so` artifacts are kept. No different v8 release was substituted for this checkout.

### 8. Home streaming resolves legacy update support before model binding

- **Cause:** the legacy omitted-support fallback was frozen false before the selected local/OAuth model was attached; Home metadata then took precedence over the correct attempt-local model.
- **Fix:** `sdk/cliproxy/auth/api_key_model_capabilities.go:19,205-210,333` retains legacy provenance and refreshes only legacy support after each execution-model binding. Explicit Home true/false remains authoritative; Home wire fields are unchanged, so no Home repository update is necessary.
- **RED:** initial command, exit **1**, reports false for legacy API-key and OAuth streaming capabilities. Additional command `go test -overlay "$OUT/red-overlay/overlay.json" ./internal/runtime/executor -run TestRound1HomeLegacyCodexStreaming -count=1`, exit **1**, proves the real Home-selected Codex HTTP request **lost its configuration_update item** (`red-home-real.log`).
- **GREEN:** consolidated command, exit **0**. Actual `Manager.ExecuteStream` with the real Codex executor retains legacy-supported updates at HTTP dispatch, keeps explicit true, and strips explicit false. The extended original Home regression also covers API-key/OAuth fallback and unmatched models.

### 9. Gemini/chat tool-name sanitation is not reversible or collision-safe

- **Cause:** declaration/history/choice names were sanitized independently and response converters returned the sanitized spelling; `get.weather` and `get_weather` collapsed.
- **Fix:** `internal/translator/claude/openai/responses/claude_openai-responses_tool_names.go:118-165` exposes a request-local adapter reusing the **existing Responses allocator**, not a new competing sanitation algorithm. Gemini request translation uses it at `claude_gemini_request.go:49` throughout declarations/history/choice; Gemini responses reverse at `claude_gemini_response.go:113,386`. Chat request mapping starts at `claude_openai_request.go:57`; paired response reversal is at `claude_openai_response.go:157,390`.
- **RED command:** `go test ./internal/runtime/executor -run TestRound1ClaudeToolNames -count=1`, exit **1**. All four real Gemini/chat × stream/nonstream cases show collision and lost client spelling (`red-names.log`).
- **GREEN:** consolidated command, exit **0**. Real Claude HTTP execution proves unique upstream names, original-history and forced-choice consistency, and both original client spellings in translated responses. Complete Claude translator packages pass as well (`targeted-packages.log`). The existing Responses mapping remains unchanged.

### 10. A final snapshot silently extends complete streamed patch JSON

- **Cause:** closing streamed JSON reached the complete phase but final completion treated its decoded input as a recoverable prefix.
- **Fix:** `internal/translator/common/apply_patch_input.go:239` requires equality when either `finished` or the parse phase is complete. Only genuinely partial JSON can recover a suffix from a final snapshot.
- **RED:** initial command, exit **1**, accepted complete `{"input":"p"}` followed by `{"input":"pq"}` in the common bridge. The original-code overlay, exit **1**, also completed the conflicting call on the real Kimi SSE path (`red-extended.log`).
- **GREEN:** consolidated command, exit **0**. Common and Kimi checks reject conflicting complete snapshots, accept equivalent complete snapshots with different JSON formatting, and retain legitimate partial-source suffix completion. No patch completion feature was removed.

### 11. Read-only mixed-layout configuration cannot start

- **Cause:** optional legacy-layout cleanup persistence was treated as a mandatory successful-load condition even for a validated, secret-free mixed layout.
- **Fix:** `internal/config/config_load.go:219` logs a warning instead of rejecting an optional cleanup write failure. Validated canonical memory state is retained; writable cleanup and mandatory security-related secret handling remain unchanged.
- **RED:** initial command, exit **1**, the real `LoadConfig` rejected `port: 8317` plus `server: {port: 8317}` with `permission denied` (`red-main.log`).
- **GREEN:** consolidated command, exit **0**. `TestRound1ReadOnlyMixedLayoutLoader` uses an owned temporary read-only file via procfs, verifies canonical port 8317 and unchanged disk bytes. This exercises the actual loader used by server startup, not only a YAML parser round trip. The procfs-specific probe is skipped on non-Linux systems.

### 12. Routine shutdown forcibly truncates inference

- **Cause:** `Server.Stop` replaced graceful shutdown with unconditional immediate HTTP Close, ignoring its caller's drain deadline.
- **Fix:** `internal/api/server.go:403-407,435-444` restores `Shutdown(ctx)` for normal operation and forces `Close` when the drain context expires/cancels. Existing listener closure and Codex live-handler cleanup remain present.
- **RED:** initial command, exit **1**, a real active HTTP response was truncated with EOF despite a five-second drain window (`red-main.log`).
- **GREEN:** consolidated command, exit **0**. `TestRound1ShutdownDrainsActiveRequest` deterministically releases an active request after listener shutdown and receives the complete body. The separate existing `TestServerStop_ViolentShutdownImmediatelyClosesWithoutContextDeadlineError` still passes for an expired context, preserving upstream's forced/deadline path. No wall-clock sleep was added to the new drain regression.

## Full repository checks and inherited failures

Final commands/results:

| Command | Exit | Evidence |
| --- | ---: | --- |
| `go build ./...` | **0** | `full-build.log`, `full-build.exit` |
| `go build -o "$OUT/cli-proxy-api" ./cmd/server` | **0** | `server-build.log`, built CLI; rerun after CLI validation |
| `GOFLAGS=-timeout=120s go test ./...` | **1** | `full-test.log`, `full-test.exit` |
| First-parent `go test ./... -timeout=120s` in an owned `git archive` scratch tree | **1** | `base-full-test-bounded.log`, `base-full-test.exit` |
| Focused full thinking/helpers/Claude translators/common/TUI/SDK translator packages | **0** | `targeted-packages.log` |
| Twelve-finding focused ledger | **0** | `green-final-ledger.log` and subsequent normalizer/TUI checks |
| Eight final standalone Go plugin builds | **0 each** | `green-plugins.exit` |
| `git diff --check` | **0** | checked before commit |

The Go timeout is **test-owned**, not an upstream network timeout. The first exact, unbounded `go test ./...` attempt exceeded the harness's 300-second command deadline; it has no usable test-process exit code and is not claimed successful (`full-test-initial.log`). The corresponding first-parent unbounded attempt was stopped before running the bounded comparison; it is not claimed complete (`base-full-test.log`).

**113 final named failures also fail on the first parent**, mechanically intersected in `inherited-failures.txt`. **Zero HEAD-only named failures** (`head-only-failures.txt` is empty). Both trees additionally time out in `TestCodexWebsocketsExecutorOptimizeMultiAgentV2/stream_enabled` at the same test-owned two-minute package deadline. Failed final packages are `internal/api`, `internal/discovery`, `internal/runtime/executor`, `sdk/api/handlers/openai`, and `test`. Examples include the existing Codex request-log fixture lacking response model identity, LAN discovery in this environment, and old executor/handler fixtures; #46's fixes were deliberately not imported. Because the inherited runtime test hangs, its later tests cannot all complete in the full-suite run; the new repair regressions were separately run to completion.

Two initial thinking failures caused by over-removing source semantic recovery were inspected and fixed, not attributed to the base. The complete thinking package and final full-suite run now pass those cases while the normalizer regression remains GREEN. Baseline-only registry/Antigravity diagnostics are retained in base logs but are not alleged regressions here.

## Remaining scope and handoff

- **Unfixed verdict findings: none.** Full-suite inherited fixture/environment failures and the inherited WebSocket hang are reported, not silently repaired or declared green.
- Nonblocking management-guide modernization and inherited WebSocket model-identity behavior remain outside this twelve-finding repair.
- Original source overlays, logs, check exits, plugin binaries and server binary are kept under `OUT`; `.local/round-answer.md` is the whole-round repository reply, copied to `OUT/round-answer.md`.
- Only a fast-forward repair commit on the current branch is created using the exact requested bot author/committer environment. The lead publishes it. Owned scratch is removed after evidence is retained and all started processes have finished or been stopped and checked.
