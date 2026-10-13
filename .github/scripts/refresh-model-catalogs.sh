#!/usr/bin/env bash
set -euo pipefail

models_repository="${MODELS_REPOSITORY_URL:-https://github.com/router-for-me/models.git}"
# Pinned, not main: an upstream catalog change must not turn our CI red overnight. Bump this ref deliberately in
# each upstream sync (smarty-dev#755/#5776), together with the tests that expect the catalog's models.
# 9fef0649 is the last router-for-me/models commit with gemini-pro-agent and gemini-3.1-pro-low (9c4717a4 drops them).
models_ref="${MODELS_REPOSITORY_REF:-9fef0649fe65dbd69c75840e4f825afe0221dc83}"
catalog_dir="${MODEL_CATALOG_DIR:-internal/registry/models}"
codex_catalog="$catalog_dir/codex_client_models.json"
codex_candidate="$(mktemp)"
trap 'rm -f "$codex_candidate"' EXIT

git fetch --depth 1 "$models_repository" "$models_ref"
git show FETCH_HEAD:models.json > "$catalog_dir/models.json"

if git show FETCH_HEAD:codex_client_models.json > "$codex_candidate" &&
  go run ./cmd/validate_codex_models --file "$codex_candidate"; then
	mv "$codex_candidate" "$codex_catalog"
	printf 'Refreshed validated Codex client model catalog.\n'
else
	printf '::warning::Remote Codex client model catalog is missing or invalid; using embedded fallback.\n'
fi

go run ./cmd/validate_codex_models --file "$codex_catalog"
