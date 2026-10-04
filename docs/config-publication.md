# Coordinated file-backed configuration publication

Management edits, SDK saves, plaintext management-key hashing and the operator
publisher use the canonical config path's sibling `.lock` file, version checking
and atomic replacement. All cooperating writers must use these entry points;
editing the live file with an editor, `cp`, or `sed -i` bypasses coordination.
The directory must be writable so the lock and staging files can be created.

## Operator workflow

Build the entry point from the repository root:

```sh
go build -o config-publish ./cmd/config-publish
```

Take one original snapshot, and compute the SHA-256 **from that snapshot**, not
from a second read of the live path. For example, on Linux:

```sh
work=$(mktemp -d)
cp config/config.yaml "$work/original.yaml"
version=$(sha256sum "$work/original.yaml" | cut -d ' ' -f 1)
cp "$work/original.yaml" "$work/edited.yaml"
# Edit only "$work/edited.yaml" with your preferred editor.
./config-publish --config config/config.yaml \
  --input "$work/edited.yaml" --expected-version "$version"
```

The command prints the published version on success. It performs the same
complete, side-effect-free validation as the server's loader before publishing.
An invalid config or a missing/stale version exits nonzero without replacing the
live file. A CAS conflict requires a **fresh snapshot and reapplication of the
edit**. Never attach today's disk hash to yesterday's replacement bytes: that
would overwrite another writer's changes. Keep snapshots private because they
contain credentials; the launcher/operator owns their eventual disposal.

SDK callers should use `LoadConfig` or `ParseConfigBytes` to retain the exact
source-byte version, then the versioned save APIs. A manually constructed,
unversioned config is not granted authority by reading the current disk hash.

## Docker Compose migration

The supplied Compose service now mounts a directory using `CLI_PROXY_CONFIG_DIR`
(default `./config`) and runs `./CLIProxyAPI --config
/CLIProxyAPI/config/config.yaml`. Before starting the updated service, migrate
an existing single-file deployment (substitute your old config path if needed):

```sh
mkdir -p ./config
cp ./config.yaml ./config/config.yaml
chmod 600 ./config/config.yaml
# Set CLI_PROXY_CONFIG_DIR to a directory, not the old CLI_PROXY_CONFIG_PATH file.
docker compose up -d --force-recreate
```

Preserve the original owner's access to the directory/file, and ensure the
container process can write it. The original file is retained by these commands.
A sibling staging file can be renamed over a file **inside** this directory
mount, including the initial plaintext-management-key hashing rewrite and
repeated management/SDK/operator publications.

A legacy single-file bind mount or cross-device/non-renameable destination is
**refused with a clear error**, not truncated in place. Migrate and recreate the
container; there is intentionally no non-atomic fallback. Startup with a
plaintext management key also refuses if its secure rewrite cannot be published.

## Security and scope

Unix staging and replacements preserve the original owner/group and use the
stricter `0600` mode, masking inherited POSIX ACL group/named-user grants. New
configs are also owner-only. This can remove existing group-read access; the
server must run as the owner. If ownership cannot be retained, publication is
refused before writing credentials. Windows publication is currently refused:
numeric mode bits cannot preserve a Windows DACL safely. Failed owner-private
staging files may remain in the config directory for diagnosis.

Only the successfully runtime-applied version is marked observed by the watcher;
load or runtime-apply failures are reported and remain eligible for retry.

This workflow covers **file-backed** configs only. Optional Postgres, git and
object-store coordination remains the separate follow-up
[smarty-dev#4527](https://github.com/Smarty-Pants-Inc/smarty-dev/issues/4527).
