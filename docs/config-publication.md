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

The command prints the hash of the published bytes on success. It performs the
same complete, side-effect-free validation as the server's loader before
publishing. A plaintext `remote-management.secret-key` is replaced with the
server's bcrypt representation before publication; all other edited bytes are
retained byte-for-byte, including comments, unknown options, line endings and
formatting. This byte-preserving contract is intentional: the publisher does not
route through the server's YAML serializer, which may normalize quotes or CRLF
line endings. Consumers should compare decoded credentials plus non-secret byte
preservation, not literal equality with serializer output. Empty and already
hashed keys are not rewritten. The edited input file is never modified, so it
may still contain plaintext and must remain private. The CAS check still uses
the original snapshot's hash, not a hash of normalized or edited bytes.

Plain, quoted (including multiline quoted), and block management-key scalars
are supported. For plaintext keys supplied through aliases, anchors, merge keys,
explicit tags, or multiline plain scalars, the command refuses publication
rather than risking a partial credential rewrite. Use an explicit unanchored
quoted scalar in the edited input for those cases.

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
The operator publisher hashes plaintext before the same locked atomic CAS
publication; it does not publish plaintext and then perform a second rewrite.

## Security and scope

Linux staging and replacements preserve the original owner/group and use
owner-only mode bits no broader than the original (`0600` for new configs),
masking inherited POSIX ACL group/named-user grants. This can remove existing
group-read access; the server must run as the owner. If ownership cannot be retained, publication is
refused before writing credentials. Windows and other non-Linux publication
are currently refused: numeric mode bits alone cannot preserve their native
ACLs safely. Native security-descriptor support needs platform-hosted validation.
Failed owner-private staging files may remain in the config directory for diagnosis.

Only the successfully runtime-applied version is marked observed by the watcher;
load or runtime-apply failures are reported and remain eligible for retry.

This workflow covers **file-backed** configs only. Optional Postgres, git and
object-store coordination remains the separate follow-up
[smarty-dev#4527](https://github.com/Smarty-Pants-Inc/smarty-dev/issues/4527).
