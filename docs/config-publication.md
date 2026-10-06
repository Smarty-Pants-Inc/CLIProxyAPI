# Coordinated file-backed configuration publication

Management edits, SDK saves, plaintext management-key hashing and the operator
publisher use the canonical config path's sibling `.lock` file, version checking
and atomic replacement. All cooperating writers must use these entry points;
editing the live file with an editor, `cp`, or `sed -i` bypasses coordination.
The directory must be writable so the lock and staging files can be created.

On Linux, the sibling lock is kept at `0600` and owned by the config
file's owner/group, independently of which cooperating writer creates it first.
A privileged container writer retains that host identity on the lock before
acquiring it; a host-first lock keeps the same identity when the container writes.
The lock inode is never unlinked or replaced, even during an ownership repair.
The host operator must own the config, or use a deployment identity authorized
to preserve that ownership. If a legacy root-owned lock prevents the host from
opening it, a fixed privileged writer will repair it on its next publication,
or a deployment administrator can adjust that existing inode's owner/group to
match the config. Do not delete/recreate the lock or make it world-writable.

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

Linux and macOS create staging files at `0600`, preserve the original owner/group,
and restore only existing policy-approved mode bits before sync and replacement:
original permissions intersected with `0640` (owner read/write plus group read).
New configs remain `0600`; group write/execute and all other-user access are never
added. If ownership cannot be retained, publication refuses before writing
credentials. This keeps a normal `0640` restricted-group reader working across
startup key hashing and subsequent publications.

Linux inspects the original access ACL through an open descriptor before writing
credentials. Publication refuses an extended POSIX access ACL because this path
cannot preserve all of its effective permissions exactly. Mode group bits are an
ACL mask in that case, not authorization for the owning group. Refusal leaves the
original bytes and ACL intact; no owner-only migration is performed implicitly.

Linux must keep inherited named POSIX ACL entries masked. If staging has named
user/group entries, the allowed mode is instead `0600` intersected with the
original: enabling the group-read mask would enable unrelated inherited readers.
If the original has an authorized owning-group reader but staging inherits named
entries, publication refuses before replacement: masking them would lose that
reader, while unmasking them would grant access to unrelated readers. Refusal
retains the original bytes, inode and effective group grant. Owner-only originals
can still publish with every inherited grant masked. The owner-only security
regression and the separate restricted-reader refusal regression cover both
boundaries. Linux SELinux label preservation remains enforced before writing.

macOS removes inherited ACLs using `/bin/chmod -N` against the open staging
descriptor (`/dev/fd/3`), before writing credentials; mode bits alone do not mask
Darwin ACL grants. Failure refuses publication. The file is synced before an
atomic same-directory rename, followed by directory sync.

Windows uses the installed `golang.org/x/sys/windows` APIs to create the empty
staging file with an owner-only protected DACL, not a post-write numeric chmod.
The descriptor is verified before writing, and an existing config must have the
same owning account. After file sync, one native `FileRenameInfoEx` POSIX
replacement commits; there is no copy/truncate fallback. Unsupported Windows
versions/filesystems refuse without changing the original. The DACL remains
owner-only and cannot inherit broad parent grants.

Other native platforms remain fail-closed. Failed staging files are retained for
diagnosis with no permissions beyond this policy. Native Windows/macOS runtime
acceptance is the manual hosted `config-native-publication` workflow's
`native-publication` matrix jobs (`windows-latest` and `macos-latest`): exact-base
public-path RED, then head GREEN for creation privacy, atomic replacement/refusal,
plaintext management-key startup and ordinary config save. Cross-compilation is
not runtime proof. The integrator must obtain hosted-spend authorization before
dispatch and retain exact-head job receipts; no automatic paid trigger is added.

Only the successfully runtime-applied version is marked observed by the watcher;
load or runtime-apply failures are reported and remain eligible for retry.

This workflow covers **file-backed** configs only. Optional Postgres, git and
object-store coordination remains the separate follow-up
[smarty-dev#4527](https://github.com/Smarty-Pants-Inc/smarty-dev/issues/4527).
