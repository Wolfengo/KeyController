# Distribution integrity and reproducible exports

KeyController's normal installation path uses the system package manager and
trusted repository package signatures. A GitHub source archive, a SHA-256 list,
and a GitHub build attestation serve different purposes; none alone makes a
project-produced binary an Omarchy-signed package.

The existing `v0.1.0` release is a historical local build. Its lightweight tag
points to `d493f037aed197cf3536c4b3da39af3465ed0d05`, that commit is unsigned,
and the release has checksums but no project package signature. Do not replace
its assets with new bytes. Security/build changes require a new version, tag,
and review. Existing checksums and old release provenance do not change when a
new verification workflow is added.

## Deterministic source exports

Run `scripts/package-source` from the repository. It uses `SOURCE_DATE_EPOCH`
when explicitly set, otherwise the checked-out Git commit timestamp. An unpacked
source archive preserves that timestamp in `.source-date-epoch`; arbitrary
non-Git trees must supply it explicitly.

Both source and standalone-widget archives have a stable order, fixed gzip and
tar timestamps, numeric ownership `0:0`, no owner names, and normalized file
permissions (`0644`, or `0755` for directories/executable files). Python bytecode
is excluded. Symlinks, devices and other unusual filesystem objects are rejected.
The generated `PKGBUILD` pins the exact source archive SHA-256. Generated local
`dist/` output is not a release publication action.

`python tests/reproducible-export.py` exercises different directories, source
mtimes, output names and simulated ownership, verifies archive metadata, and
re-exports extracted sources without Git. This establishes deterministic exports
for identical source content and epoch. It does not establish that complete
binaries have been independently rebuilt.

Release binaries always use `/usr/lib/ssh-keys/harden.so`. The original absolute
build-directory fallback is compiled only into tests/debug builds, never the
production release path. Debug builds must not be installed as the system helper.
The private startup handshake must still succeed before secrets are transferred;
missing or incompatible installed hardening code fails the operation.
The package check runs `tests/reproducible-release.py` against the built release
helper to reject embedded build-directory hardening-library paths without
executing that helper.

## Isolated verification workflow

`.github/workflows/verify-build.yml` builds the same source twice in separate
containers as a non-root user. The official Arch base image is resolved to a
content digest once, packages are installed into a builder image once, and that
same resulting image is used for both builds. The source commit, epoch, base-image
digest and builder-image ID accompany the artifacts. Actions are pinned by full
commit SHA. The package builds run without sudo, capabilities, host-home mounts,
or credentials; the workflow never installs the package on the host.

Every source archive, recipe and binary package must compare byte-for-byte before
artifacts are retained. If they differ, the workflow fails rather than silently
normalizing or ignoring package metadata. The image digest and `.BUILDINFO` help
diagnose dependency/toolchain differences. Arch repositories move over time: a
later workflow run may use different toolchain packages. Matching two isolated
builds in one run is useful evidence, not an independent third-party rebuild or
a promise of identical outputs across arbitrary dependency versions. A clean
hardware/system installation, native aarch64 build and fingerprint/TPM/sleep
validation remain separate acceptance checks.

## Provenance and publication

Pull requests and ordinary pushes receive read-only repository permissions.
Only an explicit `workflow_dispatch` on a version tag in `Wolfengo/KeyController`
may run the separate `provenance` job. It uses GitHub's official
[`actions/attest`](https://github.com/actions/attest) action with short-lived OIDC
identity, not a stored private signing key. It creates provenance for the exact
candidate archives and checksum manifest from that run. It does not create or
edit GitHub Releases, upload release assets, sign Pacman packages, or publish to
the Omarchy repository.

Before enabling release use, maintainers must protect version tags and configure
required reviewers for the `release-attestation` GitHub environment. Those are
repository settings; the workflow file does not prove they are enabled. Review
the source commit, compare results and workflow identity before authorizing a
new release. Publish only the verified artifact bytes under a new immutable
version, and enable GitHub release immutability where available. Never regenerate
and overwrite an already published release to make checks pass.

A recipient can inspect provenance with GitHub CLI, replacing the filename and
full commit with the intended release values:

```bash
gh attestation verify keycontroller-VERSION.tar.gz \
  --repo Wolfengo/KeyController \
  --signer-workflow Wolfengo/KeyController/.github/workflows/verify-build.yml \
  --source-digest FULL_RELEASE_COMMIT
```

Verify the expected repository, workflow, tag/commit and artifact digest. A valid
attestation records the build identity; it does not certify code safety. Official
Omarchy package signing and repository acceptance are separate from GitHub
attestation. Workflow execution and independent binary reproducibility must be
reported as unverified until their actual results exist.
