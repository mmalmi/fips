# Library release verification

The core and endpoint libraries are published in dependency order. Release a
fixed, clean commit containing the source, manifests, `Cargo.lock`, and the
scripts in `scripts/release/`. Keep the version-only release commit separate
from the tested implementation. Confirm that executable Rust source is unchanged
between those commits before reusing its test evidence.

## Environment and scope

The .118 qualification uses native Linux `x86_64-unknown-linux-gnu`, preinstalled
Rust and Cargo 1.93.1, and the host linker/system libraries. The exact compiler
commit is pinned in `scripts/release/inputs.json`. Core library tests use default
features (no optional WebRTC); compilation uses two jobs with incremental
compilation and dev/test debug information disabled. Reuse an agreed compatible
Cargo target directory with one writer, stage and hash test executables, then
release that writer before running fixtures. Provide a task-owned `TMPDIR` on
the admitted filesystem when the host temporary mount is constrained.

The split .118 procedure prepares source and no-build packages on Linux with
preinstalled Rust/Cargo 1.93.1, Python 3.11 or newer, Git and Node.js 22. It keeps
identity signing and registry credentials on the established Apple Silicon
publisher. The publisher uses Python 3.13 or newer and Git, without Cargo,
compilation, packaging, or source cloning. The earlier combined scripts retain
their Rust/Cargo 1.95.0 pin and original resource requirements; they are not a
smaller fallback job. Pins are recorded in `scripts/release/inputs.json`.

No container or privileged dependency installer is required. Toolchains, SDKs,
system libraries, and signing credentials must already be available. Network
access and publication authority are external prerequisites. The release scripts
do not install tools, expand permissions, or start a local Hashtree daemon.

The preinstalled `git-remote-htree` helper must match the platform and SHA-256 in
the committed inputs file. The archive hash is also pinned for installations
that acquire that artifact separately. Verify these fixed hashes before use;
never replace them with a checksum obtained alongside a mutable download.

## Qualification and source availability

Run focused tests for the actual change using a locked install, for example:

```sh
CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test --locked --offline -p nvpn-fips-core --lib --no-run
```

Verify `rustc --version --verbose` against the qualification pins before this
command. For strict clients, verify both all-current and published .117
`reply_learned` transit paths, including first contact, both directions and
transport rebind. The process fixture `reply_learned_compat_router.rs` uses only
the .117 public API and can be compiled unchanged against the published source;
pass its separately hashed executable in `FIPS_COMPAT_ROUTER_BIN` when running
the ignored `strict_client_mixed_117_reply_learned_and_tree_controls` test.

`strict_client_only` selects reply-learned routing locally and never falls back
to publishing ancestry or Bloom filters. Multi-hop deployment requires
reply-learned transit and compatible remote endpoints. Preserve ordinary Tree
foreign-root tests and the explicit Tree-only failure control. Before consumer
rollout, verify deployed router modes; client opt-in does not alter remote
configuration. The local accepting-listener API additionally requires upgraded
providers and any roster anchor. It never substitutes observed source ports for
accepting listener hints.

Run the selected tests from the resulting executable and retain complete logs,
exit status, source hashes, and benchmark limitations. Allocation benchmarks in
the unit tests are ignored by default and require an explicit test filter and
`--ignored`. Their debug timings do not establish application CPU acceptance.

Keep machine paths, identities, lease state and operational receipts in private
plans outside published source and packages. Bind the clean full release commit
and tested implementation commit, explicit existing public repository, helper
directory, inputs file, task-owned work/output paths, and separately admitted
entry/floor/growth/deadline bounds. Do not lower the earlier combined jobs'
reserves to fit a smaller operation.

```sh
python3 scripts/release/packed-source.py PRIVATE_SOURCE_PLAN prepare
```

Run the producer under a one-CPU, 1 GiB, no-swap Linux process-group supervisor.
It cold-clones the existing public repository, adds only the candidate commit's
`haps-source/FULL_COMMIT` tag from a checksum-bound bundle, and preserves all
existing public refs and HEAD. The bundle must contain only that intended public
history, not private branches or local Git configuration.

The pinned helper's streamed pack upload omits pack/index entry lengths. The
producer corrects only measured lengths and their directory ancestors using
the pinned published Hashtree codec. It requires byte-identical decode/encode
and CHK round trips for every original node, unchanged object CIDs, and remote
readback of every corrected ciphertext node. Never sign the intermediate root.

A disposable identity and loopback-only relay then exercise the actual pinned
Git helper against the corrected immutable contents. This requires a full,
non-shallow, no-alternates clone and exact public ref/object closure; a successful
`htree get` alone is insufficient. No real publisher identity is used here.

Transfer the preparation receipt over the authenticated host channel and bind
its SHA-256 in the signing plan. Run `sign-prepared-source.py` only inside
`guard-small-publish.py` and the existing atomic publisher host lease. It checks
the pinned helper, existing publisher identity and unchanged public root before
signing; it performs no source upload or Git clone. An attempted or ambiguous
sign must be reconciled before another attempt. Then verify from Linux:

```sh
python3 scripts/release/packed-source.py PRIVATE_SOURCE_PLAN verify-signed
```

This independently resolves the signed public route and cold-clones it using
fresh configuration/data directories, without publisher caches or a local
daemon. It verifies the exact corrected root, full history, refs, and every
reachable object. Source verification failure blocks registry publication.

## Package publication

```sh
python3 scripts/release/prepare-package.py PRIVATE_PACKAGE_PLAN
```

Use the same one-CPU, 1 GiB, no-swap Linux supervisor. The credentialless producer
uses pinned `cargo package --locked --no-verify`, a clean exact Git checkout and
an isolated Cargo home without credentials. Compilation is qualified separately.
It records the exact command/toolchain/producer hash and full archive file set,
including generated normalized manifests and lockfiles. Transfer the archive
and receipt through the authenticated channel and bind both hashes in the
publisher plan. Publish core first, then prepare/publish endpoint with its exact
core version available; repeat for dependent libraries in dependency order.

On the established publisher, run `upload-prepared.py PRIVATE_UPLOAD_PLAN check`
and then `publish` through the reviewed small-operation guard and existing atomic
host lease. The upload step runs no Cargo, compiler, package creation or clone.
It verifies archive expansion/entry bounds, the complete producer-bound file
set, clean local source, VCS commit/path, included source bytes/executable bits,
normalized manifest metadata, exact dependencies, and the signed public source
receipt. It rejects existing registry versions and prior upload attempts.

Only `publish` reads the existing registry credential and sends the official
Cargo registry upload request. Credential-bearing requests cannot redirect;
post-credential errors are sanitized. Optimized Python is rejected before any
operation because verification assertions must execute. The guard and outer
lease independently own resource/deadline enforcement and child closure. Run
`test-guard-failures.py` on an admitted host to exercise broken/stuck process
enumeration with a live substitute child. No unrelated dependency update is
part of a version bump.

After publication, the script checks the registry checksum and downloads the
package for an exact byte comparison. An uncertain publish result must be
reconciled against the registry; never blindly upload again. Publish release
tags only after both packages pass, then send the exact commits, versions, and
checksums to consumer owners. Preserve source and evidence until integration
acceptance and clean up only task-owned, inactive outputs.

Source availability, source review, local test results, and registry byte equality
are separate claims. This procedure does not audit every dependency or claim
reproducible native binaries. Package-byte equality proves only that the registry
serves the verified source archive; it does not establish a cross-toolchain or
cross-platform binary match.
