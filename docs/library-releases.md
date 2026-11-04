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

Source publication and no-build package creation use the existing Apple Silicon
macOS publisher with preinstalled Rust/Cargo 1.95.0, Python 3.13 or newer and Git.
The packaging override and separate native qualification pins are recorded in
`scripts/release/inputs.json`. This does not claim identical native binaries
across the two toolchains or targets.

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

Prepare a private output directory containing `preparation.json`. It binds
`root`, full `head` and `tested_head` commits, `version`, a serialized `target`
cache, explicit public `source_url`, and the admitted resource bounds:
`initial_min_bytes`, `floor_bytes`, `max_global_loss_bytes`, `source_seconds`,
`source_phase_seconds`, and `package_seconds`. Keep machine paths and operational
receipts outside published source and packages.

```sh
python3 scripts/release/source-gate.py OUTPUT_DIR VERIFIED_HELPER_DIRECTORY
```

This verifies the helper before invoking it, checks that the explicit source
destination and the authenticated `self` alias identify the same existing
repository, publishes `haps-source/FULL_COMMIT`, and reads it back. The readback
uses fresh configuration and data directories, no publisher cache or local
daemon, and no Git alternates. It requires a non-shallow repository and every
reachable Git object. A source-gate failure blocks package publication. Failed
readbacks are retained for inspection; successful temporary readbacks are removed
after their process groups have closed.

## Package publication

```sh
python3 scripts/release/package-one.py OUTPUT_DIR nvpn-fips-core
python3 scripts/release/package-one.py OUTPUT_DIR nvpn-fips-endpoint
```

Each step requires the successful source receipt for the exact release commit.
It uses `cargo package` and `cargo publish` with `--locked --no-verify`: compilation
has already been qualified separately. It rejects dirty source and existing
versions, checks package VCS provenance, compares included source files with the
checkout, and checks endpoint's exact core pin. No unrelated dependency update
is part of a version bump. Generated package lockfiles and normalized manifests
are retained for inspection.

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
