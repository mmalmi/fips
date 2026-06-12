default:
    @just --list

fmt:
    cargo fmt --check

rust-file-lines:
    ./scripts/check-rust-file-lines.sh

test-core:
    cargo test -p fips-core -- --nocapture

test-sim:
    cargo test -p fips-sim -- --nocapture

test: test-core test-sim

linux-dataplane-safety:
    ./scripts/test-dataplane-safety-linux-docker.sh

clippy-core:
    cargo clippy -p fips-core --all-targets

clippy-sim:
    cargo clippy -p fips-sim --all-targets

clippy: clippy-core clippy-sim

check: rust-file-lines fmt test clippy

sim-smoke:
    cargo run -p fips-sim --release --example production_mesh -- --compare --nodes 60 --route-probes 100 --stream-probes 2 --stream-bytes 1048576 --background-packets 1000 --summary-only --no-progress
