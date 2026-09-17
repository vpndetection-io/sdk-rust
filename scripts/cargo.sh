#!/bin/bash

# Runs any cargo command inside the official Rust image, so the box needs no
# toolchain.
#
#   ./scripts/cargo.sh test
#   ./scripts/cargo.sh clippy --all-targets -- -D warnings
#   RUST_IMAGE=rust:1.85-slim ./scripts/cargo.sh check
#
# Downloaded crates persist in a named docker VOLUME, so only the first run pays
# for the index. target/ stays inside the container and goes with it, so a build
# can neither land in the working tree nor pile up on disk between runs.

set -euo pipefail

cd "$(dirname "$0")/.."

RUST_IMAGE="${RUST_IMAGE:-rust:1-slim}"
CARGO_VOLUME="${CARGO_VOLUME:-vpndetection-rust-cargo}"
# Incremental data and full debug info were over half of target/ and buy nothing
# when every build starts cold: without them one is smaller and faster, and a
# backtrace still has file and line.
CARGO_INCREMENTAL="${CARGO_INCREMENTAL:-0}"
CARGO_PROFILE_DEV_DEBUG="${CARGO_PROFILE_DEV_DEBUG:-line-tables-only}"

exec docker run --rm -i \
    -v "$PWD:/work" \
    -v "${CARGO_VOLUME}:/cargo" \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo \
    -e CARGO_TERM_COLOR=never \
    -e CARGO_INCREMENTAL="$CARGO_INCREMENTAL" \
    -e CARGO_PROFILE_DEV_DEBUG="$CARGO_PROFILE_DEV_DEBUG" \
    -e VPNDETECTION_LIVE="${VPNDETECTION_LIVE:-}" \
    -e VPNDETECTION_API_KEY="${VPNDETECTION_API_KEY:-}" \
    -w /work \
    "$RUST_IMAGE" bash -euc "
        # rust:*-slim ships neither component, and the one behind \`cargo fmt\` is
        # named rustfmt rather than fmt.
        case \"\${1:-}\" in
            clippy) rustup component add clippy >/dev/null ;;
            fmt) rustup component add rustfmt >/dev/null ;;
        esac
        exec cargo \"\$@\"
    " bash "$@"
