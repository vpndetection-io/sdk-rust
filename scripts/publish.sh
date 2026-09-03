#!/bin/bash

# Publishes the crate to crates.io from inside the official Rust image, so a
# release needs nothing installed locally beyond docker and works identically on
# any machine. The release workflow does the same steps on a tag; this is the
# manual path for a first release or when Actions is not an option.
#
#   CARGO_REGISTRY_TOKEN=... ./scripts/publish.sh            # publish
#   DRY_RUN=1 ./scripts/publish.sh                           # rehearse
#
# The first release has to come through here: crates.io attaches a trusted
# publisher to an EXISTING crate, so there is nothing to configure until the
# crate exists. Create the token at https://crates.io/settings/tokens with the
# publish-new scope; it needs no interactive second factor.

set -euo pipefail

cd "$(dirname "$0")/.."

RUST_IMAGE="${RUST_IMAGE:-rust:1-slim}"
DRY_RUN="${DRY_RUN:-}"

if [ -z "$DRY_RUN" ] ; then
    : "${CARGO_REGISTRY_TOKEN:?set CARGO_REGISTRY_TOKEN to a crates.io token that can publish}"
    publish="cargo publish"
else
    publish="cargo publish --dry-run && cargo package --list"
fi

# The working tree is mounted READ ONLY and copied inside, so cargo cannot leave
# a root-owned target/ or Cargo.lock behind in it. The caches are docker volumes
# for the same reason.
docker run --rm \
    -v "$PWD:/src:ro" \
    -v vpndetection-rust-target:/target \
    -v vpndetection-rust-cargo:/cargo \
    -e CARGO_TARGET_DIR=/target \
    -e CARGO_HOME=/cargo \
    -e CARGO_TERM_COLOR=never \
    -e CARGO_REGISTRY_TOKEN="${CARGO_REGISTRY_TOKEN:-}" \
    "$RUST_IMAGE" bash -euc "
        cp -R /src /tmp/build
        cd /tmp/build
        rm -rf target Cargo.lock
        cargo test --all-features
        ${publish}
    "
