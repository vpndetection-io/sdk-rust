#!/bin/bash

# Runs the integration suite against the crate as PUBLISHED on crates.io, which
# is the one thing the suite in ../tests cannot check: it compiles this working
# tree, so it stays green through a tag that never landed, an `exclude` that
# dropped a module from the package, or a feature a consumer cannot turn on.
#
#   ./scripts/run.sh
#
# Two conditions make a run meaningless rather than failing, and each one skips
# with a reason instead:
#
#   1. Nothing published satisfies the requirement in Cargo.toml. Before the
#      first release there is no artifact to test, and unlike an interpreted
#      language a Rust test naming a method that version does not have will not
#      COMPILE, so this gate has to cover the whole suite rather than one test.
#   2. A tier's staging key is missing or EMPTY. The unauthenticated tests still
#      run, and each tier without a key skips from inside the suite, so the skip
#      and its reason land in the test output rather than only here.
#
# There is deliberately NO local-source escape hatch. A path dependency or a
# [patch] entry is refused outright, because a suite pointed at the working tree
# passes for the wrong reason and says so nowhere.
#
# cargo runs natively when a toolchain is present and inside the official image
# otherwise, so a dev box with no Rust and a CI runner both use this one entry
# point.

set -euo pipefail

cd "$(dirname "$0")/.."

CRATE="vpndetection"
INDEX="${CRATES_INDEX:-https://index.crates.io}"
REGISTRY_SOURCE="registry+https://github.com/rust-lang/crates.io-index"
RUST_IMAGE="${RUST_IMAGE:-rust:1-slim}"

# Mirrors the requirement in Cargo.toml, which is asserted against rather than
# parsed: the range has to be evaluated before cargo is allowed to run at all,
# and two lines kept in agreement beat a semver parser written in bash.
REQUIREMENT='^1.0'
RANGE_LOW='1.0.0'
RANGE_HIGH='2.0.0'

function main() {
    local published
    # Local source is ruled out FIRST, so a path dependency is named as one
    # rather than reported as a requirement that does not match.
    assertNoLocalSource
    assertManifestAgrees

    published="$(publishedVersions)"
    if [ -z "$published" ] ; then
        skip "no published ${CRATE} satisfies ${REQUIREMENT}, so there is no released artifact to test"
        return 0
    fi
    echo "==> ${CRATE} ${REQUIREMENT} matches published ${published//$'\n'/, }"

    reportTiers

    # Removed so every run resolves the requirement afresh. A kept lock file
    # would pin whatever the first run happened to pick, and the daily run would
    # stop noticing new releases.
    rm -f Cargo.lock
    cargoRun generate-lockfile
    assertFromTheRegistry "$published"

    cargoRun test -- --nocapture
}

# The requirement this script evaluates has to be the one cargo will evaluate.
function assertManifestAgrees() {
    if ! grep -qE "^${CRATE} = \"\\${REQUIREMENT}\"$" Cargo.toml ; then
        echo "==> FAILED: Cargo.toml does not require ${CRATE} = \"${REQUIREMENT}\"," \
            "so the range this gate checks is not the one cargo would resolve" >&2
        exit 1
    fi
}

# The suite is worthless if cargo handed it the working tree, and that failure is
# silent: every test passes, against the wrong code. Both ways in are refused
# here, before a run rather than after a green one. The lock file is checked
# again afterwards, which also catches a replacement configured outside this
# directory.
function assertNoLocalSource() {
    local hits
    hits="$(grep -nE '^\s*\[patch|(^|[^a-z_])path\s*=' Cargo.toml || true)"
    if [ -n "$hits" ] ; then
        echo "==> FAILED: Cargo.toml carries a path dependency or a [patch] section," \
            "so this would not test the release:" >&2
        echo "$hits" >&2
        exit 1
    fi
    for config in .cargo/config.toml .cargo/config ; do
        if [ -e "$config" ] ; then
            echo "==> FAILED: ${config} can redirect crates.io to a local checkout," \
                "and this suite must resolve from the registry" >&2
            exit 1
        fi
    done
}

# Every version the sparse index serves, ascending, yanked ones dropped. This is
# the index cargo itself resolves from, so the answer is exactly what an install
# would see. A crate that does not exist answers 404, which means the same thing
# here as a crate with no version in range.
function publishedVersions() {
    local body line vers
    body="$(curl -fsS "${INDEX}/$(indexPath "$CRATE")" 2>/dev/null || true)"
    while read -r line ; do
        case "$(printf '%s' "$line" | tr -d ' ')" in
            *'"yanked":true'*) continue ;;
        esac
        vers="$(printf '%s' "$line" | sed -n 's/.*"vers":"\([^"]*\)".*/\1/p')"
        if [ -n "$vers" ] && inRange "$vers" ; then
            echo "$vers"
        fi
    done <<< "$body"
    return 0
}

# The sparse index shards by name length: 1 or 2 characters live under the
# length itself, 3 under `3/<first>`, and anything longer under the first two
# characters then the next two.
function indexPath() {
    local name="$1"
    case "${#name}" in
        1|2) echo "${#name}/${name}" ;;
        3) echo "3/${name:0:1}/${name}" ;;
        *) echo "${name:0:2}/${name:2:2}/${name}" ;;
    esac
}

function inRange() {
    local vers="$1" lowest highest
    lowest="$(printf '%s\n%s\n' "$vers" "$RANGE_LOW" | sort -V | head -1)"
    highest="$(printf '%s\n%s\n' "$vers" "$RANGE_HIGH" | sort -V | head -1)"
    [ "$lowest" = "$RANGE_LOW" ] && [ "$highest" = "$vers" ] && [ "$vers" != "$RANGE_HIGH" ]
}

# What cargo actually resolved, read from the lock file it just wrote. A package
# taken from a path dependency or a [patch] carries NO `source` line at all, and
# a replaced registry carries a different one, so the entry proves where the code
# came from rather than merely naming a version.
function assertFromTheRegistry() {
    local published="$1" block vers source
    block="$(sed -n "/^name = \"${CRATE}\"\$/,/^\$/p" Cargo.lock)"
    if [ -z "$block" ] ; then
        echo "==> FAILED: ${CRATE} is not in Cargo.lock at all" >&2
        exit 1
    fi
    vers="$(printf '%s\n' "$block" | sed -n 's/^version = "\(.*\)"$/\1/p')"
    source="$(printf '%s\n' "$block" | sed -n 's/^source = "\(.*\)"$/\1/p')"

    if [ "$source" != "$REGISTRY_SOURCE" ] ; then
        echo "==> FAILED: ${CRATE} resolved from ${source:-a local path}, not from" \
            "${REGISTRY_SOURCE}, so the tests would not be testing the release" >&2
        exit 1
    fi
    if ! printf '%s\n' "$published" | grep -qx "$vers" ; then
        echo "==> FAILED: resolved ${vers}, which is not one of ${published//$'\n'/, }" >&2
        exit 1
    fi
    echo "==> testing ${CRATE} ${vers} from ${source}"
}

# Names only, never values: these logs are public.
function reportTiers() {
    local present=() absent=()
    for secret in VPNDETECTION_STAGING_KEY_FREE VPNDETECTION_STAGING_KEY_STARTER \
        VPNDETECTION_STAGING_KEY_SCALE VPNDETECTION_STAGING_KEY_MAX ; do
        # Empty counts as absent: CI interpolates a secret that does not exist to
        # an empty string, so the variable is SET and a plain unset check never
        # fires, while an empty key is sent as no key at all.
        if [ -n "${!secret:-}" ] ; then
            present+=("$secret")
        else
            absent+=("$secret")
        fi
    done
    echo "==> tiers with a key: ${present[*]:-none}"
    if [ "${#absent[@]}" -gt 0 ] ; then
        notice "no staging key for ${absent[*]}: those tiers skip from inside the suite"
    fi
}

function cargoRun() {
    echo "==> cargo $*"
    if command -v cargo >/dev/null 2>&1 ; then
        cargo "$@"
        return 0
    fi
    # Both caches live in named docker VOLUMES rather than in the working tree,
    # so neither target/ nor a registry checkout can end up in a commit.
    docker run --rm -i \
        -v "$PWD:/work" \
        -v vpndetection-rust-integration-target:/target \
        -v vpndetection-rust-integration-cargo:/cargo \
        -e CARGO_TARGET_DIR=/target \
        -e CARGO_HOME=/cargo \
        -e CARGO_TERM_COLOR=never \
        -e VPNDETECTION_STAGING_KEY_FREE -e VPNDETECTION_STAGING_KEY_STARTER \
        -e VPNDETECTION_STAGING_KEY_SCALE -e VPNDETECTION_STAGING_KEY_MAX \
        -w /work "$RUST_IMAGE" cargo "$@"
}

function skip() {
    echo "==> SKIPPED: $1"
    notice "Integration suite skipped: $1"
}

# Surfaced on the workflow run itself, so a skip is visible without opening the
# log and reading to the end of it.
function notice() {
    if [ "${GITHUB_ACTIONS:-}" = "true" ] ; then
        echo "::notice title=Integration::$1"
    fi
}

main "$@"
