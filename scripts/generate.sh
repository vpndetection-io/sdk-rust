#!/bin/bash

# Regenerates the wire MODELS under src/generated/models from the PINNED spec.
#
# The generator runs in its official container, so nothing has to be installed
# locally, and it reads the committed spec rather than a URL, so the build is
# reproducible and offline. Refresh the spec with scripts/download-spec.sh, run
# this, and commit both together so a reviewer sees which spec produced which
# client.
#
# MODELS ONLY, deliberately. `-g rust --library reqwest` also emits request
# functions, and two of the semantics this SDK is required to get right are
# unreachable through them: its ResponseContent carries `status` and `content`
# but no HEADERS, so a 429's Retry-After (the only thing separating a retryable
# rate limit from a spent quota) cannot be read, and `download_database` is
# generated as `Result<(), _>`, discarding the 302 whose Location header IS that
# endpoint's answer. Both are pinned by the conformance corpus. Six GET
# operations with no request bodies are ~70 lines of reqwest in transport.rs;
# patching the generated ones on every regeneration would be more code and more
# fragile. The models are kept because they carry the spec's optionality
# exactly, which is the absent-versus-false contract for free.
#
# The output is COMMITTED. crates.io publishes SOURCE and docs.rs compiles it,
# and neither runs a pre-build step, so a gitignored client would ship a crate
# that cannot compile itself.

set -euo pipefail

cd "$(dirname "$0")/.."

GENERATOR_IMAGE="${GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.25.0}"

PROPS="packageName=vpndetection,supportAsync=true,hideGenerationTimestamp=true"

# The spec's `Error` schema is the database API's `{rc}` envelope. Left alone it
# generates a model named Error, which is the name this crate's own failure type
# holds, so the two would collide the moment both are re-exported.
MODELS="Error=ErrorEnvelope"

# The four wrapper schemas are inline in the spec, so the generator names them
# after the operation and status code (DatabaseChecksum200ResponseChecksums), and
# one of those is public API here. --model-name-mappings does NOT reach an inline
# schema; only --inline-schema-name-mappings does, keyed by the generator's own
# placeholder name rather than by the Rust name.
NAMES="listDatabases_200_response=DatasetList"
NAMES="${NAMES},listDownloads_200_response=DownloadList"
NAMES="${NAMES},databaseChecksum_200_response=DatasetChecksumsResponse"
NAMES="${NAMES},databaseChecksum_200_response_checksums=DatasetChecksums"

rm -rf .gen
mkdir -p .gen

docker run --rm \
    -v "$PWD/spec:/spec:ro" \
    -v "$PWD/.gen:/out" \
    "$GENERATOR_IMAGE" generate \
    -i /spec/openapi.yaml \
    -g rust --library reqwest \
    -o /out \
    --global-property models,supportingFiles,modelDocs=false,modelTests=false \
    --model-name-mappings "$MODELS" \
    --inline-schema-name-mappings "$NAMES" \
    --additional-properties="$PROPS" \
    >/dev/null

# src/generated/mod.rs is HAND-WRITTEN and is not regenerated.
rm -rf src/generated/models
mkdir -p src/generated
cp -R .gen/src/models src/generated/models

rm -rf .gen

# The repo is rustfmt-clean and CI gates on it, so the generator's output is
# normalized here rather than left as a diff for the next `cargo fmt` to find.
./scripts/cargo.sh fmt

echo "regenerated src/generated/models from spec/openapi.yaml"
grep -m1 '^  version:' spec/openapi.yaml
