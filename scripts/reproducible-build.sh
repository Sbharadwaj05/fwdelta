#!/usr/bin/env bash
#
# Blueprint section 03 claims a reproducible build: "pinned toolchain and locked
# dependency graph, so a third party can rebuild the published binary and
# compare digests". This is what makes that checkable.
#
# It builds the binary twice in separate target directories and requires the two
# digests to match. Two builds on one machine catch the common causes —
# embedded paths, timestamps, incremental-compilation state, non-deterministic
# codegen ordering. They do not prove reproducibility across machines, which
# needs a different host and is what publishing the digest is for.
#
#   scripts/reproducible-build.sh          build twice and compare
#   scripts/reproducible-build.sh --digest print the digest and exit

set -euo pipefail

cd "$(dirname "$0")/.."

TARGET=x86_64-unknown-linux-musl
BIN_PATH="release/soteria"

# Every input that would otherwise vary between two builds of identical source.
#
# CARGO_ENCODED_RUSTFLAGS rather than RUSTFLAGS: the latter is split on
# whitespace, so a checkout under a path containing a space -- which this one
# was -- splits the remap flag in half and the build fails with an
# unintelligible error. The encoded form separates arguments with \x1f and has
# no such problem.
US=$'\x1f'
export CARGO_INCREMENTAL=0
export CARGO_ENCODED_RUSTFLAGS="--remap-path-prefix=${PWD}=.${US}-C${US}debuginfo=0"
export SOURCE_DATE_EPOCH=0
export LC_ALL=C
export TZ=UTC

build() {
    local dir="$1"
    # --locked: the lockfile is an input to the build, not a suggestion. Without
    # it a dependency could resolve differently between the two runs and the
    # comparison would be meaningless.
    if ! CARGO_TARGET_DIR="$dir" cargo build \
        --release --locked --target "$TARGET" -p soteria-cli >"$dir.log" 2>&1; then
        echo "build failed:" >&2
        tail -20 "$dir.log" >&2
        exit 1
    fi
    sha256sum "$dir/$TARGET/$BIN_PATH" | cut -d' ' -f1
}

if [ "${1:-}" = "--digest" ]; then
    tmp="$(mktemp -d)"
    trap 'rm -rf "$tmp"' EXIT
    build "$tmp/a"
    exit 0
fi

echo "toolchain: $(rustc --version)"
echo "target:    $TARGET"
echo

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "building (1/2)..."
A="$(build "$tmp/a")"
echo "  $A"

echo "building (2/2)..."
B="$(build "$tmp/b")"
echo "  $B"

echo
if [ "$A" != "$B" ]; then
    echo "FAIL: two builds of identical source produced different binaries"
    echo "  $A"
    echo "  $B"
    exit 1
fi

echo "PASS: reproducible"
echo
echo "sha256:    $A"
echo
echo "A third party can check this with:"
echo "  git checkout \$(git rev-parse HEAD) && scripts/reproducible-build.sh --digest"
echo "The toolchain is pinned in rust-toolchain.toml and the graph in Cargo.lock;"
echo "both are committed, so the only remaining variable is the host."
