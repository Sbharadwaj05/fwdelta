#!/usr/bin/env bash
#
# Empirical half of the air-gap claim in blueprint section 03.
#
# `deny.toml` bans network-capable crates by name, which is a tripwire at review
# time and not a proof: cargo-deny cannot tell whether a crate opens a socket,
# and `libc` is FFI to everything. This runs the shipped binary under strace and
# fails if it issues a single socket syscall.
#
# Usage: scripts/syscall-audit.sh <binary> [args...]

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: $0 <binary> [args...]" >&2
    exit 2
fi

BIN="$1"
shift

if ! command -v strace >/dev/null 2>&1; then
    echo "syscall-audit: strace is not installed" >&2
    exit 2
fi
if [ ! -x "$BIN" ]; then
    echo "syscall-audit: $BIN is not executable" >&2
    exit 2
fi

TRACE="$(mktemp)"
trap 'rm -f "$TRACE"' EXIT

# -f follows any child, so a binary that tried to shell out to curl would still
# be caught. %network covers socket, connect, bind, listen, accept, send*,
# recv*, getsockopt, setsockopt and the rest of the family.
set +e
strace -f -e trace=%network -o "$TRACE" "$BIN" "$@" >/dev/null 2>&1
STATUS=$?
set -e

if [ "$STATUS" -ne 0 ]; then
    echo "syscall-audit: the binary exited $STATUS; auditing a failed run proves nothing" >&2
    exit 2
fi

# strace writes process-lifecycle lines even when no traced syscall occurs.
CALLS="$(grep -Ev '(\+\+\+|---)' "$TRACE" | grep -Ev '^\s*$' || true)"

if [ -n "$CALLS" ]; then
    echo "FAIL: the binary issued network syscalls"
    echo "$CALLS"
    exit 1
fi

echo "PASS: no network syscalls in $(basename "$BIN")"
