#!/usr/bin/env bash
#
# Hook x match sweep.
#
# The `iifname` on an output chain bug is a class, not an incident: nftables
# accepts a rule, the kernel silently never applies it, and a model that treats
# the match as live disagrees with reality on every packet while reporting
# confidently.
#
# The differential harness cannot find these. It generates rulesets from the
# same model under test, so it only ever produces combinations already modelled
# correctly. This entire class sits in the blind spot of the project's strongest
# verification mechanism, which is why it needs a separate, exhaustive check.
#
# So: enumerate every hook the frontend accepts against every match type it
# accepts, load each combination into a namespace, send a packet the match is
# constructed to be true of, and read a counter to see whether the kernel
# actually applied it. Finite table, no judgement calls.
#
#   scripts/hook-match-sweep.sh            human-readable table
#   scripts/hook-match-sweep.sh --markdown table for docs/HOOK-MATCH-MATRIX.md
#
# Needs nftables, iproute2 and unprivileged user namespaces. No root.

set -euo pipefail

MARKDOWN=0
[ "${1:-}" = "--markdown" ] && MARKDOWN=1

if [ -z "${SWEEP_INNER:-}" ]; then
    exec env SWEEP_INNER=1 unshare -Ur -n "$0" "$@"
fi

# ---------------------------------------------------------------- topology
#
# input/output are reachable over loopback: locally generated traffic to a local
# address traverses output, then input.
#
# forward needs the host to actually route, which needs two interfaces and two
# peers:  A --veth-- [main, forwarding] --veth-- B
#
ip link set lo up
ip addr add 10.1.0.1/32 dev lo
ip addr add 10.5.0.1/32 dev lo

unshare -n sleep 3600 &
PEER_A=$!
unshare -n sleep 3600 &
PEER_B=$!
sleep 0.3
cleanup() { kill "$PEER_A" "$PEER_B" 2>/dev/null || true; }
trap cleanup EXIT

ip link add va type veth peer name vma
ip link add vb type veth peer name vmb
ip link set va netns "$PEER_A"
ip link set vb netns "$PEER_B"

ip addr add 10.7.0.254/24 dev vma && ip link set vma up
ip addr add 10.8.0.254/24 dev vmb && ip link set vmb up
echo 1 > /proc/sys/net/ipv4/ip_forward

nsenter -t "$PEER_A" -n sh -c \
    'ip link set lo up; ip addr add 10.7.0.1/24 dev va; ip link set va up; ip route add default via 10.7.0.254'
nsenter -t "$PEER_B" -n sh -c \
    'ip link set lo up; ip addr add 10.8.0.1/24 dev vb; ip link set vb up; ip route add default via 10.8.0.254'

# A listener on the destination stops an accepted datagram drawing an ICMP
# unreachable, which would traverse the hook again and move a second counter.
nsenter -t "$PEER_B" -n python3 -c "
import socket,time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.8.0.1',9999)); time.sleep(3600)" &
LISTENER=$!
trap 'cleanup; kill "$LISTENER" 2>/dev/null || true' EXIT
sleep 0.3

# ------------------------------------------------------------------ probes
#
# Each hook needs traffic that genuinely traverses it, and the match under test
# is constructed to be true of that traffic's real header.

probe() {
    case "$1" in
        input | output)
            python3 -c "
import socket
lis=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); lis.bind(('10.5.0.1',9999))
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.1.0.1',4444))
s.sendto(b'x',('10.5.0.1',9999))" ;;
        forward)
            nsenter -t "$PEER_A" -n python3 -c "
import socket
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(('10.7.0.1',4444))
s.sendto(b'x',('10.8.0.1',9999))" ;;
    esac
    sleep 0.2
}

# The real header of the probe on each hook, so a match can be built that is
# true of it. Interface names differ per hook, which is the whole point.
declare -A SADDR=([input]=10.1.0.1 [output]=10.1.0.1 [forward]=10.7.0.1)
declare -A DADDR=([input]=10.5.0.1 [output]=10.5.0.1 [forward]=10.8.0.1)
declare -A IIF=([input]=lo [output]=lo [forward]=vma)
declare -A OIF=([input]=lo [output]=lo [forward]=vmb)

match_expr() {
    local hook="$1" kind="$2"
    case "$kind" in
        "ip saddr")     echo "ip saddr ${SADDR[$hook]}" ;;
        "ip daddr")     echo "ip daddr ${DADDR[$hook]}" ;;
        "meta l4proto") echo "meta l4proto udp" ;;
        "ip protocol")  echo "ip protocol udp" ;;
        "udp sport")    echo "udp sport 4444" ;;
        "udp dport")    echo "udp dport 9999" ;;
        "iifname")      echo "iifname \"${IIF[$hook]}\"" ;;
        "oifname")      echo "oifname \"${OIF[$hook]}\"" ;;
    esac
}

HOOKS=(input output forward)
MATCHES=("ip saddr" "ip daddr" "ip protocol" "meta l4proto" "udp sport" "udp dport" "iifname" "oifname")

declare -A RESULT

for hook in "${HOOKS[@]}"; do
    for kind in "${MATCHES[@]}"; do
        expr="$(match_expr "$hook" "$kind")"
        nft flush ruleset 2>/dev/null || true

        # Rule 1 carries the match under test and a terminal verdict, so exactly
        # one of the two counters can move.
        if ! nft -f - <<NFT 2>/dev/null
table ip sweep {
  chain c {
    type filter hook $hook priority filter; policy accept;
    $expr counter accept comment "hit"
    counter accept comment "miss"
  }
}
NFT
        then
            RESULT["$hook,$kind"]="rejected-by-nft"
            continue
        fi

        probe "$hook"

        hits="$(nft list chain ip sweep c | grep 'comment "hit"' | grep -oE 'packets [0-9]+' | awk '{print $2}')"
        miss="$(nft list chain ip sweep c | grep 'comment "miss"' | grep -oE 'packets [0-9]+' | awk '{print $2}')"

        if [ "${hits:-0}" -gt 0 ]; then
            RESULT["$hook,$kind"]="applied"
        elif [ "${miss:-0}" -gt 0 ]; then
            # nft took the rule and the kernel never applied it. This is the
            # dangerous cell: the file loads, the rule looks live, and it is not.
            RESULT["$hook,$kind"]="IGNORED"
        else
            RESULT["$hook,$kind"]="no-traffic"
        fi
    done
done

# ------------------------------------------------------------------- output

if [ "$MARKDOWN" = "1" ]; then
    printf '| match |'
    for hook in "${HOOKS[@]}"; do printf ' %s |' "$hook"; done
    # printf treats a leading -- as options, so the separator row goes through %s.
    printf '%s' $'\n|---|'
    for _ in "${HOOKS[@]}"; do printf '%s' '---|'; done
    printf '\n'
    for kind in "${MATCHES[@]}"; do
        printf '| `%s` |' "$kind"
        for hook in "${HOOKS[@]}"; do
            printf ' %s |' "${RESULT[$hook,$kind]}"
        done
        printf '\n'
    done
else
    printf '%-16s' "match"
    for hook in "${HOOKS[@]}"; do printf '%-18s' "$hook"; done
    printf '\n%s\n' "----------------------------------------------------------------"
    for kind in "${MATCHES[@]}"; do
        printf '%-16s' "$kind"
        for hook in "${HOOKS[@]}"; do printf '%-18s' "${RESULT[$hook,$kind]}"; done
        printf '\n'
    done
    printf '\n'
    ignored=0
    for k in "${!RESULT[@]}"; do
        [ "${RESULT[$k]}" = "IGNORED" ] && ignored=$((ignored + 1))
    done
    echo "$ignored combination(s) accepted by nft and never applied by the kernel."
    echo "Every one must be a Soundness rejection in the frontend."
fi
