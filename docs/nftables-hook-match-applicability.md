# Interface matches that nftables accepts and never applies

nftables accepts `iifname` on an output chain and `oifname` on an input chain.
Neither is ever applied. The ruleset loads without error or warning, `nft list
ruleset` shows the rule, and its counter stays at zero for every packet.

This document records a sweep of all three filter hooks against eight match
types, the two combinations where this occurs, and how to reproduce the result.

Tested on:

| | |
|---|---|
| Kernel | Linux 7.0.0-28-generic (Linux Mint 22.3) |
| nftables | v1.0.9 |
| libnftnl | 1.2.6-2build1 |
| iproute2 | 6.1.0 |

## The observation

The input and output interfaces are netfilter metadata rather than packet header
fields, and the kernel populates them per hook. On the input hook there is no
output interface yet, because the routing decision that selects one has not been
made. On the output hook there is no input interface, because the packet was
generated locally and did not arrive on one.

nftables does not reject a match on metadata that is unset for the hook the
chain is attached to. The comparison is evaluated against an empty value, fails,
and the rule does not match.

Loading this succeeds:

```
table ip t {
  chain out {
    type filter hook output priority filter; policy accept;
    iifname "eth0" counter accept comment "hit"
    counter accept comment "miss"
  }
}
```

After sending a packet that traverses the output hook, `hit` reads zero and
`miss` reads one.

## Why it is worth knowing

A rule of the form `iifname "wan0" drop` on an output chain reads as a control.
It names an interface, it names a verdict, it appears in the ruleset, and
`nft list ruleset` prints it back. It enforces nothing.

The same applies to `oifname` on an input chain, which appears in attempts to
express "traffic leaving towards X" in the wrong place.

There is no diagnostic at any stage. `nft -c -f` accepts the file, loading
succeeds, and the only signal that the rule is inert is a counter that never
moves — and counters are not usually present.

This also matters for any tool that models nftables semantics. A model that
treats these matches as live will disagree with the kernel on every packet the
rule appears to cover, while reporting confidently.

## Method

For each combination of hook and match type:

1. Load a chain on that hook containing the match under test followed by a
   terminal verdict, then a catch-all rule with its own counter. Exactly one of
   the two counters can move per packet.
2. Send one packet that genuinely traverses that hook, with a header the match
   under test is constructed to be true of — the real source, destination,
   ports and interface names of that traffic.
3. Read both counters.

`applied` means the first counter moved. `IGNORED` means the ruleset loaded and
the second counter moved, so the kernel did not apply the match.

Everything runs inside an unprivileged user and network namespace, so no root is
required and the host's networking is untouched.

### Traffic per hook

The input and output hooks are reachable over loopback: locally generated
traffic addressed to a local address traverses output, then input.

```
ip link set lo up
ip addr add 10.1.0.1/32 dev lo
ip addr add 10.5.0.1/32 dev lo
# then send UDP 10.1.0.1:4444 -> 10.5.0.1:9999
```

The forward hook requires the host to route between two interfaces, so the sweep
builds two peer namespaces either side of a forwarding host:

```
   peer A                     main namespace                    peer B
  10.7.0.1/24  --- va | vma ---   forwarding   --- vmb | vb ---  10.8.0.1/24
                                10.7.0.254/24
                                10.8.0.254/24
```

`net.ipv4.ip_forward=1` in the main namespace, a default route in each peer, and
a UDP datagram from A to B. On the forward hook the input interface is `vma` and
the output interface is `vmb`.

A UDP listener is bound on the destination in peer B. Without it, an accepted
datagram with no listener draws an ICMP port-unreachable, which traverses the
hook again in the reverse direction and moves a second counter.

## Result

| match | input | output | forward |
|---|---|---|---|
| `ip saddr` | applied | applied | applied |
| `ip daddr` | applied | applied | applied |
| `ip protocol` | applied | applied | applied |
| `meta l4proto` | applied | applied | applied |
| `udp sport` | applied | applied | applied |
| `udp dport` | applied | applied | applied |
| `iifname` | applied | **IGNORED** | applied |
| `oifname` | **IGNORED** | applied | applied |

Two of twenty-four combinations load and are never applied. Both involve
interface metadata that the hook does not populate. Header field matches —
addresses, ports, protocol — are applied on all three hooks.

`iifname` is applied on the forward hook, where the packet did arrive on an
interface. `oifname` is applied on output and forward, where a route has been
selected.

## Reproducing

The script used is
[`scripts/hook-match-sweep.sh`](../scripts/hook-match-sweep.sh) in this
repository. It needs `nftables`, `iproute2`, `python3` and unprivileged user
namespaces, and no root:

```sh
scripts/hook-match-sweep.sh              # table
scripts/hook-match-sweep.sh --markdown   # same, as markdown
```

A single combination can be checked by hand:

```sh
unshare -Ur -n bash -c '
ip link set lo up
ip addr add 10.1.0.1/32 dev lo
ip addr add 10.5.0.1/32 dev lo

nft -f - <<NFT
table ip t {
  chain out {
    type filter hook output priority filter; policy accept;
    iifname "lo" counter accept comment "hit"
    counter accept comment "miss"
  }
}
NFT

python3 -c "
import socket
lis = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); lis.bind((\"10.5.0.1\", 9999))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind((\"10.1.0.1\", 4444))
s.sendto(b\"x\", (\"10.5.0.1\", 9999))"

nft list chain ip t out
'
```

Expected: `hit` at 0 packets, `miss` at 1. Changing the chain to
`hook input priority filter; policy accept` and re-running gives `hit` at 1,
because the input interface is set on that hook.

Note that unprivileged user namespaces are restricted by AppArmor on some
distributions, including Ubuntu 24.04. Where that applies:

```sh
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

## Notes

The behaviour follows from netfilter's hook model and is not a defect in
nftables in the sense of a violated specification: the metadata is genuinely
unavailable at those points, and a match against unavailable metadata failing is
a defensible choice. What is recorded here is that the condition is not
diagnosed, so a rule that cannot ever match is indistinguishable, by reading the
ruleset, from one that can.

The sweep covers eight match types. Other matches that read per-hook metadata —
`meta iif`, `meta oif`, `meta iifgroup`, `fib` expressions, and the numeric
`iif`/`oif` forms — were not tested and would be expected to behave the same way
where the underlying metadata is unset.

Checking for this in an existing ruleset amounts to looking for `iifname` or
`meta iif*` in output chains and `oifname` or `meta oif*` in input chains.
Adding `counter` to a suspected rule and watching whether it moves under traffic
that should match it confirms the case directly.
