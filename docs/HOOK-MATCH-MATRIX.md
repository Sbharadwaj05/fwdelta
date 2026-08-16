# Hook × match matrix

This table exists because of one bug and the suspicion that it was not alone.

`iifname` on an output chain is accepted by nftables and then never applied: the
kernel does not set an input interface on that hook, so the rule loads, looks
live, and matches nothing. A model that treats it as a live dimension disagrees
with reality on every such packet, while reporting confidently.

That is a *class*, not an incident, and it has a property that makes it
especially dangerous here: **the differential harness cannot find it.** The
harness generates rulesets from the same model it is testing, so it only ever
produces combinations the model already handles. This entire class sits in the
blind spot of the project's strongest verification mechanism.

So the cross product was enumerated exhaustively rather than sampled.

## Method

For every hook the frontend accepts and every match type it accepts:

1. Load a chain on that hook containing the match plus a terminal verdict,
   followed by a catch-all, so exactly one counter can move.
2. Send a packet the match is *constructed to be true of* — the real source,
   destination, ports and interface names of traffic that genuinely traverses
   that hook.
3. Read the counters. If the first moved, the kernel applied the match. If the
   second moved, nftables took the rule and the kernel ignored it.

Reproduce with `scripts/hook-match-sweep.sh`. It needs nftables, iproute2 and
unprivileged user namespaces, and no root. CI runs it and fails if the table
changes.

The forward hook needs the host to route, so the script builds
`A --veth-- [main, forwarding] --veth-- B` and sends between the peers.

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

**Exactly two cells are accepted by nftables and never applied**, and both are
rejected by the frontend:

- `iifname` on an output chain — rejected as `cannot be modelled soundly`.
- `oifname` on an input chain — covered by the blanket `oifname` rejection
  below, and independently unsound for this reason.

Everything else is applied on every hook. The answer to "how do you know there
are not more" is this table.

## What this table does and does not establish

Two different questions, and conflating them would be the same error the project
keeps rejecting elsewhere.

**It establishes:** whether the kernel *applies* a given match on a given hook.
That is what the counters measure, and it is what catches the silently-dead-rule
class.

**It does not establish:** that fwdelta's model of an applied match agrees with
the kernel. That is the differential harness's job, and the harness runs on the
input hook only.

The two are independent. `oifname` is `applied` on the output and forward hooks
— the kernel really does evaluate it — and it is still rejected by the frontend,
because "the kernel applies this" is not "the model gets this right". The output
interface dimension has never been checked against the kernel, and shipping a
dimension whose correctness is asserted rather than measured is the thing this
project exists not to do.

Consequently the frontend rejects `oifname` on every hook, not only on input.
The input cell has two independent reasons; the others have one.

## Scope

The table covers the match types in `docs/NFTABLES-SUBSET.md` and the three
base-chain hooks the frontend accepts. It says nothing about constructs already
rejected for other reasons — `ct state`, `limit`, NAT statements — because those
never reach the model at all.

If a match type is added to the subset, it needs a row here before it ships.
