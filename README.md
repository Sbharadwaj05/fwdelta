# Soteria

Semantic diff and formal reachability analysis for firewall policy under version
control.

> Soteria takes two firewall rulesets and prints exactly which packets changed
> status between them, so a reviewer sees the behavioural delta instead of a
> text delta.

**Status: in development. Not released.** The blueprint's release model has no
public 0.x — the repository goes public at `v1.0.0` with the parser, engine, diff
and enumerator complete and tested. Partial capability shipped early reads as
abandoned work.

## The problem

A firewall ruleset is reviewed as text. A firewall behaves as a set of permitted
packets. Nothing in the review process connects the two.

Rules are evaluated first-match, and that single property makes every edit
non-local. Narrowing a source range on rule 14 can expose rule 22, which was
previously shadowed and therefore dead, and which now matches traffic nobody has
thought about in two years. A reviewer looking at a unified diff sees one line
changed. The second-order effects are not in the diff; they are in the
interaction between the changed line and the two hundred lines around it.

```
RULESET DELTA  base 9f2c1ab .. head 4e81d33

NEWLY BLOCKED  (permitted before, denied now)
  all entries: in not lo, tcp
    10.0.0.0/8 except 10.0.0.0/15,10.9.0.0/24 -> 10.5.0.0/16 except 10.5.0.20              was allowed by rule 04, now denied by the default policy
    10.1.0.0/16                               -> 10.5.0.0/16                  :502         was allowed by rule 04, now denied by rule 05
  7.1e16 flows  (src, dst, dport, proto; sport/iif/oif quantified)

NEWLY ALLOWED  (denied before, permitted now)
  none

STRUCTURAL
  rule 03  now load-bearing  it was redundant before this change
  rule 04  modified
  rule 05  now reachable     previously shadowed by rule 04
```

One line changed in the file. Three rules changed behaviour.

## What it does not do

Stated as hard boundaries, because each is a legitimate problem and each is
someone else's.

- **Multi-hop reachability.** One host's filter table. No topology graph, no
  routing table, no BGP or OSPF simulation. If you need end-to-end reachability
  across a routed network, you need [Batfish](https://batfish.org), and the
  referral is made honestly.
- **NAT.** Address translation changes packet identity in transit. A ruleset
  containing NAT is rejected with a clear message rather than analysed with NAT
  ignored.
- **Full stateful semantics.** See the soundness boundaries below.
- **Runtime enforcement.** Soteria never connects to a device, never reads a
  running configuration and never pushes one. Configuration text is the only
  input.
- **Traffic analysis.** No packet capture, no flow records, no live observation.

## Soundness boundaries

A verification tool that is wrong is worse than no tool, because it converts
uncertainty into false confidence. The full treatment is
[docs/SEMANTICS.md](docs/SEMANTICS.md); the headlines:

| Limit | Consequence |
|---|---|
| Stateless approximation | Return traffic for permitted connections is assumed permitted. Rulesets whose security depends on asymmetric conntrack behaviour are rejected at parse time, not approximated. |
| No NAT | Filter semantics only. |
| Single host | Results describe one device's policy, not end-to-end reachability, which also depends on routing. |
| IPv4 | The header layout is 32-bit. IPv6 needs a 296-bit layout and is a version-two concern. |
| Ports on portless protocols | The model gives every packet ports, including ICMP. Sound only while port matches pin a port-bearing protocol, which the frontend enforces. |

**What a passing run establishes:** that the modelled ruleset permits exactly the
packet set computed, under the stated model, and satisfies the stated assertions.

**What it does not establish:** that the assertions are the right assertions;
that the device implements nftables faithfully; that the configuration deployed
is the configuration analysed; that anything is true about NAT, routing, or other
devices.

## How the claims are checked

Every claim above has a mechanism behind it, and each runs in CI.

| Claim | Mechanism |
|---|---|
| The model matches the kernel | `soteria-kerneldiff` loads generated rulesets into an unprivileged network namespace, sends real packets, and reads per-rule counters for the real verdict. Disagreement is a failing test with a reproducible seed. |
| The harness can actually fail | `--self-test` injects five deliberately broken models and requires every one to be detected. A fault that survives means the dimension it breaks is untested. |
| Probes exercise every dimension | Coverage is computed from the probes actually sent and printed on every run. A dimension held constant fails the run. |
| No network access | `deny.toml` bans network-capable crates, and `scripts/syscall-audit.sh` straces the shipped binary and fails on a single socket syscall. |
| One file, no dependencies | Static musl build, verified statically linked in CI. |
| No unsafe in first-party code | `#![forbid(unsafe_code)]` at every crate root. |
| The parser has a boundary | [docs/NFTABLES-SUBSET.md](docs/NFTABLES-SUBSET.md), with a test asserting the cause and position of every rejection. |
| The engine agrees with itself | The accept set is derived two independent ways and `ChainModel::verify` requires them to match, alongside the partition invariant. |

## Repository

```
crates/ir          what a rule says: seven match dimensions, 120 bits
crates/engine      what it means: BDD encoding, accept sets, diff, enumeration
crates/nft         the nftables frontend
crates/kerneldiff  differential testing against the Linux kernel
docs/SEMANTICS.md         the specification the implementation is reviewed against
docs/DECISIONS.md         architectural decisions, with the reasoning and the cost
docs/NFTABLES-SUBSET.md   the frontend's boundary
```

## Building

```sh
cargo test --workspace
cargo run --release -p soteria-engine --example delta_report
cargo build --release --target x86_64-unknown-linux-musl
```

The differential harness needs `nftables`, `iproute2`, `socat` and unprivileged
user namespaces. It needs no root.

```sh
cargo run --release -p soteria-kerneldiff -- --self-test
cargo run --release -p soteria-kerneldiff -- --rules 50 --packets 120 --rounds 4
```

## Prior art

- **Fireman** (Yuan et al., IEEE S&P 2006) — the BDD encoding of ACL header space
  and the shadowing/redundancy taxonomy. Unmaintained; the encoding is the right
  one and is used here.
- **Header Space Analysis** (Kazemian et al., NSDI 2012) — reachability as set
  algebra over a header bit vector.
- **Batfish** (Fogel et al., NSDI 2015) — defines the boundary of this project's
  scope by occupying everything beyond it. Where the two overlap, Batfish is
  deeper. Soteria is not a Batfish competitor and does not attempt to become one:
  the contribution is that the analysis runs unprompted, on every pull request,
  and produces output a human reads in five seconds.

## Licence

Apache-2.0.
