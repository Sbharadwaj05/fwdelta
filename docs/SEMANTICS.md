# Semantics

What Soteria means by a packet, a rule and a verdict. This is the M0 deliverable
and the specification the implementation is reviewed against. Where the model
and this document disagree, this document is wrong and should be corrected —
but the disagreement is a bug either way.

## 1. The header space

A packet is a point in `{0,1}^120`, being seven fields:

| Dimension | Bits | Domain |
|---|---|---|
| source address | 32 | IPv4 |
| destination address | 32 | IPv4 |
| source port | 16 | |
| destination port | 16 | |
| protocol | 8 | IP protocol number |
| input interface | 8 | symbol index |
| output interface | 8 | symbol index |

A *set of packets* is a boolean function over those 120 variables, held as a
reduced ordered binary decision diagram. Every operation in the tool is set
algebra over such functions, so every answer is exact and complete rather than a
witness or a sample.

Bit 0 of a field is its most significant bit. An address prefix of length *n* is
therefore "fix bits 0..n", which is why prefix encoding is cheap.

Variable ordering does not affect meaning, only diagram size. Two orderings are
implemented and measured; see `crates/engine/examples/thousand_rules.rs`.

## 2. Interface symbols

Interfaces are modelled symbolically. Names appearing in either revision under
comparison are collected, sorted, and assigned indices from the union, so an
index means the same thing on both sides. Nothing about the addresses behind an
interface is known or needed.

**An unconstrained interface match denotes all 256 symbol values.** Not the named
ones — all of them. Two consequences, both load-bearing:

- Introducing a new interface name in the head revision grows the symbol table.
  If "unconstrained" tracked the table, that growth would silently widen every
  unconstrained rule in *both* revisions and manufacture a delta from nothing.
- Interfaces that exist on the host but appear in neither revision are the
  unnamed indices. An unconstrained rule matches them, because the real rule
  would.

See `crates/ir/src/interface.rs` and decision D-02.

**The output interface dimension is present but unusable at 1.0.** The frontend
rejects `oifname`, so no ruleset can constrain it and it is always the full
domain. The reason is validation, not modelling: the differential harness runs
on the input hook, where the kernel never sets an output interface, so the
dimension has never been checked against the kernel. It stays in the layout so
that adding an output-hook harness later needs no change to the header space.

## 3. Rules and evaluation

A rule is a conjunctive predicate over the seven dimensions plus an action.
Actions are `accept`, `drop` and `reject`. **`reject` denies exactly as `drop`
does**; the difference is what the sender observes, which is outside a filtering
model. Reports distinguish them, the algebra does not.

A chain is an ordered rule list plus a default policy. Evaluation is first-match:
the verdict of a packet is the action of the earliest rule whose predicate holds,
or the policy if none does.

### 3.1 Forward pass

Let `m_i` be rule *i*'s predicate. Walking in order:

```
eff_i    = m_i AND NOT matched_{<i}
accept  |= eff_i                      when rule i accepts
matched |= m_i
```

`eff_i` is the set of packets rule *i* actually decides. The `eff_i` together
with the fall-through cell `NOT matched` **partition the header space exactly**:
disjoint because each excludes everything matched earlier, total because the
fall-through cell is their complement. Every packet has exactly one deciding
rule.

Two properties follow at no extra cost:

- Rule *i* is **shadowed** exactly when `eff_i` is empty.
- Attribution — "which rule is responsible for this finding" — is a set
  intersection against the partition, and is exact rather than heuristic.

### 3.2 Backward pass

Let `A_i` be the accept set of the rule suffix starting at *i*:

```
A_n = TRUE if the policy accepts else FALSE
A_i = m_i OR A_{i+1}              when rule i accepts
A_i = (NOT m_i) AND A_{i+1}       when rule i denies
```

Deleting rule *i* changes the verdict only inside `eff_i`, and only where the
suffix disagrees with the rule. So rule *i* is **redundant** — its removal leaves
the accept set unchanged — exactly when:

```
eff_i AND NOT A_{i+1}  is empty     (accepting rules)
eff_i AND A_{i+1}      is empty     (denying rules)
```

Linear, not quadratic. `A_0` equals the forward pass's accept set, which the
tests assert as an internal consistency check on both recurrences.

Shadowed rules are trivially redundant. Reports name the shadowing, which is the
sharper finding, and suppress the redundancy.

### 3.3 The diff

For two revisions compiled against a shared symbol table:

```
newly_allowed = B_accept AND NOT A_accept
newly_blocked = A_accept AND NOT B_accept
```

Both are complete and exact sets, not witnesses. Findings are attributed by
intersecting against each side's partition: the base side answers "was allowed by
rule 14", the head side answers "now denied by rule 9".

## 4. Fidelity limits

Published here rather than buried. A verification tool that overstates itself is
worse than no tool.

### 4.1 Stateless approximation

New connections in the forward direction are governed by the ruleset; return
traffic for permitted connections is assumed permitted. Rulesets whose security
depends on asymmetric conntrack behaviour are outside the model and are rejected
at parse time rather than approximated.

### 4.2 Port fields on protocols that have no ports

The model gives every packet a source and destination port, including ICMP.
An ICMP packet is therefore represented by many points that do not correspond to
any real packet — "ICMP with destination port 80" is a point in the space.

This is sound **only** under an obligation on the frontend:

> A rule may constrain a port dimension only if it also pins the protocol to one
> that has ports.

nftables enforces this naturally, since `tcp dport 22` implies `meta l4proto tcp`.
A frontend that let a bare port match through would produce a model that
disagrees with the kernel on ICMP traffic. M1 must reject such rules loudly.

### 4.3 Flow counts are a projection

Reports headline a **flow count**, not a packet count:

```
7.1e16 flows  (src, dst, dport, proto; sport/iif/oif quantified)
```

This is existential quantification — `|∃ sport, iif, oif . delta|` — so it is
exact, not an estimate or a sample. Both figures are exact; the packet count is
simply impossible to calibrate against, because a factor of 2^32 in any figure
it produces comes from source port and the two interface dimensions, which
almost no rule constrains.

Two properties are deliberate:

- **The projection set is fixed** at `{src, dst, dport, proto}`. It never adapts
  to which dimensions happen to be free in a given run. An adaptive projection
  would make two runs produce incomparable numbers, which destroys the one thing
  a count is for.
- **The exact 120-bit packet count stays in the machine-readable output.** The
  headline is for humans; nothing is lost on the JSON path.

**What the projection gives up.** Where a quantified dimension *is* constrained
— a rule matching `tcp sport 1024-65535`, or one scoped to `iifname "eth1"` —
the projection collapses that variation. Two findings that differ only in source
port count as one flow. The number remains an exact answer, but to a narrower
question than the packet count answers, and it will understate a delta whose
substance lies entirely in a quantified dimension. The packet count in the JSON
is the one to read in that case.

### 4.4 Not modelled

- **NAT.** Address translation changes packet identity in transit. Filtering
  only; a ruleset containing NAT rules is rejected with a clear message.
- **Multi-hop reachability.** One host's filter table. No routing, no topology.
- **IPv6.** The layout is IPv4. IPv6 needs a 296-bit layout and is a version-two
  concern.
- **Rate limiting, packet marking, connection state, sets and maps with
  timeouts.** Any construct the frontend cannot model is a hard error naming the
  file and line, never a silent skip.

## 5. What a passing run establishes

**Does:** the modelled ruleset permits exactly the packet set computed, under the
model above, and satisfies the stated assertions.

**Does not:** that the assertions are the right assertions; that the device
implements nftables faithfully; that the configuration deployed is the
configuration analysed; that anything is true about NAT, routing, or other
devices.

## 6. How the model's fidelity is measured

`crates/kerneldiff` loads a generated ruleset into an unprivileged network
namespace, sends packets, and reads per-rule counters to obtain the kernel's real
verdict and the rule that produced it. Disagreement is a failing test with a
reproducible seed.

The harness carries its own self-test: `--inject-fault` deliberately corrupts the
model, and a fault that goes undetected fails the run. A differential harness
that has never failed is indistinguishable from one that cannot fail. The
`ignore-interface` fault caught a genuine blind spot — every probe arrived on
`lo`, so interface matches were never exercised negatively — which is the reason
the generator now names an interface no probe arrives on.

Current coverage gaps are printed by the harness on every run and are listed in
`KNOWN_GAPS`.
