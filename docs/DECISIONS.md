# Decision record

Open decisions from blueprint section 10. Each entry is either **PROPOSED**
(awaiting maintainer confirmation, do not implement) or **ACCEPTED** with a date.

---

## D-01 Rule attribution through BDD construction — PROPOSED

Blueprint section 10, item 5. Every finding attributes to a rule
("was allowed by rule 14"). Decide how rule identity survives stage 2.

### Options

**A. Carry identity inside the diagram.** Widen the header space with
`ceil(log2 n)` tag variables so the accept set becomes a packet/rule relation.

Rejected. Three costs, one of them a soundness hazard:

- Every operation pays for the wider space, on every rule, forever.
- The tags of ruleset A and ruleset B index different rule lists, so the diff
  expressions `B_accept AND NOT A_accept` are meaningless until the tags are
  existentially quantified away. That quantification is an extra step which,
  if forgotten anywhere, silently produces a wrong delta. A wrong delta that
  still looks like a delta is the exact failure mode section 07 exists to
  prevent.
- Nothing is gained: the tag is only ever read back at enumeration time, which
  option B does more directly.

**B. Parallel per-rule structure.** Retain the per-rule effective set

```
eff_i = m_i AND NOT matched_{<i}
```

already computed as an intermediate of the forward first-match walk. `eff_i` is
exactly the set of packets rule *i* decides.

### Proposed: B

`{eff_0 .. eff_{n-1}}` together with the fall-through cell
`NOT (m_0 OR .. OR m_{n-1})` form an exact partition of the header space:

- pairwise disjoint, because `eff_i` excludes everything matched earlier;
- total, because the fall-through cell is the complement of their union.

So every packet has exactly one deciding rule, and attribution is total and
unambiguous rather than best-effort. To attribute a delta `D`, intersect:
`D AND eff_i` non-empty means rule *i* is responsible for that part of it.

Attribution is available on both sides at once — base's partition gives "was
allowed by rule 14", head's gives "now denied by rule 9" — because the two
rulesets keep separate partitions and the delta is intersected against each.

### What it costs

- **Memory.** One retained BDD per rule. A single rule's effective set is small
  (low hundreds of nodes), so a thousand-rule ruleset is a few hundred thousand
  nodes. Measure at M2 against the thousand-rule benchmark; if it ever bites,
  the fix is to drop `eff_i` for rules the delta never touches, which is a
  cache policy and not a redesign.
- **Enumeration is per cell, not global.** Rectangles cannot merge across an
  attribution boundary, so the output has slightly more lines than a global
  merge would produce. This is the right trade: a merged line carrying two
  different "was allowed by" notes would be unreadable and arguably false.

### Two properties that fall out at no extra cost

Recorded here because they change the M2/M3 plan.

**Shadowing** is `eff_i.is_false()`. No separate analysis.

**Redundancy** — "removing the rule does not change the accept set" — appeared
to need one accept-set reconstruction per rule, i.e. quadratic. It does not. Add
a backward pass computing the accept set of each *suffix*:

```
A_n = TRUE if default policy is accept else FALSE
A_i = m_i OR A_{i+1}            when rule i accepts
A_i = (NOT m_i) AND A_{i+1}     when rule i drops
```

Removing rule *i* changes the verdict only inside `eff_i`, and only if the
suffix disagrees with the rule there:

```
rule i is redundant  <=>  eff_i AND NOT A_{i+1} is empty   (accept rules)
                     <=>  eff_i AND A_{i+1}     is empty   (drop rules)
```

Two linear passes, exact. `A_0` also equals the forward pass's accept set, which
is a free internal consistency check worth asserting in tests.

---

## D-02 Interface and zone matches in the IR — PROPOSED

Blueprint section 10, item 4: first-class match dimension, or pre-resolved into
address sets by the frontend.

The two need splitting, because the blueprint's framing treats them as one
problem and they are not.

### Zones: pre-resolve. Not in doubt.

A zone is a name for a set of CIDRs, used only in the assertion file. Zones never
appear in a ruleset. Resolving `vlan_ot` to its address set is exact, needs no
data beyond the zone file the user wrote, and keeps IEC 62443 vocabulary entirely
in the policy layer where it belongs. No engine involvement.

### Interfaces: first-class dimension, symbolic.

This is a departure from the blueprint's leaning, so the reasoning is stated
rather than assumed.

**Pre-resolving interfaces to address sets is unsound.** An interface is not a
function of the address. Turning `iifname "eth1"` into a set of source prefixes
needs the host's IP configuration, which is not in the ruleset. Section 02
forbids the tool from reading a running config, so that data can only arrive as
a user-supplied map — which re-creates, in miniature, the intent-compilation
problem section 07 rejects: an operator error in the map yields an analysis that
is confidently wrong about isolation. That is the one failure this project
cannot ship.

**Rejecting interface matches outright is too narrow.** `iifname "lo" accept` is
in nearly every real nftables file. A tool that refuses those files analyses
almost nothing.

**The symbolic model needs no external data and is exact.** Interface names in a
ruleset are symbols. Assign each distinct name an index from the union of names
across both rulesets being compared, and `iifname "eth1"` becomes
`iif_index == 3`. Filter semantics are then modelled faithfully with no
knowledge of what subnet lives behind eth1 — which is knowledge the analysis
does not need, because the scope is one host's filter table, not reachability.

Proposal: two new fields, input and output interface, 8 bits each.

### What it costs

- **The header is no longer 104 bits.** It becomes 120. Blueprint section 06 and
  section 07's IPv4 note need amending. Roughly 15% more variables; the
  enumerator is already field-driven and generalises without change.
- **Two more columns** in the region type and the report.
- **256 interface names per comparison**, which is not a real limit for one host.
- **Grammar surface.** `iif`/`oif` match the kernel's numeric ifindex, which is
  not stable across reloads and is not comparable between two revisions of a
  file; only the `iifname`/`oifname` forms are. Proposal: support the name
  forms, reject the numeric forms loudly with that explanation. Wildcards
  (`iifname "eth*"`) and name sets need an explicit decision at M1 — a wildcard
  over a symbol space the tool only partially observes is a soundness question,
  not a parsing one.

### The alternative if 120 bits is unacceptable

Keep interfaces first-class in the IR but eliminate them at the engine boundary
against a declared analysis context (`--iif eth1`), printing the assumption in
the report. Sound, keeps 104 bits, but makes every result conditional on a flag
the user must remember, and a host with three interfaces becomes three runs.
Recommended only if the width measurably hurts at M2.

---

## D-03 Parser library — PROPOSED (minor)

Blueprint section 08 names `nom` or `chumsky`. Proposal: hand-written
tokeniser plus recursive descent, no parser dependency.

nftables statement syntax is small and irregular rather than deeply nested, so a
combinator library buys little; error positions good enough for "fail loudly at
file:line:col" are easier to control directly; and the dependency tree is itself
a selling point of the air-gap story that section 03 rests on, where every crate
removed is one fewer entry to justify in the `cargo-deny` allowlist.

Cost: a few hundred more lines of first-party code to maintain and test. Reverse
this if the supported grammar subset grows past what recursive descent stays
readable for.
