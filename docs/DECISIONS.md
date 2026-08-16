# Decision record

Open decisions from blueprint section 10. Each entry is either **PROPOSED**
(awaiting maintainer confirmation, do not implement) or **ACCEPTED** with a date.

---

## D-01 Rule attribution through BDD construction — ACCEPTED 2026-08-15

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

- **Memory.** One retained BDD per rule. **Measured at M2:** a thousand-rule
  chain retains about 152,000 nodes across the match and effective sets, roughly
  1.8 MiB. The concern was unfounded and needs no cache policy.
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

## D-02 Interface and zone matches in the IR — ACCEPTED 2026-08-15

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
  section 07's IPv4 note are amended accordingly (maintainer approved, revision
  0.1 is not scripture). **Measured at M2:** a diagram's size depends on the
  function it represents, not on how many variables exist, so the sixteen extra
  variables cost nothing until a rule uses them — the accept set of a
  thousand-rule chain with no interface matches touches 88 of the 120 variables
  and is byte-for-byte what a 104-bit layout would produce. Rulesets that do use
  interface matches on a fifth of rules pay roughly 15% more analysis time.
- **Two more columns** in the region type and the report.
- **256 interface names per comparison**, which is not a real limit for one host.
- **Grammar surface.** `iif`/`oif` match the kernel's numeric ifindex, which is
  not stable across reloads and is not comparable between two revisions of a
  file; only the `iifname`/`oifname` forms are. Proposal: support the name
  forms, reject the numeric forms loudly with that explanation. Wildcards
  (`iifname "eth*"`) and name sets need an explicit decision at M1 — a wildcard
  over a symbol space the tool only partially observes is a soundness question,
  not a parsing one.

### Maintainer requirement: the unconstrained domain

**An unconstrained interface field denotes all 256 symbol values, never only the
named ones.** The symbol table is built from the union of both revisions, so it
grows when the head names an interface the base never mentioned. If `Any` were
defined relative to the table, that growth would silently widen every
unconstrained rule on both sides and manufacture a delta out of nothing.

Stated in `crates/ir/src/interface.rs` and pinned by two tests. The one that
matters is `growing_the_table_does_not_move_an_unconstrained_match`: it grows the
table from one name to four and requires an unconstrained match to compile to the
identical set, which is the phantom in its purest form. Its partner,
`naming_an_interface_narrows_against_unconstrained`, requires that naming an
interface really does drop 255 of 256 symbols, so the first test cannot be
satisfied by making everything trivially equal.

The same requirement is asserted at the engine level by
`a_growing_symbol_table_does_not_move_an_unconstrained_rule`.

### The alternative if 120 bits is unacceptable

Keep interfaces first-class in the IR but eliminate them at the engine boundary
against a declared analysis context (`--iif eth1`), printing the assumption in
the report. Sound, keeps 104 bits, but makes every result conditional on a flag
the user must remember, and a host with three interfaces becomes three runs.
Recommended only if the width measurably hurts at M2.

---

## D-03 Parser library — ACCEPTED 2026-08-15

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

**Maintainer condition:** the supported-subset table ships in the repository from
M1. A hand-written parser without a written boundary is how grammar creep starts.

---

## D-04 Variable ordering — ACCEPTED 2026-08-15 (measured)

Blueprint section 06 recommends interleaving source and destination address bits
rather than grouping each field contiguously, and says it is worth measuring
rather than assuming. Measured at M2 on a thousand-rule chain:

| Ordering | accept set | analysis |
|---|---|---|
| field-major | 29,300 nodes | 2.6 s |
| interleaved | 18,246 nodes | 1.7 s |

The recommendation holds: interleaving is 38% smaller and 35% faster. Default is
`VarOrder::AddrInterleaved`; field-major stays available because the enumerator
is ordering-independent and a future workload may invert the result.

Worth recording how nearly this measurement went wrong. The first run showed the
two orderings within noise of each other — because the generated rulesets were
built from `/8`-wide prefixes, which shadowed 808 of 1000 rules. Shadowed rules
have empty effective sets and cost almost nothing, so the benchmark was measuring
shadow detection rather than analysis. A benchmark that flatters every option
equally is measuring the wrong thing.

---

## D-05 Analysis time at a thousand rules — CLOSED 2026-08-15

**Resolution: amend the blueprint, not the code.**

M2 measured `analyse` at 1.7 s for a thousand-rule chain, against the
sub-second target in blueprint section 03. The target was an estimate made
before anything was built, and it is the estimate that was wrong.

A diff is two analyses, so roughly 3.4 s. That is invisible inside CI and
tolerable locally. The latency a human actually perceives is delta enumeration,
which is 50 µs. Optimising a batch job nobody watches is the wrong use of
attention. **Section 03 is amended to drop the sub-second claim**; no public
claim should exist that the implementation does not meet.

### What was done

Only the part that was deletion rather than restructuring: the forward pass no
longer accumulates the accept set, because `A_0` from the backward pass is
exactly it. One BDD union per rule removed.

The equality of the two derivations was worth more than the 340 ms, so it is
kept as `ChainModel::forward_accept` and exercised by `ChainModel::verify`,
which runs in the test suite, on every kernel-differential round, and under
`--verify`. `verify_rejects_a_corrupted_model` confirms the check can fail,
since a self-test that cannot fail is not a check.

### What was rejected

Lazy `eff_i`. The effective sets are needed for attribution regardless, so
laziness buys little while complicating the structure correctness depends on.

### Correction to the earlier reasoning

The M2 report described the accumulation as "inherently sequential". That is
wrong and should not stand in the record.

`matched_i` is a prefix-OR over rule match sets. OR is associative, so this is a
parallel prefix scan — Blelloch, tree-shaped, standard — not a sequential
dependency. Given `eff_i`, the accept accumulation is a prefix-OR over a subset
and parallelises the same way.

Two real caveats keep it a candidate rather than a fix:

- A tree-shaped union combines non-adjacent rules, whose intermediate diagrams
  can be larger than the sequential order produces. Firewall rules adjacent in a
  file tend to share structure; rules far apart do not. The win could be eaten
  by node count.
- `biodivine-lib-bdd` thread-safety needs checking before anyone tries it. Each
  `Bdd` owns its nodes, which is promising, but "promising" is not "verified".

Neither is a reason to call the problem unimprovable, which is what the earlier
wording implied.


---

## D-06 Maximal-rectangle covering in the enumerator — DEFERRED post-1.0

Logged so it is not lost, and explicitly **not** to be touched before the
frontend exists.

The enumerator decomposes a delta into rectangles derived from root-to-one paths
through the diagram. Where a delta is genuinely non-rectangular — an accept
range with several narrower rules punching holes in it — that decomposition can
run to ten or more rows when a greedy maximal-rectangle covering would produce
perhaps three fatter ones.

The current output is honest: exact, disjoint, ordered by breadth, and the
fragmentation reflects the shape of the set rather than a defect. The gate
criterion in section 09 is met. This is a readability improvement, not a bug
fix, and it is a real algorithmic change to the highest-risk component in the
project — precisely the thing not to be reworking while the parser is unwritten.

Revisit after 1.0, against real rulesets rather than generated ones.

---

## D-07 fxhash unmaintained (RUSTSEC-2025-0057) — ACCEPTED with a scoped exception 2026-08-15

Found by `cargo deny check` on the first run of the policy, which is the point
of writing the policy before the remaining dependencies land.

`biodivine-lib-bdd` depends on `fxhash` for its node table. `fxhash` is
unmaintained as of RUSTSEC-2025-0057, and there is no safe upgrade because the
dependency is pinned upstream.

### What was considered

**Ignore it.** The advisory is `unmaintained`, not a vulnerability. `fxhash` is a
small non-cryptographic hasher with no capability that matters here.

**Change BDD engine.** Blueprint §08 names `oxidd` as the alternative. Measured
rather than assumed:

| Engine | Crates in the tree |
|---|---|
| biodivine-lib-bdd | 14 |
| oxidd | 45 |

`oxidd` brings proc-macro chains (`syn`, `quote`, `proc-macro-error`), `rayon`,
`crossbeam` and `parking_lot`. For an artifact whose deployment story is a small
auditable dependency tree, swapping a maintained-but-larger engine in to resolve
an *unmaintained* advisory on a hashing crate trades the thing being protected
for the protection.

**Vendor a patch.** Forking `biodivine-lib-bdd` to swap `fxhash` for
`rustc-hash` is a two-line change, and makes this repository responsible for
tracking an upstream it does not otherwise carry. Not worth it for an
unmaintained-status advisory.

### Decision

Ignore, scoped to the single advisory ID, with the reasoning recorded in
`deny.toml` next to the exception rather than only here.

Two conditions on the exception:

- It expires if `biodivine-lib-bdd` moves to `rustc-hash`, at which point the
  ignore should be deleted rather than left as decoration.
- It is reviewed immediately if the advisory is ever upgraded from
  `unmaintained` to a vulnerability.

The wider point is that a blanket `ignore` list is how a supply-chain policy
becomes decorative. One ID, one reason, two expiry conditions.

---

## D-08 Assertion file format: TOML, not YAML — ACCEPTED 2026-08-15

Blueprint §08 specifies YAML, on the argument that network engineers read YAML.
Amended by the maintainer; recorded here with the reasoning and the measurement.

### Hand-written parser: ruled out

A hand-written YAML subset is the cardinal sin of this project applied to the
policy file. A user writes valid YAML, the subset misreads it, and the assertion
silently means something other than what they wrote — the same failure class as
a frontend silently skipping a rule, except that it produces a *green isolation
check* instead of a loud error. D-03 permits a hand-written parser for nftables
precisely because that parser rejects everything it does not fully understand;
a format parser that must accept arbitrary valid input has no equivalent escape.

The distinction worth keeping: hand-writing a *serialiser* for output this
project defines is fine, because there is no "silently misreads" failure mode
and the schema is ours. Hand-writing a *parser* for user input is not. The JSON
writer in the CLI is hand-written on exactly that basis; the assertion reader is
not.

### TOML over serde_yaml_ng

Measured rather than argued:

| Crate | Transitive crates | Notes |
|---|---|---|
| `toml` | 7 | Cargo team; `serde_spanned` gives line/column for free |
| `serde_yaml_ng` | 9 | a fork of a deprecated crate; pulls `unsafe-libyaml` |

Three reasons, in order of weight:

1. **Longevity.** `serde_yaml` was deprecated by its author and `serde_yaml_ng`
   is a fork with an uncertain lifespan. `deny.toml` is now a live gate, so
   dependency longevity is a cost the project actually pays.
2. **Deterministic typing.** YAML 1.1 implicit typing turns `no` into `false`,
   `10:30` into a sexagesimal integer, and has a family of similar surprises.
   Assertion files are full of protocol names, port literals and CIDR strings,
   which is exactly where that bites. TOML's spec is much smaller and its typing
   is explicit.
3. **Diagnostics.** `serde_spanned` means an assertion error can name a line and
   column, matching the standard the nftables frontend already sets.

The flat property list in §10 maps onto TOML naturally, and the familiarity
argument costs little for a file with eight fields.

Reconsider if the audience turns out to be Ansible-adjacent enough that YAML is
genuinely load-bearing.

---

## D-09 Attestation is unsigned; the caller signs it — ACCEPTED 2026-08-15

Blueprint §02 lists a signed report as a 1.0 capability. Soteria emits an
in-toto predicate and does not sign it. Signing is the caller's business,
detached, with their own tooling and their own key.

Two reasons, and the second is the stronger one:

- **Zero crypto dependencies.** Signing means `ring` or `ed25519-dalek`. `ring`
  is already on the `deny.toml` denylist, and pulling either would widen the
  dependency graph in the one direction the project's deployment story cannot
  afford.
- **A tool that promises to touch nothing should never hold a private key.**
  Section 02 is emphatic that Soteria never connects to a device and never
  pushes configuration. Key custody is the same category of promise. An offline
  analyser that reads two text files has no business managing key material, and
  an operator who has to hand it one has been given a reason to distrust the
  rest of the claim.

The attestation is therefore a complete, deterministic, machine-readable
predicate carrying the commit hash, ruleset digests, assertion results and tool
version — an input to whatever signing the organisation already runs, rather
than a substitute for it. §02's "signed report" is amended to "attestation,
signed by the caller".
