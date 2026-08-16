# Supported nftables subset

This table is the boundary of the frontend. It exists because a hand-written
parser without a written boundary grows indefinitely, and because blueprint
section 06 requires that anything unmodellable fails loudly rather than being
skipped.

**Every construct not listed as supported is a hard error naming the file, line
and column.** A rule is never partially understood and never silently dropped: a
model that quietly disagrees with the kernel is the worst outcome available to a
verification tool.

This table is maintained by hand. What keeps it from drifting is
`unsupported_constructs_fail_loudly_with_a_position` in
`crates/nft/tests/subset.rs`, which enumerates every rejection below and asserts
the cause and the reported position for each. A row that starts passing there is
a row that is out of date here.

The frontend is also checked against itself: `soteria-kerneldiff` generates a
ruleset, emits it as nftables, parses it back and requires the IR to survive the
trip. Emitter and parser are independent code running in opposite directions, so
a shared misunderstanding of the syntax cannot cancel itself out.

## Structure

| Construct | Status | Notes |
|---|---|---|
| `table ip <name>` | supported | IPv4 only |
| `table ip6 / inet / arp / bridge / netdev` | rejected | IPv4 at 1.0; `inet` needs a dual layout |
| `chain <name> { type filter hook <h> priority <p>; policy <v>; }` | supported | |
| hooks `input`, `output`, `forward` | supported | |
| hooks `prerouting`, `postrouting` | rejected | only reachable with NAT or routing in scope |
| `type nat` / `type route` | rejected | NAT is a non-goal (blueprint §02) |
| regular (non-base) chains | rejected | needs `jump`/`goto`, see below |
| `policy accept` / `policy drop` | supported | |
| `include`, `define`, `set`, `map`, `element` | rejected | deferred; would need a resolution pass |

## Match expressions

| Construct | Status | Notes |
|---|---|---|
| `ip saddr` / `ip daddr` | supported | |
| `ip protocol <name\|number>` | supported | |
| `meta l4proto <name\|number>` | supported | |
| `tcp sport` / `tcp dport` | supported | implies protocol tcp |
| `udp sport` / `udp dport` | supported | implies protocol udp |
| `sctp` / `dccp` ports | rejected | trivial to add; not yet exercised against the kernel |
| `iifname` / `oifname` | supported | quoted or bare names |
| `iif` / `oif` | rejected | matches the numeric ifindex, which is not stable across reloads and not comparable between two revisions of a file |
| interface wildcards (`"eth*"`) | rejected | a wildcard over a symbol space the tool only partially observes is a soundness question, not a parsing one (D-02) |
| `ct state` and all conntrack matches | rejected | outside the stateless model (SEMANTICS §4.1) |
| `meta mark`, `meta skuid`, packet marking | rejected | not in the header space |
| `limit rate`, `quota` | rejected | not a function of the packet header |
| named sets (`@allowlist`) | rejected | deferred with `set` declarations |
| service names (`tcp dport ssh`) | rejected | resolution depends on the host's `/etc/services`, which is not in the ruleset |

### Value syntax

| Form | Example | Status |
|---|---|---|
| single address | `10.0.5.14` | supported |
| prefix | `10.1.0.0/16` | supported |
| address range | `10.0.0.1-10.0.0.50` | supported |
| anonymous set | `{ 10.1.0.0/16, 10.2.0.0/16 }` | supported |
| negation | `!= 10.1.0.0/16` | supported |
| single port | `502` | supported |
| port range | `1024-65535` | supported |
| port set | `{ 22, 80, 443 }` | supported |

## Statements and verdicts

| Construct | Status | Notes |
|---|---|---|
| `accept` | supported | |
| `drop` | supported | |
| `reject` (with optional `with ...`) | supported | denies exactly as `drop` in the model |
| `counter` | supported | no semantic effect; parsed and ignored |
| `comment "..."` | supported | no semantic effect |
| `log` (with `prefix`, `level`, `flags`) | supported | no semantic effect |
| `jump`, `goto` | rejected | multi-chain traversal is not modelled at 1.0 |
| `return` | rejected | only meaningful inside a regular chain |
| `queue`, `dup`, `fwd` | rejected | not a filtering verdict |
| `snat`, `dnat`, `masquerade`, `redirect` | rejected | NAT is a non-goal (blueprint §02) |
| a rule with no verdict | rejected | falls through in nftables; ambiguous in a report |

## Soundness obligations enforced at parse time

These are rejections that exist because of the *model*, not the grammar.

1. **A port match requires a port-bearing protocol.** `tcp dport 22` pins tcp
   implicitly and is fine. A rule that constrained a port dimension without
   pinning tcp, udp or sctp would produce a model disagreeing with the kernel on
   ICMP traffic, because the model gives every packet ports. See SEMANTICS §4.2.

2. **Contradictory matches are rejected, not silently emptied.** A rule pinning
   two different protocols matches nothing. That is almost always a typo, and a
   rule that matches nothing is indistinguishable in a report from one that was
   never written.

3. **NAT anywhere in the file rejects the whole file.** Not just the NAT rule:
   if translation happens, the filter analysis describes packets that do not
   exist as analysed.
