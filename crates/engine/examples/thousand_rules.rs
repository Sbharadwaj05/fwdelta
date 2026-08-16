//! M2 benchmark: does 120 bits and per-rule BDD retention cost anything?
//!
//! Two questions the blueprint says to measure rather than assume:
//!
//! 1. Variable ordering. Section 06 recommends interleaving address bits. That
//!    is a claim about diagram size and it is checkable.
//! 2. The price of decision D-02. Widening the header from 104 to 120 bits adds
//!    sixteen variables. A BDD's size depends on the function it represents, not
//!    on how many variables exist, so unused interface dimensions should cost
//!    nothing at all — but "should" is why this file exists.
//!
//! Run with: `cargo run --release -p soteria-engine --example thousand_rules`

use std::time::Instant;

use soteria_engine::{EnumOptions, Field, Layout, VarOrder, analyse, enumerate};
use soteria_ir::{Action, Chain, Hook, IfMatch, Match, Origin, Ruleset, SymbolTable};

/// Deterministic, dependency-free, and good enough to shape a ruleset.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

const IFACES: [&str; 4] = ["eth0", "eth1", "lo", "wg0"];

/// A ruleset shaped like a real one: mostly narrow accepts over a deny policy,
/// a spread of address and port constraints, and interface scoping on the
/// fraction of rules that would carry it in practice.
fn generate(n: usize, iface_fraction: u64, seed: u64) -> Ruleset {
    let mut rng = Rng(seed);
    let mut chain = Chain::new("input", Hook::Input, Action::Drop);

    for i in 0..n {
        let mut m = Match::any();

        // Protocol: mostly tcp, some udp, occasional icmp.
        let proto = match rng.below(10) {
            0..=6 => 6,
            7..=8 => 17,
            _ => 1,
        };
        m = m.with_value(Field::Proto, proto);

        // Source: mostly /24s and hosts. Real chains are made of narrow
        // service rules; a handful of broad ones, not a majority, or the
        // benchmark measures shadowing rather than analysis.
        let src_len = [16u32, 24, 24, 24, 32][rng.below(5) as usize];
        let src = 0x0A00_0000 | rng.below(0x00FF_FFFF);
        m = m.with_prefix(Field::SrcAddr, src, src_len);

        // Destination: narrower still, spread across the server range.
        let dst_len = [24u32, 32, 32, 32][rng.below(4) as usize];
        let dst = 0x0A05_0000 | rng.below(0x0000_FFFF);
        m = m.with_prefix(Field::DstAddr, dst, dst_len);

        // Ports only where the protocol has them.
        if proto == 6 || proto == 17 {
            match rng.below(4) {
                0 => {
                    let lo = rng.below(60000);
                    m = m.with_range(Field::DstPort, lo, lo + rng.below(500));
                }
                1 => {}
                _ => m = m.with_value(Field::DstPort, [22u64, 80, 443, 502, 161, 3389][rng.below(6) as usize]),
            }
        }

        if rng.below(100) < iface_fraction {
            m = m.with_iif(IfMatch::one(IFACES[rng.below(4) as usize]));
        }

        // Mostly accepts, with a scattering of explicit denies.
        let action = if rng.below(10) < 8 { Action::Accept } else { Action::Drop };
        chain.push(
            m,
            action,
            Origin { file: "bench.nft".into(), line: i as u32 + 1, column: 1, text: String::new() },
        );
    }

    Ruleset { label: format!("generated-{n}"), chains: vec![chain] }
}

fn nodes(model: &soteria_engine::ChainModel) -> (usize, usize, usize) {
    let matched: usize = model.rules.iter().map(|r| r.matched.size()).sum();
    let effective: usize = model.rules.iter().map(|r| r.effective.size()).sum();
    (model.accept.size(), matched, effective)
}

/// Edit one load-bearing rule, the way a change under review would.
///
/// The rule has to be one that actually decides packets: narrowing a shadowed
/// rule changes nothing, and a benchmark whose delta is empty measures nothing.
fn mutate(rs: &Ruleset, model: &soteria_engine::ChainModel) -> Ruleset {
    let target = model
        .rules
        .iter()
        .find(|r| !r.shadowed && r.action == Action::Accept)
        .map(|r| r.number)
        .expect("generated chain has no load-bearing accept rule");

    let mut out = rs.clone();
    let chain = &mut out.chains[0];
    let rule = &mut chain.rules[target as usize - 1];
    // Narrow a source range: the archetypal edit that quietly exposes or closes
    // traffic nobody was thinking about.
    rule.matches = rule.matches.clone().with_prefix(Field::SrcAddr, 0x0A01_0000, 16);
    out
}

fn run(label: &str, order: VarOrder, rs: &Ruleset, syms: &SymbolTable) {
    let layout = Layout::new(order);
    let chain = &rs.chains[0];

    // Phase breakdown: compiling predicates is unavoidable work, whereas the
    // set-algebra passes are where an optimisation would have to land.
    let t_m = Instant::now();
    let compiled: Vec<_> =
        chain.rules.iter().map(|r| layout.match_bdd(&r.matches, syms)).collect();
    let compile = t_m.elapsed();
    std::hint::black_box(&compiled);

    let t0 = Instant::now();
    let model = analyse(&layout, syms, chain);
    let analysis = t0.elapsed();

    let (accept_nodes, matched_nodes, eff_nodes) = nodes(&model);
    let retained = matched_nodes + eff_nodes;

    // The realistic workload: one rule edited, then the delta enumerated. This
    // is what `soteria diff` actually does, and it is the number that has to
    // stay sub-second.
    let head = mutate(rs, &model);
    let t1 = Instant::now();
    let head_model = analyse(&layout, syms, &head.chains[0]);
    let newly_blocked = model.accept.and_not(&head_model.accept);
    let newly_allowed = head_model.accept.and_not(&model.accept);
    let delta_algebra = t1.elapsed();

    let t2 = Instant::now();
    let e = enumerate(&layout, &newly_blocked, EnumOptions::default());
    let delta_enum = t2.elapsed();

    let shadowed = model.shadowed().count();
    let redundant = model.redundant().count();

    println!(
        "  {label:<26} analyse {:>7.1?} (compile {:>6.1?} + algebra {:>7.1?})  \
         diff {:>7.1?}  enum-delta {:>7.1?}  accept {:>5}n  retained {:>6}n (~{:>4}KiB)  \
         shadow {shadowed:>3}  redun {redundant:>3}  delta {} rects",
        analysis,
        compile,
        analysis.saturating_sub(compile),
        delta_algebra,
        delta_enum,
        accept_nodes,
        retained,
        retained * 12 / 1024,
        e.regions.len(),
    );
    // The invariant every downstream claim rests on.
    assert!(model.partition_holds(&layout), "{label}: effective sets do not partition");
    assert_eq!(e.shown_packets + e.omitted_packets, e.total_packets, "{label}: lost packets");
    assert!(newly_allowed.and(&newly_blocked).is_false(), "{label}: delta directions overlap");
}

fn main() {
    println!("SOTERIA M2 BENCHMARK\n");

    for n in [100usize, 1000] {
        // No interface matches anywhere: the two interface dimensions exist in
        // the variable set but appear in no diagram.
        let clean = generate(n, 0, 0x2026_0815);
        let syms_clean = SymbolTable::default();

        // A fifth of rules scoped to an interface, which is realistic.
        let scoped = generate(n, 20, 0x2026_0815);
        let syms_scoped = SymbolTable::from_names(IFACES).unwrap();

        println!("{n} rules");
        run("field-major, no iface", VarOrder::FieldMajor, &clean, &syms_clean);
        run("interleaved, no iface", VarOrder::AddrInterleaved, &clean, &syms_clean);
        run("field-major, 20% iface", VarOrder::FieldMajor, &scoped, &syms_scoped);
        run("interleaved, 20% iface", VarOrder::AddrInterleaved, &scoped, &syms_scoped);
        println!();
    }

    // The D-02 cost question, isolated: identical rules, identical everything,
    // with the interface dimensions present but unconstrained. If the widening
    // were expensive it would show here.
    let rs = generate(1000, 0, 7);
    let syms = SymbolTable::default();
    let layout = Layout::new(VarOrder::AddrInterleaved);
    let model = analyse(&layout, &syms, &rs.chains[0]);
    let support: usize = model.accept.support_set().len();
    println!(
        "D-02 check: header declares {} variables, the accept set's diagram touches {}",
        soteria_engine::HEADER_BITS,
        support
    );
    println!("            unused dimensions contribute no nodes, so the widening is free until used\n");
}
