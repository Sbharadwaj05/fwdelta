//! The enumerator gate.
//!
//! Hand-built BDDs only: no parser, no IR, no file I/O. Each case is a delta
//! shape that a real firewall edit produces. The question the output has to
//! answer in five seconds is "what changed".
//!
//! Run with: `cargo run -p soteria-engine --example enumerator_gate`

use std::time::Instant;

use biodivine_lib_bdd::Bdd;
use soteria_engine::render::{self, Style};
use soteria_engine::{EnumOptions, Field, Layout, SymbolTable, VarOrder, enumerate};

fn ip(a: u8, b: u8, c: u8, d: u8) -> u64 {
    ((a as u64) << 24) | ((b as u64) << 16) | ((c as u64) << 8) | d as u64
}

const TCP: u64 = 6;
const UDP: u64 = 17;

/// A rule-shaped conjunction, used to build fixtures the way a ruleset would.
struct Flow<'a> {
    l: &'a Layout,
    b: Bdd,
}

impl<'a> Flow<'a> {
    fn new(l: &'a Layout) -> Self {
        Self { l, b: l.tt() }
    }
    fn proto(mut self, p: u64) -> Self {
        self.b = self.b.and(&self.l.eq(Field::Proto, p));
        self
    }
    fn src(mut self, v: u64, len: u32) -> Self {
        self.b = self.b.and(&self.l.prefix(Field::SrcAddr, v, len));
        self
    }
    fn dst(mut self, v: u64, len: u32) -> Self {
        self.b = self.b.and(&self.l.prefix(Field::DstAddr, v, len));
        self
    }
    fn dport(mut self, p: u64) -> Self {
        self.b = self.b.and(&self.l.eq(Field::DstPort, p));
        self
    }
    fn done(self) -> Bdd {
        self.b
    }
}

fn case(layout: &Layout, name: &str, description: &str, set: &Bdd) {
    let syms = SymbolTable::default();
    let opts = EnumOptions::default();
    let t0 = Instant::now();
    let e = enumerate(layout, set, opts);
    let elapsed = t0.elapsed();

    println!("\n\x1b[1m{name}\x1b[0m");
    println!("  {description}");
    println!();
    let style = Style::default();
    let rows: Vec<render::Row> =
        e.regions.iter().map(|r| render::row(r, "was allowed by rule 14", &syms, &style)).collect();
    print!("{}", render::table(&rows, "    "));
    if e.omitted_regions > 0 {
        println!(
            "    ... {} further entries omitted, covering {} packets",
            e.omitted_regions,
            render::count(e.omitted_packets)
        );
    }
    if e.incomplete {
        println!("    WARNING: incomplete enumeration");
    }
    println!();
    println!(
        "  bdd nodes {:<6} cubes {:<6} rects {} -> {} ({:.0}x)  packets {}  {:?}",
        set.size(),
        e.cubes_visited,
        e.regions_before_merge,
        e.regions.len(),
        e.merge_ratio(),
        render::count(e.total_packets),
        elapsed
    );
    assert_eq!(e.shown_packets + e.omitted_packets, e.total_packets, "{name}: lost packets");
}

/// The strongest correctness check available: rebuild the diagram from the
/// rendered rectangles and require it to equal the input exactly.
fn assert_lossless(layout: &Layout, set: &Bdd, name: &str) {
    let e = enumerate(layout, set, EnumOptions { max_regions: usize::MAX, ..Default::default() });
    let mut rebuilt = layout.ff();
    for r in &e.regions {
        rebuilt = rebuilt.or(&r.to_bdd(layout));
    }
    assert_eq!(&rebuilt, set, "{name}: enumeration is not lossless");
}

fn main() {
    let layout = Layout::new(VarOrder::AddrInterleaved);
    let l = &layout;

    println!("SOTERIA ENUMERATOR GATE");
    println!("120-bit header space, variable order {:?}", l.order());

    // 1. A single host and port behind a source prefix. The commonest delta of
    //    all: one service exposure changed.
    let one = Flow::new(l)
        .proto(TCP)
        .src(ip(10, 1, 0, 0), 16)
        .dst(ip(10, 0, 5, 14), 32)
        .dport(502)
        .done();
    case(l, "1. single host and port", "tcp from a /16 to one host on one port", &one);
    assert_lossless(l, &one, "case 1");

    // 2. A /16 with a /24 punched out of it. This is the shape that a naive
    //    enumerator renders as eight prefixes and a careless one as 65280 hosts.
    let two = Flow::new(l)
        .proto(TCP)
        .dst(ip(10, 5, 0, 0), 16)
        .dport(443)
        .done()
        .and(&l.prefix(Field::DstAddr, ip(10, 5, 3, 0), 24).not());
    case(l, "2. prefix minus a hole", "tcp to a /16 except one /24, on 443", &two);
    assert_lossless(l, &two, "case 2");

    // 3. A port range crossed with a set of source prefixes.
    let three = l
        .eq(Field::Proto, TCP)
        .and(&l.range(Field::DstPort, 1024, 65535))
        .and(&l.eq(Field::DstAddr, ip(10, 5, 0, 20)))
        .and(
            &l.prefix(Field::SrcAddr, ip(10, 1, 0, 0), 16)
                .or(&l.prefix(Field::SrcAddr, ip(10, 2, 0, 0), 16))
                .or(&l.prefix(Field::SrcAddr, ip(192, 168, 4, 0), 24)),
        );
    case(
        l,
        "3. port range by source set",
        "ephemeral range to one host from three source blocks",
        &three,
    );
    assert_lossless(l, &three, "case 3");

    // 4. A delta spanning several disjoint destinations and both protocols.
    let four = {
        let mut acc = l.ff();
        for (d, p) in [
            (ip(10, 5, 0, 14), 502u64),
            (ip(10, 5, 0, 20), 443),
            (ip(10, 5, 1, 7), 22),
            (ip(10, 6, 2, 9), 161),
        ] {
            acc = acc.or(&Flow::new(l).src(ip(10, 1, 0, 0), 16).dst(d, 32).dport(p).done());
        }
        acc.and(&l.eq(Field::Proto, TCP).or(&l.eq(Field::Proto, UDP)))
    };
    case(
        l,
        "4. several disjoint destinations",
        "four unrelated services opened from one source block",
        &four,
    );
    assert_lossless(l, &four, "case 4");

    // 5. The failure mode the gate exists to catch. Built as 1024 separate
    //    single-host single-port terms; if the merge pass is wrong this prints
    //    1024 lines and the project stops.
    let five = {
        let mut acc = l.ff();
        for host in 0..=255u64 {
            for port in [80u64, 443, 8080, 8443] {
                acc = acc.or(&Flow::new(l)
                    .proto(TCP)
                    .src(ip(10, 1, 0, 0), 16)
                    .dst(ip(10, 5, 7, 0) | host, 32)
                    .dport(port)
                    .done());
            }
        }
        acc
    };
    case(l, "5. 1024 host/port terms", "256 hosts x 4 ports, built one term at a time", &five);
    assert_lossless(l, &five, "case 5");

    // 6. Deliberately awkward: a source set that is genuinely 300 scattered
    //    blocks. There is no compact truth here, so the tool must truncate and
    //    say so rather than print 300 lines or lie about the total.
    let six = {
        let mut acc = l.ff();
        for i in 0..300u64 {
            let a = 10 + (i % 100) as u8;
            let b = (i * 7 % 251) as u8;
            acc = acc.or(&l.prefix(Field::SrcAddr, ip(a, b, 0, 0), 24));
        }
        acc.and(&l.eq(Field::Proto, TCP)).and(&l.eq(Field::DstPort, 22))
    };
    case(l, "6. genuinely scattered delta", "300 unrelated source /24s to ssh", &six);

    println!("\nall cases lossless: rebuilt BDD equals input\n");
}
