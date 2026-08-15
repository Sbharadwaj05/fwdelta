//! Differential testing of the model against the Linux kernel.
//!
//! Per blueprint section 07 this is the single most valuable piece of
//! engineering in the project: it converts the correctness claim from an
//! argument into a measurement. The model is only worth anything if it agrees
//! with the thing it models, and the only authority on nftables semantics is
//! nftables.
//!
//! # How a real verdict is obtained
//!
//! Everything runs inside an unprivileged user and network namespace, so no root
//! is required and CI can run it. Inside, source and destination addresses are
//! assigned to loopback and the generated ruleset is loaded on the input hook
//! with a `counter` and a position comment on every rule. Locally generated
//! traffic to a local address traverses the input hook, so sending one packet
//! and reading the counters says exactly which rule the kernel used.
//!
//! One wrinkle worth recording: a packet the kernel *accepts* with no socket
//! listening provokes an ICMP unreachable, which loops back and moves counters
//! of its own. Binding a receiver on the destination before each probe removes
//! that noise, and without it the harness reports phantom disagreements.
//!
//! # Coverage and its limits
//!
//! Probes are UDP. That exercises source and destination address, both ports,
//! and the input interface, and it exercises the protocol dimension negatively
//! — a UDP packet must not match a tcp rule. Sending TCP and ICMP probes needs
//! either raw sockets or an external helper with a per-probe timeout, and is a
//! known gap rather than a solved problem. See `KNOWN_GAPS` below.

mod emit;

use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::process::{Command, Stdio};

use soteria_engine::{Layout, VarOrder, analyse};
use soteria_ir::{
    Action, Chain, Field, Hook, IfMatch, Match, Origin, SymbolTable,
};

const TABLE: &str = "soteria_diff";
const LOOPBACK: &str = "lo";
/// An interface name that exists in the ruleset but never carries a probe.
///
/// Without it the interface dimension is untested: every probe arrives on `lo`,
/// so a rule saying `iifname "lo"` matches exactly when no rule would, and a
/// model that ignored interfaces entirely would agree with the kernel on every
/// packet. The `ignore-interface` self-test detected precisely that hole.
const ABSENT_IF: &str = "eth-absent";
const IFACES: [&str; 2] = [LOOPBACK, ABSENT_IF];
const UDP: u64 = 17;

/// Documented so the correctness claim is not overstated.
const KNOWN_GAPS: &[&str] = &[
    "probes are UDP only; tcp and icmp rules are exercised negatively, not positively",
    "the input hook means oifname is never set, so the output interface dimension is untested",
    "connection tracking is out of the model and out of these probes",
];

// ---------------------------------------------------------------- environment

fn sh(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program)
        .args(args)
        .output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn load_ruleset(text: &str) -> Result<(), String> {
    use std::io::Write;
    let mut child = Command::new("nft")
        .arg("-f")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn nft: {e}"))?;
    child
        .stdin
        .as_mut()
        .ok_or("no stdin")?
        .write_all(text.as_bytes())
        .map_err(|e| format!("write ruleset: {e}"))?;
    let out = child.wait_with_output().map_err(|e| format!("nft: {e}"))?;
    if !out.status.success() {
        return Err(format!("nft -f rejected the ruleset: {}", String::from_utf8_lossy(&out.stderr)));
    }
    Ok(())
}

/// Per-rule packet counts, keyed by the rule number in the comment.
///
/// Parsed from `nft list chain` text rather than its JSON, to keep the harness
/// free of a serialisation dependency.
fn counters() -> Result<BTreeMap<u32, u64>, String> {
    let text = sh("nft", &["list", "chain", "ip", TABLE, "input"])?;
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let Some(cpos) = line.find("counter packets ") else { continue };
        let Some(mpos) = line.find("comment \"r") else { continue };
        let n: u64 = line[cpos + 16..]
            .split_whitespace()
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("unparsable counter: {line}"))?;
        let id: u32 = line[mpos + 10..]
            .split('"')
            .next()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| format!("unparsable comment: {line}"))?;
        out.insert(id, n);
    }
    Ok(out)
}

// --------------------------------------------------------------------- probes

#[derive(Clone, Copy, Debug)]
struct Packet {
    src: u32,
    dst: u32,
    sport: u16,
    dport: u16,
    proto: u64,
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let ip = |v: u32| format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff);
        write!(
            f,
            "{} {}:{} -> {}:{}",
            match self.proto {
                6 => "tcp",
                17 => "udp",
                1 => "icmp",
                _ => "ip",
            },
            ip(self.src),
            self.sport,
            ip(self.dst),
            self.dport
        )
    }
}

fn ip_string(v: u32) -> String {
    format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

/// What the kernel did with a packet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Verdict {
    /// Rule number that decided it, or `None` for the chain policy.
    decider: Option<u32>,
    permitted: bool,
}

/// Send one packet and read back which rule decided it.
fn probe(p: &Packet, chain: &Chain) -> Result<Verdict, String> {
    sh("nft", &["reset", "counters", "table", "ip", TABLE])?;
    let before = counters()?;

    // A listener on the destination stops the kernel answering an accepted
    // packet with an ICMP unreachable, which would move counters of its own.
    let listener = UdpSocket::bind((ip_string(p.dst).as_str(), p.dport))
        .map_err(|e| format!("bind listener {}:{}: {e}", ip_string(p.dst), p.dport))?;
    let sender = UdpSocket::bind((ip_string(p.src).as_str(), p.sport))
        .map_err(|e| format!("bind sender {}:{}: {e}", ip_string(p.src), p.sport))?;
    sender
        .send_to(b"soteria", (ip_string(p.dst).as_str(), p.dport))
        .map_err(|e| format!("send: {e}"))?;
    drop(sender);
    drop(listener);

    let after = counters()?;
    let moved: Vec<u32> =
        after.iter().filter(|(k, v)| **v > before.get(k).copied().unwrap_or(0)).map(|(k, _)| *k).collect();

    match moved.as_slice() {
        [] => Ok(Verdict { decider: None, permitted: chain.policy.permits() }),
        [one] => {
            let action = chain
                .rules
                .iter()
                .find(|r| r.number == *one)
                .map(|r| r.action)
                .ok_or_else(|| format!("counter for unknown rule {one}"))?;
            Ok(Verdict { decider: Some(*one), permitted: action.permits() })
        }
        many => Err(format!(
            "{many:?} rules counted one packet; first-match should fire exactly one"
        )),
    }
}

// ---------------------------------------------------------------- the model

fn model_verdict(
    layout: &Layout,
    syms: &SymbolTable,
    model: &soteria_engine::ChainModel,
    p: &Packet,
) -> Verdict {
    let lo = syms.index_of(LOOPBACK).map(u64::from);
    let mut point = layout
        .eq(Field::SrcAddr, u64::from(p.src))
        .and(&layout.eq(Field::DstAddr, u64::from(p.dst)))
        .and(&layout.eq(Field::SrcPort, u64::from(p.sport)))
        .and(&layout.eq(Field::DstPort, u64::from(p.dport)))
        .and(&layout.eq(Field::Proto, p.proto));
    // Traffic between two loopback addresses arrives on lo. The output
    // interface is never set on the input hook, so it stays free.
    if let Some(i) = lo {
        point = point.and(&layout.eq(Field::IfIn, i));
    }

    let permitted = point.and_not(&model.accept).is_false();
    let decider = match model.attribute(&point).as_slice() {
        [(soteria_engine::Decider::Rule(n), _)] => Some(*n),
        _ => None,
    };
    Verdict { decider, permitted }
}

// ------------------------------------------------------------------ generator

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
    fn pick<T: Copy>(&mut self, xs: &[T]) -> T {
        xs[self.below(xs.len() as u64) as usize]
    }
}

const SRCS: [u32; 4] = [0x0A01_0001, 0x0A01_0002, 0x0A01_0003, 0x0A01_0004];
const DSTS: [u32; 4] = [0x0A05_0001, 0x0A05_0002, 0x0A05_0003, 0x0A05_0004];
const PORTS: [u16; 6] = [22, 80, 443, 502, 1161, 8080];

/// A ruleset over the address pool, shaped to produce overlap and therefore
/// to make rule ordering matter.
fn generate(n: usize, seed: u64) -> Chain {
    let mut rng = Rng(seed);
    let mut chain = Chain::new(
        "input",
        Hook::Input,
        if seed % 2 == 0 { Action::Drop } else { Action::Accept },
    );

    for i in 0..n {
        let mut m = Match::any();
        // A single pinned protocol keeps the emitted syntax unambiguous.
        let proto = rng.pick(&[6u64, 17, 17, 1]);
        m = m.with_value(Field::Proto, proto);

        match rng.below(3) {
            0 => m = m.with_prefix(Field::SrcAddr, u64::from(rng.pick(&SRCS)), 32),
            1 => m = m.with_prefix(Field::SrcAddr, 0x0A01_0000, 24),
            _ => {}
        }
        match rng.below(3) {
            0 => m = m.with_prefix(Field::DstAddr, u64::from(rng.pick(&DSTS)), 32),
            1 => m = m.with_prefix(Field::DstAddr, 0x0A05_0000, 24),
            _ => {}
        }

        if proto == 6 || proto == 17 {
            match rng.below(4) {
                0 => m = m.with_value(Field::DstPort, u64::from(rng.pick(&PORTS))),
                1 => {
                    let lo = rng.below(60000);
                    m = m.with_range(Field::DstPort, lo, lo + rng.below(2000));
                }
                2 => m = m.with_range(Field::SrcPort, 1024, 65535),
                _ => {}
            }
        }

        // Only the input interface: oifname is never set on this hook. Half of
        // these name an interface no probe arrives on, so the dimension is
        // exercised in both directions rather than only where it always holds.
        if rng.below(10) < 4 {
            m = m.with_iif(IfMatch::one(rng.pick(&IFACES)));
        }

        let action = rng.pick(&[Action::Accept, Action::Accept, Action::Drop]);
        chain.push(
            m,
            action,
            Origin { file: "generated".into(), line: i as u32 + 1, column: 1, text: String::new() },
        );
    }
    chain
}

fn random_packet(rng: &mut Rng) -> Packet {
    Packet {
        src: rng.pick(&SRCS),
        dst: rng.pick(&DSTS),
        // Ephemeral source ports, plus the well-known ones so rules that pin
        // sport are actually reached.
        sport: if rng.below(4) == 0 { rng.pick(&PORTS) } else { (rng.below(40000) + 20000) as u16 },
        dport: if rng.below(2) == 0 { rng.pick(&PORTS) } else { rng.below(65535) as u16 },
        proto: UDP,
    }
}

// ----------------------------------------------------------------------- main

struct Args {
    rules: usize,
    packets: usize,
    seed: u64,
    rounds: usize,
    /// Deliberately corrupt the model to prove the harness can fail.
    fault: Option<Fault>,
}

/// Ways to break the model on purpose.
///
/// A differential harness that has never failed is indistinguishable from one
/// that cannot fail. These faults are the self-test: each is a plausible
/// implementation mistake, and the harness is required to catch every one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// Evaluate the chain last-match instead of first-match.
    LastMatch,
    /// Ignore the interface dimension entirely.
    IgnoreInterface,
    /// Treat reject as if it permitted.
    RejectPermits,
}

impl Fault {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "last-match" => Some(Fault::LastMatch),
            "ignore-interface" => Some(Fault::IgnoreInterface),
            "reject-permits" => Some(Fault::RejectPermits),
            _ => None,
        }
    }

    /// Corrupt the chain the *model* sees. The kernel still gets the original.
    fn corrupt(self, chain: &Chain) -> Chain {
        let mut c = chain.clone();
        match self {
            Fault::LastMatch => c.rules.reverse(),
            Fault::IgnoreInterface => {
                for r in &mut c.rules {
                    r.matches = r.matches.clone().with_iif(IfMatch::Any);
                }
            }
            Fault::RejectPermits => {
                for r in &mut c.rules {
                    if r.action == Action::Drop {
                        r.action = Action::Accept;
                    }
                }
            }
        }
        c
    }
}

/// Accepts decimal or `0x`-prefixed hex. Getting this wrong means a reported
/// seed does not reproduce the failure it came from, which defeats the harness.
fn parse_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse().ok(),
    }
}

fn parse_args() -> Args {
    let mut a = Args { rules: 40, packets: 120, seed: 0x2026_0815, rounds: 3, fault: None };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let raw = argv.get(i + 1);
        let num = raw.and_then(|s| parse_u64(s));
        match argv[i].as_str() {
            "--rules" => a.rules = num.unwrap_or(a.rules as u64) as usize,
            "--packets" => a.packets = num.unwrap_or(a.packets as u64) as usize,
            "--rounds" => a.rounds = num.unwrap_or(a.rounds as u64) as usize,
            "--seed" => {
                a.seed = match num {
                    Some(v) => v,
                    None => {
                        eprintln!("--seed needs a decimal or 0x-prefixed value");
                        std::process::exit(2);
                    }
                }
            }
            "--inject-fault" => {
                a.fault = raw.map(String::as_str).and_then(Fault::parse);
                if a.fault.is_none() {
                    eprintln!("--inject-fault expects last-match, ignore-interface or reject-permits");
                    std::process::exit(2);
                }
            }
            other => eprintln!("ignoring unknown argument {other}"),
        }
        i += if argv[i].starts_with("--") { 2 } else { 1 };
    }
    a
}

fn setup_namespace() -> Result<(), String> {
    sh("ip", &["link", "set", LOOPBACK, "up"])?;
    for a in SRCS.iter().chain(DSTS.iter()) {
        sh("ip", &["addr", "add", &format!("{}/32", ip_string(*a)), "dev", LOOPBACK])?;
    }
    Ok(())
}

fn run_round(args: &Args, round: usize) -> Result<usize, String> {
    let seed = args.seed.wrapping_add(round as u64 * 0x9E37_79B9);
    let chain = generate(args.rules, seed);

    let Some(text) = emit::chain(TABLE, &chain) else {
        return Err("generator produced a rule the emitter cannot express".into());
    };
    sh("nft", &["flush", "ruleset"])?;
    load_ruleset(&text)?;

    let layout = Layout::new(VarOrder::AddrInterleaved);
    let syms = SymbolTable::from_names(IFACES).map_err(|e| e.to_string())?;
    // The kernel always gets the genuine chain; only the model is corrupted.
    let modelled = match args.fault {
        Some(f) => f.corrupt(&chain),
        None => chain.clone(),
    };
    let model = analyse(&layout, &syms, &modelled);
    assert!(model.partition_holds(&layout), "effective sets do not partition");

    let mut rng = Rng(seed ^ 0xDEAD_BEEF);
    let mut checked = 0usize;
    for _ in 0..args.packets {
        let p = random_packet(&mut rng);
        let kernel = probe(&p, &chain)?;
        let ours = model_verdict(&layout, &syms, &model, &p);

        if kernel != ours {
            eprintln!("\nDISAGREEMENT");
            eprintln!("  packet     {p}");
            eprintln!(
                "  kernel     {} by {}",
                if kernel.permitted { "permit" } else { "deny" },
                kernel.decider.map(|n| format!("rule {n}")).unwrap_or_else(|| "policy".into())
            );
            eprintln!(
                "  model      {} by {}",
                if ours.permitted { "permit" } else { "deny" },
                ours.decider.map(|n| format!("rule {n}")).unwrap_or_else(|| "policy".into())
            );
            eprintln!("  reproduce  --seed {} --rounds {} --rules {}", args.seed, round + 1, args.rules);
            eprintln!("\nruleset under test:\n{text}");
            return Err("model disagrees with the kernel".into());
        }
        checked += 1;
    }
    Ok(checked)
}

fn main() {
    // Re-enter under an unprivileged user and network namespace, so the harness
    // needs no root and cannot touch the host's networking.
    if std::env::var_os("SOTERIA_KERNELDIFF_INNER").is_none() {
        let exe = match std::env::current_exe() {
            Ok(e) => e,
            Err(e) => {
                eprintln!("cannot locate self: {e}");
                std::process::exit(2);
            }
        };
        let status = Command::new("unshare")
            .args(["-Ur", "-n"])
            .arg(exe)
            .args(std::env::args().skip(1))
            .env("SOTERIA_KERNELDIFF_INNER", "1")
            .status();
        match status {
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => {
                eprintln!("cannot create a user namespace: {e}");
                eprintln!("this harness needs unprivileged user namespaces, or run it as root");
                std::process::exit(2);
            }
        }
    }

    let args = parse_args();
    println!("SOTERIA KERNEL DIFFERENTIAL");
    println!(
        "{} rounds x {} rules x {} packets, seed {:#x}",
        args.rounds, args.rules, args.packets, args.seed
    );
    match args.fault {
        Some(f) => println!("SELF-TEST: model corrupted with {f:?}; a disagreement is the pass condition\n"),
        None => println!(),
    }

    if let Err(e) = setup_namespace() {
        eprintln!("namespace setup failed: {e}");
        std::process::exit(2);
    }

    let mut total = 0usize;
    for round in 0..args.rounds {
        match run_round(&args, round) {
            Ok(n) => {
                total += n;
                println!("  round {:<3} {n} packets agreed", round + 1);
            }
            Err(e) => {
                if args.fault.is_some() {
                    println!("\nround {} disagreed, as required: {e}", round + 1);
                    println!("\nSELF-TEST PASSED: the harness detects a broken model");
                    std::process::exit(0);
                }
                eprintln!("\nround {} failed: {e}", round + 1);
                std::process::exit(1);
            }
        }
    }

    if let Some(f) = args.fault {
        eprintln!("\nSELF-TEST FAILED: {f:?} went undetected across {total} packets");
        eprintln!("the harness is not sensitive enough to be trusted");
        std::process::exit(1);
    }
    println!("\n{total} packets, model and kernel agree on every one");
    println!("\nknown gaps in this harness:");
    for g in KNOWN_GAPS {
        println!("  - {g}");
    }
}
