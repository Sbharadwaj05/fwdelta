//! Differential testing of the model against the Linux kernel.
//!
//! Per blueprint section 07 this is the single most valuable piece of
//! engineering in the project: it converts the correctness claim from an
//! argument into a measurement. The model is only worth anything if it agrees
//! with the thing it models, and the only authority on nftables semantics is
//! nftables.
//!
//! # Obtaining a real verdict
//!
//! Everything runs inside an unprivileged user and network namespace, so no root
//! is required and CI can run it. The generated ruleset is loaded on the input
//! hook with a `counter` and a position comment on every rule, plus a
//! verdict-less sentinel counter at the end of the chain. Exactly one counter
//! moves per probe: a rule's, or the sentinel's when the packet falls through to
//! the policy. Silence therefore means "has not arrived yet" rather than "the
//! policy decided it", which is what makes polling for the result reliable.
//!
//! Two kinds of interference had to be removed before the oracle was sound:
//!
//! * A packet the kernel *accepts* with no socket listening provokes an ICMP
//!   unreachable, which loops back and moves counters of its own.
//! * Replies traverse the input hook too — a TCP handshake response, an ICMP
//!   echo reply — so one probe could move two counters.
//!
//! A prefilter chain at higher priority drops anything whose source is one of
//! the destination addresses, which removes every reply. Probe traffic only ever
//! runs source-pool to destination-pool, so nothing legitimate is caught.
//!
//! # Why coverage is computed rather than claimed
//!
//! See [`coverage`]. A dimension not varied across probes is untested, and the
//! harness will report agreement anyway.

#![forbid(unsafe_code)]

mod coverage;
mod emit;

use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use coverage::Coverage;
use soteria_engine::{ChainModel, Layout, VarOrder, analyse};
use soteria_ir::{Action, Chain, Field, Hook, IfMatch, Match, Origin, SymbolTable};

const TABLE: &str = "soteria_diff";

/// Probes arrive on one of these two. Varying the input interface needs traffic
/// that genuinely crosses a link, which is why a peer namespace exists at all.
const IF_LOOPBACK: &str = "lo";
const IF_WIRE: &str = "veth-b";
/// Named in rules but never carrying a probe, so interface matches are
/// exercised negatively as well as positively.
const IF_ABSENT: &str = "eth-absent";
const IFACES: [&str; 3] = [IF_LOOPBACK, IF_WIRE, IF_ABSENT];

const ICMP: u64 = 1;
const TCP: u64 = 6;
const UDP: u64 = 17;

/// Loopback path: both pools live on `lo` in the main namespace.
const LO_SRCS: [u32; 4] = [0x0A01_0001, 0x0A01_0002, 0x0A01_0003, 0x0A01_0004];
const LO_DSTS: [u32; 4] = [0x0A05_0001, 0x0A05_0002, 0x0A05_0003, 0x0A05_0004];
/// Wire path: sources sit in the peer namespace, destinations on our veth end.
const WIRE_SRCS: [u32; 4] = [0x0A07_0001, 0x0A07_0002, 0x0A07_0003, 0x0A07_0004];
const WIRE_DSTS: [u32; 4] = [0x0A07_0065, 0x0A07_0066, 0x0A07_0067, 0x0A07_0068];

const PORTS: [u16; 6] = [22, 80, 443, 502, 1161, 8080];

// ---------------------------------------------------------------- environment

fn sh(program: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(program).args(args).output().map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "{program} {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn ip_string(v: u32) -> String {
    format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

/// A peer network namespace, joined to ours by a veth pair.
///
/// Held open by a parked child process; entering it is `nsenter -t <pid> -n`.
/// `ip netns add` is unavailable here because it wants to write under `/run`,
/// which an unprivileged user namespace cannot do.
struct Peer {
    child: Child,
}

impl Peer {
    fn create() -> Result<Self, String> {
        let child = Command::new("unshare")
            .args(["-n", "sleep", "86400"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn peer namespace: {e}"))?;
        // Let the child enter its new namespace before moving an interface in.
        std::thread::sleep(Duration::from_millis(200));

        let peer = Self { child };
        sh("ip", &["link", "add", "veth-a", "type", "veth", "peer", "name", IF_WIRE])?;
        sh("ip", &["link", "set", "veth-a", "netns", &peer.pid()])?;
        for a in WIRE_DSTS {
            sh("ip", &["addr", "add", &format!("{}/24", ip_string(a)), "dev", IF_WIRE])?;
        }
        sh("ip", &["link", "set", IF_WIRE, "up"])?;
        peer.exec(&["ip", "link", "set", "lo", "up"])?;
        for a in WIRE_SRCS {
            peer.exec(&["ip", "addr", "add", &format!("{}/24", ip_string(a)), "dev", "veth-a"])?;
        }
        peer.exec(&["ip", "link", "set", "veth-a", "up"])?;
        Ok(peer)
    }

    fn pid(&self) -> String {
        self.child.id().to_string()
    }

    fn exec(&self, argv: &[&str]) -> Result<String, String> {
        let pid = self.pid();
        let mut full: Vec<&str> = vec!["-t", &pid, "-n"];
        full.extend_from_slice(argv);
        sh("nsenter", &full)
    }

    /// Spawn without waiting. Probe helpers block until a timeout when the
    /// packet is dropped; the counters say when it has landed.
    fn spawn(&self, argv: &[&str]) -> Result<Child, String> {
        let pid = self.pid();
        Command::new("nsenter")
            .args(["-t", &pid, "-n"])
            .args(argv)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("spawn in peer: {e}"))
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn spawn_local(argv: &[&str]) -> Result<Child, String> {
    Command::new(argv[0])
        .args(&argv[1..])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn {}: {e}", argv[0]))
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
        return Err(format!(
            "nft -f rejected the ruleset: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

/// The empty prefilter table, created once per round.
///
/// A base chain at priority -100 runs before the chain under test. An `accept`
/// verdict there lets the packet continue to the next base chain, so the
/// prefilter can decide what the measured chain is allowed to see without
/// altering the verdict the measured chain produces.
fn prefilter_table() -> String {
    "table ip soteria_pre {\n  chain pre {\n    \
     type filter hook input priority -100; policy accept;\n  }\n}\n"
        .to_string()
}

/// Admit exactly one 5-tuple and drop everything else.
///
/// Started as "drop the replies", which was the wrong shape. Replies are only
/// one source of stray traffic: a datagram from an earlier probe can arrive
/// after the counters have been reset for the next one, and it will move a
/// counter that has nothing to do with the packet under test. Chasing each
/// source of interference individually is a losing game.
///
/// Allowing only the current tuple inverts the problem. The measured chain sees
/// exactly one packet per probe by construction, so "exactly one counter moved"
/// stops being an assumption that holds when nothing goes wrong and becomes a
/// property of the setup.
fn prefilter_for(p: &Packet) -> String {
    let mut m = format!(
        "meta l4proto {} ip saddr {} ip daddr {}",
        match p.proto {
            ICMP => "icmp",
            TCP => "tcp",
            UDP => "udp",
            other => return format!("# unsupported protocol {other}"),
        },
        ip_string(p.src),
        ip_string(p.dst)
    );
    if let Some((sp, dp)) = p.ports {
        let l4 = if p.proto == TCP { "tcp" } else { "udp" };
        m.push_str(&format!(" {l4} sport {sp} {l4} dport {dp}"));
    }
    format!(
        "flush chain ip soteria_pre pre\n\
         add rule ip soteria_pre pre {m} accept\n\
         add rule ip soteria_pre pre drop\n"
    )
}

/// Per-rule packet counts, keyed by rule number. Zero is the sentinel.
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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Path {
    /// Both endpoints on `lo`; arrives on `lo`.
    Loopback,
    /// Sent from the peer namespace; arrives on `veth-b`.
    Wire,
}

impl Path {
    fn arrival_interface(self) -> &'static str {
        match self {
            Path::Loopback => IF_LOOPBACK,
            Path::Wire => IF_WIRE,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Packet {
    path: Path,
    src: u32,
    dst: u32,
    /// `None` for protocols without ports, where the model leaves both port
    /// dimensions free.
    ports: Option<(u16, u16)>,
    proto: u64,
}

impl std::fmt::Display for Packet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self.proto {
            ICMP => "icmp",
            TCP => "tcp",
            UDP => "udp",
            _ => "ip",
        };
        match self.ports {
            Some((sp, dp)) => write!(
                f,
                "{name} {}:{sp} -> {}:{dp} on {}",
                ip_string(self.src),
                ip_string(self.dst),
                self.path.arrival_interface()
            ),
            None => write!(
                f,
                "{name} {} -> {} on {}",
                ip_string(self.src),
                ip_string(self.dst),
                self.path.arrival_interface()
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Verdict {
    /// Rule number, or `None` when the chain policy decided.
    decider: Option<u32>,
    permitted: bool,
}

/// Send one packet and read back which rule the kernel used.
fn probe(p: &Packet, chain: &Chain, peer: &Peer) -> Result<Verdict, String> {
    // Narrow the prefilter to this probe before clearing the counters, so any
    // packet still in flight from the previous probe is already being dropped.
    load_ruleset(&prefilter_for(p))?;
    // `reset counters` clears named counter *objects*; the counters embedded in
    // rules are anonymous and need `reset rules`. Getting this wrong makes the
    // reset a silent no-op, so a stale count from an earlier probe reads as a
    // second rule firing on this one.
    sh("nft", &["reset", "rules", "table", "ip", TABLE])?;

    let mut helper: Option<Child> = None;
    // A listener stops an accepted UDP packet drawing an ICMP unreachable.
    let mut _listener: Option<UdpSocket> = None;

    let src = ip_string(p.src);
    let dst = ip_string(p.dst);

    match p.proto {
        UDP => {
            let (sp, dp) = p.ports.ok_or("udp probe without ports")?;
            _listener = UdpSocket::bind((dst.as_str(), dp)).ok();
            match p.path {
                Path::Loopback => {
                    let sender = UdpSocket::bind((src.as_str(), sp))
                        .map_err(|e| format!("bind sender {src}:{sp}: {e}"))?;
                    sender
                        .send_to(b"soteria", (dst.as_str(), dp))
                        .map_err(|e| format!("send: {e}"))?;
                }
                Path::Wire => {
                    // Re-enter the peer namespace as ourselves rather than
                    // reaching for socat: `socat - UDP-DATAGRAM:...` reads EOF
                    // from a closed stdin and exits without sending anything,
                    // and the std socket path here is already known to work.
                    let exe = std::env::current_exe().map_err(|e| format!("locate self: {e}"))?;
                    let exe = exe.to_string_lossy().into_owned();
                    let (sp_s, dp_s) = (sp.to_string(), dp.to_string());
                    helper = Some(peer.spawn(&[&exe, "--send-udp", &src, &sp_s, &dst, &dp_s])?);
                }
            }
        }
        TCP => {
            let (sp, dp) = p.ports.ok_or("tcp probe without ports")?;
            let spec = format!("TCP:{dst}:{dp},bind={src}:{sp},connect-timeout=0.4");
            let argv = ["socat", "-T1", &spec, "/dev/null"];
            helper = Some(match p.path {
                Path::Wire => peer.spawn(&argv)?,
                Path::Loopback => spawn_local(&argv)?,
            });
        }
        ICMP => {
            let argv = ["ping", "-c", "1", "-W", "1", "-I", &src, &dst];
            helper = Some(match p.path {
                Path::Wire => peer.spawn(&argv)?,
                Path::Loopback => spawn_local(&argv)?,
            });
        }
        other => return Err(format!("no probe method for protocol {other}")),
    }

    // Poll until a counter moves. The sentinel guarantees one always does, so a
    // timeout means the packet never arrived rather than that the policy decided.
    let deadline = Instant::now() + Duration::from_millis(2000);
    let mut moved: Vec<u32> = Vec::new();
    while Instant::now() < deadline {
        let now = counters()?;
        moved = now.iter().filter(|(_, v)| **v > 0).map(|(k, _)| *k).collect();
        if !moved.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if let Some(mut h) = helper {
        let _ = h.kill();
        let _ = h.wait();
    }

    match moved.as_slice() {
        [] => Err(format!("no counter moved for {p}; the probe never reached the chain")),
        [0] => Ok(Verdict { decider: None, permitted: chain.policy.permits() }),
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
            "{many:?} counters moved for one packet; first-match fires exactly one. \
             The prefilter admits only this probe's 5-tuple, so either it failed to \
             load or a rule in the measured chain is non-terminal."
        )),
    }
}

// ----------------------------------------------------------------- the model

fn model_verdict(
    layout: &Layout,
    syms: &SymbolTable,
    model: &ChainModel,
    p: &Packet,
) -> Result<Verdict, String> {
    let iface = p.path.arrival_interface();
    let idx = syms
        .index_of(iface)
        .ok_or_else(|| format!("interface {iface} missing from the symbol table"))?;

    let mut point = layout
        .eq(Field::SrcAddr, u64::from(p.src))
        .and(&layout.eq(Field::DstAddr, u64::from(p.dst)))
        .and(&layout.eq(Field::Proto, p.proto))
        .and(&layout.eq(Field::IfIn, u64::from(idx)));

    if let Some((sp, dp)) = p.ports {
        point = point
            .and(&layout.eq(Field::SrcPort, u64::from(sp)))
            .and(&layout.eq(Field::DstPort, u64::from(dp)));
    }

    // A portless protocol leaves both port dimensions free, so the "packet" is a
    // set of points. Every one must get the same verdict — that is the soundness
    // obligation in SEMANTICS.md section 4.2, and checking it here turns a
    // documented assumption into a tested one.
    let all_permitted = point.and_not(&model.accept).is_false();
    let none_permitted = point.and(&model.accept).is_false();
    if !all_permitted && !none_permitted {
        return Err(format!(
            "the model gives {p} more than one verdict: a rule constrains a port \
             dimension without pinning a protocol that has ports"
        ));
    }

    let cells = model.attribute(&point);
    let decider = match cells.as_slice() {
        [] => None,
        [(soteria_engine::Decider::Rule(n), _)] => Some(*n),
        [(soteria_engine::Decider::Policy, _)] => None,
        _ => return Err(format!("the model attributes {p} to {} different deciders", cells.len())),
    };
    Ok(Verdict { decider, permitted: all_permitted })
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

fn generate(n: usize, seed: u64) -> Chain {
    let mut rng = Rng(seed);
    let mut chain =
        Chain::new("input", Hook::Input, if seed % 2 == 0 { Action::Drop } else { Action::Accept });
    let all_srcs: Vec<u32> = LO_SRCS.iter().chain(WIRE_SRCS.iter()).copied().collect();
    let all_dsts: Vec<u32> = LO_DSTS.iter().chain(WIRE_DSTS.iter()).copied().collect();

    for i in 0..n {
        let mut m = Match::any();
        let proto = rng.pick(&[TCP, UDP, UDP, ICMP]);
        m = m.with_value(Field::Proto, proto);

        match rng.below(3) {
            0 => m = m.with_prefix(Field::SrcAddr, u64::from(rng.pick(&all_srcs)), 32),
            1 => m = m.with_prefix(Field::SrcAddr, 0x0A01_0000, 24),
            _ => {}
        }
        match rng.below(3) {
            0 => m = m.with_prefix(Field::DstAddr, u64::from(rng.pick(&all_dsts)), 32),
            1 => m = m.with_prefix(Field::DstAddr, 0x0A07_0000, 24),
            _ => {}
        }

        // Ports only where the protocol has them. The emitter refuses a port
        // constraint on a portless protocol, which is the same obligation the
        // model relies on.
        if proto == TCP || proto == UDP {
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

        // Only the input interface: oifname is never set on this hook.
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
    let path = if rng.below(2) == 0 { Path::Loopback } else { Path::Wire };
    let (srcs, dsts) = match path {
        Path::Loopback => (LO_SRCS, LO_DSTS),
        Path::Wire => (WIRE_SRCS, WIRE_DSTS),
    };
    let proto = rng.pick(&[UDP, UDP, TCP, ICMP]);
    let ports = if proto == ICMP {
        None
    } else {
        let sp =
            if rng.below(4) == 0 { rng.pick(&PORTS) } else { (rng.below(40000) + 20000) as u16 };
        let dp = if rng.below(2) == 0 { rng.pick(&PORTS) } else { rng.below(65535) as u16 };
        Some((sp, dp))
    };
    Packet { path, src: rng.pick(&srcs), dst: rng.pick(&dsts), ports, proto }
}

// ------------------------------------------------------------- fault injection

/// Ways to break the model on purpose.
///
/// A differential harness that has never failed is indistinguishable from one
/// that cannot fail. Each fault is a plausible implementation mistake and the
/// harness is required to catch every one. `IgnoreInterface` originally went
/// undetected, which is how the interface dimension was found to be untested;
/// `IgnoreProtocol` exists because protocol was in exactly that state
/// afterwards, with every probe being UDP.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    LastMatch,
    IgnoreInterface,
    IgnoreProtocol,
    IgnorePorts,
    RejectPermits,
}

impl Fault {
    const ALL: [Fault; 5] = [
        Fault::LastMatch,
        Fault::IgnoreInterface,
        Fault::IgnoreProtocol,
        Fault::IgnorePorts,
        Fault::RejectPermits,
    ];

    fn parse(s: &str) -> Option<Self> {
        match s {
            "last-match" => Some(Fault::LastMatch),
            "ignore-interface" => Some(Fault::IgnoreInterface),
            "ignore-protocol" => Some(Fault::IgnoreProtocol),
            "ignore-ports" => Some(Fault::IgnorePorts),
            "reject-permits" => Some(Fault::RejectPermits),
            _ => None,
        }
    }

    /// Corrupt the chain the *model* sees. The kernel still gets the original.
    fn corrupt(self, chain: &Chain) -> Chain {
        let mut c = chain.clone();
        match self {
            Fault::LastMatch => c.rules.reverse(),
            // `relax`, not `constrain`: the latter intersects, so handing it a
            // full set changes nothing. Two faults were silently no-ops that way
            // and reported as undetected, which is how this was found.
            Fault::IgnoreInterface => {
                for r in &mut c.rules {
                    r.matches = r.matches.clone().relax(Field::IfIn);
                }
            }
            Fault::IgnoreProtocol => {
                for r in &mut c.rules {
                    r.matches = r.matches.clone().relax(Field::Proto);
                }
            }
            Fault::IgnorePorts => {
                for r in &mut c.rules {
                    r.matches = r.matches.clone().relax(Field::SrcPort).relax(Field::DstPort);
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

// ----------------------------------------------------------------------- main

#[derive(Clone, Copy)]
struct Args {
    rules: usize,
    packets: usize,
    seed: u64,
    rounds: usize,
    fault: Option<Fault>,
    self_test: bool,
}

/// Accepts decimal or `0x`-prefixed hex. Getting this wrong means a reported
/// seed does not reproduce the failure it came from.
fn parse_u64(s: &str) -> Option<u64> {
    let t = s.trim();
    match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => t.parse().ok(),
    }
}

fn parse_args() -> Args {
    let mut a = Args {
        rules: 40,
        packets: 60,
        seed: 0x2026_0815,
        rounds: 3,
        fault: None,
        self_test: false,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let raw = argv.get(i + 1);
        let num = raw.and_then(|s| parse_u64(s));
        match argv[i].as_str() {
            "--self-test" => {
                a.self_test = true;
                i += 1;
                continue;
            }
            "--rules" => a.rules = num.unwrap_or(a.rules as u64) as usize,
            "--packets" => a.packets = num.unwrap_or(a.packets as u64) as usize,
            "--rounds" => a.rounds = num.unwrap_or(a.rounds as u64) as usize,
            "--seed" => match num {
                Some(v) => a.seed = v,
                None => {
                    eprintln!("--seed needs a decimal or 0x-prefixed value");
                    std::process::exit(2);
                }
            },
            "--inject-fault" => {
                a.fault = raw.map(String::as_str).and_then(Fault::parse);
                if a.fault.is_none() {
                    eprintln!(
                        "--inject-fault expects one of: last-match, ignore-interface, \
                         ignore-protocol, ignore-ports, reject-permits"
                    );
                    std::process::exit(2);
                }
            }
            other => eprintln!("ignoring unknown argument {other}"),
        }
        i += 2;
    }
    a
}

fn setup_loopback() -> Result<(), String> {
    sh("ip", &["link", "set", IF_LOOPBACK, "up"])?;
    for a in LO_SRCS.iter().chain(LO_DSTS.iter()) {
        sh("ip", &["addr", "add", &format!("{}/32", ip_string(*a)), "dev", IF_LOOPBACK])?;
    }
    Ok(())
}

fn run_round(args: &Args, round: usize, peer: &Peer, cov: &mut Coverage) -> Result<usize, String> {
    let seed = args.seed.wrapping_add(round as u64 * 0x9E37_79B9);
    let chain = generate(args.rules, seed);

    let Some(text) = emit::chain(TABLE, &chain) else {
        return Err("generator produced a rule the emitter cannot express".into());
    };

    // Blueprint M1: the frontend must round-trip real rulesets. The generator
    // produces IR, the emitter writes nftables, and the frontend reads it back;
    // the two IRs have to agree. Emitter and parser are independent code with
    // opposite directions, so a shared misunderstanding of the syntax cannot
    // cancel itself out here the way it could if one were built from the other.
    roundtrip(&chain)?;
    sh("nft", &["flush", "ruleset"])?;
    load_ruleset(&prefilter_table())?;
    load_ruleset(&text)?;

    let layout = Layout::new(VarOrder::AddrInterleaved);
    let syms = SymbolTable::from_names(IFACES).map_err(|e| e.to_string())?;
    // The kernel always gets the genuine chain; only the model is corrupted.
    let modelled = match args.fault {
        Some(f) => f.corrupt(&chain),
        None => chain.clone(),
    };
    let model = analyse(&layout, &syms, &modelled);
    if args.fault.is_none() {
        model.verify(&layout)?;
    }

    let mut rng = Rng(seed ^ 0xDEAD_BEEF);
    let mut checked = 0usize;
    for _ in 0..args.packets {
        let p = random_packet(&mut rng);

        cov.probes += 1;
        cov.src.insert(p.src);
        cov.dst.insert(p.dst);
        cov.proto.insert(p.proto);
        cov.record_iif(p.path.arrival_interface());
        match p.ports {
            Some((sp, dp)) => {
                cov.sport.insert(sp);
                cov.dport.insert(dp);
            }
            None => cov.portless += 1,
        }

        let kernel = match probe(&p, &chain, peer) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("\nPROBE FAILURE on {p}\n  {e}\n\nruleset under test:\n{text}");
                eprintln!("prefilter:\n{}", prefilter_for(&p));
                return Err(e);
            }
        };
        let ours = model_verdict(&layout, &syms, &model, &p)?;

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
            eprintln!(
                "  reproduce  --seed {:#x} --rounds {} --rules {}",
                args.seed,
                round + 1,
                args.rules
            );
            eprintln!("\nruleset under test:\n{text}");
            return Err("model disagrees with the kernel".into());
        }
        checked += 1;
    }
    Ok(checked)
}

/// Emit the chain, parse it back, and require the IR to survive the trip.
fn roundtrip(chain: &Chain) -> Result<(), String> {
    let text = emit::chain_with(TABLE, chain, false).ok_or("emitter cannot express this chain")?;
    let reparsed = soteria_nft::parse("roundtrip.nft", &text)
        .map_err(|e| format!("frontend rejected emitted nftables:\n{e}\n{text}"))?;

    let [back] = reparsed.chains.as_slice() else {
        return Err(format!("expected one chain back, got {}", reparsed.chains.len()));
    };
    if back.policy != chain.policy || back.hook != chain.hook {
        return Err(format!(
            "chain header changed: {:?}/{:?} became {:?}/{:?}",
            chain.hook, chain.policy, back.hook, back.policy
        ));
    }
    if back.rules.len() != chain.rules.len() {
        return Err(format!(
            "{} rules went out, {} came back",
            chain.rules.len(),
            back.rules.len()
        ));
    }
    for (before, after) in chain.rules.iter().zip(&back.rules) {
        if before.action != after.action {
            return Err(format!("rule {}: verdict changed", before.number));
        }
        if before.matches != after.matches {
            return Err(format!(
                "rule {}: predicate changed across the round trip\n  before {:?}\n  after  {:?}",
                before.number, before.matches, after.matches
            ));
        }
    }
    Ok(())
}

/// Run every fault and require each to be detected.
fn self_test(args: &Args, peer: &Peer) -> i32 {
    println!("SELF-TEST: every fault must be detected, or the harness cannot be trusted\n");
    let mut undetected = Vec::new();
    for fault in Fault::ALL {
        let sub = Args { fault: Some(fault), ..*args };
        let mut cov = Coverage::default();
        let mut detected = false;
        for round in 0..sub.rounds {
            if run_round(&sub, round, peer, &mut cov).is_err() {
                detected = true;
                break;
            }
        }
        println!(
            "  {:<18} {}",
            format!("{fault:?}"),
            if detected {
                "detected".to_string()
            } else {
                "NOT DETECTED -- the dimension it breaks is untested".to_string()
            }
        );
        if !detected {
            undetected.push(fault);
        }
    }
    if !undetected.is_empty() {
        eprintln!("\n{undetected:?} went undetected; the harness is not sensitive enough to trust");
        return 1;
    }
    println!("\nall faults detected");
    0
}

/// Send one datagram and exit. Used to originate traffic inside the peer
/// namespace, entered via `nsenter`.
fn send_udp_mode(argv: &[String]) -> ! {
    let [src, sport, dst, dport] = argv else {
        eprintln!("--send-udp needs src sport dst dport");
        std::process::exit(2);
    };
    let bind = (src.as_str(), sport.parse::<u16>().unwrap_or(0));
    let to = (dst.as_str(), dport.parse::<u16>().unwrap_or(0));
    match UdpSocket::bind(bind).and_then(|s| s.send_to(b"soteria", to)) {
        Ok(_) => std::process::exit(0),
        Err(e) => {
            eprintln!("send failed: {e}");
            std::process::exit(1);
        }
    }
}

fn main() {
    let raw: Vec<String> = std::env::args().collect();
    if raw.get(1).map(String::as_str) == Some("--send-udp") {
        send_udp_mode(&raw[2..]);
    }

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
        "{} rounds x {} rules x {} packets, seed {:#x}\n",
        args.rounds, args.rules, args.packets, args.seed
    );

    let peer = match Peer::create() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("peer namespace setup failed: {e}");
            std::process::exit(2);
        }
    };
    if let Err(e) = setup_loopback() {
        eprintln!("namespace setup failed: {e}");
        std::process::exit(2);
    }

    if args.self_test {
        std::process::exit(self_test(&args, &peer));
    }

    if let Some(f) = args.fault {
        println!("model corrupted with {f:?}; a disagreement is the pass condition\n");
    }

    let mut cov = Coverage::default();
    let mut total = 0usize;
    for round in 0..args.rounds {
        match run_round(&args, round, &peer, &mut cov) {
            Ok(n) => {
                total += n;
                println!("  round {:<3} {n} packets agreed", round + 1);
            }
            Err(e) => {
                if args.fault.is_some() {
                    println!("\nround {} disagreed, as required: {e}", round + 1);
                    println!("SELF-TEST PASSED: the harness detects a broken model");
                    std::process::exit(0);
                }
                eprintln!("\nround {} failed: {e}", round + 1);
                std::process::exit(1);
            }
        }
    }

    if let Some(f) = args.fault {
        eprintln!("\nSELF-TEST FAILED: {f:?} went undetected across {total} packets");
        std::process::exit(1);
    }

    println!("\n{total} packets, model and kernel agree on every one\n");
    print!("{}", cov.report());

    if !cov.complete() {
        eprintln!(
            "\nA dimension was held constant across every probe. The agreement above \
             does not test it: a model ignoring that dimension entirely would have \
             passed identically. Vary it in the generator before trusting this run."
        );
        std::process::exit(1);
    }
}
