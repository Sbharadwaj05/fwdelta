//! IR to nftables text.
//!
//! **This is not the frontend and must never become it.** The frontend reads
//! nftables and produces IR; this writes IR back out as nftables so the kernel
//! can be asked what it thinks. Keeping them separate is the point: if the same
//! code did both, a misunderstanding of nftables syntax would cancel itself out
//! and the differential test would agree with the model while both were wrong.
//!
//! Every rule carries a `counter` and a comment naming its position, which is
//! how the kernel's verdict is read back.

use soteria_ir::{Action, Chain, Field, IntervalSet, Rule, set_to_prefixes};

fn ipv4(v: u64) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

fn addr_expr(keyword: &str, set: &IntervalSet) -> Option<String> {
    if set.is_full() {
        return None;
    }
    let parts: Vec<String> = set_to_prefixes(set)
        .into_iter()
        .map(|(v, len)| if len == 32 { ipv4(v) } else { format!("{}/{}", ipv4(v), len) })
        .collect();
    Some(match parts.len() {
        1 => format!("ip {keyword} {}", parts[0]),
        _ => format!("ip {keyword} {{ {} }}", parts.join(", ")),
    })
}

fn port_expr(proto: &str, keyword: &str, set: &IntervalSet) -> Option<String> {
    if set.is_full() {
        return None;
    }
    let parts: Vec<String> = set
        .ranges()
        .iter()
        .map(|&(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
        .collect();
    Some(match parts.len() {
        1 => format!("{proto} {keyword} {}", parts[0]),
        _ => format!("{proto} {keyword} {{ {} }}", parts.join(", ")),
    })
}

fn proto_keyword(v: u64) -> &'static str {
    match v {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        _ => "ip",
    }
}

/// Render one rule. Returns `None` for predicates this emitter cannot express,
/// which the generator is written to avoid producing.
pub fn rule(r: &Rule) -> Option<String> {
    let mut parts = Vec::new();

    if let soteria_ir::IfMatch::OneOf(names) = &r.matches.iif {
        let list: Vec<String> = names.iter().map(|n| format!("\"{n}\"")).collect();
        parts.push(match list.len() {
            1 => format!("iifname {}", list[0]),
            _ => format!("iifname {{ {} }}", list.join(", ")),
        });
    }

    let proto_set = r.matches.packet_dim(Field::Proto);
    // The generator only ever pins a single protocol, which keeps the emitted
    // syntax unambiguous about which layer-4 keyword the port matches belong to.
    let proto_value = match proto_set.ranges() {
        [(lo, hi)] if lo == hi => Some(*lo),
        _ => None,
    };
    let l4 = proto_value.map(proto_keyword).unwrap_or("ip");
    if let Some(v) = proto_value {
        parts.push(format!(
            "meta l4proto {}",
            match v {
                1 => "icmp".to_string(),
                6 => "tcp".to_string(),
                17 => "udp".to_string(),
                other => other.to_string(),
            }
        ));
    }

    if let Some(e) = addr_expr("saddr", r.matches.packet_dim(Field::SrcAddr)) {
        parts.push(e);
    }
    if let Some(e) = addr_expr("daddr", r.matches.packet_dim(Field::DstAddr)) {
        parts.push(e);
    }
    if l4 == "tcp" || l4 == "udp" {
        if let Some(e) = port_expr(l4, "sport", r.matches.packet_dim(Field::SrcPort)) {
            parts.push(e);
        }
        if let Some(e) = port_expr(l4, "dport", r.matches.packet_dim(Field::DstPort)) {
            parts.push(e);
        }
    } else if !r.matches.packet_dim(Field::SrcPort).is_full()
        || !r.matches.packet_dim(Field::DstPort).is_full()
    {
        // A port constraint on a protocol without ports cannot be expressed and
        // must not be silently dropped.
        return None;
    }

    let verdict = match r.action {
        Action::Accept => "accept",
        Action::Drop => "drop",
        Action::Reject => "reject",
    };
    parts.push(format!("counter {verdict} comment \"r{}\"", r.number));
    Some(format!("    {}", parts.join(" ")))
}

/// Render a whole chain as a loadable ruleset.
pub fn chain(table: &str, c: &Chain) -> Option<String> {
    chain_with(table, c, true)
}

/// `sentinel` adds the verdict-less counter the harness polls on. It is a
/// harness artifact and not valid frontend input, so the round-trip check
/// asks for the ruleset without it.
pub fn chain_with(table: &str, c: &Chain, sentinel: bool) -> Option<String> {
    let policy = match c.policy {
        Action::Accept => "accept",
        _ => "drop",
    };
    let mut out = format!("table ip {table} {{\n  chain {} {{\n", c.name);
    out.push_str(&format!("    type filter hook {} priority filter; policy {policy};\n", c.hook));
    for r in &c.rules {
        out.push_str(&rule(r)?);
        out.push('\n');
    }
    // Sentinel: counts packets that reached the end of the chain and are about
    // to be decided by the policy. It carries no verdict, so it changes nothing
    // semantically, and it makes "the policy decided this" an observable event
    // rather than an absence. Without it, no-counter-moved is ambiguous between
    // "policy" and "the packet has not arrived yet", and the harness cannot poll.
    if sentinel {
        out.push_str("    counter comment \"r0\"\n");
    }
    out.push_str("  }\n}\n");
    Some(out)
}
