//! M3 demonstration: the behavioural delta of a plausible OT firewall edit.
//!
//! The chain segments an enterprise VLAN from a cell network. The edit is the
//! kind that looks harmless in a unified diff: one source range is narrowed from
//! a /8 to a /16, on the assumption that nothing outside 10.0/16 was using it.
//!
//! Run with: `cargo run --release -p fwdelta-engine --example delta_report`

use fwdelta_engine::report::{ReportOptions, render_diff};
use fwdelta_engine::{Field, Layout, VarOrder, analyse, diff};
use fwdelta_ir::{Action, Chain, Hook, IfMatch, Match, Origin, Ruleset, shared_symbols};

fn ip(a: u8, b: u8, c: u8, d: u8) -> u64 {
    ((a as u64) << 24) | ((b as u64) << 16) | ((c as u64) << 8) | d as u64
}

const TCP: u64 = 6;
const UDP: u64 = 17;
const ICMP: u64 = 1;

/// `enterprise_src` is the rule the change touches.
fn build(enterprise_prefix_len: u32) -> Chain {
    let mut c = Chain::new("input", Hook::Input, Action::Drop);
    let mut line = 0u32;
    let mut push = |c: &mut Chain, m: Match, a: Action, text: &str| {
        line += 1;
        c.push(
            m,
            a,
            Origin { file: "cell-gateway.nft".into(), line, column: 5, text: text.into() },
        );
    };

    push(&mut c, Match::any().with_iif(IfMatch::one("lo")), Action::Accept, "iifname lo accept");
    push(
        &mut c,
        Match::any().with_value(Field::Proto, ICMP).with_prefix(Field::SrcAddr, ip(10, 0, 0, 0), 8),
        Action::Accept,
        "icmp from rfc1918",
    );
    // Management plane.
    push(
        &mut c,
        Match::any()
            .with_value(Field::Proto, TCP)
            .with_prefix(Field::SrcAddr, ip(10, 9, 0, 0), 24)
            .with_prefix(Field::DstAddr, ip(10, 5, 0, 0), 16)
            .with_value(Field::DstPort, 22),
        Action::Accept,
        "mgmt ssh",
    );
    // The rule under edit: enterprise reaching the cell network.
    push(
        &mut c,
        Match::any()
            .with_value(Field::Proto, TCP)
            .with_prefix(Field::SrcAddr, ip(10, 0, 0, 0), enterprise_prefix_len)
            .with_prefix(Field::DstAddr, ip(10, 5, 0, 0), 16),
        Action::Accept,
        "enterprise to cell",
    );
    // Historically dead: rule 4 already accepted all of this.
    push(
        &mut c,
        Match::any()
            .with_value(Field::Proto, TCP)
            .with_prefix(Field::SrcAddr, ip(10, 1, 0, 0), 16)
            .with_prefix(Field::DstAddr, ip(10, 5, 0, 0), 16)
            .with_value(Field::DstPort, 502),
        Action::Drop,
        "no modbus from vlan_corp",
    );
    push(
        &mut c,
        Match::any()
            .with_value(Field::Proto, UDP)
            .with_prefix(Field::DstAddr, ip(10, 5, 0, 0), 16)
            .with_value(Field::DstPort, 161),
        Action::Accept,
        "snmp polling",
    );
    push(
        &mut c,
        Match::any()
            .with_value(Field::Proto, TCP)
            .with_prefix(Field::DstAddr, ip(10, 5, 0, 20), 32)
            .with_value(Field::DstPort, 443),
        Action::Accept,
        "historian https",
    );
    c
}

fn main() {
    let base_chain = build(8);
    let head_chain = build(16);

    let base_rs = Ruleset { label: "9f2c1ab".into(), chains: vec![base_chain.clone()] };
    let head_rs = Ruleset { label: "4e81d33".into(), chains: vec![head_chain.clone()] };
    let syms = shared_symbols(&base_rs, &head_rs).expect("interface names");

    let layout = Layout::new(VarOrder::AddrInterleaved);
    let base = analyse(&layout, &syms, &base_chain);
    let head = analyse(&layout, &syms, &head_chain);

    base.verify(&layout).expect("base model self-check");
    head.verify(&layout).expect("head model self-check");

    let d = diff(&base, &head);
    println!(
        "{}",
        render_diff(
            &layout,
            &syms,
            &base,
            &head,
            &d,
            (&base_rs.label, &head_rs.label),
            &ReportOptions::default(),
        )
    );

    println!("--- what a text diff would have shown ---");
    println!("  -    ip saddr 10.0.0.0/8  ip daddr 10.5.0.0/16 tcp accept");
    println!("  +    ip saddr 10.0.0.0/16 ip daddr 10.5.0.0/16 tcp accept");
    println!("\none line changed. Two rules changed behaviour.");
}
