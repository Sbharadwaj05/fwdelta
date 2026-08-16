//! The supported subset, tested against the table that documents it.
//!
//! Two halves, and the second matters more. The first is that supported syntax
//! parses to the right IR. The second is that *every* unsupported construct
//! fails with a position and a cause — because the failure mode this project
//! cannot have is a rule that was quietly dropped, leaving a model that
//! confidently disagrees with the kernel.

use soteria_ir::{Action, Field, Hook, IfMatch};
use soteria_nft::{Cause, parse};

const GATEWAY: &str = r#"
# Cell gateway, revision under review.
table ip filter {
  chain input {
    type filter hook input priority filter; policy drop;

    iifname "lo" accept
    ip protocol icmp ip saddr 10.0.0.0/8 counter accept comment "diagnostics"

    # management plane
    iifname { "eth0", "eth1" } tcp dport 22 ip saddr 10.9.0.0/24 accept

    # enterprise reaching the cell network
    tcp dport { 443, 8443 } ip saddr 10.0.0.0/8 ip daddr 10.5.0.0/16 accept
    udp dport 161 ip daddr 10.5.0.0/16 log prefix "snmp " accept

    tcp dport 502 ip saddr 10.1.0.0/16 reject with icmp type port-unreachable
    ip saddr 10.0.0.1-10.0.0.50 ip daddr != 10.5.0.20 drop
    iifname != "wg0" ip protocol { tcp, udp } drop
  }
}
"#;

#[test]
fn a_realistic_ruleset_parses_to_the_expected_shape() {
    let rs = parse("gateway.nft", GATEWAY).expect("should parse");
    assert_eq!(rs.chains.len(), 1);
    let c = &rs.chains[0];
    assert_eq!(c.name, "input");
    assert_eq!(c.hook, Hook::Input);
    assert_eq!(c.policy, Action::Drop);
    assert_eq!(c.rules.len(), 8);

    // `iifname "lo" accept`
    assert_eq!(c.rules[0].action, Action::Accept);
    assert_eq!(c.rules[0].matches.iif, IfMatch::one("lo"));

    // `ip protocol icmp ip saddr 10.0.0.0/8` — counter and comment are noise.
    assert_eq!(c.rules[1].matches.packet_dim(Field::Proto).ranges(), &[(1, 1)]);
    assert_eq!(c.rules[1].matches.packet_dim(Field::SrcAddr).count(), 1 << 24);

    // An interface set, and `tcp dport` pinning the protocol implicitly.
    assert_eq!(c.rules[2].matches.iif, IfMatch::OneOf(["eth0".into(), "eth1".into()].into()));
    assert_eq!(c.rules[2].matches.packet_dim(Field::Proto).ranges(), &[(6, 6)]);
    assert_eq!(c.rules[2].matches.packet_dim(Field::DstPort).ranges(), &[(22, 22)]);

    // A port set.
    assert_eq!(c.rules[3].matches.packet_dim(Field::DstPort).ranges(), &[(443, 443), (8443, 8443)]);

    // `reject` is a distinct action that denies like drop.
    assert_eq!(c.rules[5].action, Action::Reject);

    // An address range, and a negated destination.
    assert_eq!(c.rules[6].matches.packet_dim(Field::SrcAddr).count(), 50);
    let dst = c.rules[6].matches.packet_dim(Field::DstAddr);
    assert!(!dst.contains(0x0A05_0014));
    assert_eq!(dst.count(), (1u128 << 32) - 1);

    // A negated interface, and a protocol set.
    assert_eq!(c.rules[7].matches.iif, IfMatch::not_one("wg0"));
    assert_eq!(c.rules[7].matches.packet_dim(Field::Proto).ranges(), &[(6, 6), (17, 17)]);
}

#[test]
fn rules_carry_their_source_position() {
    let rs = parse("gateway.nft", GATEWAY).unwrap();
    let r = &rs.chains[0].rules[0];
    assert_eq!(r.origin.file, "gateway.nft");
    assert_eq!(r.origin.line, 7);
    assert_eq!(r.origin.text, "iifname \"lo\" accept");
    // The quoted line must be the one the position names.
    let line = GATEWAY.lines().nth(r.origin.line as usize - 1).unwrap();
    assert_eq!(line.trim(), r.origin.text);
}

/// Every rejection in one place: the construct, where it should be flagged, and
/// why. If a row here starts passing, the subset table is out of date.
#[test]
fn unsupported_constructs_fail_loudly_with_a_position() {
    let cases: &[(&str, Cause, &str)] = &[
        ("ct state established,related accept", Cause::OutOfScope, "connection tracking"),
        ("iif 3 accept", Cause::OutOfScope, "numeric interface index"),
        ("oif 3 accept", Cause::OutOfScope, "numeric interface index"),
        ("iifname \"eth*\" accept", Cause::Soundness, "wildcard"),
        ("limit rate 10/second accept", Cause::OutOfScope, "not a function of the packet header"),
        ("meta mark 1 accept", Cause::Unimplemented, "meta mark"),
        ("tcp dport ssh accept", Cause::OutOfScope, "service name"),
        ("ip saddr @allowlist accept", Cause::Unimplemented, "named sets"),
        ("jump other_chain", Cause::OutOfScope, "jump"),
        ("goto other_chain", Cause::OutOfScope, "goto"),
        ("return", Cause::OutOfScope, "return"),
        ("queue num 0", Cause::OutOfScope, "queue"),
        ("masquerade", Cause::OutOfScope, "address translation"),
        ("snat to 10.0.0.1", Cause::OutOfScope, "address translation"),
        ("ip saddr 10.0.0.0/8", Cause::OutOfScope, "no verdict"),
        ("ip protocol icmp ip protocol tcp accept", Cause::Soundness, "never match"),
        ("ip frag-off 0 accept", Cause::Unimplemented, "supported subset"),
        // The output-interface dimension has never been differentially
        // validated, so it is rejected rather than shipped on trust.
        ("oifname \"eth0\" accept", Cause::Unimplemented, "not supported yet"),
        ("meta oifname \"eth0\" accept", Cause::Unimplemented, "not supported yet"),
    ];

    for (stmt, want_cause, want_text) in cases {
        let src = format!(
            "table ip filter {{\n  chain input {{\n    type filter hook input priority filter; policy drop;\n    {stmt}\n  }}\n}}\n"
        );
        let err = parse("t.nft", &src)
            .map(|_| ())
            .expect_err(&format!("`{stmt}` should have been rejected"));

        assert_eq!(err.cause, *want_cause, "wrong cause for `{stmt}`: {err}");
        assert_eq!(err.line, 4, "wrong line for `{stmt}`: {err}");
        let text = err.to_string().to_lowercase();
        assert!(
            text.contains(&want_text.to_lowercase()),
            "message for `{stmt}` should mention {want_text:?}, got:\n{err}"
        );
        // Every rejection quotes the offending line.
        assert!(err.snippet.contains(stmt.split_whitespace().next().unwrap()), "{err}");
    }
}

/// Rejecting `oifname` has to say *why*, because "not supported yet" without a
/// reason reads as an oversight rather than a deliberate boundary.
#[test]
fn the_oifname_rejection_explains_that_it_is_unvalidated() {
    let src = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    oifname \"eth0\" accept\n  }\n}";
    let err = parse("t.nft", src).map(|_| ()).unwrap_err();
    let text = err.to_string();
    assert!(text.contains("differential harness"), "{text}");
    assert!(text.contains("output hook"), "{text}");
    assert!(text.contains("never been validated"), "{text}");
}

/// nftables accepts `iifname` on an output chain and then never applies it.
/// Verified against real nft: the rule counts zero packets. Modelling it as a
/// live dimension would disagree with the kernel on every such rule.
#[test]
fn iifname_on_an_output_chain_is_rejected_as_unsound() {
    let src = "table ip filter {\n  chain out {\n    type filter hook output priority filter; policy accept;\n    iifname \"eth0\" accept\n  }\n}";
    let err = parse("t.nft", src).map(|_| ()).unwrap_err();
    assert_eq!(err.cause, Cause::Soundness, "{err}");
    assert!(err.to_string().contains("can never match"), "{err}");

    // The same rule on an input chain is fine.
    let ok = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iifname \"eth0\" accept\n  }\n}";
    assert!(parse("t.nft", ok).is_ok());
}

#[test]
fn structural_constructs_outside_the_subset_are_rejected() {
    let cases: &[(&str, Cause, &str)] = &[
        (
            "table ip6 filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n  }\n}",
            Cause::OutOfScope,
            "ip6",
        ),
        (
            "table ip nat {\n  chain pre {\n    type nat hook prerouting priority filter; policy accept;\n  }\n}",
            Cause::OutOfScope,
            "nat",
        ),
        (
            "table ip filter {\n  chain helper {\n    ip saddr 10.0.0.0/8 accept\n  }\n}",
            Cause::OutOfScope,
            "regular chain",
        ),
        (
            "table ip filter {\n  chain input {\n    type filter hook prerouting priority filter; policy drop;\n  }\n}",
            Cause::OutOfScope,
            "prerouting",
        ),
        ("include \"other.nft\"", Cause::Unimplemented, "include"),
        ("table ip filter {\n  set allowlist { type ipv4_addr; }\n}", Cause::Unimplemented, "set"),
    ];

    for (src, want_cause, want_text) in cases {
        let err = parse("t.nft", src).map(|_| ()).expect_err(&format!("should reject:\n{src}"));
        assert_eq!(err.cause, *want_cause, "for:\n{src}\ngot: {err}");
        assert!(
            err.to_string().to_lowercase().contains(&want_text.to_lowercase()),
            "for:\n{src}\ngot: {err}"
        );
    }
}

/// The SEMANTICS 4.2 obligation, which is what makes the model's treatment of
/// ports on portless protocols sound.
#[test]
fn a_port_match_must_pin_a_protocol_that_has_ports() {
    // nftables itself makes this hard to write, which is the point: `tcp dport`
    // pins tcp. The check exists so that a future frontend construct cannot
    // quietly violate it.
    let ok = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    tcp dport 22 accept\n  }\n}";
    let rs = parse("t.nft", ok).unwrap();
    assert_eq!(rs.chains[0].rules[0].matches.packet_dim(Field::Proto).ranges(), &[(6, 6)]);

    // Pinning icmp and then a tcp port contradicts, and is caught.
    let bad = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    ip protocol icmp tcp dport 22 accept\n  }\n}";
    let err = parse("t.nft", bad).map(|_| ()).unwrap_err();
    assert_eq!(err.cause, Cause::Soundness);
}

#[test]
fn syntax_errors_report_the_column_not_just_the_line() {
    let src = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    ip saddr 10.0.0.300 accept\n  }\n}";
    let err = parse("t.nft", src).map(|_| ()).unwrap_err();
    assert_eq!(err.cause, Cause::Syntax);
    assert_eq!(err.line, 4);
    assert!(err.column > 1, "column should point into the line: {err}");
}

#[test]
fn an_empty_file_is_an_empty_ruleset_not_an_error() {
    let rs = parse("t.nft", "# nothing here\n\n").unwrap();
    assert!(rs.chains.is_empty());
    assert_eq!(rs.rule_count(), 0);
}

#[test]
fn a_chain_without_a_policy_defaults_to_accept() {
    let src = "table ip filter {\n  chain input {\n    type filter hook input priority 0;\n    drop\n  }\n}";
    let rs = parse("t.nft", src).unwrap();
    assert_eq!(rs.chains[0].policy, Action::Accept);
}

#[test]
fn negative_priorities_parse() {
    let src = "table ip filter {\n  chain input {\n    type filter hook input priority -100; policy drop;\n    accept\n  }\n}";
    assert!(parse("t.nft", src).is_ok());
}

#[test]
fn the_counter_syntax_nft_list_emits_is_accepted() {
    // Round-tripping a live ruleset means reading back what `nft list` printed.
    let src = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    tcp dport 22 counter packets 17 bytes 1024 accept\n  }\n}";
    let rs = parse("t.nft", src).unwrap();
    assert_eq!(rs.chains[0].rules[0].action, Action::Accept);
}

#[test]
fn interface_names_parse_quoted_or_bare() {
    let src = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    iifname veth-b accept\n    iifname \"veth-b\" accept\n  }\n}";
    let rs = parse("t.nft", src).unwrap();
    assert_eq!(rs.chains[0].rules[0].matches.iif, rs.chains[0].rules[1].matches.iif);
}
