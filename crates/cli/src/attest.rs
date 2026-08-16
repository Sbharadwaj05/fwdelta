//! The in-toto attestation.
//!
//! **Unsigned, by design.** Decision D-09: signing means a crypto dependency
//! and, more importantly, key custody. A tool whose whole claim is that it
//! connects to nothing and writes nothing has no business holding a private
//! key. The predicate is a complete, deterministic input to whatever signing
//! the organisation already runs, not a substitute for it.
//!
//! # Why the boundaries are in the predicate
//!
//! An attestation that carries only a verdict overstates itself in the same way
//! an unqualified `PASS` does. An auditor reading `"result": "pass"` six months
//! from now cannot tell whether NAT was considered, whether the analysis was
//! stateful, or whether it covered one host or a network — and every one of
//! those changes what the evidence is worth.
//!
//! So the predicate carries `modelBoundaries` alongside the results: what was
//! checked, under which approximations, and explicitly what the run does *not*
//! establish. It is the same list the README publishes, emitted as data so it
//! travels with the evidence rather than living in documentation the auditor
//! may never see.

use soteria_policy::{Kind, Outcome, Report};

use crate::json::Json;
use crate::sha256;

pub const PREDICATE_TYPE: &str = "https://soteria.tools/attestation/policy-diff/v1";
pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";

/// One analysed input.
pub struct Input {
    pub role: &'static str,
    pub label: String,
    pub text: String,
}

impl Input {
    fn to_json(&self) -> Json {
        Json::obj([
            ("role", Json::str(self.role)),
            ("name", Json::str(&self.label)),
            ("digest", Json::obj([("sha256", Json::str(sha256::hex_digest(&self.text)))])),
        ])
    }
}

/// What the model approximates, and what a passing run therefore does not say.
///
/// Emitted as data so an auditor reading the predicate sees the limits without
/// having to find the documentation.
fn model_boundaries() -> Json {
    Json::obj([
        ("headerBits", Json::Num(u64::from(soteria_engine::HEADER_BITS))),
        (
            "dimensions",
            Json::arr(
                [
                    "srcAddr",
                    "dstAddr",
                    "srcPort",
                    "dstPort",
                    "protocol",
                    "inputInterface",
                    "outputInterface",
                ]
                .into_iter()
                .map(Json::str),
            ),
        ),
        (
            "approximations",
            Json::obj([
                (
                    "statefulness",
                    Json::str(
                        "stateless. New connections in the forward direction are governed by the \
                         ruleset; return traffic for permitted connections is assumed permitted. \
                         Rulesets whose security depends on connection tracking are rejected at \
                         parse time rather than approximated.",
                    ),
                ),
                (
                    "nat",
                    Json::str(
                        "not modelled. Address translation changes packet identity in transit; a \
                         ruleset containing NAT is rejected rather than analysed with NAT ignored.",
                    ),
                ),
                (
                    "scope",
                    Json::str(
                        "one host's filter table. Not end-to-end reachability, which also depends \
                         on routing and on other devices.",
                    ),
                ),
                (
                    "addressFamily",
                    Json::str("IPv4 only. The header layout is 32-bit; IPv6 is not analysed."),
                ),
                (
                    "portsOnPortlessProtocols",
                    Json::str(
                        "every packet is given source and destination ports, including ICMP. Sound \
                         only because the frontend requires a port match to pin a protocol that \
                         has ports.",
                    ),
                ),
                (
                    "frontendSubset",
                    Json::str(
                        "a documented subset of nftables. Every construct outside it is a hard \
                         error, so no rule was silently skipped.",
                    ),
                ),
            ]),
        ),
        (
            "establishes",
            Json::str(
                "the modelled ruleset permits exactly the packet set computed, under the model \
                 above, and satisfies the assertions reported as PASS.",
            ),
        ),
        (
            "doesNotEstablish",
            Json::arr(
                [
                    "that the assertions are the right assertions",
                    "that the device implements nftables faithfully",
                    "that the configuration deployed is the configuration analysed",
                    "anything about NAT, routing, or other devices",
                    "anything about assertions reported as VACUOUS, which held trivially",
                ]
                .into_iter()
                .map(Json::str),
            ),
        ),
    ])
}

fn assertion_json(r: &Report) -> Json {
    let mut fields = vec![
        ("name".to_string(), Json::str(&r.name)),
        (
            "kind".to_string(),
            Json::str(match r.kind {
                Kind::Isolation => "isolation",
                Kind::Reachability => "reachability",
            }),
        ),
        ("chain".to_string(), Json::str(&r.chain)),
        ("claim".to_string(), Json::str(&r.summary)),
        ("outcome".to_string(), Json::str(r.outcome.label())),
    ];
    match &r.outcome {
        Outcome::Fail { counterexample } => {
            fields.push((
                "counterexample".to_string(),
                Json::obj([
                    ("src", Json::str(ipv4(counterexample.src))),
                    ("dst", Json::str(ipv4(counterexample.dst))),
                    ("srcPort", Json::Num(u64::from(counterexample.sport))),
                    ("dstPort", Json::Num(u64::from(counterexample.dport))),
                    ("protocol", Json::Num(u64::from(counterexample.proto))),
                ]),
            ));
        }
        Outcome::Vacuous { reason } => {
            fields.push(("vacuousBecause".to_string(), Json::str(reason)));
        }
        Outcome::Pass => {}
    }
    Json::Obj(fields)
}

fn ipv4(v: u32) -> String {
    format!("{}.{}.{}.{}", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

/// Build the statement. `commit` is whatever revision the caller was analysing,
/// when it knows.
pub fn statement(
    inputs: &[Input],
    assertions: &[Report],
    delta: Json,
    commit: Option<&str>,
) -> Json {
    let subject: Vec<Json> = inputs
        .iter()
        .filter(|i| i.role == "head")
        .map(|i| {
            Json::obj([
                ("name", Json::str(&i.label)),
                ("digest", Json::obj([("sha256", Json::str(sha256::hex_digest(&i.text)))])),
            ])
        })
        .collect();

    let failed = assertions.iter().filter(|a| matches!(a.outcome, Outcome::Fail { .. })).count();
    let vacuous =
        assertions.iter().filter(|a| matches!(a.outcome, Outcome::Vacuous { .. })).count();
    let passed = assertions.iter().filter(|a| a.outcome.is_pass()).count();

    let mut predicate = vec![
        (
            "tool".to_string(),
            Json::obj([
                ("name", Json::str("soteria")),
                ("version", Json::str(env!("CARGO_PKG_VERSION"))),
            ]),
        ),
        ("inputs".to_string(), Json::arr(inputs.iter().map(Input::to_json))),
        ("modelBoundaries".to_string(), model_boundaries()),
        ("delta".to_string(), delta),
        ("assertions".to_string(), Json::arr(assertions.iter().map(assertion_json))),
        (
            "summary".to_string(),
            Json::obj([
                ("checked", Json::Num(assertions.len() as u64)),
                ("passed", Json::Num(passed as u64)),
                ("failed", Json::Num(failed as u64)),
                // Surfaced at the top level rather than buried in the list: a
                // vacuous assertion is not a pass, and a summary that folded it
                // into one would repeat the mistake the outcome exists to stop.
                ("vacuous", Json::Num(vacuous as u64)),
            ]),
        ),
        (
            "signing".to_string(),
            Json::str(
                "this predicate is unsigned by design; sign it detached with your own tooling. \
                 Soteria holds no key material.",
            ),
        ),
    ];
    if let Some(c) = commit {
        predicate.insert(2, ("commit".to_string(), Json::str(c)));
    }

    Json::obj([
        ("_type", Json::str(STATEMENT_TYPE)),
        ("subject", Json::Arr(subject)),
        ("predicateType", Json::str(PREDICATE_TYPE)),
        ("predicate", Json::Obj(predicate)),
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> Vec<Input> {
        vec![
            Input { role: "base", label: "base.nft".into(), text: "a".into() },
            Input { role: "head", label: "head.nft".into(), text: "b".into() },
        ]
    }

    #[test]
    fn the_subject_is_the_head_ruleset_with_its_digest() {
        let s = statement(&inputs(), &[], Json::Obj(vec![]), None).render();
        assert!(s.contains("\"head.nft\""));
        assert!(!s.contains("\"subject\": []"));
        // sha256("b")
        assert!(
            s.contains("3e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d"),
            "{s}"
        );
    }

    #[test]
    fn both_inputs_are_recorded_with_digests() {
        let s = statement(&inputs(), &[], Json::Obj(vec![]), None).render();
        assert!(s.contains("\"role\": \"base\""));
        assert!(s.contains("\"role\": \"head\""));
        // sha256("a")
        assert!(s.contains("ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb"));
    }

    /// The requirement: an auditor must be able to see what the check did not
    /// cover, without leaving the document.
    #[test]
    fn the_predicate_states_what_it_does_not_establish() {
        let s = statement(&inputs(), &[], Json::Obj(vec![]), None).render();
        for expected in [
            "modelBoundaries",
            "stateless",
            "not modelled",
            "IPv4 only",
            "doesNotEstablish",
            "the configuration deployed is the configuration analysed",
            "one host's filter table",
        ] {
            assert!(s.contains(expected), "predicate is missing {expected:?}:\n{s}");
        }
    }

    #[test]
    fn it_says_it_is_unsigned() {
        let s = statement(&inputs(), &[], Json::Obj(vec![]), None).render();
        assert!(s.contains("unsigned by design"));
        assert!(s.contains("holds no key material"));
    }

    #[test]
    fn vacuous_assertions_are_counted_separately_from_passes() {
        let reports = vec![
            Report {
                name: "a".into(),
                kind: Kind::Isolation,
                summary: "x".into(),
                chain: "input".into(),
                outcome: Outcome::Pass,
            },
            Report {
                name: "b".into(),
                kind: Kind::Isolation,
                summary: "y".into(),
                chain: "input".into(),
                outcome: Outcome::Vacuous { reason: "nothing matches".into() },
            },
        ];
        let s = statement(&inputs(), &reports, Json::Obj(vec![]), None).render();
        assert!(s.contains("\"passed\": 1"), "{s}");
        assert!(s.contains("\"vacuous\": 1"), "{s}");
        assert!(s.contains("\"outcome\": \"VACUOUS\""), "{s}");
        assert!(s.contains("vacuousBecause"), "{s}");
    }

    #[test]
    fn the_statement_type_is_in_toto_v1() {
        let s = statement(&inputs(), &[], Json::Obj(vec![]), None).render();
        assert!(s.contains("https://in-toto.io/Statement/v1"));
        assert!(s.contains(PREDICATE_TYPE));
    }
}
