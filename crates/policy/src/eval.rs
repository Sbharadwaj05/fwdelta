//! Checking assertions against the model.
//!
//! Both kinds reduce to the same set algebra:
//!
//! * **isolation** — `assertion ∩ accept` must be empty.
//! * **reachability** — `assertion \ accept` must be empty.
//!
//! Failure returns a counterexample packet extracted from whichever set was
//! supposed to be empty and was not.
//!
//! # Vacuity
//!
//! A third outcome exists because two of them are not enough. An isolation
//! assertion whose packet set is empty passes, and so does one over addresses
//! no rule in either revision mentions. Both are green results that establish
//! nothing, and both happen from a single typo. Reporting them as `PASS` is the
//! policy-file equivalent of a frontend silently skipping a rule: the run stays
//! green and the check that was meant to catch the problem is the thing that
//! failed.

use biodivine_lib_bdd::Bdd;
use soteria_engine::packet::{Packet, witness};
use soteria_engine::{ChainModel, Field, IntervalSet, Layout};
use soteria_ir::{Match, Ruleset, SymbolTable};

use crate::parse::{Assertion, Endpoint, Kind, Policy, PolicyError};

/// What checking an assertion established.
#[derive(Clone, Debug)]
pub enum Outcome {
    /// The property holds over a non-empty set of packets.
    Pass,
    /// The property does not hold, and here is a packet that breaks it.
    Fail { counterexample: Packet },
    /// The property holds trivially, so the check established nothing.
    Vacuous { reason: String },
}

impl Outcome {
    pub fn label(&self) -> &'static str {
        match self {
            Outcome::Pass => "PASS",
            Outcome::Fail { .. } => "FAIL",
            Outcome::Vacuous { .. } => "VACUOUS",
        }
    }

    pub fn is_pass(&self) -> bool {
        matches!(self, Outcome::Pass)
    }
}

/// One assertion's result.
#[derive(Clone, Debug)]
pub struct Report {
    pub name: String,
    pub kind: Kind,
    pub summary: String,
    pub outcome: Outcome,
    /// Chain the assertion was checked against.
    pub chain: String,
}

/// Addresses any rule in either revision actually talks about.
///
/// Used only to detect vacuity. A rule that leaves an address dimension
/// unconstrained says nothing about any particular address, so it does not
/// count: including it would make every zone appear mentioned and the check
/// useless.
pub struct Mentioned {
    addresses: IntervalSet,
}

impl Mentioned {
    pub fn of(rulesets: &[&Ruleset]) -> Self {
        let mut addresses = IntervalSet::empty(32);
        for rs in rulesets {
            for chain in &rs.chains {
                for rule in &chain.rules {
                    for f in [Field::SrcAddr, Field::DstAddr] {
                        let set = rule.matches.packet_dim(f);
                        if !set.is_full() {
                            addresses = addresses.union(set);
                        }
                    }
                }
            }
        }
        Self { addresses }
    }

    fn covers(&self, set: &IntervalSet) -> bool {
        !self.addresses.intersect(set).is_empty()
    }
}

/// Compile an assertion into the packet set it describes.
fn assertion_set(
    layout: &Layout,
    syms: &SymbolTable,
    policy: &Policy,
    a: &Assertion,
) -> Result<Bdd, PolicyError> {
    let mut m = Match::any();
    if let Some(e) = &a.from {
        m = m.constrain(Field::SrcAddr, &policy.resolve(e)?);
    }
    if let Some(e) = &a.to {
        m = m.constrain(Field::DstAddr, &policy.resolve(e)?);
    }
    if let Some(p) = &a.proto {
        m = m.constrain(Field::Proto, p);
    }
    if let Some(p) = &a.sport {
        m = m.constrain(Field::SrcPort, p);
    }
    if let Some(p) = &a.dport {
        m = m.constrain(Field::DstPort, p);
    }
    m = m.with_iif(a.iif_match()).with_oif(a.oif_match());
    Ok(layout.match_bdd(&m, syms))
}

/// Check one assertion against one chain's accept set.
pub fn check(
    layout: &Layout,
    syms: &SymbolTable,
    policy: &Policy,
    model: &ChainModel,
    mentioned: &Mentioned,
    a: &Assertion,
) -> Result<Report, PolicyError> {
    let set = assertion_set(layout, syms, policy, a)?;

    let outcome = if set.is_false() {
        // Contradictory constraints, or an interface name that resolved to
        // nothing. Either way the assertion covers no packet at all.
        Outcome::Vacuous {
            reason: "the assertion describes no packet; its constraints contradict each other"
                .to_string(),
        }
    } else if set.and(&model.matched_any).is_false() {
        // No rule in the chain matches any packet the assertion describes, so
        // the verdict comes entirely from the default policy and the assertion
        // says nothing about the rules. This is the precise version of the
        // typo case: a slipped digit in a zone moves the assertion onto
        // addresses the ruleset never decides, and the check goes green.
        //
        // Note what this is *not*: "the zone is not mentioned by name". A rule
        // reading `ip daddr 10.5.0.0/16 accept` decides traffic from every
        // source without naming any of them, and an assertion about those
        // sources is perfectly meaningful. Testing for mention rather than for
        // match reported those as vacuous, which is why it is tested for match.
        let mut reason = format!(
            "no rule in chain `{}` matches any packet this assertion describes, \
             so the result comes from the default policy rather than from the rules",
            model.name
        );
        if let Some(hint) = unmentioned_endpoint(policy, a, mentioned)? {
            reason.push_str(&format!(". {hint}"));
        }
        Outcome::Vacuous { reason }
    } else {
        let offending = match a.kind {
            Kind::Isolation => set.and(&model.accept),
            Kind::Reachability => set.and_not(&model.accept),
        };
        match witness(layout, &offending) {
            Some(counterexample) => Outcome::Fail { counterexample },
            None => Outcome::Pass,
        }
    };

    Ok(Report {
        name: a.name.clone(),
        kind: a.kind,
        summary: a.summary.clone(),
        outcome,
        chain: model.name.clone(),
    })
}

/// A diagnostic hint, not the vacuity test itself.
///
/// Once an assertion is known to be vacuous, naming an endpoint whose addresses
/// appear nowhere in either revision is usually enough to spot the typo that
/// caused it.
fn unmentioned_endpoint(
    policy: &Policy,
    a: &Assertion,
    mentioned: &Mentioned,
) -> Result<Option<String>, PolicyError> {
    // Every unmentioned endpoint, not just the first: when both ends are
    // unmentioned, naming only one sends the reader to the wrong line.
    let mut found = Vec::new();
    for (side, e) in [("from", a.from.as_ref()), ("to", a.to.as_ref())] {
        let Some(e) = e else { continue };
        if mentioned.covers(&policy.resolve(e)?) {
            continue;
        }
        found.push(match e {
            Endpoint::Zone(n) => format!("{side} zone `{n}`"),
            Endpoint::Literal(n) => format!("{side} `{n}`"),
        });
    }
    if found.is_empty() {
        return Ok(None);
    }
    Ok(Some(format!(
        "No address in {} appears anywhere in either revision, \
         which usually means a typo in the zone definition",
        found.join(" or ")
    )))
}

/// Check every assertion against every chain it applies to.
pub fn evaluate(
    layout: &Layout,
    syms: &SymbolTable,
    policy: &Policy,
    models: &[ChainModel],
    mentioned: &Mentioned,
) -> Result<Vec<Report>, PolicyError> {
    let mut out = Vec::new();
    for a in &policy.assertions {
        let targets: Vec<&ChainModel> = match &a.chain {
            Some(name) => models.iter().filter(|m| &m.name == name).collect(),
            None => models.iter().collect(),
        };
        if targets.is_empty() {
            let named = a.chain.clone().unwrap_or_default();
            return Err(PolicyError::new(format!("no chain named `{named}`"))
                .at(format!("assertion `{}`", a.name)));
        }
        for model in targets {
            out.push(check(layout, syms, policy, model, mentioned, a)?);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_engine::{VarOrder, analyse};
    use soteria_ir::{Action, Chain, Hook, Origin};

    fn ruleset(rules: Vec<(Match, Action)>, policy: Action) -> Ruleset {
        let mut c = Chain::new("input", Hook::Input, policy);
        for (m, a) in rules {
            c.push(m, a, Origin::default());
        }
        Ruleset { label: "t".into(), chains: vec![c] }
    }

    fn setup(rs: &Ruleset, doc: &str) -> (Layout, SymbolTable, Policy, ChainModel, Mentioned) {
        let policy = crate::parse::parse(doc).expect("policy parses");
        let layout = Layout::new(VarOrder::AddrInterleaved);
        let syms = SymbolTable::from_names(
            rs.interface_names().chain(policy.interface_names()).map(str::to_string),
        )
        .unwrap();
        let model = analyse(&layout, &syms, &rs.chains[0]);
        let mentioned = Mentioned::of(&[rs]);
        (layout, syms, policy, model, mentioned)
    }

    const ZONES: &str = "[zones]\nvlan_corp = [\"10.1.0.0/16\"]\nvlan_ot = [\"10.5.0.0/16\"]\n";

    #[test]
    fn isolation_holds_when_the_traffic_is_denied() {
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Drop)],
            Action::Accept,
        );
        let doc = format!(
            "{ZONES}\n[[assert]]\nname=\"iso\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\nproto=\"tcp\"\ndport=502\n"
        );
        let (l, s, p, m, mm) = setup(&rs, &doc);
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();
        assert!(r.outcome.is_pass(), "{:?}", r.outcome);
    }

    #[test]
    fn isolation_fails_with_a_counterexample_inside_the_assertion() {
        let rs = ruleset(vec![(Match::any(), Action::Accept)], Action::Accept);
        let doc = format!(
            "{ZONES}\n[[assert]]\nname=\"iso\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\nproto=\"tcp\"\ndport=502\n"
        );
        let (l, s, p, m, mm) = setup(&rs, &doc);
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();
        let Outcome::Fail { counterexample } = r.outcome else {
            panic!("expected a failure, got {:?}", r.outcome);
        };
        // The counterexample must satisfy the assertion it disproves.
        assert_eq!(counterexample.src >> 16, 0x0A01);
        assert_eq!(counterexample.dst >> 16, 0x0A05);
        assert_eq!(counterexample.dport, 502);
        assert_eq!(counterexample.proto, 6);
    }

    #[test]
    fn reachability_fails_when_the_path_is_closed() {
        let doc = format!(
            "{ZONES}\n[[assert]]\nname=\"reach\"\nkind=\"reachability\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\nproto=\"tcp\"\ndport=22\n"
        );
        // The rule has to mention the zone's addresses, or the result would be
        // vacuous rather than a genuine failure.
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Drop)],
            Action::Drop,
        );
        let (l, s, p, m, mm) = setup(&rs, &doc);
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();
        assert!(matches!(r.outcome, Outcome::Fail { .. }), "{:?}", r.outcome);
    }

    /// The requirement: a typo'd zone must not read as a green isolation check.
    #[test]
    fn an_assertion_over_addresses_no_rule_mentions_is_vacuous_not_passing() {
        // The ruleset talks about 10.5/16. The zone says 10.50/16 -- a slipped
        // digit -- so the isolation check would pass no matter what the rules do.
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Accept)],
            Action::Drop,
        );
        let doc = "[zones]\nvlan_corp = [\"10.1.0.0/16\"]\nvlan_ot = [\"10.50.0.0/16\"]\n\n[[assert]]\nname=\"iso\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\n";
        let (l, s, p, m, mm) = setup(&rs, doc);
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();

        match &r.outcome {
            Outcome::Vacuous { reason } => {
                assert!(reason.contains("no rule in chain `input` matches"), "{reason}");
                // And the hint should point at the slipped digit.
                assert!(reason.contains("vlan_ot"), "{reason}");
                assert!(reason.contains("typo"), "{reason}");
            }
            other => panic!("a typo'd zone must not pass: {other:?}"),
        }
        assert!(!r.outcome.is_pass());
    }

    /// The corrected zone must produce a real result, or the test above could
    /// be satisfied by calling everything vacuous.
    #[test]
    fn the_same_assertion_with_the_right_zone_is_not_vacuous() {
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Accept)],
            Action::Drop,
        );
        let doc = "[zones]\nvlan_corp = [\"10.1.0.0/16\"]\nvlan_ot = [\"10.5.0.0/16\"]\n\n[[assert]]\nname=\"iso\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\n";
        let (l, s, p, m, mm) = setup(&rs, doc);
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();
        assert!(matches!(r.outcome, Outcome::Fail { .. }), "{:?}", r.outcome);
    }

    #[test]
    fn a_contradictory_assertion_is_vacuous() {
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Accept)],
            Action::Drop,
        );
        // An interface name absent from the symbol table resolves to the empty
        // set, so the assertion describes no packet at all.
        let doc = "[zones]\nz = [\"10.5.0.0/16\"]\n\n[[assert]]\nname=\"x\"\nkind=\"isolation\"\nto=\"z\"\niif=\"nonexistent0\"\n";
        let policy = crate::parse::parse(doc).unwrap();
        let layout = Layout::new(VarOrder::AddrInterleaved);
        // Deliberately omit the assertion's interface from the table.
        let syms = SymbolTable::from_names(["eth0"]).unwrap();
        let model = analyse(&layout, &syms, &rs.chains[0]);
        let mentioned = Mentioned::of(&[&rs]);
        let r = check(&layout, &syms, &policy, &model, &mentioned, &policy.assertions[0]).unwrap();
        assert!(matches!(r.outcome, Outcome::Vacuous { .. }), "{:?}", r.outcome);
    }

    #[test]
    fn unconstrained_dimensions_do_not_count_as_mentioning_an_address() {
        // A totally unconstrained rule names no address, so it cannot be used
        // as evidence that a zone was mentioned.
        let rs = ruleset(vec![(Match::any(), Action::Accept)], Action::Drop);
        let m = Mentioned::of(&[&rs]);
        assert!(!m.covers(&IntervalSet::prefix(32, 0x0A05_0000, 16)));
    }

    /// Vacuity is about whether a rule *matches* the assertion's packets, not
    /// whether a rule *names* its addresses. A rule that accepts all traffic to
    /// a subnet decides traffic from every source without naming one, and an
    /// assertion about those sources is meaningful.
    #[test]
    fn a_rule_that_names_no_source_still_decides_source_assertions() {
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Accept)],
            Action::Drop,
        );
        let doc = "[zones]\nvlan_corp = [\"10.1.0.0/16\"]\nvlan_ot = [\"10.5.0.0/16\"]\n\n[[assert]]\nname=\"iso\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\n";
        let (l, s, p, m, mm) = setup(&rs, doc);
        // 10.1.0.0/16 is named by no rule, yet the assertion is decided.
        assert!(!mm.covers(&p.zones["vlan_corp"]));
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();
        assert!(matches!(r.outcome, Outcome::Fail { .. }), "{:?}", r.outcome);
    }

    /// An assertion resting entirely on the default policy is reported as such,
    /// because "your isolation holds because nothing opened it" is a different
    /// fact from "a rule enforces your isolation".
    #[test]
    fn an_assertion_decided_only_by_the_policy_is_vacuous() {
        let rs = ruleset(
            vec![(Match::any().with_prefix(Field::DstAddr, 0x0A09_0000, 16), Action::Accept)],
            Action::Drop,
        );
        let doc = "[zones]\nvlan_ot = [\"10.5.0.0/16\"]\n\n[[assert]]\nname=\"iso\"\nkind=\"isolation\"\nto=\"vlan_ot\"\n";
        let (l, s, p, m, mm) = setup(&rs, doc);
        let r = check(&l, &s, &p, &m, &mm, &p.assertions[0]).unwrap();
        match &r.outcome {
            Outcome::Vacuous { reason } => {
                assert!(reason.contains("default policy"), "{reason}")
            }
            other => panic!("expected vacuous, got {other:?}"),
        }
    }
}
