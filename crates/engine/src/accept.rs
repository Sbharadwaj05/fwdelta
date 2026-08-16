//! Stage 2: first-match evaluation as set algebra.
//!
//! Two linear passes over a chain produce everything the rest of the tool needs.
//!
//! **Forward.** Walking rules in order, accumulate the set matched so far. The
//! packets a rule actually decides are those it matches and nothing earlier did:
//!
//! ```text
//! eff_i    = m_i AND NOT matched_{<i}
//! accept  |= eff_i                      when the rule accepts
//! matched |= m_i
//! ```
//!
//! The `eff_i`, together with the fall-through cell `NOT matched`, are an exact
//! partition of the header space: pairwise disjoint because each excludes
//! everything matched earlier, and total because the fall-through cell is the
//! complement of their union. Every packet therefore has exactly one deciding
//! rule, which is what makes attribution exact rather than best-effort, and what
//! makes shadow detection free — a shadowed rule is one whose `eff_i` is empty.
//!
//! **Backward.** Let `A_i` be the accept set of the rule suffix starting at *i*:
//!
//! ```text
//! A_n = TRUE if the policy accepts else FALSE
//! A_i = m_i OR A_{i+1}              when rule i accepts
//! A_i = (NOT m_i) AND A_{i+1}       when rule i denies
//! ```
//!
//! Deleting rule *i* changes the verdict only inside `eff_i`, and only where the
//! suffix disagrees with the rule. So redundancy — "removing this rule does not
//! change the accept set" — is exact in linear time rather than quadratic:
//!
//! ```text
//! redundant  <=>  eff_i AND NOT A_{i+1}  is empty   (accepting rules)
//! redundant  <=>  eff_i AND A_{i+1}      is empty   (denying rules)
//! ```
//!
//! `A_0` also equals the forward pass's accept set, which the tests assert as a
//! free internal consistency check on both recurrences.

use std::hash::{DefaultHasher, Hash, Hasher};

use biodivine_lib_bdd::Bdd;
use fwdelta_ir::{Action, Chain, Hook, Match, SymbolTable};

use crate::header::Layout;

/// What decides a packet: a rule, or the chain's default policy.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Decider {
    /// Rule number, counted from 1 as the file reads.
    Rule(u32),
    Policy,
}

impl core::fmt::Display for Decider {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Decider::Rule(n) => write!(f, "rule {n:02}"),
            Decider::Policy => f.write_str("the default policy"),
        }
    }
}

/// One rule's contribution to the model.
#[derive(Clone, Debug)]
pub struct RuleModel {
    pub number: u32,
    pub action: Action,
    /// Hash of the predicate and action, used to pair rules across revisions.
    ///
    /// Pairing by position would report every rule after an insertion as
    /// changed. Identity here is what the rule *says*, so an inserted rule shows
    /// up as one addition and its neighbours keep their identity even though
    /// their numbers moved.
    pub content_key: u64,
    /// Packets the predicate admits, ignoring position.
    pub matched: Bdd,
    /// Packets this rule actually decides. Empty exactly when shadowed.
    pub effective: Bdd,
    /// No packet reaches this rule: earlier rules already cover its match set.
    pub shadowed: bool,
    /// Deleting this rule would not change the chain's accept set.
    pub redundant: bool,
}

/// A chain compiled to set algebra.
#[derive(Clone, Debug)]
pub struct ChainModel {
    pub name: String,
    pub hook: Hook,
    pub policy: Action,
    /// The packets this chain permits. The product of the whole stage.
    pub accept: Bdd,
    /// Union of every rule's match set.
    pub matched_any: Bdd,
    /// Packets no rule matches, decided by the policy.
    pub fallthrough: Bdd,
    pub rules: Vec<RuleModel>,
}

impl ChainModel {
    /// Split a packet set by which rule decides each part.
    ///
    /// Returns only non-empty cells, in rule order, with the policy cell last.
    /// Because the cells partition the space, the returned sets are disjoint and
    /// their union is exactly `set`.
    pub fn attribute(&self, set: &Bdd) -> Vec<(Decider, Bdd)> {
        let mut out = Vec::new();
        for r in &self.rules {
            if r.shadowed {
                continue;
            }
            let part = set.and(&r.effective);
            if !part.is_false() {
                out.push((Decider::Rule(r.number), part));
            }
        }
        let part = set.and(&self.fallthrough);
        if !part.is_false() {
            out.push((Decider::Policy, part));
        }
        out
    }

    /// Which earlier rules cover a shadowed rule's match set.
    ///
    /// Computed on demand rather than during analysis: it costs a scan per rule
    /// asked about, and a report only asks about the handful it prints. Prefers
    /// a single covering rule, which is the common and most legible case.
    pub fn explain_shadow(&self, number: u32) -> Vec<u32> {
        let Some(idx) = self.rules.iter().position(|r| r.number == number) else {
            return Vec::new();
        };
        let target = &self.rules[idx].matched;
        if target.is_false() {
            return Vec::new();
        }

        for earlier in &self.rules[..idx] {
            if target.and_not(&earlier.matched).is_false() {
                return vec![earlier.number];
            }
        }

        // No single rule covers it. Report the earliest prefix that does,
        // naming only the rules in that prefix which actually overlap.
        let mut acc = self.vars_false(target);
        let mut contributors = Vec::new();
        for earlier in &self.rules[..idx] {
            if target.and(&earlier.matched).is_false() {
                continue;
            }
            contributors.push(earlier.number);
            acc = acc.or(&earlier.matched);
            if target.and_not(&acc).is_false() {
                break;
            }
        }
        contributors
    }

    fn vars_false(&self, like: &Bdd) -> Bdd {
        // A false BDD over the same variable set as `like`.
        like.and_not(like)
    }

    /// Rules that never decide a packet.
    pub fn shadowed(&self) -> impl Iterator<Item = &RuleModel> {
        self.rules.iter().filter(|r| r.shadowed)
    }

    /// Rules whose removal would not change the accept set. Shadowed rules are
    /// trivially redundant and are excluded, since shadowing is the sharper
    /// finding and reporting both would be noise.
    pub fn redundant(&self) -> impl Iterator<Item = &RuleModel> {
        self.rules.iter().filter(|r| r.redundant && !r.shadowed)
    }

    /// Recompute the accept set the forward way, from the effective sets.
    ///
    /// [`analyse`] takes the accept set from the backward pass, since `A_0` is
    /// exactly it and computing both costs a union per rule for no new
    /// information. This is the other route to the same answer, kept because the
    /// two recurrences are independent derivations and their agreement is a
    /// self-test on the core of the engine.
    pub fn forward_accept(&self, layout: &Layout) -> Bdd {
        let mut acc = layout.ff();
        for r in &self.rules {
            if r.action.permits() {
                acc = acc.or(&r.effective);
            }
        }
        if self.policy.permits() {
            acc = acc.or(&self.fallthrough);
        }
        acc
    }

    /// Both engine self-checks: the partition invariant, and the two
    /// independent derivations of the accept set agreeing.
    ///
    /// Wired to `--verify` rather than run unconditionally, and always run in
    /// the test suite.
    pub fn verify(&self, layout: &Layout) -> Result<(), &'static str> {
        if !self.partition_holds(layout) {
            return Err("effective sets do not partition the header space");
        }
        if self.forward_accept(layout) != self.accept {
            return Err("forward and backward accept sets disagree");
        }
        Ok(())
    }

    /// Check that the effective sets really do partition the header space.
    ///
    /// Exposed rather than hidden in tests because it is cheap relative to the
    /// analysis and is the invariant every downstream claim depends on.
    pub fn partition_holds(&self, layout: &Layout) -> bool {
        let mut union = layout.ff();
        for r in &self.rules {
            if !union.and(&r.effective).is_false() {
                return false;
            }
            union = union.or(&r.effective);
        }
        if !union.and(&self.fallthrough).is_false() {
            return false;
        }
        union.or(&self.fallthrough).is_true()
    }
}

/// Identity of a rule by what it says rather than where it sits.
fn content_key(m: &Match, action: Action) -> u64 {
    let mut h = DefaultHasher::new();
    m.hash(&mut h);
    action.hash(&mut h);
    h.finish()
}

/// Compile a chain into its accept set and per-rule structure.
pub fn analyse(layout: &Layout, syms: &SymbolTable, chain: &Chain) -> ChainModel {
    let mut rules: Vec<RuleModel> = Vec::with_capacity(chain.rules.len());

    // Forward pass: accept set, and the partition that carries attribution.
    let mut matched_any = layout.ff();
    let mut saturated = false;
    for rule in &chain.rules {
        let m = layout.match_bdd(&rule.matches, syms);
        // Once earlier rules cover the whole space nothing later can decide a
        // packet. Short-circuiting is exact, not an approximation: every
        // remaining effective set is empty by definition. The match set is still
        // built, because the backward pass and shadow explanations need it.
        let effective = if saturated { layout.ff() } else { m.and_not(&matched_any) };
        if !saturated {
            matched_any = matched_any.or(&m);
            saturated = matched_any.is_true();
        }
        rules.push(RuleModel {
            number: rule.number,
            action: rule.action,
            content_key: content_key(&rule.matches, rule.action),
            shadowed: effective.is_false(),
            matched: m,
            effective,
            redundant: false,
        });
    }

    let fallthrough = matched_any.not();

    // Backward pass: redundancy against the accept set of each suffix, and the
    // accept set itself, since `A_0` is exactly it. Only the rolling suffix is
    // retained, so this costs no additional storage. Accumulating the accept set
    // forwards as well would cost a union per rule to arrive at the same answer;
    // `ChainModel::forward_accept` does that on demand for `--verify`.
    let mut suffix = if chain.policy.permits() { layout.tt() } else { layout.ff() };
    for r in rules.iter_mut().rev() {
        r.redundant = if r.action.permits() {
            r.effective.and_not(&suffix).is_false()
        } else {
            r.effective.and(&suffix).is_false()
        };
        suffix =
            if r.action.permits() { r.matched.or(&suffix) } else { r.matched.not().and(&suffix) };
    }

    ChainModel {
        name: chain.name.clone(),
        hook: chain.hook,
        policy: chain.policy,
        accept: suffix,
        matched_any,
        fallthrough,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fwdelta_ir::{Field, IfMatch, Match, Origin};

    const TCP: u64 = 6;

    fn chain_of(policy: Action, rules: Vec<(Match, Action)>) -> Chain {
        let mut c = Chain::new("input", Hook::Input, policy);
        for (m, a) in rules {
            c.push(m, a, Origin::default());
        }
        c
    }

    fn setup() -> (Layout, SymbolTable) {
        (Layout::default(), SymbolTable::from_names(["eth0", "eth1"]).unwrap())
    }

    #[test]
    fn an_empty_chain_is_its_policy() {
        let (l, s) = setup();
        let open = analyse(&l, &s, &chain_of(Action::Accept, vec![]));
        assert!(open.accept.is_true());
        let shut = analyse(&l, &s, &chain_of(Action::Drop, vec![]));
        assert!(shut.accept.is_false());
    }

    #[test]
    fn first_match_wins() {
        let (l, s) = setup();
        // Accept ssh, then drop the whole subnet. First match means ssh survives.
        let c = chain_of(
            Action::Drop,
            vec![
                (
                    Match::any().with_value(Field::Proto, TCP).with_value(Field::DstPort, 22),
                    Action::Accept,
                ),
                (Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Drop),
            ],
        );
        let m = analyse(&l, &s, &c);
        let ssh = l.eq(Field::Proto, TCP).and(&l.eq(Field::DstPort, 22));
        assert!(ssh.and_not(&m.accept).is_false(), "ssh must survive the later drop");
    }

    #[test]
    fn order_matters_and_the_model_sees_it() {
        let (l, s) = setup();
        let ssh = (
            Match::any().with_value(Field::Proto, TCP).with_value(Field::DstPort, 22),
            Action::Accept,
        );
        let deny = (Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Drop);

        let permissive = analyse(&l, &s, &chain_of(Action::Drop, vec![ssh.clone(), deny.clone()]));
        let strict = analyse(&l, &s, &chain_of(Action::Drop, vec![deny, ssh]));
        assert_ne!(permissive.accept, strict.accept);
        // Reordering only ever removes access here, never adds it.
        assert!(strict.accept.and_not(&permissive.accept).is_false());
    }

    #[test]
    fn the_effective_sets_partition_the_space() {
        let (l, s) = setup();
        let c = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_iif(IfMatch::one("eth0")), Action::Accept),
                (Match::any().with_value(Field::Proto, TCP), Action::Accept),
                (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 8), Action::Drop),
            ],
        );
        assert!(analyse(&l, &s, &c).partition_holds(&l));
    }

    /// The accept set comes from the backward pass. This checks it against the
    /// forward derivation, which is an independent route to the same set.
    #[test]
    fn the_two_derivations_of_the_accept_set_agree() {
        let (l, s) = setup();
        for policy in [Action::Accept, Action::Drop] {
            // A chain with every action kind and overlapping matches.
            let c = chain_of(
                policy,
                vec![
                    (Match::any().with_value(Field::DstPort, 22), Action::Accept),
                    (Match::any().with_prefix(Field::SrcAddr, 0x0A01_0000, 16), Action::Drop),
                    (Match::any().with_value(Field::Proto, TCP), Action::Reject),
                    (Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Accept),
                    (Match::any().with_iif(IfMatch::one("eth1")), Action::Accept),
                ],
            );
            let m = analyse(&l, &s, &c);
            assert_eq!(m.forward_accept(&l), m.accept, "policy {policy}");
            assert_eq!(m.verify(&l), Ok(()), "policy {policy}");
        }
    }

    /// The self-check has to be capable of failing, or it checks nothing.
    #[test]
    fn verify_rejects_a_corrupted_model() {
        let (l, s) = setup();
        let c = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_value(Field::DstPort, 22), Action::Accept),
                (Match::any().with_value(Field::Proto, TCP), Action::Accept),
            ],
        );
        let mut m = analyse(&l, &s, &c);
        assert_eq!(m.verify(&l), Ok(()));

        // Widen the accept set behind the effective sets' back.
        m.accept = m.accept.or(&l.eq(Field::DstPort, 9999));
        assert!(m.verify(&l).is_err());
    }

    #[test]
    fn a_fully_covered_rule_is_shadowed_and_explained() {
        let (l, s) = setup();
        let c = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_prefix(Field::DstAddr, 0x0A05_0000, 16), Action::Accept),
                (Match::any().with_value(Field::Proto, TCP), Action::Accept),
                // Strictly inside rule 1's match set: unreachable.
                (Match::any().with_prefix(Field::DstAddr, 0x0A05_0300, 24), Action::Drop),
            ],
        );
        let m = analyse(&l, &s, &c);
        assert!(!m.rules[0].shadowed);
        assert!(m.rules[2].shadowed);
        assert_eq!(m.explain_shadow(3), vec![1]);
    }

    #[test]
    fn shadowing_can_need_several_rules_to_explain() {
        let (l, s) = setup();
        // Neither rule 1 nor rule 2 covers rule 3 alone; together they do.
        let c = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_range(Field::DstPort, 0, 1000), Action::Accept),
                (Match::any().with_range(Field::DstPort, 1001, 65535), Action::Accept),
                (Match::any().with_value(Field::Proto, TCP), Action::Drop),
            ],
        );
        let m = analyse(&l, &s, &c);
        assert!(m.rules[2].shadowed);
        assert_eq!(m.explain_shadow(3), vec![1, 2]);
    }

    #[test]
    fn a_redundant_rule_agrees_with_what_follows_it() {
        let (l, s) = setup();
        // Rule 1 drops ssh; the policy drops everything anyway. Removing rule 1
        // changes nothing, and it is not shadowed, so it is genuinely redundant.
        let c = chain_of(
            Action::Drop,
            vec![(Match::any().with_value(Field::DstPort, 22), Action::Drop)],
        );
        let m = analyse(&l, &s, &c);
        assert!(!m.rules[0].shadowed);
        assert!(m.rules[0].redundant);
    }

    #[test]
    fn a_load_bearing_rule_is_not_redundant() {
        let (l, s) = setup();
        // Same shape, opposite verdict: this rule is the only thing letting
        // anything through, so removing it would change the accept set.
        let c = chain_of(
            Action::Drop,
            vec![(Match::any().with_value(Field::DstPort, 22), Action::Accept)],
        );
        let m = analyse(&l, &s, &c);
        assert!(!m.rules[0].redundant);
    }

    #[test]
    fn attribution_covers_the_set_exactly_once() {
        let (l, s) = setup();
        let c = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_value(Field::DstPort, 22), Action::Accept),
                (Match::any().with_value(Field::DstPort, 443), Action::Accept),
                (Match::any().with_value(Field::Proto, TCP), Action::Accept),
            ],
        );
        let m = analyse(&l, &s, &c);
        let parts = m.attribute(&m.accept);
        assert_eq!(parts.len(), 3);

        let mut union = l.ff();
        for (_, part) in &parts {
            assert!(union.and(part).is_false(), "attribution cells overlap");
            union = union.or(part);
        }
        assert_eq!(union, m.accept);
    }

    #[test]
    fn the_policy_cell_is_attributed_too() {
        let (l, s) = setup();
        let c = chain_of(
            Action::Accept,
            vec![(Match::any().with_value(Field::DstPort, 22), Action::Drop)],
        );
        let m = analyse(&l, &s, &c);
        let parts = m.attribute(&m.accept);
        assert_eq!(parts.len(), 1);
        assert_eq!(parts[0].0, Decider::Policy);
    }

    #[test]
    fn reject_denies_exactly_as_drop_does() {
        let (l, s) = setup();
        let with_drop = analyse(
            &l,
            &s,
            &chain_of(
                Action::Accept,
                vec![(Match::any().with_value(Field::DstPort, 22), Action::Drop)],
            ),
        );
        let with_reject = analyse(
            &l,
            &s,
            &chain_of(
                Action::Accept,
                vec![(Match::any().with_value(Field::DstPort, 22), Action::Reject)],
            ),
        );
        assert_eq!(with_drop.accept, with_reject.accept);
    }
}
