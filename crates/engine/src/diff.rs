//! Stage 3: the behavioural delta between two revisions.
//!
//! The whole analytical contribution of the tool is two expressions:
//!
//! ```text
//! newly_allowed = head_accept AND NOT base_accept
//! newly_blocked = base_accept AND NOT head_accept
//! ```
//!
//! Each is a complete and exact set rather than a witness. That is why the
//! representation is a decision diagram and not an SMT solver: a solver returns
//! one satisfying packet and leaves enumerating the rest as an exercise, and the
//! full answer is the product here.
//!
//! Everything else in this module exists to make those two sets legible:
//! attributing each part of a delta to the rule responsible on both sides, and
//! reporting which rules changed reachability status.

use std::collections::HashMap;

use biodivine_lib_bdd::Bdd;

use crate::accept::{ChainModel, Decider};

/// A slice of a delta, with the rule responsible on each side.
///
/// `was` comes from the base ruleset's partition and `now` from the head's, so a
/// finding reads "was allowed by rule 14, now denied by rule 22" without either
/// half being guesswork. Both are exact: the effective sets partition the header
/// space, so every packet has exactly one deciding rule per revision.
#[derive(Clone, Debug)]
pub struct Attribution {
    pub was: Decider,
    pub now: Decider,
    pub set: Bdd,
}

/// A change in a rule's reachability or usefulness between revisions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Structural {
    /// Was reachable, now no packet reaches it.
    NowUnreachable { number: u32, covered_by: Vec<u32> },
    /// Was dead, now decides packets. The dangerous one: a rule nobody has
    /// looked at in years starts taking effect.
    NowReachable { number: u32, previously_covered_by: Vec<u32> },
    /// Still reachable, but removing it would no longer change anything.
    NowRedundant { number: u32 },
    /// Was redundant, now load-bearing.
    NoLongerRedundant { number: u32 },
    Added { number: u32 },
    Removed { number: u32 },
    /// A rule was edited in place: the predicate or action changed while the
    /// position stayed. Content pairing sees this as a removal and an addition;
    /// reporting it that way is technically true and reads badly.
    Modified { number: u32 },
}

impl Structural {
    pub fn number(&self) -> u32 {
        match self {
            Structural::NowUnreachable { number, .. }
            | Structural::NowReachable { number, .. }
            | Structural::NowRedundant { number }
            | Structural::NoLongerRedundant { number }
            | Structural::Added { number }
            | Structural::Removed { number }
            | Structural::Modified { number } => *number,
        }
    }
}

/// The delta between two revisions of one chain.
#[derive(Clone, Debug)]
pub struct ChainDiff {
    pub name: String,
    /// Permitted now, denied before.
    pub newly_allowed: Bdd,
    /// Denied now, permitted before. Empty in most correct changes, and
    /// non-empty exactly when the author has done something they did not mean to.
    pub newly_blocked: Bdd,
    pub structural: Vec<Structural>,
}

impl ChainDiff {
    /// True when the two revisions permit exactly the same packets. A textual
    /// diff can be large while this is empty, which is the entire point.
    pub fn is_behaviourally_identical(&self) -> bool {
        self.newly_allowed.is_false() && self.newly_blocked.is_false()
    }
}

/// Compare two compiled chains.
pub fn diff(base: &ChainModel, head: &ChainModel) -> ChainDiff {
    ChainDiff {
        name: head.name.clone(),
        newly_allowed: head.accept.and_not(&base.accept),
        newly_blocked: base.accept.and_not(&head.accept),
        structural: structural_changes(base, head),
    }
}

/// Split a delta into parts, each with the rule responsible on both sides.
///
/// Returns parts in base-rule order. The second element is true when the cell
/// cap was reached, in which case the parts cover only some of the delta.
///
/// Cost is one intersection per base rule, plus one per head rule for each base
/// cell that survives. A delta is normally decided by a handful of rules, so the
/// quadratic worst case is not the usual case — but the cap is there because
/// "not the usual case" is not "impossible".
pub fn attribute(
    base: &ChainModel,
    head: &ChainModel,
    delta: &Bdd,
    max_cells: usize,
) -> (Vec<Attribution>, bool) {
    let mut out = Vec::new();
    if delta.is_false() {
        return (out, false);
    }
    for (was, base_part) in base.attribute(delta) {
        for (now, both) in head.attribute(&base_part) {
            if out.len() >= max_cells {
                return (out, true);
            }
            out.push(Attribution { was, now, set: both });
        }
    }
    (out, false)
}

/// Pair rules between revisions by what they say, not where they sit.
///
/// Matching by position would report every rule after an insertion as changed.
/// Pairing on the predicate and action means an inserted rule shows up as one
/// addition, and the rules around it keep their identity even though their
/// numbers moved.
fn pair_rules(base: &ChainModel, head: &ChainModel) -> (Vec<(u32, u32)>, Vec<u32>, Vec<u32>) {
    let mut by_key: HashMap<u64, Vec<u32>> = HashMap::new();
    for r in &head.rules {
        by_key.entry(r.content_key).or_default().push(r.number);
    }
    // Later positions are consumed first from the back, so equal rules pair in
    // file order.
    for v in by_key.values_mut() {
        v.reverse();
    }

    let mut paired = Vec::new();
    let mut removed = Vec::new();
    for r in &base.rules {
        match by_key.get_mut(&r.content_key).and_then(Vec::pop) {
            Some(h) => paired.push((r.number, h)),
            None => removed.push(r.number),
        }
    }
    let mut added: Vec<u32> = by_key.into_values().flatten().collect();
    added.sort_unstable();
    (paired, removed, added)
}

fn structural_changes(base: &ChainModel, head: &ChainModel) -> Vec<Structural> {
    let (paired, removed, added) = pair_rules(base, head);
    let mut out = Vec::new();

    for (b, h) in paired {
        let (bi, hi) = match (
            base.rules.iter().find(|r| r.number == b),
            head.rules.iter().find(|r| r.number == h),
        ) {
            (Some(bi), Some(hi)) => (bi, hi),
            _ => continue,
        };

        match (bi.shadowed, hi.shadowed) {
            (false, true) => out.push(Structural::NowUnreachable {
                number: h,
                covered_by: head.explain_shadow(h),
            }),
            (true, false) => out.push(Structural::NowReachable {
                number: h,
                previously_covered_by: base.explain_shadow(b),
            }),
            _ => {}
        }

        // Shadowed rules are trivially redundant; reporting both would be noise,
        // and the shadowing is the sharper finding.
        if !bi.shadowed && !hi.shadowed {
            match (bi.redundant, hi.redundant) {
                (false, true) => out.push(Structural::NowRedundant { number: h }),
                (true, false) => out.push(Structural::NoLongerRedundant { number: h }),
                _ => {}
            }
        }
    }

    // A rule edited in place leaves one unmatched removal and one unmatched
    // addition at the same position. Pairing those by number turns "rule 04
    // added, rule 04 removed" into the single fact it actually is.
    let mut added_left: Vec<u32> = added;
    let mut removed_left: Vec<u32> = Vec::new();
    for number in removed {
        if let Some(pos) = added_left.iter().position(|&a| a == number) {
            added_left.remove(pos);
            out.push(Structural::Modified { number });
        } else {
            removed_left.push(number);
        }
    }
    out.extend(removed_left.into_iter().map(|number| Structural::Removed { number }));
    out.extend(added_left.into_iter().map(|number| Structural::Added { number }));
    out.sort_by(|a, b| a.number().cmp(&b.number()).then_with(|| format!("{a:?}").cmp(&format!("{b:?}"))));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept::analyse;
    use crate::header::Layout;
    use soteria_ir::{Action, Chain, Field, Hook, Match, Origin, SymbolTable};

    const TCP: u64 = 6;

    fn chain_of(policy: Action, rules: Vec<(Match, Action)>) -> Chain {
        let mut c = Chain::new("input", Hook::Input, policy);
        for (m, a) in rules {
            c.push(m, a, Origin::default());
        }
        c
    }

    fn setup() -> (Layout, SymbolTable) {
        (Layout::default(), SymbolTable::default())
    }

    #[test]
    fn an_unchanged_ruleset_has_no_delta() {
        let (l, s) = setup();
        let c = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_value(Field::DstPort, 22), Action::Accept),
                (Match::any().with_value(Field::Proto, TCP), Action::Drop),
            ],
        );
        let d = diff(&analyse(&l, &s, &c), &analyse(&l, &s, &c));
        assert!(d.is_behaviourally_identical());
        assert!(d.structural.is_empty());
    }

    #[test]
    fn the_two_directions_never_overlap_and_cover_the_difference() {
        let (l, s) = setup();
        let base = chain_of(
            Action::Drop,
            vec![(Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 8), Action::Accept)],
        );
        let head = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 16), Action::Accept),
                (Match::any().with_value(Field::DstPort, 443), Action::Accept),
            ],
        );
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);

        assert!(d.newly_allowed.and(&d.newly_blocked).is_false());
        assert_eq!(d.newly_allowed.or(&d.newly_blocked), bm.accept.xor(&hm.accept));
    }

    /// Reordering rules that cannot both match the same packet changes nothing.
    #[test]
    fn reordering_independent_rules_is_not_a_change() {
        let (l, s) = setup();
        let a = (Match::any().with_value(Field::DstPort, 22), Action::Accept);
        let b = (Match::any().with_value(Field::DstPort, 443), Action::Accept);
        let first = chain_of(Action::Drop, vec![a.clone(), b.clone()]);
        let second = chain_of(Action::Drop, vec![b, a]);
        let d = diff(&analyse(&l, &s, &first), &analyse(&l, &s, &second));
        assert!(d.is_behaviourally_identical());
    }

    /// Reordering rules whose match sets overlap and whose actions differ does
    /// change the verdict, for packets neither rule's text mentions alone.
    #[test]
    fn reordering_overlapping_rules_is_a_change() {
        let (l, s) = setup();
        let allow = (Match::any().with_value(Field::DstPort, 22), Action::Accept);
        let deny = (Match::any().with_prefix(Field::SrcAddr, 0x0A01_0000, 16), Action::Drop);
        let first = chain_of(Action::Drop, vec![allow.clone(), deny.clone()]);
        let second = chain_of(Action::Drop, vec![deny, allow]);
        let d = diff(&analyse(&l, &s, &first), &analyse(&l, &s, &second));
        assert!(!d.newly_blocked.is_false(), "ssh from 10.1/16 lost access");
        assert!(d.newly_allowed.is_false());
    }

    /// The blueprint's motivating failure, in full: narrowing one rule exposes
    /// another that has been dead for years, and traffic silently stops.
    #[test]
    fn narrowing_a_rule_exposes_a_shadowed_one() {
        let (l, s) = setup();
        // Rule 1 accepts all of 10/8. Rule 2 would drop modbus from 10.1/16,
        // but nothing reaches it.
        let broad = (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 8), Action::Accept);
        let narrow = (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 16), Action::Accept);
        let modbus = (
            Match::any()
                .with_prefix(Field::SrcAddr, 0x0A01_0000, 16)
                .with_value(Field::Proto, TCP)
                .with_value(Field::DstPort, 502),
            Action::Drop,
        );

        let base = chain_of(Action::Drop, vec![broad, modbus.clone()]);
        let head = chain_of(Action::Drop, vec![narrow, modbus]);
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));

        assert!(bm.rules[1].shadowed, "rule 2 should start dead");
        assert!(!hm.rules[1].shadowed, "narrowing rule 1 should wake rule 2");

        let d = diff(&bm, &hm);
        assert!(d.newly_allowed.is_false());
        assert!(!d.newly_blocked.is_false());
        assert!(
            d.structural.contains(&Structural::NowReachable {
                number: 2,
                previously_covered_by: vec![1]
            }),
            "structural findings: {:?}",
            d.structural
        );

        // Attribution has to name both halves of the story.
        let (parts, truncated) = attribute(&bm, &hm, &d.newly_blocked, 64);
        assert!(!truncated);
        let modbus_cell = parts
            .iter()
            .find(|a| a.was == Decider::Rule(1) && a.now == Decider::Rule(2))
            .expect("modbus traffic was allowed by rule 1 and is now denied by rule 2");
        assert!(!modbus_cell.set.is_false());
    }

    #[test]
    fn attribution_cells_partition_the_delta() {
        let (l, s) = setup();
        let base = chain_of(
            Action::Drop,
            vec![
                (Match::any().with_value(Field::DstPort, 22), Action::Accept),
                (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 8), Action::Accept),
            ],
        );
        let head = chain_of(
            Action::Drop,
            vec![(Match::any().with_value(Field::DstPort, 22), Action::Accept)],
        );
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let (parts, _) = attribute(&bm, &hm, &d.newly_blocked, 256);

        let mut union = l.ff();
        for p in &parts {
            assert!(union.and(&p.set).is_false(), "attribution cells overlap");
            union = union.or(&p.set);
        }
        assert_eq!(union, d.newly_blocked);
    }

    /// Inserting a rule must not report every later rule as changed.
    #[test]
    fn rules_are_paired_by_content_not_position() {
        let (l, s) = setup();
        let a = (Match::any().with_value(Field::DstPort, 22), Action::Accept);
        let b = (Match::any().with_value(Field::DstPort, 443), Action::Accept);
        let inserted = (Match::any().with_value(Field::DstPort, 8080), Action::Accept);

        let base = chain_of(Action::Drop, vec![a.clone(), b.clone()]);
        let head = chain_of(Action::Drop, vec![a, inserted, b]);
        let d = diff(&analyse(&l, &s, &base), &analyse(&l, &s, &head));

        assert_eq!(d.structural, vec![Structural::Added { number: 2 }]);
        assert!(d.newly_blocked.is_false());
        assert!(!d.newly_allowed.is_false());
    }

    #[test]
    fn a_deleted_rule_is_reported_as_removed() {
        let (l, s) = setup();
        let a = (Match::any().with_value(Field::DstPort, 22), Action::Accept);
        let b = (Match::any().with_value(Field::DstPort, 443), Action::Accept);
        let base = chain_of(Action::Drop, vec![a.clone(), b]);
        let head = chain_of(Action::Drop, vec![a]);
        let d = diff(&analyse(&l, &s, &base), &analyse(&l, &s, &head));
        assert_eq!(d.structural, vec![Structural::Removed { number: 2 }]);
    }

    /// Editing a rule in place is one fact, not a removal plus an addition.
    #[test]
    fn an_edited_rule_reports_as_modified() {
        let (l, s) = setup();
        let keep = (Match::any().with_value(Field::DstPort, 22), Action::Accept);
        let before = (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 8), Action::Accept);
        let after = (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 16), Action::Accept);

        let base = chain_of(Action::Drop, vec![keep.clone(), before]);
        let head = chain_of(Action::Drop, vec![keep, after]);
        let d = diff(&analyse(&l, &s, &base), &analyse(&l, &s, &head));
        assert_eq!(d.structural, vec![Structural::Modified { number: 2 }]);
    }

    #[test]
    fn a_rule_can_become_redundant_without_becoming_unreachable() {
        let (l, s) = setup();
        // Rule 2 drops ssh. Under an accept policy it is load-bearing; flip the
        // policy to drop and it agrees with what follows, so it stops mattering.
        let rules = vec![
            (Match::any().with_prefix(Field::SrcAddr, 0x0A00_0000, 8), Action::Accept),
            (Match::any().with_value(Field::DstPort, 22), Action::Drop),
        ];
        let base = chain_of(Action::Accept, rules.clone());
        let head = chain_of(Action::Drop, rules);
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));

        assert!(!bm.rules[1].shadowed && !hm.rules[1].shadowed);
        let d = diff(&bm, &hm);
        assert!(
            d.structural.contains(&Structural::NowRedundant { number: 2 }),
            "structural findings: {:?}",
            d.structural
        );
    }
}
