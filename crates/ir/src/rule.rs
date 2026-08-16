//! Rules, chains and rulesets.
//!
//! A rule is a match predicate over the seven dimensions plus an action. Rules
//! keep their source position so a finding can be pointed back at the line that
//! caused it. Evaluation is first-match; the written semantics are in
//! `docs/SEMANTICS.md` and the executable statement of them is
//! `soteria_engine::accept`.

use core::fmt;

use crate::field::Field;
use crate::interface::IfMatch;
use crate::intervals::IntervalSet;

/// What a rule does to the packets it decides.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Action {
    Accept,
    Drop,
    /// Distinct from `Drop` in the report and identical to it in the model: both
    /// deny. The difference is what the sender observes, which is outside a
    /// filtering model.
    Reject,
}

impl Action {
    #[inline]
    pub fn permits(self) -> bool {
        matches!(self, Action::Accept)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Action::Accept => "accept",
            Action::Drop => "drop",
            Action::Reject => "reject",
        })
    }
}

/// Where a rule came from, so findings can cite it.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Origin {
    pub file: String,
    pub line: u32,
    pub column: u32,
    /// The source text, quoted verbatim in reports.
    pub text: String,
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}:{}", self.file, self.line, self.column)
    }
}

/// A match predicate over the seven dimensions.
///
/// The five packet fields are stored resolved, as value sets. The two interface
/// dimensions keep their names and resolve against a symbol table at the engine
/// boundary, so the IR stays faithful to what the file said.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Match {
    src_addr: IntervalSet,
    dst_addr: IntervalSet,
    src_port: IntervalSet,
    dst_port: IntervalSet,
    proto: IntervalSet,
    pub iif: IfMatch,
    pub oif: IfMatch,
}

impl Default for Match {
    fn default() -> Self {
        Self::any()
    }
}

impl Match {
    /// Matches every packet.
    pub fn any() -> Self {
        Self {
            src_addr: IntervalSet::full(Field::SrcAddr.bits()),
            dst_addr: IntervalSet::full(Field::DstAddr.bits()),
            src_port: IntervalSet::full(Field::SrcPort.bits()),
            dst_port: IntervalSet::full(Field::DstPort.bits()),
            proto: IntervalSet::full(Field::Proto.bits()),
            iif: IfMatch::Any,
            oif: IfMatch::Any,
        }
    }

    /// The value set for one of the five packet dimensions.
    ///
    /// Panics on the interface dimensions, which are not resolved at this level.
    pub fn packet_dim(&self, field: Field) -> &IntervalSet {
        match field {
            Field::SrcAddr => &self.src_addr,
            Field::DstAddr => &self.dst_addr,
            Field::SrcPort => &self.src_port,
            Field::DstPort => &self.dst_port,
            Field::Proto => &self.proto,
            Field::IfIn | Field::IfOut => {
                panic!("{field} is symbolic; resolve it through IfMatch")
            }
        }
    }

    /// Constrain one packet dimension, intersecting with what is already there.
    pub fn constrain(mut self, field: Field, set: &IntervalSet) -> Self {
        debug_assert_eq!(set.bits(), field.bits());
        let slot = match field {
            Field::SrcAddr => &mut self.src_addr,
            Field::DstAddr => &mut self.dst_addr,
            Field::SrcPort => &mut self.src_port,
            Field::DstPort => &mut self.dst_port,
            Field::Proto => &mut self.proto,
            Field::IfIn | Field::IfOut => {
                panic!("{field} is symbolic; set Match::iif or Match::oif")
            }
        };
        *slot = slot.intersect(set);
        self
    }

    /// Remove any constraint on one packet dimension.
    ///
    /// The counterpart to [`Match::constrain`], which intersects and therefore
    /// cannot widen. Anything wanting to *replace* a dimension needs this;
    /// passing a full set to `constrain` is a no-op, which is a quiet way to
    /// write code that does nothing.
    pub fn relax(mut self, field: Field) -> Self {
        let full = IntervalSet::full(field.bits());
        match field {
            Field::SrcAddr => self.src_addr = full,
            Field::DstAddr => self.dst_addr = full,
            Field::SrcPort => self.src_port = full,
            Field::DstPort => self.dst_port = full,
            Field::Proto => self.proto = full,
            Field::IfIn => self.iif = IfMatch::Any,
            Field::IfOut => self.oif = IfMatch::Any,
        }
        self
    }

    /// Convenience for the common address-prefix constraint.
    pub fn with_prefix(self, field: Field, value: u64, len: u32) -> Self {
        let set = IntervalSet::prefix(field.bits(), value, len);
        self.constrain(field, &set)
    }

    /// Convenience for a single value.
    pub fn with_value(self, field: Field, value: u64) -> Self {
        let set = IntervalSet::point(field.bits(), value);
        self.constrain(field, &set)
    }

    /// Convenience for an inclusive range.
    pub fn with_range(self, field: Field, lo: u64, hi: u64) -> Self {
        let set = IntervalSet::range(field.bits(), lo, hi);
        self.constrain(field, &set)
    }

    pub fn with_iif(mut self, m: IfMatch) -> Self {
        self.iif = m;
        self
    }

    pub fn with_oif(mut self, m: IfMatch) -> Self {
        self.oif = m;
        self
    }

    /// True when the predicate can never hold, which the frontend should reject
    /// rather than pass on: a rule that matches nothing is almost always a typo.
    pub fn is_unsatisfiable(&self) -> bool {
        Field::ALL
            .iter()
            .filter(|f| !f.is_interface())
            .any(|&f| self.packet_dim(f).is_empty())
    }

    /// Every interface name the predicate mentions.
    pub fn interface_names(&self) -> impl Iterator<Item = &str> {
        self.iif.names().chain(self.oif.names())
    }
}

/// One rule: a predicate, an action and a provenance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Position in the chain, counted from 1 to match how engineers read files.
    pub number: u32,
    pub matches: Match,
    pub action: Action,
    pub origin: Origin,
}

/// Netfilter hook a base chain attaches to.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Hook {
    Input,
    Output,
    Forward,
}

impl fmt::Display for Hook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Hook::Input => "input",
            Hook::Output => "output",
            Hook::Forward => "forward",
        })
    }
}

/// A base chain: an ordered rule list and a default policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chain {
    pub name: String,
    pub hook: Hook,
    pub policy: Action,
    pub rules: Vec<Rule>,
}

impl Chain {
    pub fn new(name: impl Into<String>, hook: Hook, policy: Action) -> Self {
        Self { name: name.into(), hook, policy, rules: Vec::new() }
    }

    pub fn push(&mut self, matches: Match, action: Action, origin: Origin) {
        let number = self.rules.len() as u32 + 1;
        self.rules.push(Rule { number, matches, action, origin });
    }
}

/// One host's filter policy: the base chains of a single table.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Ruleset {
    /// Where this revision came from, for the report header.
    pub label: String,
    pub chains: Vec<Chain>,
}

impl Ruleset {
    pub fn chain(&self, name: &str) -> Option<&Chain> {
        self.chains.iter().find(|c| c.name == name)
    }

    pub fn rule_count(&self) -> usize {
        self.chains.iter().map(|c| c.rules.len()).sum()
    }

    /// Every interface name in the ruleset, for symbol table construction.
    pub fn interface_names(&self) -> impl Iterator<Item = &str> {
        self.chains
            .iter()
            .flat_map(|c| c.rules.iter())
            .flat_map(|r| r.matches.interface_names())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_default_match_admits_everything() {
        let m = Match::any();
        for f in Field::ALL.iter().filter(|f| !f.is_interface()) {
            assert!(m.packet_dim(*f).is_full());
        }
        assert!(!m.is_unsatisfiable());
    }

    #[test]
    fn constraints_intersect_rather_than_replace() {
        let m = Match::any()
            .with_range(Field::DstPort, 100, 200)
            .with_range(Field::DstPort, 150, 300);
        assert_eq!(m.packet_dim(Field::DstPort).ranges(), &[(150, 200)]);
    }

    /// `constrain` intersects, so it can only narrow. Widening needs `relax`.
    /// Passing a full set to `constrain` does nothing, which is an easy way to
    /// write code that silently has no effect.
    #[test]
    fn constrain_cannot_widen_but_relax_can() {
        let narrowed = Match::any().with_value(Field::Proto, 6);
        let no_op = narrowed.clone().constrain(Field::Proto, &IntervalSet::full(8));
        assert_eq!(no_op.packet_dim(Field::Proto).count(), 1, "constrain must not widen");

        let widened = narrowed.relax(Field::Proto);
        assert!(widened.packet_dim(Field::Proto).is_full());
    }

    #[test]
    fn relax_clears_interface_matches_too() {
        let m = Match::any().with_iif(IfMatch::one("eth0")).with_oif(IfMatch::one("eth1"));
        assert_eq!(m.clone().relax(Field::IfIn).iif, IfMatch::Any);
        assert_eq!(m.relax(Field::IfOut).oif, IfMatch::Any);
    }

    #[test]
    fn contradictory_constraints_are_detectable() {
        let m = Match::any().with_value(Field::Proto, 6).with_value(Field::Proto, 17);
        assert!(m.is_unsatisfiable());
    }

    #[test]
    fn rules_are_numbered_from_one() {
        let mut c = Chain::new("input", Hook::Input, Action::Drop);
        c.push(Match::any(), Action::Accept, Origin::default());
        c.push(Match::any(), Action::Drop, Origin::default());
        assert_eq!(c.rules[0].number, 1);
        assert_eq!(c.rules[1].number, 2);
    }

    #[test]
    fn interface_names_are_collected_from_both_directions() {
        let mut c = Chain::new("input", Hook::Input, Action::Drop);
        c.push(
            Match::any().with_iif(IfMatch::one("eth0")).with_oif(IfMatch::not_one("lo")),
            Action::Accept,
            Origin::default(),
        );
        let rs = Ruleset { label: "t".into(), chains: vec![c] };
        let mut names: Vec<&str> = rs.interface_names().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["eth0", "lo"]);
    }
}
