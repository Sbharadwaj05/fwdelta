//! Symbolic interface identity.
//!
//! An interface match is not a function of the address, so it cannot be resolved
//! into an address set without the host's IP configuration — data this tool is
//! forbidden from reading and unsound to accept from a hand-written map. It is
//! instead modelled as a symbol: names get indices, and `iifname "eth1"` becomes
//! an equality test on an 8-bit dimension. Nothing about the subnet behind eth1
//! is needed to model one host's filter table faithfully.
//!
//! # The unconstrained-field rule
//!
//! **An unconstrained interface match denotes all 256 symbol values, not merely
//! the ones named in the rulesets.**
//!
//! This is load-bearing, not a detail. The symbol table is built from the union
//! of names across both revisions being compared, so it *grows* when the head
//! revision introduces an interface the base never mentioned. If "unconstrained"
//! meant "the named values", that growth would silently widen every
//! unconstrained rule in both files and manufacture a delta out of nothing. The
//! full 8-bit domain is also what makes the model honest about interfaces that
//! exist on the host but appear in neither file: they are the unnamed indices,
//! and an unconstrained rule matches them because the real rule would.

use std::collections::BTreeSet;

use crate::intervals::IntervalSet;

/// Maximum distinct interface names across a comparison.
pub const MAX_INTERFACES: usize = 256;

/// Width of an interface dimension.
const IF_BITS: u32 = 8;

/// Interface names mapped to dimension values.
///
/// Indices are assigned in sorted name order over the union of both rulesets, so
/// a given pair of inputs always produces the same table and therefore the same
/// attestation digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SymbolTable {
    names: Vec<String>,
}

impl SymbolTable {
    /// Build from every name appearing in either revision.
    pub fn from_names<I, S>(names: I) -> Result<Self, TooManyInterfaces>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let set: BTreeSet<String> = names.into_iter().map(Into::into).collect();
        if set.len() > MAX_INTERFACES {
            return Err(TooManyInterfaces { found: set.len() });
        }
        Ok(Self { names: set.into_iter().collect() })
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    pub fn index_of(&self, name: &str) -> Option<u8> {
        self.names.binary_search_by(|n| n.as_str().cmp(name)).ok().map(|i| i as u8)
    }

    pub fn name_of(&self, index: u8) -> Option<&str> {
        self.names.get(usize::from(index)).map(String::as_str)
    }

    /// True when every value in the set has a name. Values without one are real
    /// interfaces that neither revision mentioned.
    pub fn all_named(&self, set: &IntervalSet) -> bool {
        set.ranges().iter().all(|&(_, hi)| (hi as usize) < self.names.len())
    }

    pub fn names(&self) -> &[String] {
        &self.names
    }
}

/// More distinct interface names than the dimension can hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooManyInterfaces {
    pub found: usize,
}

impl core::fmt::Display for TooManyInterfaces {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{} distinct interface names across the two rulesets, limit is {MAX_INTERFACES}",
            self.found
        )
    }
}

impl std::error::Error for TooManyInterfaces {}

/// An interface match as written in the source.
///
/// Names are kept rather than resolved so the IR stays faithful to the file and
/// findings can quote what the rule actually said.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub enum IfMatch {
    /// No interface constraint. Denotes the whole 8-bit domain.
    #[default]
    Any,
    /// `iifname "eth0"` or `iifname { "eth0", "eth1" }`.
    OneOf(BTreeSet<String>),
    /// `iifname != "eth0"`.
    NoneOf(BTreeSet<String>),
}

impl IfMatch {
    pub fn one(name: impl Into<String>) -> Self {
        IfMatch::OneOf(BTreeSet::from([name.into()]))
    }

    pub fn not_one(name: impl Into<String>) -> Self {
        IfMatch::NoneOf(BTreeSet::from([name.into()]))
    }

    /// Every name this match mentions, for building the symbol table.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        let set = match self {
            IfMatch::Any => None,
            IfMatch::OneOf(s) | IfMatch::NoneOf(s) => Some(s),
        };
        set.into_iter().flatten().map(String::as_str)
    }

    /// Resolve to the set of dimension values this match admits.
    ///
    /// `Any` is the full domain; see the module note on why that matters. A name
    /// absent from the table cannot match anything, which only happens if the
    /// table was not built from this ruleset.
    pub fn resolve(&self, syms: &SymbolTable) -> IntervalSet {
        match self {
            IfMatch::Any => IntervalSet::full(IF_BITS),
            IfMatch::OneOf(names) => {
                let mut acc = IntervalSet::empty(IF_BITS);
                for n in names {
                    if let Some(i) = syms.index_of(n) {
                        acc = acc.union(&IntervalSet::point(IF_BITS, u64::from(i)));
                    }
                }
                acc
            }
            IfMatch::NoneOf(names) => {
                let mut excluded = IntervalSet::empty(IF_BITS);
                for n in names {
                    if let Some(i) = syms.index_of(n) {
                        excluded = excluded.union(&IntervalSet::point(IF_BITS, u64::from(i)));
                    }
                }
                excluded.complement()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indices_follow_sorted_name_order() {
        let t = SymbolTable::from_names(["eth1", "eth0", "lo"]).unwrap();
        assert_eq!(t.index_of("eth0"), Some(0));
        assert_eq!(t.index_of("eth1"), Some(1));
        assert_eq!(t.index_of("lo"), Some(2));
        assert_eq!(t.name_of(2), Some("lo"));
        assert_eq!(t.index_of("wg0"), None);
    }

    #[test]
    fn table_is_deterministic_regardless_of_input_order() {
        let a = SymbolTable::from_names(["lo", "eth0", "eth1"]).unwrap();
        let b = SymbolTable::from_names(["eth1", "lo", "eth0", "lo"]).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn too_many_names_is_an_error_not_a_truncation() {
        let many: Vec<String> = (0..300).map(|i| format!("veth{i}")).collect();
        assert!(SymbolTable::from_names(many).is_err());
    }

    /// The requirement that prevents phantom deltas.
    #[test]
    fn unconstrained_means_all_256_values() {
        let t = SymbolTable::from_names(["eth0", "eth1"]).unwrap();
        let any = IfMatch::Any.resolve(&t);
        assert!(any.is_full());
        assert_eq!(any.count(), 256);
    }

    /// The phantom itself: growing the table must not move an unconstrained
    /// rule. A head revision that introduces `eth2` widens the table, and if
    /// `Any` tracked the table, every unconstrained rule in both files would
    /// appear to change.
    #[test]
    fn growing_the_table_does_not_move_an_unconstrained_match() {
        let base = SymbolTable::from_names(["eth0"]).unwrap();
        let head = SymbolTable::from_names(["eth0", "eth1", "eth2"]).unwrap();
        assert_eq!(IfMatch::Any.resolve(&base), IfMatch::Any.resolve(&head));
    }

    /// Naming an interface really is a narrowing, and by the full 8-bit measure.
    #[test]
    fn naming_an_interface_narrows_against_unconstrained() {
        let t = SymbolTable::from_names(["eth0", "eth1", "eth2"]).unwrap();
        let any = IfMatch::Any.resolve(&t);
        let one = IfMatch::one("eth2").resolve(&t);
        assert_eq!(one.count(), 1);
        assert_eq!(any.difference(&one).count(), 255);
    }

    #[test]
    fn negation_covers_the_unnamed_indices() {
        let t = SymbolTable::from_names(["eth0", "eth1"]).unwrap();
        let not_eth0 = IfMatch::not_one("eth0").resolve(&t);
        assert_eq!(not_eth0.count(), 255);
        assert!(!t.all_named(&not_eth0), "unnamed indices must remain reachable");
        assert!(t.all_named(&IfMatch::one("eth1").resolve(&t)));
    }

    #[test]
    fn a_set_of_names_unions() {
        let t = SymbolTable::from_names(["eth0", "eth1", "lo"]).unwrap();
        let s = IfMatch::OneOf(["eth0".into(), "lo".into()].into()).resolve(&t);
        assert_eq!(s.count(), 2);
        assert!(s.contains(0) && s.contains(2) && !s.contains(1));
    }
}
