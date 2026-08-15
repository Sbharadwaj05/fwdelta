//! Soteria's vendor-neutral intermediate representation.
//!
//! Every frontend targets this and the engine consumes only this, so adding
//! iptables or pfSense later costs a parser and nothing else.
//!
//! This crate describes what a rule *says*. Computing with it — accept sets,
//! diffs, enumeration — is `soteria-engine`. Nothing here performs I/O.

#![forbid(unsafe_code)]

pub mod field;
pub mod interface;
pub mod intervals;
pub mod rule;

pub use field::{Field, HEADER_BITS};
pub use interface::{IfMatch, MAX_INTERFACES, SymbolTable, TooManyInterfaces};
pub use intervals::{IntervalSet, range_to_prefixes, set_to_prefixes};
pub use rule::{Action, Chain, Hook, Match, Origin, Rule, Ruleset};

/// Build the symbol table covering both revisions of a comparison.
///
/// Both sides must share one table: an interface index means the same thing on
/// each side only if it was assigned from the union.
pub fn shared_symbols(base: &Ruleset, head: &Ruleset) -> Result<SymbolTable, TooManyInterfaces> {
    SymbolTable::from_names(base.interface_names().chain(head.interface_names()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_shared_table_spans_both_revisions() {
        let mut b = Chain::new("input", Hook::Input, Action::Drop);
        b.push(Match::any().with_iif(IfMatch::one("eth0")), Action::Accept, Origin::default());
        let mut h = Chain::new("input", Hook::Input, Action::Drop);
        h.push(Match::any().with_iif(IfMatch::one("eth2")), Action::Accept, Origin::default());

        let base = Ruleset { label: "base".into(), chains: vec![b] };
        let head = Ruleset { label: "head".into(), chains: vec![h] };
        let syms = shared_symbols(&base, &head).unwrap();

        assert_eq!(syms.len(), 2);
        assert_eq!(syms.index_of("eth0"), Some(0));
        assert_eq!(syms.index_of("eth2"), Some(1));
    }
}
