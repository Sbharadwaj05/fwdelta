//! Mapping the 120-bit header space onto BDD variables.
//!
//! A packet is a point in `{0,1}^120`. A set of packets is a boolean function
//! over those variables, held as a reduced ordered binary decision diagram.
//!
//! Bit positions within a field are numbered from the most significant bit, so
//! an address prefix is exactly "fix bits 0..len". That keeps prefix encoding
//! cheap and is what the enumerator relies on when reading fixed bits back out.

use biodivine_lib_bdd::{Bdd, BddVariable, BddVariableSet};
use soteria_ir::{Field, HEADER_BITS, IntervalSet, Match, SymbolTable};

/// BDD variable ordering.
///
/// Ordering changes the size of the diagrams and therefore the running time, not
/// the meaning of anything. The enumerator reads fixed bits per field and is
/// independent of the choice, so this stays swappable and measurable rather than
/// baked in. See `examples/thousand_rules.rs` for the measurement.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum VarOrder {
    /// Cheap dimensions first, then each field's bits contiguously, MSB first.
    FieldMajor,
    /// Cheap dimensions first, then source and destination address bits
    /// interleaved MSB-first, then the two port fields interleaved. Rules that
    /// constrain both addresses to prefixes stay shallow because the diagram
    /// decides both dimensions near the root.
    #[default]
    AddrInterleaved,
}

impl VarOrder {
    /// The global variable sequence: position *i* is BDD variable *i*.
    fn sequence(self) -> Vec<(Field, u32)> {
        let mut v = Vec::with_capacity(HEADER_BITS as usize);
        // The three narrow dimensions lead in both orderings. Nearly every real
        // rule constrains protocol, and interface matches sit at the top of most
        // chains, so deciding them at the root prunes the widest.
        for f in [Field::Proto, Field::IfIn, Field::IfOut] {
            for b in 0..f.bits() {
                v.push((f, b));
            }
        }
        match self {
            VarOrder::FieldMajor => {
                for f in [Field::SrcAddr, Field::DstAddr, Field::SrcPort, Field::DstPort] {
                    for b in 0..f.bits() {
                        v.push((f, b));
                    }
                }
            }
            VarOrder::AddrInterleaved => {
                for b in 0..32 {
                    v.push((Field::SrcAddr, b));
                    v.push((Field::DstAddr, b));
                }
                for b in 0..16 {
                    v.push((Field::SrcPort, b));
                    v.push((Field::DstPort, b));
                }
            }
        }
        debug_assert_eq!(v.len(), HEADER_BITS as usize);
        v
    }
}

/// The variable set plus the field/bit addressing on top of it.
#[derive(Clone, Debug)]
pub struct Layout {
    vars: BddVariableSet,
    order: VarOrder,
    /// `pos[field][bit]` is the global variable index.
    pos: [[u16; 32]; 7],
    /// Variables in declaration order; `all[i]` is global variable `i`.
    all: Vec<BddVariable>,
    sequence: Vec<(Field, u32)>,
}

impl Default for Layout {
    fn default() -> Self {
        Self::new(VarOrder::default())
    }
}

impl Layout {
    pub fn new(order: VarOrder) -> Self {
        let sequence = order.sequence();
        let names: Vec<String> =
            sequence.iter().map(|(f, b)| format!("{}{:02}", f.short(), b)).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let vars = BddVariableSet::new(&name_refs);

        let mut pos = [[u16::MAX; 32]; 7];
        for (i, &(f, b)) in sequence.iter().enumerate() {
            pos[f.index()][b as usize] = i as u16;
        }
        let all = vars.variables();
        Self { vars, order, pos, all, sequence }
    }

    #[inline]
    pub fn vars(&self) -> &BddVariableSet {
        &self.vars
    }

    #[inline]
    pub fn order(&self) -> VarOrder {
        self.order
    }

    #[inline]
    pub fn sequence(&self) -> &[(Field, u32)] {
        &self.sequence
    }

    /// The BDD variable holding bit `bit` of `field`, counted from the MSB.
    #[inline]
    pub fn var(&self, field: Field, bit: u32) -> BddVariable {
        debug_assert!(bit < field.bits());
        self.all[usize::from(self.pos[field.index()][bit as usize])]
    }

    /// Global variable index of a field bit.
    #[inline]
    pub fn var_index(&self, field: Field, bit: u32) -> usize {
        usize::from(self.pos[field.index()][bit as usize])
    }

    #[inline]
    pub fn tt(&self) -> Bdd {
        self.vars.mk_true()
    }

    #[inline]
    pub fn ff(&self) -> Bdd {
        self.vars.mk_false()
    }

    /// One literal: bit `bit` of `field` equals `value`.
    #[inline]
    pub fn lit(&self, field: Field, bit: u32, value: bool) -> Bdd {
        self.vars.mk_literal(self.var(field, bit), value)
    }

    /// `field == value`.
    pub fn eq(&self, field: Field, value: u64) -> Bdd {
        self.prefix(field, value, field.bits())
    }

    /// `field` matches the given prefix, `len` bits fixed from the MSB.
    pub fn prefix(&self, field: Field, value: u64, len: u32) -> Bdd {
        assert!(len <= field.bits(), "prefix length {len} exceeds {field}");
        let w = field.bits();
        let mut acc = self.tt();
        for b in 0..len {
            let bit = (value >> (w - 1 - b)) & 1 == 1;
            acc = acc.and(&self.lit(field, b, bit));
        }
        acc
    }

    /// `field >= lo`, built LSB-first so the diagram stays linear in the width.
    fn geq(&self, field: Field, lo: u64) -> Bdd {
        let w = field.bits();
        let mut acc = self.tt();
        for b in (0..w).rev() {
            let bit = (lo >> (w - 1 - b)) & 1 == 1;
            acc = if bit {
                // lo has a 1 here: x needs a 1 too, and the suffix must still be >=.
                self.lit(field, b, true).and(&acc)
            } else {
                // lo has a 0 here: a 1 in x already settles it.
                self.lit(field, b, true).or(&acc)
            };
        }
        acc
    }

    /// `field <= hi`. Mirror of [`Layout::geq`].
    fn leq(&self, field: Field, hi: u64) -> Bdd {
        let w = field.bits();
        let mut acc = self.tt();
        for b in (0..w).rev() {
            let bit = (hi >> (w - 1 - b)) & 1 == 1;
            acc = if bit {
                self.lit(field, b, false).or(&acc)
            } else {
                self.lit(field, b, false).and(&acc)
            };
        }
        acc
    }

    /// `lo <= field <= hi`.
    pub fn range(&self, field: Field, lo: u64, hi: u64) -> Bdd {
        let max = IntervalSet::domain_max(field.bits());
        if lo > hi {
            return self.ff();
        }
        match (lo == 0, hi >= max) {
            (true, true) => self.tt(),
            (true, false) => self.leq(field, hi),
            (false, true) => self.geq(field, lo),
            (false, false) => self.geq(field, lo).and(&self.leq(field, hi)),
        }
    }

    /// A whole interval set as a BDD, as the union of its ranges.
    pub fn set(&self, field: Field, set: &IntervalSet) -> Bdd {
        debug_assert_eq!(set.bits(), field.bits());
        if set.is_full() {
            return self.tt();
        }
        let mut acc = self.ff();
        for &(lo, hi) in set.ranges() {
            acc = acc.or(&self.range(field, lo, hi));
        }
        acc
    }

    /// Compile an IR match predicate into the set of packets it admits.
    ///
    /// The interface dimensions resolve against the shared symbol table here,
    /// which is the only place symbols become numbers.
    pub fn match_bdd(&self, m: &Match, syms: &SymbolTable) -> Bdd {
        let mut acc = self.tt();
        for f in Field::ALL {
            let set = match f {
                Field::IfIn => m.iif.resolve(syms),
                Field::IfOut => m.oif.resolve(syms),
                other => m.packet_dim(other).clone(),
            };
            if set.is_full() {
                continue;
            }
            acc = acc.and(&self.set(f, &set));
            if acc.is_false() {
                break;
            }
        }
        acc
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use soteria_ir::IfMatch;

    fn layouts() -> Vec<Layout> {
        vec![Layout::new(VarOrder::FieldMajor), Layout::new(VarOrder::AddrInterleaved)]
    }

    #[test]
    fn header_is_one_hundred_and_twenty_bits() {
        for l in layouts() {
            assert_eq!(l.vars().num_vars(), HEADER_BITS as u16);
        }
    }

    #[test]
    fn every_variable_is_addressed_exactly_once() {
        for l in layouts() {
            let mut seen = vec![false; HEADER_BITS as usize];
            for f in Field::ALL {
                for b in 0..f.bits() {
                    let idx = l.var_index(f, b);
                    assert!(!seen[idx], "variable {idx} claimed twice");
                    seen[idx] = true;
                }
            }
            assert!(seen.iter().all(|&s| s));
        }
    }

    #[test]
    fn range_matches_prefix_where_they_coincide() {
        for l in layouts() {
            let via_prefix = l.prefix(Field::SrcAddr, 0x0A010000, 16);
            let via_range = l.range(Field::SrcAddr, 0x0A010000, 0x0A01FFFF);
            assert_eq!(via_prefix, via_range);
        }
    }

    #[test]
    fn port_range_boundaries() {
        let l = Layout::default();
        for (lo, hi) in [(0u64, 0u64), (0, 65535), (65535, 65535), (1, 2), (502, 502)] {
            let b = l.range(Field::DstPort, lo, hi);
            let width = 1u128 << (HEADER_BITS - 16);
            assert_eq!(
                b.exact_cardinality().to_string(),
                ((hi - lo + 1) as u128 * width).to_string(),
                "range {lo}..={hi}"
            );
        }
    }

    #[test]
    fn set_encoding_agrees_with_union_of_ranges() {
        let l = Layout::default();
        let s = IntervalSet::from_ranges(16, vec![(80, 80), (443, 443), (8000, 8080)]);
        let via_set = l.set(Field::DstPort, &s);
        let via_or = l
            .range(Field::DstPort, 80, 80)
            .or(&l.range(Field::DstPort, 443, 443))
            .or(&l.range(Field::DstPort, 8000, 8080));
        assert_eq!(via_set, via_or);
    }

    #[test]
    fn full_set_is_tautology() {
        let l = Layout::default();
        assert!(l.set(Field::Proto, &IntervalSet::full(8)).is_true());
        assert!(l.range(Field::SrcAddr, 0, u32::MAX as u64).is_true());
    }

    #[test]
    fn an_unconstrained_match_is_the_whole_space() {
        let l = Layout::default();
        let syms = SymbolTable::from_names(["eth0", "eth1"]).unwrap();
        assert!(l.match_bdd(&Match::any(), &syms).is_true());
    }

    /// The phantom-delta guard, at the level where it would actually bite.
    #[test]
    fn a_growing_symbol_table_does_not_move_an_unconstrained_rule() {
        let l = Layout::default();
        let narrow = SymbolTable::from_names(["eth0"]).unwrap();
        let wide = SymbolTable::from_names(["eth0", "eth1", "eth2", "wg0"]).unwrap();
        let m = Match::any().with_value(Field::Proto, 6).with_value(Field::DstPort, 22);
        assert_eq!(l.match_bdd(&m, &narrow), l.match_bdd(&m, &wide));
    }

    #[test]
    fn naming_an_interface_is_a_real_narrowing() {
        let l = Layout::default();
        let syms = SymbolTable::from_names(["eth0", "eth1", "eth2"]).unwrap();
        let open = l.match_bdd(&Match::any().with_value(Field::DstPort, 22), &syms);
        let scoped = l.match_bdd(
            &Match::any().with_value(Field::DstPort, 22).with_iif(IfMatch::one("eth2")),
            &syms,
        );
        let lost = open.and_not(&scoped);
        assert!(!lost.is_false(), "scoping to one interface must narrow");
        // Exactly 255 of the 256 interface symbols were dropped.
        let open_n = open.exact_cardinality().to_string().parse::<u128>().unwrap();
        let scoped_n = scoped.exact_cardinality().to_string().parse::<u128>().unwrap();
        assert_eq!(open_n / scoped_n, 256);
    }

    #[test]
    fn a_contradictory_match_compiles_to_nothing() {
        let l = Layout::default();
        let syms = SymbolTable::default();
        let m = Match::any().with_value(Field::Proto, 6).with_value(Field::Proto, 17);
        assert!(l.match_bdd(&m, &syms).is_false());
    }
}
