//! Stage 4: decision diagram to a short list of rectangles a human can read.
//!
//! A BDD is a boolean function. A reviewer needs a handful of CIDR blocks and
//! port ranges. This module is the bridge, and per the blueprint's risk register
//! it is the component that decides whether the tool is usable at all.
//!
//! The walk has three steps:
//!
//! 1. Enumerate root-to-one paths. Paths through a BDD are mutually exclusive,
//!    so the cubes partition the set and nothing is double counted.
//! 2. Turn each cube into one rectangle. A cube fixes some bits of each field
//!    and leaves the rest free; `(value, mask)` expands to an exact interval set.
//! 3. Merge rectangles differing in one dimension, then sort by how much packet
//!    space each covers and truncate with an explicit count of what was dropped.
//!
//! Every step is exact. Where exactness cannot be maintained inside the work
//! budget the result is marked incomplete rather than approximated, because a
//! verification tool that quietly rounds is worse than no tool.

use biodivine_lib_bdd::Bdd;

use soteria_ir::{Field, IntervalSet};

use crate::header::Layout;
use crate::region::{Region, merge};

/// Work limits for a single enumeration.
#[derive(Clone, Copy, Debug)]
pub struct EnumOptions {
    /// Maximum root-to-one paths to visit before giving up.
    pub max_cubes: usize,
    /// Maximum intervals one field of one cube may expand to.
    pub mask_expand_cap: usize,
    /// Maximum rectangles to return after merging.
    pub max_regions: usize,
    /// Maximum merge rounds over the five dimensions.
    pub merge_passes: usize,
}

impl Default for EnumOptions {
    fn default() -> Self {
        Self {
            max_cubes: 200_000,
            mask_expand_cap: 4096,
            max_regions: 40,
            merge_passes: 8,
        }
    }
}

/// The result of enumerating one set of packets.
#[derive(Clone, Debug, Default)]
pub struct Enumeration {
    /// Rectangles to show, largest first.
    pub regions: Vec<Region>,
    /// Exact size of the input set.
    pub total_packets: u128,
    /// Packets covered by [`Enumeration::regions`].
    pub shown_packets: u128,
    /// Rectangles dropped by the display cap.
    pub omitted_regions: usize,
    /// Packets in the input but not in [`Enumeration::regions`], for any reason:
    /// display cap, cube budget, or a cube too awkward to render exactly.
    pub omitted_packets: u128,
    /// Of the omitted packets, those in cubes that could not be rendered
    /// exactly within `mask_expand_cap`. Diagnostic only.
    pub unrenderable_packets: u128,
    /// Paths visited, for benchmarking.
    pub cubes_visited: usize,
    /// Rectangle count before merging, for benchmarking the merge pass.
    pub regions_before_merge: usize,
    /// Set when a work limit stopped the walk early. The output is then a
    /// strict subset of the input and must be reported as such.
    pub incomplete: bool,
}

impl Enumeration {
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty() && self.total_packets == 0
    }

    /// Compression achieved by the merge pass, for the benchmark output.
    pub fn merge_ratio(&self) -> f64 {
        if self.regions.is_empty() {
            return 1.0;
        }
        self.regions_before_merge as f64 / self.regions.len() as f64
    }
}

/// Expand a `(value, mask)` bit pattern into the exact set of values it denotes.
///
/// Bits set in `mask` are fixed to the corresponding bit of `value`; the rest are
/// free. The result is a union of intervals: every bit below the lowest fixed bit
/// contributes a contiguous run, and every free bit above it doubles the number
/// of runs. Returns `None` when that doubling exceeds `cap`.
fn mask_to_intervals(bits: u32, value: u64, mask: u64, cap: usize) -> Option<IntervalSet> {
    let domain = IntervalSet::domain_max(bits);
    let mask = mask & domain;
    if mask == 0 {
        return Some(IntervalSet::full(bits));
    }
    let value = value & mask;

    let lsb = mask & mask.wrapping_neg();
    let low_span = lsb - 1;
    let free_high = !mask & !low_span & domain;
    let k = free_high.count_ones();
    if k >= usize::BITS || (1usize << k) > cap {
        return None;
    }

    let positions: Vec<u32> = (0..bits).filter(|&p| free_high & (1u64 << p) != 0).collect();
    let mut ranges = Vec::with_capacity(1usize << k);
    for combo in 0..(1usize << k) {
        let mut scattered = 0u64;
        for (i, &p) in positions.iter().enumerate() {
            if (combo >> i) & 1 == 1 {
                scattered |= 1u64 << p;
            }
        }
        let base = value | scattered;
        ranges.push((base, base | low_span));
    }
    Some(IntervalSet::from_ranges(bits, ranges))
}

/// Values a `(value, mask)` pattern denotes, without building the intervals.
fn mask_count(bits: u32, mask: u64) -> u128 {
    1u128 << (bits - mask.count_ones())
}

/// Enumerate the packet set as readable rectangles.
pub fn enumerate(layout: &Layout, set: &Bdd, opts: EnumOptions) -> Enumeration {
    let mut out = Enumeration {
        total_packets: exact_cardinality(set),
        ..Default::default()
    };
    if set.is_false() {
        return out;
    }

    let mut raw: Vec<Region> = Vec::new();
    let mut skipped_packets: u128 = 0;

    for cube in set.sat_clauses() {
        if out.cubes_visited >= opts.max_cubes {
            out.incomplete = true;
            break;
        }
        out.cubes_visited += 1;

        let mut dims: [Option<IntervalSet>; 7] =
            [None, None, None, None, None, None, None];
        let mut cube_packets: u128 = 1;
        let mut usable = true;

        for f in Field::ALL {
            let (value, mask) = read_field(layout, &cube, f);
            cube_packets *= mask_count(f.bits(), mask);
            match mask_to_intervals(f.bits(), value, mask, opts.mask_expand_cap) {
                Some(is) => dims[f.index()] = Some(is),
                None => {
                    usable = false;
                    break;
                }
            }
        }

        if usable {
            let d = dims.map(|d| d.expect("all seven dimensions were filled"));
            raw.push(Region::from_dims(d));
        } else {
            // Exact rendering of this cube would need more intervals than the
            // cap allows. Account for it and say so, rather than widening it.
            skipped_packets += cube_packets;
            out.incomplete = true;
        }
    }

    out.regions_before_merge = raw.len();
    let mut regions = merge(raw, opts.merge_passes);

    // Largest first: a reviewer's attention should land on the widest change.
    regions.sort_by(|a, b| {
        b.count()
            .cmp(&a.count())
            .then_with(|| a.constrained_dims().cmp(&b.constrained_dims()))
            .then_with(|| a.cmp(b))
    });

    if regions.len() > opts.max_regions {
        let dropped = regions.split_off(opts.max_regions);
        out.omitted_regions = dropped.len();
    }

    // Rectangles are pairwise disjoint — cubes are root-to-one paths, which are
    // mutually exclusive, and merging replaces a group by the exact union of its
    // members — so the shown packets can simply be summed, and whatever is left
    // over is what the reader is not being shown. Deriving omission this way
    // rather than accumulating it keeps the books balanced no matter which limit
    // stopped the walk.
    out.shown_packets = regions.iter().map(Region::count).sum();
    out.omitted_packets = out.total_packets.saturating_sub(out.shown_packets);
    out.unrenderable_packets = skipped_packets;
    out.regions = regions;
    debug_assert_eq!(out.shown_packets + out.omitted_packets, out.total_packets);
    out
}

fn read_field(
    layout: &Layout,
    cube: &biodivine_lib_bdd::BddPartialValuation,
    field: Field,
) -> (u64, u64) {
    let w = field.bits();
    let mut value = 0u64;
    let mut mask = 0u64;
    for b in 0..w {
        if let Some(v) = cube.get_value(layout.var(field, b)) {
            // Bit `b` counts from the MSB; the numeric weight is the mirror.
            let weight = 1u64 << (w - 1 - b);
            mask |= weight;
            if v {
                value |= weight;
            }
        }
    }
    (value, mask)
}

/// Exact size of the packet set. The header space is 2^120, which fits `u128`.
pub fn exact_cardinality(set: &Bdd) -> u128 {
    set.exact_cardinality().to_string().parse::<u128>().unwrap_or(u128::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::VarOrder;

    #[test]
    fn mask_expansion_of_a_prefix_is_one_interval() {
        // Top 16 bits fixed to 0x0A01: exactly 10.1.0.0/16.
        let is = mask_to_intervals(32, 0x0A01_0000, 0xFFFF_0000, 64).unwrap();
        assert_eq!(is.ranges(), &[(0x0A01_0000, 0x0A01_FFFF)]);
    }

    #[test]
    fn mask_expansion_with_a_hole_splits() {
        // Bits 0..5 and bit 7 of the top octet fixed, bit 6 free: 0.x and 2.x.
        let value = 0u64;
        let mask = 0b1111_1101u64 << 24;
        let is = mask_to_intervals(32, value, mask, 64).unwrap();
        assert_eq!(is.ranges().len(), 2);
        assert_eq!(is.count(), 2 * (1 << 24));
    }

    #[test]
    fn mask_expansion_refuses_rather_than_approximates() {
        // Alternating fixed bits across a 16-bit field: 2^7 intervals needed.
        let mask = 0b1010_1010_1010_1010u64;
        assert!(mask_to_intervals(16, mask, mask, 8).is_none());
        assert!(mask_to_intervals(16, mask, mask, 256).is_some());
    }

    #[test]
    fn unconstrained_field_is_full() {
        let is = mask_to_intervals(16, 0, 0, 4).unwrap();
        assert!(is.is_full());
    }

    #[test]
    fn empty_set_enumerates_to_nothing() {
        let l = Layout::default();
        let e = enumerate(&l, &l.ff(), EnumOptions::default());
        assert!(e.regions.is_empty());
        assert_eq!(e.total_packets, 0);
        assert!(!e.incomplete);
    }

    #[test]
    fn whole_space_enumerates_to_one_rectangle() {
        for order in [VarOrder::FieldMajor, VarOrder::AddrInterleaved] {
            let l = Layout::new(order);
            let e = enumerate(&l, &l.tt(), EnumOptions::default());
            assert_eq!(e.regions.len(), 1);
            assert_eq!(e.total_packets, 1u128 << 120);
            assert_eq!(e.shown_packets, e.total_packets);
        }
    }

    /// The books must balance whichever limit stopped the walk. This is the
    /// invariant the thousand-rule benchmark broke on first run.
    #[test]
    fn accounting_balances_when_a_budget_stops_the_walk() {
        let l = Layout::default();
        // A set with many root-to-one paths: an eight-way source union.
        let mut b = l.ff();
        for i in 0..8u64 {
            b = b.or(&l.prefix(Field::SrcAddr, (10 + i * 17) << 24, 24));
        }
        b = b.and(&l.eq(Field::Proto, 6));

        for max_cubes in [1usize, 2, 3, 5, 1000] {
            let e = enumerate(&l, &b, EnumOptions { max_cubes, ..Default::default() });
            assert_eq!(
                e.shown_packets + e.omitted_packets,
                e.total_packets,
                "max_cubes {max_cubes}: books do not balance"
            );
            assert_eq!(e.incomplete, max_cubes < 8, "max_cubes {max_cubes}: wrong flag");
        }
    }

    #[test]
    fn accounting_balances_when_the_display_cap_truncates() {
        let l = Layout::default();
        let mut b = l.ff();
        for i in 0..20u64 {
            b = b.or(&l.eq(Field::DstAddr, 0x0A05_0000 | (i * 4099)).and(&l.eq(Field::DstPort, 1000 + i)));
        }
        let e = enumerate(&l, &b, EnumOptions { max_regions: 5, ..Default::default() });
        assert_eq!(e.regions.len(), 5);
        assert_eq!(e.omitted_regions, 15);
        assert_eq!(e.shown_packets + e.omitted_packets, e.total_packets);
        assert!(!e.incomplete, "a display cap is not an incomplete analysis");
    }

    #[test]
    fn cardinality_survives_the_round_trip() {
        let l = Layout::default();
        let b = l
            .prefix(Field::SrcAddr, 0x0A01_0000, 16)
            .and(&l.eq(Field::DstAddr, 0x0A00_050E))
            .and(&l.eq(Field::DstPort, 502))
            .and(&l.eq(Field::Proto, 6));
        let e = enumerate(&l, &b, EnumOptions::default());
        assert_eq!(e.total_packets, e.shown_packets);
        assert_eq!(e.omitted_packets, 0);
        assert!(!e.incomplete);
    }
}

// ---------------------------------------------------------------- projection

/// The dimensions a flow count keeps.
///
/// **Fixed, never adaptive.** Choosing the projection per run — say, dropping
/// whichever dimensions happen to be unconstrained in this delta — would make
/// two runs produce incomparable numbers, which destroys the one thing a count
/// is for. A number a reviewer cannot calibrate against is worse than none.
pub const FLOW_DIMS: [Field; 4] =
    [Field::SrcAddr, Field::DstAddr, Field::DstPort, Field::Proto];

/// The dimensions a flow count quantifies away.
pub const QUANTIFIED_DIMS: [Field; 3] = [Field::SrcPort, Field::IfIn, Field::IfOut];

/// Count distinct flows: `|∃ sport, iif, oif . set|`.
///
/// This is existential quantification, so it is exact rather than an estimate.
/// It answers a narrower question than the packet count — see `SEMANTICS.md`
/// section 4.4 — but it is the question a network engineer asks, and unlike the
/// raw 2^120 packet count it is a number a human can calibrate against.
pub fn flow_count(layout: &Layout, set: &Bdd) -> u128 {
    let mut projected = set.clone();
    let mut quantified_bits = 0u32;
    for f in QUANTIFIED_DIMS {
        quantified_bits += f.bits();
        for b in 0..f.bits() {
            let v = layout.var(f, b);
            // Existential quantification over one variable is the disjunction of
            // its two cofactors.
            projected = projected
                .restrict(&[(v, true)])
                .or(&projected.restrict(&[(v, false)]));
        }
    }
    // The result no longer depends on the quantified variables, so its
    // cardinality over the full space is exactly flows * 2^quantified_bits.
    exact_cardinality(&projected) >> quantified_bits
}

#[cfg(test)]
mod projection_tests {
    use super::*;

    #[test]
    fn the_projection_set_covers_every_dimension_exactly_once() {
        let mut seen: Vec<Field> = FLOW_DIMS.to_vec();
        seen.extend(QUANTIFIED_DIMS);
        seen.sort();
        let mut all = Field::ALL.to_vec();
        all.sort();
        assert_eq!(seen, all, "flow dims and quantified dims must partition the header");
    }

    #[test]
    fn one_flow_is_one_flow_however_many_packets_it_holds() {
        let l = Layout::default();
        // One src, one dst, one port, one protocol; source port left free.
        let one = l
            .eq(Field::SrcAddr, 0x0A01_0001)
            .and(&l.eq(Field::DstAddr, 0x0A05_000E))
            .and(&l.eq(Field::DstPort, 502))
            .and(&l.eq(Field::Proto, 6));
        assert_eq!(flow_count(&l, &one), 1);
        // 65536 source ports x 256 x 256 interface symbols.
        assert_eq!(exact_cardinality(&one), 1u128 << 32);
    }

    #[test]
    fn quantified_dimensions_do_not_multiply_the_count() {
        let l = Layout::default();
        let base = l.eq(Field::DstAddr, 0x0A05_0014).and(&l.eq(Field::Proto, 6));
        // Pinning a source port must not change how many flows there are.
        let pinned = base.and(&l.eq(Field::SrcPort, 44000));
        assert_eq!(flow_count(&l, &base), flow_count(&l, &pinned));
    }

    #[test]
    fn flows_scale_with_the_kept_dimensions() {
        let l = Layout::default();
        let hosts = l.prefix(Field::DstAddr, 0x0A05_0000, 24);
        let two_ports = l.eq(Field::DstPort, 80).or(&l.eq(Field::DstPort, 443));
        let set = hosts.and(&two_ports).and(&l.eq(Field::Proto, 6)).and(
            &l.prefix(Field::SrcAddr, 0x0A01_0000, 24),
        );
        // 256 sources x 256 destinations x 2 ports x 1 protocol.
        assert_eq!(flow_count(&l, &set), 256 * 256 * 2);
    }

    #[test]
    fn the_empty_set_has_no_flows() {
        let l = Layout::default();
        assert_eq!(flow_count(&l, &l.ff()), 0);
    }
}
