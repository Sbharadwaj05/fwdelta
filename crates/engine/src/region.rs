//! Rectangles in the five-dimensional match space.
//!
//! A [`Region`] is a product set: one interval set per dimension. Products are
//! the shape a human reads — "these sources, to these destinations, on these
//! ports" — and they are closed under the merge operation, because two products
//! that agree on four dimensions union cleanly on the fifth.

use std::collections::HashMap;

use biodivine_lib_bdd::Bdd;

use soteria_ir::{Field, IntervalSet};

use crate::header::Layout;

/// A product of five interval sets: one rectangle of packet space.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct Region {
    dims: [IntervalSet; 7],
}

impl Region {
    /// The whole header space.
    pub fn full() -> Self {
        Self {
            dims: [
                IntervalSet::full(Field::SrcAddr.bits()),
                IntervalSet::full(Field::DstAddr.bits()),
                IntervalSet::full(Field::SrcPort.bits()),
                IntervalSet::full(Field::DstPort.bits()),
                IntervalSet::full(Field::Proto.bits()),
                IntervalSet::full(Field::IfIn.bits()),
                IntervalSet::full(Field::IfOut.bits()),
            ],
        }
    }

    pub fn from_dims(dims: [IntervalSet; 7]) -> Self {
        Self { dims }
    }

    #[inline]
    pub fn get(&self, field: Field) -> &IntervalSet {
        &self.dims[field.index()]
    }

    #[inline]
    pub fn with(mut self, field: Field, set: IntervalSet) -> Self {
        self.dims[field.index()] = set;
        self
    }

    #[inline]
    pub(crate) fn dim_mut(&mut self, i: usize) -> &mut IntervalSet {
        &mut self.dims[i]
    }

    #[inline]
    pub(crate) fn dim(&self, i: usize) -> &IntervalSet {
        &self.dims[i]
    }

    pub fn is_empty(&self) -> bool {
        self.dims.iter().any(IntervalSet::is_empty)
    }

    /// Number of packets the rectangle covers. Bounded by 2^104, so `u128`.
    pub fn count(&self) -> u128 {
        if self.is_empty() {
            return 0;
        }
        self.dims.iter().map(IntervalSet::count).product()
    }

    /// How many dimensions are constrained at all. Used only for tie-breaking
    /// the display order, so that broader entries read first.
    pub fn constrained_dims(&self) -> usize {
        self.dims.iter().filter(|d| !d.is_full()).count()
    }

    /// Rebuild the rectangle as a BDD. The enumerator's correctness test is that
    /// the union of these equals the diagram it started from.
    pub fn to_bdd(&self, layout: &Layout) -> Bdd {
        let mut acc = layout.tt();
        for f in Field::ALL {
            acc = acc.and(&layout.set(f, self.get(f)));
        }
        acc
    }
}

/// Merge rectangles that differ in exactly one dimension, to a fixed point.
///
/// Rather than testing pairs, this groups by "the other four dimensions" and
/// unions a whole group at once, which subsumes pairwise merging and costs one
/// hash pass per dimension. Cycling the five dimensions until the count stops
/// falling converges in a handful of rounds on real deltas.
pub fn merge(mut regions: Vec<Region>, max_passes: usize) -> Vec<Region> {
    regions.retain(|r| !r.is_empty());
    regions.sort_unstable();
    regions.dedup();

    for _ in 0..max_passes {
        let before = regions.len();
        for d in 0..7 {
            regions = merge_along(regions, d);
        }
        if regions.len() == before {
            break;
        }
    }
    regions
}

fn merge_along(regions: Vec<Region>, d: usize) -> Vec<Region> {
    let mut seen: HashMap<[IntervalSet; 6], usize> = HashMap::with_capacity(regions.len());
    let mut out: Vec<Region> = Vec::with_capacity(regions.len());

    for r in regions {
        let mut key: [IntervalSet; 6] = [
            IntervalSet::empty(0),
            IntervalSet::empty(0),
            IntervalSet::empty(0),
            IntervalSet::empty(0),
            IntervalSet::empty(0),
            IntervalSet::empty(0),
        ];
        let mut k = 0;
        for i in 0..7 {
            if i != d {
                key[k] = r.dim(i).clone();
                k += 1;
            }
        }
        match seen.get(&key) {
            Some(&idx) => {
                let merged = out[idx].dim(d).union(r.dim(d));
                *out[idx].dim_mut(d) = merged;
            }
            None => {
                seen.insert(key, out.len());
                out.push(r);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(v: u64, len: u32) -> IntervalSet {
        IntervalSet::prefix(32, v, len)
    }

    #[test]
    fn full_region_covers_the_whole_space() {
        assert_eq!(Region::full().count(), 1u128 << 120);
        assert_eq!(Region::full().constrained_dims(), 0);
    }

    #[test]
    fn two_ports_on_one_destination_collapse_to_one_region() {
        let base = Region::full()
            .with(Field::DstAddr, addr(0x0A00050E, 32))
            .with(Field::Proto, IntervalSet::point(8, 6));
        let a = base.clone().with(Field::DstPort, IntervalSet::point(16, 502));
        let b = base.clone().with(Field::DstPort, IntervalSet::point(16, 443));

        let merged = merge(vec![a, b], 8);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].get(Field::DstPort).ranges(), &[(443, 443), (502, 502)]);
    }

    #[test]
    fn adjacent_ports_coalesce_into_a_range() {
        let base = Region::full().with(Field::Proto, IntervalSet::point(8, 6));
        let regions: Vec<Region> = (1000..1010)
            .map(|p| base.clone().with(Field::DstPort, IntervalSet::point(16, p)))
            .collect();
        let merged = merge(regions, 8);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].get(Field::DstPort).ranges(), &[(1000, 1009)]);
    }

    #[test]
    fn regions_differing_in_two_dimensions_do_not_merge() {
        let a = Region::full()
            .with(Field::DstAddr, addr(0x0A000001, 32))
            .with(Field::DstPort, IntervalSet::point(16, 22));
        let b = Region::full()
            .with(Field::DstAddr, addr(0x0A000002, 32))
            .with(Field::DstPort, IntervalSet::point(16, 23));
        assert_eq!(merge(vec![a, b], 8).len(), 2);
    }

    #[test]
    fn merging_preserves_packet_count_when_disjoint() {
        let base = Region::full().with(Field::SrcAddr, addr(0x0A010000, 16));
        let a = base.clone().with(Field::DstPort, IntervalSet::point(16, 80));
        let b = base.clone().with(Field::DstPort, IntervalSet::point(16, 443));
        let total: u128 = a.count() + b.count();
        let merged = merge(vec![a, b], 8);
        assert_eq!(merged.iter().map(Region::count).sum::<u128>(), total);
    }
}
