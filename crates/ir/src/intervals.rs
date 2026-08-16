//! Normalised sets of integer intervals over a fixed-width unsigned domain.
//!
//! Every match dimension in the header space is an unsigned integer field, so
//! one interval-set type serves addresses (32 bit), ports (16 bit) and protocol
//! (8 bit). The representation is canonical: ranges are sorted, disjoint and
//! never adjacent, so structural equality is set equality. The enumerator's
//! merge pass depends on that property.

use core::fmt;

/// A set of values over `[0, 2^bits - 1]`, stored as sorted disjoint ranges.
///
/// Both endpoints are inclusive. The canonical form makes `PartialEq` and
/// `Hash` agree with set semantics, which is what lets the merge pass group
/// regions by "the other four dimensions" with a hash map.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct IntervalSet {
    bits: u32,
    ranges: Vec<(u64, u64)>,
}

impl IntervalSet {
    /// Largest representable value in a `bits`-wide field.
    #[inline]
    pub const fn domain_max(bits: u32) -> u64 {
        if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 }
    }

    /// The empty set over a `bits`-wide field.
    pub const fn empty(bits: u32) -> Self {
        Self { bits, ranges: Vec::new() }
    }

    /// Every value of a `bits`-wide field.
    pub fn full(bits: u32) -> Self {
        Self { bits, ranges: vec![(0, Self::domain_max(bits))] }
    }

    /// A single value.
    pub fn point(bits: u32, v: u64) -> Self {
        debug_assert!(v <= Self::domain_max(bits));
        Self { bits, ranges: vec![(v, v)] }
    }

    /// One inclusive range. Returns the empty set if `lo > hi`.
    pub fn range(bits: u32, lo: u64, hi: u64) -> Self {
        if lo > hi {
            return Self::empty(bits);
        }
        let max = Self::domain_max(bits);
        Self { bits, ranges: vec![(lo.min(max), hi.min(max))] }
    }

    /// Build from arbitrary, possibly overlapping ranges.
    pub fn from_ranges(bits: u32, mut ranges: Vec<(u64, u64)>) -> Self {
        ranges.retain(|(lo, hi)| lo <= hi);
        let max = Self::domain_max(bits);
        for r in &mut ranges {
            r.0 = r.0.min(max);
            r.1 = r.1.min(max);
        }
        ranges.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (lo, hi) in ranges {
            match out.last_mut() {
                // `hi + 1` cannot overflow: hi <= domain_max <= u64::MAX only
                // when bits >= 64, which no header field uses.
                Some(last) if lo <= last.1.saturating_add(1) => {
                    if hi > last.1 {
                        last.1 = hi;
                    }
                }
                _ => out.push((lo, hi)),
            }
        }
        Self { bits, ranges: out }
    }

    /// An IPv4 prefix, as a range. `len` is the prefix length in bits.
    pub fn prefix(bits: u32, value: u64, len: u32) -> Self {
        assert!(len <= bits, "prefix length {len} exceeds field width {bits}");
        let host_bits = bits - len;
        let base = if host_bits >= 64 { 0 } else { (value >> host_bits) << host_bits };
        let span = if host_bits >= 64 { u64::MAX } else { (1u64 << host_bits) - 1 };
        Self { bits, ranges: vec![(base, base | span)] }
    }

    #[inline]
    pub fn bits(&self) -> u32 {
        self.bits
    }

    #[inline]
    pub fn ranges(&self) -> &[(u64, u64)] {
        &self.ranges
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// True when the set covers the whole field, i.e. the dimension is unconstrained.
    pub fn is_full(&self) -> bool {
        matches!(self.ranges.as_slice(), [(0, hi)] if *hi == Self::domain_max(self.bits))
    }

    /// Number of values in the set. A 32-bit field can hold 2^32 values, so the
    /// count needs more than 32 bits.
    pub fn count(&self) -> u128 {
        self.ranges.iter().map(|&(lo, hi)| (hi - lo) as u128 + 1).sum()
    }

    pub fn contains(&self, v: u64) -> bool {
        self.ranges.iter().any(|&(lo, hi)| lo <= v && v <= hi)
    }

    pub fn union(&self, other: &Self) -> Self {
        debug_assert_eq!(self.bits, other.bits);
        let mut all = self.ranges.clone();
        all.extend_from_slice(&other.ranges);
        Self::from_ranges(self.bits, all)
    }

    pub fn intersect(&self, other: &Self) -> Self {
        debug_assert_eq!(self.bits, other.bits);
        let (mut i, mut j) = (0usize, 0usize);
        let mut out = Vec::new();
        while i < self.ranges.len() && j < other.ranges.len() {
            let a = self.ranges[i];
            let b = other.ranges[j];
            let lo = a.0.max(b.0);
            let hi = a.1.min(b.1);
            if lo <= hi {
                out.push((lo, hi));
            }
            if a.1 < b.1 { i += 1 } else { j += 1 }
        }
        // Inputs are canonical and the sweep emits in order, so no re-merge is needed.
        Self { bits: self.bits, ranges: out }
    }

    /// Set complement within the field domain.
    pub fn complement(&self) -> Self {
        let max = Self::domain_max(self.bits);
        let mut out = Vec::with_capacity(self.ranges.len() + 1);
        let mut cursor: u64 = 0;
        for &(lo, hi) in &self.ranges {
            if lo > cursor {
                out.push((cursor, lo - 1));
            }
            if hi == max {
                return Self { bits: self.bits, ranges: out };
            }
            cursor = hi + 1;
        }
        out.push((cursor, max));
        Self { bits: self.bits, ranges: out }
    }

    pub fn difference(&self, other: &Self) -> Self {
        self.intersect(&other.complement())
    }

    /// Smallest range covering the whole set, or `None` when empty.
    pub fn hull(&self) -> Option<(u64, u64)> {
        match (self.ranges.first(), self.ranges.last()) {
            (Some(f), Some(l)) => Some((f.0, l.1)),
            _ => None,
        }
    }
}

impl fmt::Display for IntervalSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_empty() {
            return write!(f, "<empty>");
        }
        for (i, &(lo, hi)) in self.ranges.iter().enumerate() {
            if i > 0 {
                write!(f, ",")?;
            }
            if lo == hi {
                write!(f, "{lo}")?;
            } else {
                write!(f, "{lo}-{hi}")?;
            }
        }
        Ok(())
    }
}

/// Decompose an inclusive range into the minimal cover of aligned CIDR blocks.
///
/// Arithmetic is in `u64` so that the full 32-bit domain (span `2^32`) does not
/// overflow at the `0.0.0.0/0` boundary.
pub fn range_to_prefixes(bits: u32, lo: u64, hi: u64) -> Vec<(u64, u32)> {
    let mut out = Vec::new();
    let mut cur = lo;
    while cur <= hi {
        // Largest block the alignment of `cur` permits.
        let align = if cur == 0 { bits } else { cur.trailing_zeros().min(bits) };
        // Largest block that still fits inside the remaining span.
        let remaining = hi - cur + 1;
        let span_pow = 63 - remaining.leading_zeros();
        let n = align.min(span_pow).min(bits);
        out.push((cur, bits - n));
        let step = 1u64 << n;
        match cur.checked_add(step) {
            Some(next) => cur = next,
            None => break,
        }
    }
    out
}

/// Minimal CIDR cover of a whole interval set.
pub fn set_to_prefixes(set: &IntervalSet) -> Vec<(u64, u32)> {
    set.ranges().iter().flat_map(|&(lo, hi)| range_to_prefixes(set.bits(), lo, hi)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalisation_merges_overlap_and_adjacency() {
        let s = IntervalSet::from_ranges(16, vec![(10, 20), (21, 30), (5, 7), (15, 25)]);
        assert_eq!(s.ranges(), &[(5, 7), (10, 30)]);
    }

    #[test]
    fn complement_round_trips() {
        let s = IntervalSet::from_ranges(16, vec![(10, 20), (100, 200)]);
        assert_eq!(s.complement().complement(), s);
        assert!(s.union(&s.complement()).is_full());
        assert!(s.intersect(&s.complement()).is_empty());
    }

    #[test]
    fn full_domain_counts() {
        assert_eq!(IntervalSet::full(32).count(), 1u128 << 32);
        assert_eq!(IntervalSet::full(8).count(), 256);
        assert!(IntervalSet::full(32).complement().is_empty());
    }

    #[test]
    fn prefix_bounds() {
        let p = IntervalSet::prefix(32, 0x0A010000, 16);
        assert_eq!(p.ranges(), &[(0x0A010000, 0x0A01FFFF)]);
        let d = IntervalSet::prefix(32, 0, 0);
        assert!(d.is_full());
        let h = IntervalSet::prefix(32, 0x0A00050E, 32);
        assert_eq!(h.count(), 1);
    }

    #[test]
    fn default_route_decomposes_to_one_block() {
        let cidrs = range_to_prefixes(32, 0, u32::MAX as u64);
        assert_eq!(cidrs, vec![(0, 0)]);
    }

    #[test]
    fn slash_sixteen_minus_slash_twentyfour() {
        let base = IntervalSet::prefix(32, 0x0A050000, 16);
        let hole = IntervalSet::prefix(32, 0x0A050300, 24);
        let d = base.difference(&hole);
        assert_eq!(d.count(), 65536 - 256);
        assert_eq!(d.ranges().len(), 2);
    }
}
