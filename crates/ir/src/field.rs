//! The match dimensions of the packet header space.
//!
//! Seven dimensions, 120 bits. Five are packet header fields in the ordinary
//! sense. Two are interface identity, which is not a header field at all but a
//! property of how the packet arrived; see [`crate::interface`] for why it is
//! modelled symbolically and why it must be a dimension rather than something
//! the frontend resolves away.

use core::fmt;

/// One match dimension.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Field {
    SrcAddr,
    DstAddr,
    SrcPort,
    DstPort,
    Proto,
    /// Input interface symbol.
    IfIn,
    /// Output interface symbol.
    IfOut,
}

impl Field {
    pub const ALL: [Field; 7] = [
        Field::SrcAddr,
        Field::DstAddr,
        Field::SrcPort,
        Field::DstPort,
        Field::Proto,
        Field::IfIn,
        Field::IfOut,
    ];

    /// Field width in bits. These seven sum to [`HEADER_BITS`].
    #[inline]
    pub const fn bits(self) -> u32 {
        match self {
            Field::SrcAddr | Field::DstAddr => 32,
            Field::SrcPort | Field::DstPort => 16,
            Field::Proto | Field::IfIn | Field::IfOut => 8,
        }
    }

    #[inline]
    pub const fn index(self) -> usize {
        match self {
            Field::SrcAddr => 0,
            Field::DstAddr => 1,
            Field::SrcPort => 2,
            Field::DstPort => 3,
            Field::Proto => 4,
            Field::IfIn => 5,
            Field::IfOut => 6,
        }
    }

    /// Short tag used in BDD variable names.
    #[inline]
    pub const fn short(self) -> &'static str {
        match self {
            Field::SrcAddr => "sa",
            Field::DstAddr => "da",
            Field::SrcPort => "sp",
            Field::DstPort => "dp",
            Field::Proto => "pr",
            Field::IfIn => "ii",
            Field::IfOut => "oi",
        }
    }

    /// True for the two interface dimensions, which render by name.
    #[inline]
    pub const fn is_interface(self) -> bool {
        matches!(self, Field::IfIn | Field::IfOut)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Field::SrcAddr => "saddr",
            Field::DstAddr => "daddr",
            Field::SrcPort => "sport",
            Field::DstPort => "dport",
            Field::Proto => "protocol",
            Field::IfIn => "iifname",
            Field::IfOut => "oifname",
        };
        f.write_str(s)
    }
}

/// Total width of the header space.
///
/// Blueprint revision 0.1 said 104. The two interface dimensions were promoted
/// to first-class in decision D-02, because resolving an interface to an address
/// set requires host configuration the tool is forbidden from reading.
pub const HEADER_BITS: u32 = 120;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_sum_to_the_header() {
        assert_eq!(Field::ALL.iter().map(|f| f.bits()).sum::<u32>(), HEADER_BITS);
    }

    #[test]
    fn indices_are_dense_and_unique() {
        let mut seen = [false; 7];
        for f in Field::ALL {
            assert!(!seen[f.index()]);
            seen[f.index()] = true;
        }
        assert!(seen.iter().all(|&s| s));
    }
}
