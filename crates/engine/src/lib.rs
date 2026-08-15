//! Soteria engine: header-space encoding, set algebra and enumeration.
//!
//! This crate is deliberately free of any notion of a file, a parser or a rule
//! syntax. It knows about packets, sets of packets, and how to say what is in a
//! set out loud. The frontend and the diff sit on top of it later.
//!
//! Nothing here performs I/O of any kind.

#![forbid(unsafe_code)]

pub mod enumerate;
pub mod header;
pub mod intervals;
pub mod region;
pub mod render;

pub use enumerate::{EnumOptions, Enumeration, enumerate, exact_cardinality};
pub use header::{Field, HEADER_BITS, Layout, VarOrder};
pub use intervals::IntervalSet;
pub use region::Region;
