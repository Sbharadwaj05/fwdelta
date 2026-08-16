//! Soteria engine: header-space encoding, set algebra and enumeration.
//!
//! This crate knows about packets, sets of packets, and how to say what is in a
//! set out loud. It consumes `soteria-ir` and knows nothing about file syntax.
//!
//! Nothing here performs I/O of any kind.

#![forbid(unsafe_code)]

pub mod accept;
pub mod diff;
pub mod enumerate;
pub mod header;
pub mod region;
pub mod render;
pub mod report;

pub use accept::{ChainModel, Decider, RuleModel, analyse};
pub use diff::{Attribution, ChainDiff, Structural, attribute, diff};
pub use enumerate::{
    EnumOptions, Enumeration, FLOW_DIMS, QUANTIFIED_DIMS, enumerate, exact_cardinality, flow_count,
};
pub use header::{Layout, VarOrder};
pub use region::Region;
pub use report::{ReportOptions, render_diff};

// Re-exported so downstream crates need one import for the common vocabulary.
pub use soteria_ir::{Field, HEADER_BITS, IntervalSet, SymbolTable};
