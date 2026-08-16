//! nftables frontend.
//!
//! Reads a documented subset of nftables and produces `fwdelta-ir`. The subset
//! is published as `docs/NFTABLES-SUBSET.md` and everything outside it is a hard
//! error naming the file, line and column.
//!
//! The boundary is the point. A hand-written parser without a written boundary
//! grows indefinitely, and a construct the frontend quietly drops produces a
//! model that confidently disagrees with the kernel — the worst outcome
//! available to a verification tool.

#![forbid(unsafe_code)]

pub mod error;
pub mod lex;
pub mod parse;

pub use error::{Cause, ParseError};
pub use parse::parse;
