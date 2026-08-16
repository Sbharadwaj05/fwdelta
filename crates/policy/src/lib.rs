//! Intent assertions and the zone vocabulary.
//!
//! An assertion is a declarative claim about which packets may flow, checked
//! against the model as pass or fail with a counterexample. Zones name address
//! sets so a claim can be written in the language of IEC 62443 rather than in
//! CIDRs — and, per decision D-02, zones are purely a naming layer resolved
//! here. The engine never learns what a zone is.
//!
//! # Why an assertion can be neither pass nor fail
//!
//! An isolation assertion over addresses no rule mentions passes trivially, and
//! that pass means nothing. It is what happens the first time someone typos a
//! CIDR in a zone definition, and it is worse than a failure: a red result gets
//! investigated, a green one gets merged. [`Outcome::Vacuous`] exists so that
//! case is reported as its own thing and, by default, fails the run.
//!
//! The parser for this file is a real TOML library, not a hand-written subset.
//! Decision D-08 records why: a subset that misreads valid input makes an
//! assertion silently mean something other than what was written, which is the
//! same failure class as a frontend silently skipping a rule, except that it
//! produces a green isolation check instead of a loud error.

#![forbid(unsafe_code)]

pub mod eval;
pub mod parse;

pub use eval::{Outcome, Report, evaluate};
pub use parse::{Assertion, Endpoint, Kind, Policy, PolicyError};
