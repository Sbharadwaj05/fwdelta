//! Which dimensions the probes actually varied.
//!
//! The harness once passed 900 consecutive packets while a model that ignored
//! interfaces entirely would have passed them too, because every probe arrived
//! on `lo`. The generalisation is the important part:
//!
//! > **A dimension not varied across probes is untested, and the harness will
//! > report agreement anyway.**
//!
//! That is not a property of interfaces; it is a property of differential
//! testing. So rather than asserting coverage in a comment where it can rot,
//! this counts distinct values per dimension from the probes actually sent and
//! prints the result on every run. A dimension that has stopped varying becomes
//! visible immediately instead of after someone thinks to look.

use std::collections::BTreeSet;

/// Distinct values seen per dimension, accumulated across a whole run.
#[derive(Default)]
pub struct Coverage {
    pub src: BTreeSet<u32>,
    pub dst: BTreeSet<u32>,
    pub sport: BTreeSet<u16>,
    pub dport: BTreeSet<u16>,
    pub proto: BTreeSet<u64>,
    pub iif: BTreeSet<String>,
    /// Probes whose protocol carries no ports, so the port dimensions are free
    /// rather than constant. Counted separately so they do not read as coverage.
    pub portless: usize,
    pub probes: usize,
}

/// How a dimension fared.
pub enum Verdict {
    /// Varied across probes: differential testing can see a bug here.
    Exercised(usize),
    /// One value only. A model that ignored this dimension would still pass.
    Constant(String),
    /// Cannot vary given the hook under test, with the reason.
    NotApplicable(&'static str),
}

impl Coverage {
    pub fn record_iif(&mut self, name: &str) {
        self.iif.insert(name.to_string());
    }

    pub fn rows(&self) -> Vec<(&'static str, Verdict)> {
        fn judge<T: std::fmt::Debug>(set: &BTreeSet<T>) -> Verdict {
            match set.len() {
                0 => Verdict::Constant("no values".into()),
                1 => Verdict::Constant(format!("{:?}", set.iter().next().unwrap())),
                n => Verdict::Exercised(n),
            }
        }
        vec![
            ("source address", judge(&self.src)),
            ("destination address", judge(&self.dst)),
            ("source port", judge(&self.sport)),
            ("destination port", judge(&self.dport)),
            ("protocol", judge(&self.proto)),
            ("input interface", judge(&self.iif)),
            (
                "output interface",
                Verdict::NotApplicable("never set on the input hook; needs an output-hook harness"),
            ),
        ]
    }

    /// True when every dimension that can vary did. The run fails otherwise, so
    /// that a silently narrowing generator cannot masquerade as a passing suite.
    pub fn complete(&self) -> bool {
        self.rows().iter().all(|(_, v)| !matches!(v, Verdict::Constant(_)))
    }

    pub fn report(&self) -> String {
        let mut out = format!("dimension coverage across {} probes:\n", self.probes);
        for (name, v) in self.rows() {
            let line = match v {
                Verdict::Exercised(n) => format!("  {name:<22} {n:>5} distinct"),
                Verdict::Constant(what) => {
                    format!("  {name:<22} {:>5}          HELD CONSTANT at {what} -- untested", 1)
                }
                Verdict::NotApplicable(why) => {
                    format!("  {name:<22} {:>5}          not applicable: {why}", "-")
                }
            };
            out.push_str(&line);
            out.push('\n');
        }
        if self.portless > 0 {
            out.push_str(&format!(
                "  ({} probes carried no ports; those dimensions were free, not constant)\n",
                self.portless
            ));
        }
        out
    }
}
