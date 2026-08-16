//! Terminal rendering of a [`DiffReport`].
//!
//! A pure function of the model. Nothing is decided here — ordering, hoisting,
//! attribution and omission accounting all happened in [`super::build`], so this
//! and the HTML renderer cannot disagree about what the findings are.

use super::{DiffReport, DirectionReport, StructuralRow};
use crate::render;

/// The whole report, in the blueprint's shape.
pub fn render(r: &DiffReport) -> String {
    let mut out = format!("RULESET DELTA  base {} .. head {}\n", r.base_label, r.head_label);

    let multi = r.chains.len() > 1;
    for (i, chain) in r.chains.iter().enumerate() {
        if multi {
            out.push_str(&format!("\n{}CHAIN {}\n", if i > 0 { "\n" } else { "" }, chain.name));
        }
        out.push('\n');
        out.push_str(&direction(&chain.blocked));
        out.push('\n');
        out.push_str(&direction(&chain.allowed));

        if !chain.structural.is_empty() {
            out.push('\n');
            out.push_str(&structural(&chain.structural));
        }
    }

    for n in &r.notes {
        out.push_str(&format!("\n{n}\n"));
    }

    if !r.assertions.is_empty() {
        out.push('\n');
        out.push_str(&intent(r));
    }

    if r.traffic_lost() {
        out.push_str(
            "\nTraffic lost access. This does not block the build; pass \
             --fail-on-newly-blocked if it should.\n",
        );
    }
    out
}

fn direction(d: &DirectionReport) -> String {
    let (title, subtitle) = d.direction.heading();
    let mut out = format!("{title}  {subtitle}\n");

    if d.is_empty() {
        out.push_str("  none\n");
        return out;
    }

    if !d.qualifiers.is_empty() {
        out.push_str(&format!("  all entries: {}\n", d.qualifiers.join(", ")));
    }
    out.push_str(&render::table(&d.rows, "  "));
    out.push_str(&format!(
        "  {} flows  ({})\n",
        render::count(d.flows),
        DirectionReport::PROJECTION
    ));

    if d.omitted_rows > 0 {
        out.push_str(&format!(
            "  ... {} further {} omitted, covering {} flows\n",
            d.omitted_rows,
            if d.omitted_rows == 1 { "entry" } else { "entries" },
            render::count(d.omitted_flows)
        ));
    }
    if d.cells_truncated {
        out.push_str("  ... attribution cell cap reached; some of the delta is not listed\n");
    }
    if d.incomplete {
        out.push_str("  WARNING: enumeration hit a work limit; the list above is incomplete\n");
    }
    out
}

fn structural(rows: &[StructuralRow]) -> String {
    let lines: Vec<(String, &str)> = rows
        .iter()
        .map(|r| (format!("rule {:02}  {}", r.number, r.what), r.why.as_str()))
        .collect();
    let width = lines.iter().map(|(l, _)| l.len()).max().unwrap_or(0);

    let mut out = String::from("STRUCTURAL\n");
    for (left, right) in lines {
        out.push_str(format!("  {left:<width$}  {right}").trim_end());
        out.push('\n');
    }
    out
}

fn intent(r: &DiffReport) -> String {
    let width = r.assertions.iter().map(|a| a.name.len()).max().unwrap_or(0);
    let mut out = String::from("INTENT\n");
    for a in &r.assertions {
        out.push_str(&format!("  {:<7} {:<width$}  {}\n", a.outcome, a.name, a.detail));
        if a.is_fail() {
            out.push_str(&format!(
                "  {:<7} {:<width$}  required by assertion {}\n",
                "", "", a.name
            ));
        }
    }

    out.push_str(&format!("\n{} assertions checked", r.assertions.len()));
    if r.failed() > 0 {
        out.push_str(&format!(", {} failed", r.failed()));
    }
    if r.vacuous() > 0 {
        // Named separately and never folded into the pass count: a vacuous
        // assertion held trivially and established nothing.
        out.push_str(&format!(", {} vacuous", r.vacuous()));
    }
    out.push_str(".\n");
    out
}
