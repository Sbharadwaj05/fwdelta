//! The primary artifact: what a reviewer reads.
//!
//! Blueprint section 02 is blunt that this output *is* the product and
//! everything else exists to produce it. The format follows the blueprint's
//! sample, with one addition: findings name the rule responsible on both sides
//! rather than only the base side. "Was allowed by rule 14" says what broke;
//! "now denied by rule 22" says where to go and look, and the partition makes
//! both exact rather than guesswork.

use soteria_ir::SymbolTable;

use crate::accept::{ChainModel, Decider};
use crate::diff::{ChainDiff, Structural, attribute};
use crate::enumerate::{EnumOptions, enumerate, flow_count};
use crate::header::Layout;
use crate::render::{self, Row, Style};

/// Which way a delta runs. Only the wording differs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Direction {
    Blocked,
    Allowed,
}

impl Direction {
    fn heading(self) -> (&'static str, &'static str) {
        match self {
            Direction::Blocked => ("NEWLY BLOCKED", "(permitted before, denied now)"),
            Direction::Allowed => ("NEWLY ALLOWED", "(denied before, permitted now)"),
        }
    }

    fn note(self, was: Decider, now: Decider) -> String {
        match self {
            Direction::Blocked => format!("was allowed by {was}, now denied by {now}"),
            Direction::Allowed => format!("was denied by {was}, now allowed by {now}"),
        }
    }
}

/// Knobs for rendering a report.
#[derive(Clone, Copy, Debug)]
pub struct ReportOptions {
    pub style: Style,
    pub enumeration: EnumOptions,
    /// Cap on attribution cells per direction.
    pub max_cells: usize,
    /// Cap on printed lines per direction, applied after global size ordering.
    pub max_rows: usize,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            style: Style::default(),
            enumeration: EnumOptions::default(),
            max_cells: 64,
            max_rows: 12,
        }
    }
}

fn direction_section(
    layout: &Layout,
    syms: &SymbolTable,
    base: &ChainModel,
    head: &ChainModel,
    delta: &biodivine_lib_bdd::Bdd,
    dir: Direction,
    opts: &ReportOptions,
) -> String {
    let (title, subtitle) = dir.heading();
    let mut out = format!("{title}  {subtitle}\n");

    if delta.is_false() {
        out.push_str("  none\n");
        return out;
    }

    let (cells, truncated) = attribute(base, head, delta, opts.max_cells);
    let mut found: Vec<(u128, crate::region::Region, Row)> = Vec::new();
    let mut omitted_regions = 0usize;
    let mut omitted_packets = 0u128;
    let mut incomplete = false;

    for cell in &cells {
        let e = enumerate(layout, &cell.set, opts.enumeration);
        let note = dir.note(cell.was, cell.now);
        found.extend(
            e.regions
                .iter()
                .map(|r| (r.count(), r.clone(), render::row(r, &note, syms, &opts.style))),
        );
        omitted_regions += e.omitted_regions;
        omitted_packets += e.omitted_packets;
        incomplete |= e.incomplete;
    }

    // Order by breadth across every cell, not within each one. Sorting per cell
    // lets a narrow finding from an early rule lead while the widest change in
    // the diff sits halfway down the page.
    found.sort_by_key(|(count, _, _)| std::cmp::Reverse(*count));
    let mut omitted_flows = 0u128;
    if found.len() > opts.max_rows {
        let dropped = found.split_off(opts.max_rows);
        omitted_regions += dropped.len();
        omitted_packets += dropped.iter().map(|(n, _, _)| *n).sum::<u128>();

        // Flow counts are a projection, and projections do not add: two
        // rectangles that differ only in source port are disjoint as packet
        // sets and collapse to the same flow. Summing per-rectangle flow counts
        // would therefore overstate the remainder. Rebuild the union and
        // project that instead.
        let mut union = layout.ff();
        for (_, region, _) in &dropped {
            union = union.or(&region.to_bdd(layout));
        }
        omitted_flows = flow_count(layout, &union);
    }
    let mut rows: Vec<Row> = found.into_iter().map(|(_, _, r)| r).collect();

    // Anything identical on every line is a qualifier on the section, not a
    // column. Repeating `in not lo` down the page costs width and says nothing.
    let mut qualifiers: Vec<String> = Vec::new();
    hoist(&mut rows, &mut qualifiers, |r| &mut r.iif);
    hoist(&mut rows, &mut qualifiers, |r| &mut r.oif);
    hoist(&mut rows, &mut qualifiers, |r| &mut r.proto);
    if !qualifiers.is_empty() {
        out.push_str(&format!("  all entries: {}\n", qualifiers.join(", ")));
    }

    out.push_str(&render::table(&rows, "  "));

    // The headline magnitude is a flow count, not a packet count. Both are
    // exact; the packet count is simply uncalibratable, because roughly sixteen
    // million of any figure it produces comes from source port and the two
    // interface dimensions, which almost nothing constrains. The projection is
    // existential quantification and its membership is fixed, so two runs are
    // always comparable. The exact 120-bit figure goes to the JSON path.
    out.push_str(&format!(
        "  {} flows  (src, dst, dport, proto; sport/iif/oif quantified)\n",
        render::count(flow_count(layout, delta))
    ));
    if omitted_regions > 0 {
        // Reported in flows, matching the headline. Mixing units across two
        // adjacent lines invites a reader to compare figures that are not
        // comparable.
        let _ = omitted_packets;
        out.push_str(&format!(
            "  ... {omitted_regions} further {} omitted, covering {} flows\n",
            if omitted_regions == 1 { "entry" } else { "entries" },
            render::count(omitted_flows)
        ));
    }
    if truncated {
        out.push_str("  ... attribution cell cap reached; some of the delta is not listed\n");
    }
    if incomplete {
        out.push_str("  WARNING: enumeration hit a work limit; the list above is incomplete\n");
    }
    out
}

/// Move a column into the section qualifier when every row agrees on it.
fn hoist(rows: &mut [Row], qualifiers: &mut Vec<String>, field: fn(&mut Row) -> &mut String) {
    if rows.len() < 2 {
        return;
    }
    let first = field(&mut rows[0]).clone();
    if first.is_empty() || first == "any" {
        return;
    }
    if !rows.iter_mut().all(|r| *field(r) == first) {
        return;
    }
    qualifiers.push(first);
    for r in rows.iter_mut() {
        field(r).clear();
    }
}

fn structural_section(changes: &[Structural]) -> String {
    if changes.is_empty() {
        return String::new();
    }
    let mut lines: Vec<(String, String)> = Vec::new();
    for c in changes {
        let (what, why) = match c {
            Structural::NowReachable { previously_covered_by, .. } => (
                "now reachable".to_string(),
                match previously_covered_by.as_slice() {
                    [] => String::new(),
                    [one] => format!("previously shadowed by rule {one:02}"),
                    many => format!(
                        "previously shadowed by rules {}",
                        many.iter().map(|n| format!("{n:02}")).collect::<Vec<_>>().join(", ")
                    ),
                },
            ),
            Structural::NowUnreachable { covered_by, .. } => (
                "now unreachable".to_string(),
                match covered_by.as_slice() {
                    [] => String::new(),
                    [one] => format!("fully covered by rule {one:02}"),
                    many => format!(
                        "fully covered by rules {}",
                        many.iter().map(|n| format!("{n:02}")).collect::<Vec<_>>().join(", ")
                    ),
                },
            ),
            Structural::NowRedundant { .. } => (
                "now redundant".to_string(),
                "removing it would not change the accept set".to_string(),
            ),
            Structural::NoLongerRedundant { .. } => {
                ("now load-bearing".to_string(), "it was redundant before this change".to_string())
            }
            Structural::Added { .. } => ("added".to_string(), String::new()),
            Structural::Removed { .. } => ("removed".to_string(), String::new()),
            Structural::Modified { .. } => ("modified".to_string(), String::new()),
        };
        lines.push((format!("rule {:02}  {what}", c.number()), why));
    }

    let width = lines.iter().map(|(l, _)| l.len()).max().unwrap_or(0);
    let mut out = String::from("STRUCTURAL\n");
    for (left, right) in lines {
        out.push_str(format!("  {left:<width$}  {right}").trim_end());
        out.push('\n');
    }
    out
}

/// Render the whole delta for one chain.
pub fn render_diff(
    layout: &Layout,
    syms: &SymbolTable,
    base: &ChainModel,
    head: &ChainModel,
    d: &ChainDiff,
    labels: (&str, &str),
    opts: &ReportOptions,
) -> String {
    let mut out = format!("RULESET DELTA  base {} .. head {}\n\n", labels.0, labels.1);

    out.push_str(&direction_section(
        layout,
        syms,
        base,
        head,
        &d.newly_blocked,
        Direction::Blocked,
        opts,
    ));
    out.push('\n');
    out.push_str(&direction_section(
        layout,
        syms,
        base,
        head,
        &d.newly_allowed,
        Direction::Allowed,
        opts,
    ));

    let structural = structural_section(&d.structural);
    if !structural.is_empty() {
        out.push('\n');
        out.push_str(&structural);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::accept::analyse;
    use crate::diff::diff;
    use soteria_ir::{Action, Chain, Field, Hook, Match, Origin};

    const TCP: u64 = 6;

    fn scenario() -> (Layout, SymbolTable, Chain, Chain) {
        let broad =
            Match::any().with_value(Field::Proto, TCP).with_prefix(Field::SrcAddr, 0x0A00_0000, 8);
        let narrow =
            Match::any().with_value(Field::Proto, TCP).with_prefix(Field::SrcAddr, 0x0A00_0000, 16);
        let modbus = Match::any()
            .with_prefix(Field::SrcAddr, 0x0A01_0000, 16)
            .with_value(Field::Proto, TCP)
            .with_value(Field::DstPort, 502);

        let mut base = Chain::new("input", Hook::Input, Action::Drop);
        base.push(broad, Action::Accept, Origin::default());
        base.push(modbus.clone(), Action::Drop, Origin::default());

        let mut head = Chain::new("input", Hook::Input, Action::Drop);
        head.push(narrow, Action::Accept, Origin::default());
        head.push(modbus, Action::Drop, Origin::default());

        (Layout::default(), SymbolTable::default(), base, head)
    }

    #[test]
    fn an_identical_ruleset_reports_none_in_both_directions() {
        let (l, s, base, _) = scenario();
        let m = analyse(&l, &s, &base);
        let d = diff(&m, &m);
        let text =
            render_diff(&l, &s, &m, &m, &d, ("abc1234", "abc1234"), &ReportOptions::default());
        assert_eq!(text.matches("  none\n").count(), 2);
        assert!(!text.contains("STRUCTURAL"));
    }

    #[test]
    fn the_report_names_the_rule_on_both_sides() {
        let (l, s, base, head) = scenario();
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let text =
            render_diff(&l, &s, &bm, &hm, &d, ("9f2c1ab", "4e81d33"), &ReportOptions::default());

        assert!(text.contains("RULESET DELTA  base 9f2c1ab .. head 4e81d33"));
        assert!(
            text.contains("was allowed by rule 01, now denied by rule 02"),
            "report was:\n{text}"
        );
        // The modbus port and the exposed source block both have to be visible.
        assert!(text.contains(":502"), "report was:\n{text}");
        assert!(text.contains("10.1.0.0/16"), "report was:\n{text}");
    }

    #[test]
    fn a_woken_rule_is_reported_structurally() {
        let (l, s, base, head) = scenario();
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let text =
            render_diff(&l, &s, &bm, &hm, &d, ("9f2c1ab", "4e81d33"), &ReportOptions::default());
        assert!(
            text.contains("rule 02  now reachable")
                && text.contains("previously shadowed by rule 01"),
            "report was:\n{text}"
        );
    }

    /// A value shared by every line belongs in the heading, not in a column
    /// repeated down the page.
    #[test]
    fn a_constant_column_is_hoisted_out_of_the_table() {
        let (l, s, base, head) = scenario();
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let text = render_diff(&l, &s, &bm, &hm, &d, ("a", "b"), &ReportOptions::default());

        let body: Vec<&str> = text.lines().filter(|line| line.contains("was allowed by")).collect();
        assert!(body.len() > 1, "need several rows to hoist anything");
        assert!(text.contains("all entries: "), "report was:\n{text}");
        // Every row carries tcp, so no row should still print it.
        assert!(
            body.iter().all(|line| !line.contains(" tcp ")),
            "protocol should have been hoisted:\n{text}"
        );
    }

    /// Breadth ordering has to be global; sorting inside each attribution cell
    /// lets a narrow finding lead while the widest change sits further down.
    #[test]
    fn the_widest_finding_leads() {
        let (l, s, base, head) = scenario();
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let text = render_diff(&l, &s, &bm, &hm, &d, ("a", "b"), &ReportOptions::default());
        let first = text
            .lines()
            .find(|line| line.contains("was allowed by"))
            .expect("at least one finding");
        // The modbus rule decides a single port; it must not be the headline.
        assert!(!first.contains(":502"), "narrowest finding led:\n{text}");
    }

    /// The headline has to declare what it projected away, or it is a number
    /// with no stated meaning.
    #[test]
    fn the_flow_headline_names_its_projection() {
        let (l, s, base, head) = scenario();
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let text = render_diff(&l, &s, &bm, &hm, &d, ("a", "b"), &ReportOptions::default());
        assert!(
            text.contains("flows  (src, dst, dport, proto; sport/iif/oif quantified)"),
            "report was:\n{text}"
        );
    }

    /// The flow figure must be the projection of the delta, not of the rows
    /// that survived the display cap.
    #[test]
    fn the_flow_count_measures_the_whole_delta() {
        let (l, s, base, head) = scenario();
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        let tight = ReportOptions { max_rows: 1, ..Default::default() };
        let full = ReportOptions::default();
        let flows = |o| {
            let t = render_diff(&l, &s, &bm, &hm, &d, ("a", "b"), &o);
            t.lines()
                .find(|line| line.contains("flows  ("))
                .map(str::to_string)
                .expect("a flow line")
        };
        assert_eq!(flows(tight), flows(full));
    }

    #[test]
    fn newly_allowed_uses_the_opposite_wording() {
        let (l, s, base, head) = scenario();
        // Swapped: the head is the broader one, so access is gained.
        let (bm, hm) = (analyse(&l, &s, &head), analyse(&l, &s, &base));
        let d = diff(&bm, &hm);
        let text = render_diff(&l, &s, &bm, &hm, &d, ("head", "base"), &ReportOptions::default());
        assert!(text.contains("was denied by"), "report was:\n{text}");
        assert!(text.contains("now allowed by"), "report was:\n{text}");
    }
}
