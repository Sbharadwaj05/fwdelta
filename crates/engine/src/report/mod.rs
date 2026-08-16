//! The primary artifact: what a reviewer reads.
//!
//! Blueprint section 02 is blunt that this output *is* the product and
//! everything else exists to produce it. The format follows the blueprint's
//! sample, with one addition: findings name the rule responsible on both sides
//! rather than only the base side. "Was allowed by rule 14" says what broke;
//! "now denied by rule 22" says where to go and look, and the partition makes
//! both exact rather than guesswork.
//!
//! # One model, several renderers
//!
//! [`DiffReport`] is built once by [`build`], and every output format is a pure
//! function of it. Text and HTML are not two formatting paths over the same
//! inputs — they are two views of the same value.
//!
//! That is a correctness property, not tidiness. All the decisions that make the
//! output trustworthy live in the build step: ordering by breadth across
//! attribution cells, hoisting constant columns, deriving omission from the
//! union rather than by summing, attributing on both sides. Duplicating those in
//! a second renderer would mean two chances to get them subtly different, and a
//! reviewer comparing an HTML report against the terminal would have no way to
//! tell which one was lying.

pub mod html;
pub mod text;

use fwdelta_ir::SymbolTable;

use crate::accept::{ChainModel, Decider};
use crate::diff::{ChainDiff, Structural, attribute};
use crate::enumerate::{EnumOptions, enumerate, exact_cardinality, flow_count};
use crate::header::Layout;
use crate::render::{self, Row, Style};

/// Which way a delta runs. Only the wording differs.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Direction {
    Blocked,
    Allowed,
}

impl Direction {
    pub fn heading(self) -> (&'static str, &'static str) {
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

/// Knobs for building a report.
#[derive(Clone, Copy, Debug)]
pub struct ReportOptions {
    pub style: Style,
    pub enumeration: EnumOptions,
    /// Cap on attribution cells per direction.
    pub max_cells: usize,
    /// Cap on rows per direction, applied after global size ordering.
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

// ------------------------------------------------------------------- model

/// One direction of one chain's delta, ready to render.
#[derive(Clone, Debug)]
pub struct DirectionReport {
    pub direction: Direction,
    /// Values identical on every row, lifted out of the table.
    pub qualifiers: Vec<String>,
    pub rows: Vec<Row>,
    /// Exact, and the headline magnitude. See [`crate::enumerate::flow_count`].
    pub flows: u128,
    /// Exact 120-bit count, for the machine-readable path.
    pub packets: u128,
    pub omitted_rows: usize,
    pub omitted_flows: u128,
    /// The attribution cell cap was reached; part of the delta is unlisted.
    pub cells_truncated: bool,
    /// Enumeration hit a work limit; the listing is a strict subset.
    pub incomplete: bool,
}

impl DirectionReport {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty() && self.omitted_rows == 0
    }

    /// The projection the flow count uses, stated wherever the count appears.
    pub const PROJECTION: &'static str = "src, dst, dport, proto; sport/iif/oif quantified";
}

#[derive(Clone, Debug)]
pub struct StructuralRow {
    pub number: u32,
    pub what: String,
    pub why: String,
}

/// An assertion result, flattened.
///
/// Deliberately not `fwdelta_policy::Report`: the policy crate depends on this
/// one, so holding its types here would be a cycle. The CLI flattens across the
/// boundary.
#[derive(Clone, Debug)]
pub struct AssertionRow {
    pub name: String,
    pub kind: String,
    /// `PASS`, `FAIL` or `VACUOUS`.
    pub outcome: String,
    /// The explanation: a claim restated, a counterexample, or why it was empty.
    pub detail: String,
}

impl AssertionRow {
    pub fn is_pass(&self) -> bool {
        self.outcome == "PASS"
    }
    pub fn is_fail(&self) -> bool {
        self.outcome == "FAIL"
    }
    pub fn is_vacuous(&self) -> bool {
        self.outcome == "VACUOUS"
    }
}

#[derive(Clone, Debug)]
pub struct ChainReport {
    pub name: String,
    pub blocked: DirectionReport,
    pub allowed: DirectionReport,
    pub structural: Vec<StructuralRow>,
}

/// Everything a rendered report contains.
#[derive(Clone, Debug)]
pub struct DiffReport {
    pub base_label: String,
    pub head_label: String,
    pub tool_version: String,
    pub generated_at: String,
    pub chains: Vec<ChainReport>,
    pub assertions: Vec<AssertionRow>,
    /// Chains present in only one revision, and similar remarks.
    pub notes: Vec<String>,
}

impl DiffReport {
    pub fn traffic_lost(&self) -> bool {
        self.chains.iter().any(|c| !c.blocked.is_empty())
    }
    pub fn passed(&self) -> usize {
        self.assertions.iter().filter(|a| a.is_pass()).count()
    }
    pub fn failed(&self) -> usize {
        self.assertions.iter().filter(|a| a.is_fail()).count()
    }
    pub fn vacuous(&self) -> usize {
        self.assertions.iter().filter(|a| a.is_vacuous()).count()
    }
    /// Every finding note across both directions and all chains. The set two
    /// renderers must agree on.
    pub fn finding_notes(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for c in &self.chains {
            for d in [&c.blocked, &c.allowed] {
                out.extend(d.rows.iter().map(|r| r.note.clone()));
            }
        }
        out
    }
}

/// What the model approximates, and what a passing run therefore does not say.
///
/// Single source of truth: the HTML report shows this on the page and the
/// attestation embeds it in the predicate. Two copies would drift, and the copy
/// that drifted would be the one making a promise the model does not keep.
pub fn model_boundaries() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "Statefulness",
            "Stateless. New connections in the forward direction are governed by the ruleset; \
             return traffic for permitted connections is assumed permitted. Rulesets whose \
             security depends on connection tracking are rejected at parse time rather than \
             approximated.",
        ),
        (
            "NAT",
            "Not modelled. Address translation changes packet identity in transit, so a ruleset \
             containing NAT is rejected rather than analysed with NAT ignored.",
        ),
        (
            "Scope",
            "One host's filter table. Not end-to-end reachability, which also depends on routing \
             and on other devices.",
        ),
        ("Address family", "IPv4 only. The header layout is 32-bit; IPv6 is not analysed."),
        (
            "Ports on portless protocols",
            "Every packet is given source and destination ports, including ICMP. Sound only \
             because the frontend requires a port match to pin a protocol that has ports.",
        ),
        (
            "Output interface",
            "Rejected, not modelled. The differential harness runs on the input hook, where the \
             output interface is never set, so the dimension has never been checked against the \
             kernel.",
        ),
        (
            "Frontend subset",
            "A documented subset of nftables. Every construct outside it is a hard error, so no \
             rule was silently skipped.",
        ),
    ]
}

/// What a passing run does not establish.
pub fn does_not_establish() -> &'static [&'static str] {
    &[
        "that the assertions are the right assertions",
        "that the device implements nftables faithfully",
        "that the configuration deployed is the configuration analysed",
        "anything about NAT, routing, or other devices",
        "anything about assertions reported as VACUOUS, which held trivially",
    ]
}

// ------------------------------------------------------------------- build

/// One chain's two compiled revisions and their delta.
pub struct ChainInput<'a> {
    pub name: &'a str,
    pub base: &'a ChainModel,
    pub head: &'a ChainModel,
    pub diff: &'a ChainDiff,
}

/// Build the report. Every renderer is a pure function of the result.
pub fn build(
    layout: &Layout,
    syms: &SymbolTable,
    chains: &[ChainInput<'_>],
    labels: (&str, &str),
    assertions: Vec<AssertionRow>,
    notes: Vec<String>,
    opts: &ReportOptions,
) -> DiffReport {
    let chains = chains
        .iter()
        .map(|c| ChainReport {
            name: c.name.to_string(),
            blocked: direction(
                layout,
                syms,
                c.base,
                c.head,
                &c.diff.newly_blocked,
                Direction::Blocked,
                opts,
            ),
            allowed: direction(
                layout,
                syms,
                c.base,
                c.head,
                &c.diff.newly_allowed,
                Direction::Allowed,
                opts,
            ),
            structural: c.diff.structural.iter().map(structural_row).collect(),
        })
        .collect();

    DiffReport {
        base_label: labels.0.to_string(),
        head_label: labels.1.to_string(),
        tool_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at: timestamp(),
        chains,
        assertions,
        notes,
    }
}

fn direction(
    layout: &Layout,
    syms: &SymbolTable,
    base: &ChainModel,
    head: &ChainModel,
    delta: &biodivine_lib_bdd::Bdd,
    dir: Direction,
    opts: &ReportOptions,
) -> DirectionReport {
    let mut out = DirectionReport {
        direction: dir,
        qualifiers: Vec::new(),
        rows: Vec::new(),
        flows: flow_count(layout, delta),
        packets: exact_cardinality(delta),
        omitted_rows: 0,
        omitted_flows: 0,
        cells_truncated: false,
        incomplete: false,
    };
    if delta.is_false() {
        return out;
    }

    let (cells, truncated) = attribute(base, head, delta, opts.max_cells);
    out.cells_truncated = truncated;

    let mut found: Vec<(u128, crate::region::Region, Row)> = Vec::new();
    for cell in &cells {
        let e = enumerate(layout, &cell.set, opts.enumeration);
        let note = dir.note(cell.was, cell.now);
        found.extend(
            e.regions
                .iter()
                .map(|r| (r.count(), r.clone(), render::row(r, &note, syms, &opts.style))),
        );
        out.omitted_rows += e.omitted_regions;
        out.incomplete |= e.incomplete;
    }

    // Order by breadth across every cell, not within each one. Sorting per cell
    // lets a narrow finding from an early rule lead while the widest change in
    // the diff sits halfway down the page.
    found.sort_by_key(|(count, _, _)| std::cmp::Reverse(*count));

    if found.len() > opts.max_rows {
        let dropped = found.split_off(opts.max_rows);
        out.omitted_rows += dropped.len();

        // Flow counts are a projection, and projections do not add: two
        // rectangles differing only in source port are disjoint as packet sets
        // and collapse to the same flow. Summing per-rectangle counts would
        // overstate the remainder, so the union is rebuilt and projected.
        let mut union = layout.ff();
        for (_, region, _) in &dropped {
            union = union.or(&region.to_bdd(layout));
        }
        out.omitted_flows = flow_count(layout, &union);
    }

    let mut rows: Vec<Row> = found.into_iter().map(|(_, _, r)| r).collect();

    // Anything identical on every line is a qualifier on the section, not a
    // column. Repeating `in not lo` down the page costs width and says nothing.
    hoist(&mut rows, &mut out.qualifiers, |r| &mut r.iif);
    hoist(&mut rows, &mut out.qualifiers, |r| &mut r.oif);
    hoist(&mut rows, &mut out.qualifiers, |r| &mut r.proto);
    out.rows = rows;
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

fn structural_row(c: &Structural) -> StructuralRow {
    let list = |ns: &[u32], lead: &str| -> String {
        match ns {
            [] => String::new(),
            [one] => format!("{lead} rule {one:02}"),
            many => format!(
                "{lead} rules {}",
                many.iter().map(|n| format!("{n:02}")).collect::<Vec<_>>().join(", ")
            ),
        }
    };
    let (what, why) = match c {
        Structural::NowReachable { previously_covered_by, .. } => {
            ("now reachable".to_string(), list(previously_covered_by, "previously shadowed by"))
        }
        Structural::NowUnreachable { covered_by, .. } => {
            ("now unreachable".to_string(), list(covered_by, "fully covered by"))
        }
        Structural::NowRedundant { .. } => {
            ("now redundant".to_string(), "removing it would not change the accept set".to_string())
        }
        Structural::NoLongerRedundant { .. } => {
            ("now load-bearing".to_string(), "it was redundant before this change".to_string())
        }
        Structural::Added { .. } => ("added".to_string(), String::new()),
        Structural::Removed { .. } => ("removed".to_string(), String::new()),
        Structural::Modified { .. } => ("modified".to_string(), String::new()),
    };
    StructuralRow { number: c.number(), what, why }
}

/// UTC, ISO 8601, seconds resolution.
///
/// Honours `SOURCE_DATE_EPOCH` so a committed example report does not churn on
/// every regeneration, which is the same convention the reproducible build uses.
fn timestamp() -> String {
    timestamp_from(epoch_seconds())
}

fn epoch_seconds() -> i64 {
    std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|v| v.parse().ok())
        .or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64)
        })
        .unwrap_or(0)
}

/// Split out so it can be tested without mutating process environment, which
/// edition 2024 makes `unsafe` and this crate forbids.
fn timestamp_from(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

/// Days since the Unix epoch to a calendar date. Howard Hinnant's algorithm;
/// a fixed transform with no input from the user and no dependency worth taking.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_convert_against_known_points() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        // A leap day, which is where a wrong algorithm usually shows.
        assert_eq!(civil_from_days(19_782), (2024, 2, 29));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
    }

    #[test]
    fn timestamps_format_as_utc_iso8601() {
        assert_eq!(timestamp_from(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp_from(1_755_300_000), "2025-08-15T23:20:00Z");
        // Same input, same output: what SOURCE_DATE_EPOCH buys the committed
        // example report, which would otherwise churn on every regeneration.
        assert_eq!(timestamp_from(1_755_300_000), timestamp_from(1_755_300_000));
    }
}

#[cfg(test)]
mod render_tests {
    use super::*;
    use crate::accept::analyse;
    use crate::diff::diff;
    use fwdelta_ir::{Action, Chain, Field, Hook, Match, Origin};

    const TCP: u64 = 6;

    /// The blueprint's motivating change: narrowing one rule wakes another.
    fn scenario() -> (Layout, SymbolTable, ChainModel, ChainModel, ChainDiff) {
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

        let (l, s) = (Layout::default(), SymbolTable::default());
        let (bm, hm) = (analyse(&l, &s, &base), analyse(&l, &s, &head));
        let d = diff(&bm, &hm);
        (l, s, bm, hm, d)
    }

    fn report_of(assertions: Vec<AssertionRow>) -> DiffReport {
        let (l, s, bm, hm, d) = scenario();
        build(
            &l,
            &s,
            &[ChainInput { name: "input", base: &bm, head: &hm, diff: &d }],
            ("9f2c1ab", "4e81d33"),
            assertions,
            Vec::new(),
            &ReportOptions::default(),
        )
    }

    fn sample_assertions() -> Vec<AssertionRow> {
        vec![
            AssertionRow {
                name: "ot-cell-isolation".into(),
                kind: "isolation".into(),
                outcome: "FAIL".into(),
                detail: "tcp 10.1.0.0:0 -> 10.5.0.0:502 permitted".into(),
            },
            AssertionRow {
                name: "mgmt-plane-reachable".into(),
                kind: "reachability".into(),
                outcome: "PASS".into(),
                detail: "all permitted mgmt -> vlan_ot:22".into(),
            },
            AssertionRow {
                name: "typod-zone".into(),
                kind: "isolation".into(),
                outcome: "VACUOUS".into(),
                detail: "no rule in chain `input` matches any packet this assertion describes"
                    .into(),
            },
        ]
    }

    // ------------------------------------------------------------- the model

    #[test]
    fn an_identical_ruleset_has_nothing_in_either_direction() {
        let (l, s, bm, _, _) = scenario();
        let d = diff(&bm, &bm);
        let m = build(
            &l,
            &s,
            &[ChainInput { name: "input", base: &bm, head: &bm, diff: &d }],
            ("a", "a"),
            Vec::new(),
            Vec::new(),
            &ReportOptions::default(),
        );
        assert!(m.chains[0].blocked.is_empty() && m.chains[0].allowed.is_empty());
        assert!(m.chains[0].structural.is_empty());
        assert_eq!(text::render(&m).matches("  none\n").count(), 2);
    }

    #[test]
    fn findings_name_the_rule_on_both_sides() {
        let m = report_of(Vec::new());
        assert!(
            m.finding_notes().iter().any(|n| n.contains("was allowed by rule 01, now denied by")),
            "{:?}",
            m.finding_notes()
        );
    }

    #[test]
    fn a_woken_rule_appears_in_structural() {
        let m = report_of(Vec::new());
        let s = &m.chains[0].structural;
        assert!(s.iter().any(|r| r.number == 2 && r.what == "now reachable"), "{s:?}");
    }

    #[test]
    fn a_constant_column_is_hoisted_out_of_the_rows() {
        let m = report_of(Vec::new());
        let d = &m.chains[0].blocked;
        assert!(d.rows.len() > 1, "need several rows to hoist anything");
        assert!(d.qualifiers.iter().any(|q| q == "tcp"), "{:?}", d.qualifiers);
        assert!(d.rows.iter().all(|r| r.proto.is_empty()));
    }

    #[test]
    fn the_widest_finding_leads() {
        let m = report_of(Vec::new());
        let first = &m.chains[0].blocked.rows[0];
        // The modbus rule decides a single port; it must not be the headline.
        assert!(!first.dport.contains("502"), "narrowest finding led: {first:?}");
    }

    /// The flow figure is the projection of the whole delta, not of the rows
    /// that survived the display cap.
    #[test]
    fn the_flow_count_measures_the_whole_delta() {
        let (l, s, bm, hm, d) = scenario();
        let one = |max_rows| {
            build(
                &l,
                &s,
                &[ChainInput { name: "input", base: &bm, head: &hm, diff: &d }],
                ("a", "b"),
                Vec::new(),
                Vec::new(),
                &ReportOptions { max_rows, ..Default::default() },
            )
            .chains[0]
                .blocked
                .flows
        };
        assert_eq!(one(1), one(64));
    }

    // ------------------------------------------------- the two must agree

    /// The requirement: text and HTML are two views of one value, so they
    /// cannot disagree about what was found or how much of it there is.
    #[test]
    fn text_and_html_agree_on_findings_and_counts() {
        let m = report_of(sample_assertions());
        let t = text::render(&m);
        let h = html::render(&m);

        // Every finding note appears in both. This is the set of findings.
        let notes = m.finding_notes();
        assert!(!notes.is_empty(), "the fixture must produce findings");
        for n in &notes {
            assert!(t.contains(n), "text is missing a finding: {n}");
            assert!(h.contains(&html_escape_for_test(n)), "html is missing a finding: {n}");
        }

        // Counts: the flow figure for each direction, rendered identically.
        for chain in &m.chains {
            for d in [&chain.blocked, &chain.allowed] {
                if d.is_empty() {
                    continue;
                }
                let flows = render::count(d.flows);
                assert!(t.contains(&flows), "text is missing flow count {flows}");
                assert!(h.contains(&flows), "html is missing flow count {flows}");
            }
        }

        // Structural findings.
        for row in &m.chains[0].structural {
            assert!(t.contains(&row.what), "text is missing structural `{}`", row.what);
            assert!(h.contains(&row.what), "html is missing structural `{}`", row.what);
        }

        // Assertion outcomes, including the vacuous/passed split.
        for a in &m.assertions {
            assert!(t.contains(&a.name), "text is missing assertion {}", a.name);
            assert!(h.contains(&a.name), "html is missing assertion {}", a.name);
        }
        assert_eq!((m.passed(), m.failed(), m.vacuous()), (1, 1, 1));
        for out in ["PASS", "FAIL", "VACUOUS"] {
            assert!(t.contains(out), "text is missing outcome {out}");
            assert!(h.contains(out), "html is missing outcome {out}");
        }
    }

    /// Minimal mirror of the HTML escaper, so the agreement test compares like
    /// with like without reaching into a private function.
    fn html_escape_for_test(s: &str) -> String {
        s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
    }

    #[test]
    fn both_renderers_state_the_projection_with_the_count() {
        let m = report_of(Vec::new());
        let t = text::render(&m);
        let h = html::render(&m);
        assert!(t.contains(DirectionReport::PROJECTION), "{t}");
        assert!(h.contains(DirectionReport::PROJECTION), "{h}");
    }

    // ------------------------------------------------------------- the html

    /// The constraint that matters: one file, opens with no network.
    #[test]
    fn the_html_is_self_contained() {
        let h = html::render(&report_of(sample_assertions()));
        for forbidden in [
            "<script",
            "src=",
            "href=",
            "@import",
            "url(http",
            "//cdn",
            "fetch(",
            "XMLHttpRequest",
            "<iframe",
            "<object",
            "<embed",
        ] {
            assert!(!h.contains(forbidden), "html contains {forbidden:?}, which reaches outside");
        }
        assert!(h.starts_with("<!doctype html>"));
        assert!(h.trim_end().ends_with("</html>"));
        // The style must actually be inline, not merely absent.
        assert!(h.contains("<style>") && h.contains("prefers-color-scheme"));
    }

    #[test]
    fn the_html_shows_the_model_boundaries_on_the_page() {
        let h = html::render(&report_of(sample_assertions()));
        assert!(h.contains("What this analysis did not cover"));
        for (name, _) in model_boundaries() {
            assert!(h.contains(name), "boundary `{name}` is missing");
        }
        for item in does_not_establish() {
            assert!(h.contains(item), "missing: {item}");
        }
    }

    #[test]
    fn the_html_never_folds_vacuous_into_passed() {
        let h = html::render(&report_of(sample_assertions()));
        assert!(h.contains("1 passed"), "{h}");
        assert!(h.contains("1 vacuous"), "{h}");
        assert!(h.contains("held trivially"), "the page should say what vacuous means");
    }

    #[test]
    fn the_html_header_carries_the_revisions_version_and_time() {
        let m = report_of(Vec::new());
        let h = html::render(&m);
        assert!(h.contains("9f2c1ab") && h.contains("4e81d33"));
        assert!(h.contains(&m.tool_version));
        assert!(h.contains(&m.generated_at));
    }

    #[test]
    fn the_html_escapes_content_from_the_ruleset() {
        let m = report_of(vec![AssertionRow {
            name: "<img src=x onerror=alert(1)>".into(),
            kind: "isolation".into(),
            outcome: "PASS".into(),
            detail: "a & b".into(),
        }]);
        let h = html::render(&m);
        assert!(!h.contains("<img src=x"), "unescaped markup reached the page");
        assert!(h.contains("&lt;img src=x onerror=alert(1)&gt;"));
        assert!(h.contains("a &amp; b"));
    }
}
