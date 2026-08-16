//! `fwdelta` — the command line interface.
//!
//! Two execution contexts, per blueprint section 03: locally before the push,
//! and as a step in CI on the pull request. Both run the same code and differ
//! only in what they do with the exit status.
//!
//! Exit codes:
//!
//! * `0` — the comparison completed and no gate failed.
//! * `1` — a gate failed. Today that is `--fail-on-newly-blocked`; intent
//!   assertions will join it at M5.
//! * `2` — the tool could not do its job: bad arguments, unreadable input, or a
//!   ruleset outside the supported subset.
//!
//! The separation matters for CI. A non-empty newly-blocked set does **not**
//! block a merge by default, because most such changes are deliberate; it is
//! surfaced for the reviewer to acknowledge. Something the tool could not
//! analyse is a different matter and always exits 2, because a green build from
//! a ruleset that was never modelled is the outcome this project exists to
//! prevent.

#![forbid(unsafe_code)]

mod attest;
mod json;
mod sha256;
mod source;

use fwdelta_engine::report::{self, AssertionRow, ChainInput, ReportOptions};
use fwdelta_engine::{
    ChainModel, Field, IntervalSet, Layout, Region, SymbolTable, VarOrder, analyse, diff,
    enumerate, exact_cardinality, flow_count,
};
use fwdelta_engine::{
    diff::{ChainDiff, Structural},
    enumerate::EnumOptions,
    render,
};
use fwdelta_ir::{Ruleset, set_to_prefixes};
use fwdelta_policy::eval::Mentioned;
use fwdelta_policy::{Outcome, Policy, Report};
use json::Json;

const VERSION: &str = env!("CARGO_PKG_VERSION");

const USAGE: &str = "\
fwdelta — semantic diff for firewall policy

USAGE
  fwdelta diff --base <ref> --head <ref> [options]
  fwdelta check <file> [options]
  fwdelta version

DIFF OPTIONS
  --base <ref>       base ruleset: a file path, or a git revision with --path
  --head <ref>       head ruleset: likewise
  --path <file>      file within the repository, when a ref is a git revision
  --chain <name>     compare only this chain (default: every chain in both)
  --format <fmt>     text (default), json, or html
  --fail-on-newly-blocked
                     exit 1 when traffic lost access. Off by default: most such
                     changes are deliberate and are surfaced, not blocked
  --out <file>       write the report here instead of stdout
  --assert <file>    TOML assertion file: zones and intent claims
  --attest <file>    write an unsigned in-toto predicate here, or - for stdout
  --allow-vacuous    do not fail on assertions that hold trivially
  --verify           run the engine's internal self-checks on every chain
  --max-rows <n>     lines per section before truncating (default 12)

CHECK OPTIONS
  --format <fmt>     text (default) or json
  --verify           as above

EXIT CODES
  0  completed, no gate failed
  1  a gate failed: a failed assertion, an assertion that held only trivially,
     or --fail-on-newly-blocked with traffic lost
  2  could not analyse: bad arguments, unreadable input, unsupported construct
";

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("fwdelta: {e}");
            std::process::exit(2);
        }
    }
}

/// How the report is written out.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
enum Format {
    #[default]
    Text,
    Json,
    /// One self-contained file: no scripts, no external assets, opens from
    /// `file://` on a machine with no network.
    Html,
}

#[derive(Default)]
struct Options {
    base: Option<String>,
    head: Option<String>,
    path: Option<String>,
    chain: Option<String>,
    format: Format,
    out: Option<String>,
    fail_on_newly_blocked: bool,
    verify: bool,
    max_rows: usize,
    assert_file: Option<String>,
    attest_to: Option<String>,
    allow_vacuous: bool,
    positional: Vec<String>,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut o = Options { max_rows: 12, ..Default::default() };
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        let value = || args.get(i + 1).cloned().ok_or_else(|| format!("{a} needs a value"));
        match a.as_str() {
            "--base" => {
                o.base = Some(value()?);
                i += 2;
            }
            "--head" => {
                o.head = Some(value()?);
                i += 2;
            }
            "--path" => {
                o.path = Some(value()?);
                i += 2;
            }
            "--chain" => {
                o.chain = Some(value()?);
                i += 2;
            }
            "--max-rows" => {
                o.max_rows =
                    value()?.parse().map_err(|_| "--max-rows needs a number".to_string())?;
                i += 2;
            }
            "--format" => {
                o.format = match value()?.as_str() {
                    "json" => Format::Json,
                    "text" => Format::Text,
                    "html" => Format::Html,
                    other => {
                        return Err(format!("unknown format `{other}`; use text, json or html"));
                    }
                };
                i += 2;
            }
            "--out" => {
                o.out = Some(value()?);
                i += 2;
            }
            "--assert" => {
                o.assert_file = Some(value()?);
                i += 2;
            }
            "--attest" => {
                o.attest_to = Some(value()?);
                i += 2;
            }
            "--allow-vacuous" => {
                o.allow_vacuous = true;
                i += 1;
            }
            "--fail-on-newly-blocked" => {
                o.fail_on_newly_blocked = true;
                i += 1;
            }
            "--verify" => {
                o.verify = true;
                i += 1;
            }
            "-h" | "--help" => {
                print!("{USAGE}");
                std::process::exit(0);
            }
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            other => {
                o.positional.push(other.to_string());
                i += 1;
            }
        }
    }
    Ok(o)
}

fn run() -> Result<i32, String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().cloned() else {
        print!("{USAGE}");
        return Ok(2);
    };
    let opts = parse_options(&args[1..])?;

    match command.as_str() {
        "diff" => cmd_diff(opts),
        "check" => cmd_check(opts),
        "version" => {
            println!("fwdelta {VERSION}");
            Ok(0)
        }
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
            Ok(0)
        }
        other => Err(format!("unknown command `{other}`. Try `fwdelta --help`")),
    }
}

/// Parse a ruleset, turning a rejection into a message the caller can act on.
fn parse(label: &str, text: &str) -> Result<Ruleset, String> {
    let mut rs = fwdelta_nft::parse(label, text).map_err(|e| format!("\n{e}"))?;
    rs.label = label.to_string();
    Ok(rs)
}

// ------------------------------------------------------------------- diff

fn cmd_diff(o: Options) -> Result<i32, String> {
    let base_ref = o.base.as_deref().ok_or("diff needs --base")?;
    let head_ref = o.head.as_deref().ok_or("diff needs --head")?;

    let base_src = source::load(base_ref, o.path.as_deref())?;
    let head_src = source::load(head_ref, o.path.as_deref())?;
    let base_rs = parse(&base_src.label, &base_src.text)?;
    let head_rs = parse(&head_src.label, &head_src.text)?;

    let policy: Option<Policy> = match &o.assert_file {
        Some(path) => {
            let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
            Some(fwdelta_policy::parse::parse(&text).map_err(|e| format!("{path}: {e}"))?)
        }
        None => None,
    };

    // The table spans both revisions *and* the assertion file. An interface
    // named only by an assertion still has to get an index: "what happens to
    // traffic arriving on eth7" is a real question even when no rule mentions
    // eth7, and leaving the name out would resolve it to the empty set and make
    // the assertion vacuous for the wrong reason.
    let syms = SymbolTable::from_names(
        base_rs
            .interface_names()
            .chain(head_rs.interface_names())
            .chain(policy.iter().flat_map(|p| p.interface_names()))
            .map(str::to_string),
    )
    .map_err(|e| e.to_string())?;
    let layout = Layout::new(VarOrder::AddrInterleaved);

    // Chains are matched by name across the two revisions. A chain present in
    // only one is reported rather than skipped: it is a change in what the host
    // filters at all, which is at least as significant as a rule edit.
    let mut names: Vec<String> =
        base_rs.chains.iter().chain(&head_rs.chains).map(|c| c.name.clone()).collect();
    names.sort();
    names.dedup();
    if let Some(only) = &o.chain {
        names.retain(|n| n == only);
        if names.is_empty() {
            return Err(format!("no chain named `{only}` in either ruleset"));
        }
    }

    let mut sections: Vec<(String, ChainModel, ChainModel, ChainDiff)> = Vec::new();
    let mut unmatched: Vec<String> = Vec::new();
    for name in &names {
        match (base_rs.chain(name), head_rs.chain(name)) {
            (Some(b), Some(h)) => {
                let bm = analyse(&layout, &syms, b);
                let hm = analyse(&layout, &syms, h);
                if o.verify {
                    bm.verify(&layout).map_err(|e| format!("base chain `{name}`: {e}"))?;
                    hm.verify(&layout).map_err(|e| format!("head chain `{name}`: {e}"))?;
                }
                let d = diff(&bm, &hm);
                sections.push((name.clone(), bm, hm, d));
            }
            (Some(_), None) => unmatched.push(format!("chain `{name}` was removed")),
            (None, Some(_)) => unmatched.push(format!("chain `{name}` was added")),
            (None, None) => {}
        }
    }

    // Assertions are checked against the head revision: the question is whether
    // the change being reviewed still satisfies intent, not whether the old one did.
    let mut assertions: Vec<Report> = Vec::new();
    if let Some(p) = &policy {
        let head_models: Vec<ChainModel> =
            sections.iter().map(|(_, _, hm, _)| hm.clone()).collect();
        let mentioned = Mentioned::of(&[&base_rs, &head_rs]);
        assertions = fwdelta_policy::evaluate(&layout, &syms, p, &head_models, &mentioned)
            .map_err(|e| e.to_string())?;
    }

    let lost = sections.iter().any(|(_, _, _, d)| !d.newly_blocked.is_false());
    let failed = assertions.iter().any(|a| matches!(a.outcome, Outcome::Fail { .. }));
    // A vacuous assertion fails by default. It is a green result that
    // establishes nothing, which is worse than a red one: red gets
    // investigated, green gets merged.
    let vacuous =
        !o.allow_vacuous && assertions.iter().any(|a| matches!(a.outcome, Outcome::Vacuous { .. }));
    let exit = if failed || vacuous || (o.fail_on_newly_blocked && lost) { 1 } else { 0 };

    if let Some(dest) = &o.attest_to {
        let inputs = vec![
            attest::Input {
                role: "base",
                label: base_src.label.clone(),
                text: base_src.text.clone(),
            },
            attest::Input {
                role: "head",
                label: head_src.label.clone(),
                text: head_src.text.clone(),
            },
        ];
        let delta = Json::arr(sections.iter().map(|(name, bm, hm, d)| {
            Json::obj([
                ("chain", Json::str(name)),
                ("newlyBlocked", delta_json(&layout, &syms, bm, hm, &d.newly_blocked)),
                ("newlyAllowed", delta_json(&layout, &syms, bm, hm, &d.newly_allowed)),
            ])
        }));
        let text = attest::statement(&inputs, &assertions, delta, None).render();
        if dest == "-" {
            print!("{text}");
        } else {
            std::fs::write(dest, &text).map_err(|e| format!("{dest}: {e}"))?;
        }
    }

    // One model, then a renderer. Text and HTML are two views of the same
    // value, so they cannot disagree about what the findings are.
    let report_opts = ReportOptions { max_rows: o.max_rows, ..Default::default() };
    let inputs: Vec<ChainInput<'_>> = sections
        .iter()
        .map(|(name, bm, hm, d)| ChainInput { name, base: bm, head: hm, diff: d })
        .collect();
    let mut notes = unmatched.clone();
    if lost && !o.fail_on_newly_blocked && o.format == Format::Html {
        notes.push(
            "Traffic lost access. This did not fail the run; --fail-on-newly-blocked makes it."
                .to_string(),
        );
    }
    let model = report::build(
        &layout,
        &syms,
        &inputs,
        (&base_src.label, &head_src.label),
        assertions.iter().map(|a| assertion_row(a, &syms)).collect(),
        notes,
        &report_opts,
    );

    let rendered = match o.format {
        Format::Json => {
            diff_json(&layout, &syms, &base_rs, &head_rs, &sections, &unmatched, exit).render()
        }
        Format::Text => report::text::render(&model),
        Format::Html => report::html::render(&model),
    };

    match &o.out {
        Some(path) if path != "-" => {
            std::fs::write(path, &rendered).map_err(|e| format!("{path}: {e}"))?
        }
        _ => print!("{rendered}"),
    }

    Ok(exit)
}

/// Flatten a policy result into the report model.
///
/// The policy crate depends on the engine, so the engine cannot name its types;
/// the crossing happens here. Wording follows the assertion kind: "no path" is
/// right for isolation and exactly backwards for reachability, where passing
/// means a path exists.
fn assertion_row(r: &Report, syms: &SymbolTable) -> AssertionRow {
    let detail = match &r.outcome {
        Outcome::Pass => match r.kind {
            fwdelta_policy::Kind::Isolation => format!("no path {}", r.summary),
            fwdelta_policy::Kind::Reachability => format!("all permitted {}", r.summary),
        },
        Outcome::Fail { counterexample } => {
            let verb = match r.kind {
                fwdelta_policy::Kind::Isolation => "permitted",
                fwdelta_policy::Kind::Reachability => "denied",
            };
            format!("{} {verb}", counterexample.describe(syms))
        }
        Outcome::Vacuous { reason } => reason.clone(),
    };
    AssertionRow {
        name: r.name.clone(),
        kind: r.kind.as_str().to_string(),
        outcome: r.outcome.label().to_string(),
        detail,
    }
}

// ------------------------------------------------------------------ check

fn cmd_check(o: Options) -> Result<i32, String> {
    let file = o.positional.first().ok_or("check needs a file")?;
    let src = source::load(file, o.path.as_deref())?;
    let rs = parse(&src.label, &src.text)?;
    let syms = SymbolTable::from_names(rs.interface_names().map(str::to_string))
        .map_err(|e| e.to_string())?;
    let layout = Layout::new(VarOrder::AddrInterleaved);

    let mut findings = Vec::new();
    let mut chains_json = Vec::new();
    for chain in &rs.chains {
        let m = analyse(&layout, &syms, chain);
        if o.verify {
            m.verify(&layout).map_err(|e| format!("chain `{}`: {e}", chain.name))?;
        }
        let shadowed: Vec<u32> = m.shadowed().map(|r| r.number).collect();
        let redundant: Vec<u32> = m.redundant().map(|r| r.number).collect();
        for n in &shadowed {
            findings.push((chain.name.clone(), *n, "unreachable", m.explain_shadow(*n)));
        }
        for n in &redundant {
            findings.push((chain.name.clone(), *n, "redundant", Vec::new()));
        }
        chains_json.push(Json::obj([
            ("name", Json::str(&chain.name)),
            ("rules", Json::Num(chain.rules.len() as u64)),
            ("unreachable", Json::arr(shadowed.iter().map(|n| Json::Num(*n as u64)))),
            ("redundant", Json::arr(redundant.iter().map(|n| Json::Num(*n as u64)))),
        ]));
    }

    if o.format == Format::Json {
        print!(
            "{}",
            Json::obj([
                ("tool", tool_json()),
                ("ruleset", Json::str(&rs.label)),
                ("chains", Json::arr(chains_json)),
            ])
            .render()
        );
        return Ok(0);
    }
    if o.format == Format::Html {
        return Err("check does not produce html; use diff --format html".to_string());
    }

    println!("{}: {} chains, {} rules", rs.label, rs.chains.len(), rs.rule_count());
    if findings.is_empty() {
        println!("no unreachable or redundant rules");
        return Ok(0);
    }
    for (chain, number, what, covered) in &findings {
        let rule = rs.chain(chain).and_then(|c| c.rules.iter().find(|r| r.number == *number));
        let origin = rule.map(|r| r.origin.to_string()).unwrap_or_default();
        let detail = match covered.as_slice() {
            [] => String::new(),
            [one] => format!("  covered by rule {one:02}"),
            many => format!(
                "  covered by rules {}",
                many.iter().map(|n| format!("{n:02}")).collect::<Vec<_>>().join(", ")
            ),
        };
        println!("  {origin}  rule {number:02} {what}{detail}");
        if let Some(r) = rule {
            if !r.origin.text.is_empty() {
                println!("      {}", r.origin.text);
            }
        }
    }
    Ok(0)
}

// ------------------------------------------------------------------- json

fn tool_json() -> Json {
    Json::obj([("name", Json::str("fwdelta")), ("version", Json::str(VERSION))])
}

/// Dimension terms for the machine-readable path.
///
/// `None` means unconstrained, which JSON renders as `null` so that a consumer
/// can tell "any" from "a set that happens to cover everything". Rendering is
/// untruncated here: the text report is a summary for a human, the JSON is the
/// complete answer.
fn addr_terms(set: &IntervalSet) -> Option<Vec<String>> {
    if set.is_full() {
        return None;
    }
    Some(set_to_prefixes(set).into_iter().map(|(v, l)| render::cidr(v, l)).collect())
}

fn range_terms(set: &IntervalSet) -> Option<Vec<String>> {
    if set.is_full() {
        return None;
    }
    Some(
        set.ranges()
            .iter()
            .map(|&(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
            .collect(),
    )
}

fn iface_terms(set: &IntervalSet, syms: &SymbolTable) -> Option<Vec<String>> {
    if set.is_full() {
        return None;
    }
    Some(
        set.ranges()
            .iter()
            .flat_map(|&(lo, hi)| lo..=hi)
            .map(|v| match syms.name_of(v as u8) {
                Some(n) => n.to_string(),
                None => format!("if#{v}"),
            })
            .collect(),
    )
}

fn terms_json(t: Option<Vec<String>>) -> Json {
    Json::opt(t.map(|v| Json::arr(v.into_iter().map(Json::Str))))
}

fn region_json(r: &Region, syms: &SymbolTable) -> Json {
    Json::obj([
        ("src", terms_json(addr_terms(r.get(Field::SrcAddr)))),
        ("dst", terms_json(addr_terms(r.get(Field::DstAddr)))),
        ("sport", terms_json(range_terms(r.get(Field::SrcPort)))),
        ("dport", terms_json(range_terms(r.get(Field::DstPort)))),
        ("proto", terms_json(range_terms(r.get(Field::Proto)))),
        ("iif", terms_json(iface_terms(r.get(Field::IfIn), syms))),
        ("oif", terms_json(iface_terms(r.get(Field::IfOut), syms))),
        ("packets", Json::big(r.count())),
    ])
}

fn delta_json(
    layout: &Layout,
    syms: &SymbolTable,
    base: &ChainModel,
    head: &ChainModel,
    set: &biodivine_lib_bdd::Bdd,
) -> Json {
    let (cells, truncated) = fwdelta_engine::attribute(base, head, set, 4096);
    let mut entries = Vec::new();
    let mut incomplete = false;
    for cell in &cells {
        let e = enumerate(
            layout,
            &cell.set,
            EnumOptions { max_regions: usize::MAX, ..Default::default() },
        );
        incomplete |= e.incomplete;
        for r in &e.regions {
            let Json::Obj(mut fields) = region_json(r, syms) else { unreachable!() };
            fields.insert(0, ("was".into(), Json::str(cell.was.to_string())));
            fields.insert(1, ("now".into(), Json::str(cell.now.to_string())));
            entries.push(Json::Obj(fields));
        }
    }
    Json::obj([
        ("packets", Json::big(exact_cardinality(set))),
        ("flows", Json::big(flow_count(layout, set))),
        ("entries", Json::arr(entries)),
        ("complete", Json::Bool(!truncated && !incomplete)),
    ])
}

fn structural_json(s: &Structural) -> Json {
    let (kind, detail) = match s {
        Structural::NowReachable { previously_covered_by, .. } => {
            ("now_reachable", previously_covered_by.clone())
        }
        Structural::NowUnreachable { covered_by, .. } => ("now_unreachable", covered_by.clone()),
        Structural::NowRedundant { .. } => ("now_redundant", Vec::new()),
        Structural::NoLongerRedundant { .. } => ("no_longer_redundant", Vec::new()),
        Structural::Added { .. } => ("added", Vec::new()),
        Structural::Removed { .. } => ("removed", Vec::new()),
        Structural::Modified { .. } => ("modified", Vec::new()),
    };
    Json::obj([
        ("rule", Json::Num(s.number() as u64)),
        ("change", Json::str(kind)),
        ("covered_by", Json::arr(detail.into_iter().map(|n| Json::Num(n as u64)))),
    ])
}

#[allow(clippy::too_many_arguments)]
fn diff_json(
    layout: &Layout,
    syms: &SymbolTable,
    base_rs: &Ruleset,
    head_rs: &Ruleset,
    sections: &[(String, ChainModel, ChainModel, ChainDiff)],
    unmatched: &[String],
    exit: i32,
) -> Json {
    let ruleset_json = |rs: &Ruleset| {
        Json::obj([
            ("label", Json::str(&rs.label)),
            ("chains", Json::Num(rs.chains.len() as u64)),
            ("rules", Json::Num(rs.rule_count() as u64)),
        ])
    };
    let chains = sections.iter().map(|(name, bm, hm, d)| {
        Json::obj([
            ("name", Json::str(name)),
            ("newly_blocked", delta_json(layout, syms, bm, hm, &d.newly_blocked)),
            ("newly_allowed", delta_json(layout, syms, bm, hm, &d.newly_allowed)),
            ("structural", Json::arr(d.structural.iter().map(structural_json))),
        ])
    });

    Json::obj([
        ("tool", tool_json()),
        ("base", ruleset_json(base_rs)),
        ("head", ruleset_json(head_rs)),
        ("interfaces", Json::arr(syms.names().iter().map(Json::str))),
        ("chains", Json::arr(chains)),
        ("unmatched_chains", Json::arr(unmatched.iter().map(Json::str))),
        ("exit", Json::Num(exit as u64)),
    ])
}
