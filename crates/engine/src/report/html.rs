//! Self-contained HTML rendering of a [`DiffReport`].
//!
//! The constraints are the binary's constraints, for the same reason. A report
//! about an air-gapped network's firewall is not much use if opening it needs a
//! CDN, and a report that phones out when opened is an exfiltration path for a
//! document describing exactly where the trust boundaries are.
//!
//! So: one file, no `<script src>`, no `<link href>`, no webfonts, no remote
//! images, no `fetch`. All CSS is inline and all data is already in the markup.
//! There is no JavaScript at all — not because it is forbidden but because
//! nothing here needs it, and the absence is easier to verify than a policy.
//! `scripts/syscall-audit.sh` covers an HTML run so the air-gap gate includes
//! this path.
//!
//! Everything rendered is a pure function of the model, so this and the text
//! renderer cannot disagree about the findings.

use super::{DiffReport, DirectionReport, StructuralRow, does_not_establish, model_boundaries};
use crate::render::{self, Row};

/// Escape for HTML text and attribute content.
///
/// Report content includes file paths, rule text quoted from the source, and
/// zone names — all attacker-adjacent in the sense that a ruleset under review
/// is not necessarily written by whoever reads the report.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root {
  --bg: #ffffff; --fg: #16181d; --dim: #5c6370; --line: #e2e5ea;
  --panel: #f6f7f9; --accent: #b4341f; --ok: #1f7a3f; --warn: #8a6d00;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #14161a; --fg: #e6e8ec; --dim: #9098a6; --line: #2a2e36;
    --panel: #1b1e24; --accent: #ef6a52; --ok: #5fca86; --warn: #d7b34a;
  }
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 2rem 1.25rem 4rem; background: var(--bg); color: var(--fg);
  font: 14px/1.55 var(--mono); -webkit-text-size-adjust: 100%;
}
main { max-width: 76rem; margin: 0 auto; }
h1 { font-size: 1.05rem; letter-spacing: .12em; text-transform: uppercase; margin: 0 0 .25rem; }
h2 {
  font-size: .82rem; letter-spacing: .14em; text-transform: uppercase;
  margin: 2.25rem 0 .6rem; color: var(--accent); border-bottom: 1px solid var(--line);
  padding-bottom: .35rem;
}
h3 { font-size: .78rem; letter-spacing: .1em; text-transform: uppercase; color: var(--dim); margin: 1.5rem 0 .5rem; }
.sub { color: var(--dim); font-weight: normal; text-transform: none; letter-spacing: 0; }
.meta { color: var(--dim); margin-bottom: 1.5rem; }
.meta b { color: var(--fg); font-weight: 600; }
.cards { display: flex; flex-wrap: wrap; gap: .6rem; margin: 1rem 0 0; }
.card {
  background: var(--panel); border: 1px solid var(--line); border-radius: 6px;
  padding: .6rem .9rem; min-width: 9rem;
}
.card .n { font-size: 1.3rem; font-weight: 600; }
.card .l { color: var(--dim); font-size: .78rem; letter-spacing: .06em; text-transform: uppercase; }
.scroll { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th {
  text-align: left; color: var(--dim); font-weight: 600; font-size: .72rem;
  letter-spacing: .08em; text-transform: uppercase; padding: .3rem .7rem .3rem 0;
  border-bottom: 1px solid var(--line); white-space: nowrap;
}
td { padding: .28rem .7rem .28rem 0; vertical-align: top; border-bottom: 1px solid var(--line); }
td.wrap { white-space: normal; }
td:not(.wrap), th { white-space: nowrap; }
.note { color: var(--dim); }
.none { color: var(--dim); font-style: italic; }
.qual { color: var(--dim); margin: 0 0 .5rem; }
.total { margin: .55rem 0 0; }
.proj { color: var(--dim); }
.warn { color: var(--warn); }
.tag {
  display: inline-block; padding: .05rem .45rem; border-radius: 3px;
  font-size: .74rem; letter-spacing: .06em; border: 1px solid currentColor;
}
.pass { color: var(--ok); } .fail { color: var(--accent); } .vac { color: var(--warn); }
.bounds { background: var(--panel); border: 1px solid var(--line); border-radius: 6px; padding: 1rem 1.1rem; }
.bounds dt { font-weight: 600; margin-top: .7rem; }
.bounds dt:first-child { margin-top: 0; }
.bounds dd { margin: .15rem 0 0; color: var(--dim); }
.bounds ul { margin: .3rem 0 0; padding-left: 1.1rem; color: var(--dim); }
footer { margin-top: 3rem; color: var(--dim); font-size: .8rem; border-top: 1px solid var(--line); padding-top: .8rem; }
@media print { body { padding: 0; } .card, .bounds { break-inside: avoid; } }
"#;

/// Render the whole report as one self-contained document.
pub fn render(r: &DiffReport) -> String {
    let mut h = String::with_capacity(16 * 1024);

    h.push_str("<!doctype html>\n<html lang=\"en\">\n<head>\n");
    h.push_str("<meta charset=\"utf-8\">\n");
    h.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    h.push_str(&format!(
        "<title>fwdelta: {} .. {}</title>\n",
        esc(&r.base_label),
        esc(&r.head_label)
    ));
    h.push_str("<style>");
    h.push_str(STYLE);
    h.push_str("</style>\n</head>\n<body>\n<main>\n");

    // ------------------------------------------------------------- header
    h.push_str("<h1>Ruleset delta</h1>\n<p class=\"meta\">\n");
    h.push_str(&format!(
        "base <b>{}</b> &rarr; head <b>{}</b><br>\n",
        esc(&r.base_label),
        esc(&r.head_label)
    ));
    h.push_str(&format!(
        "fwdelta {} &middot; generated {}\n",
        esc(&r.tool_version),
        esc(&r.generated_at)
    ));
    h.push_str("</p>\n");

    h.push_str(&summary(r));

    // ------------------------------------------------------------- chains
    let multi = r.chains.len() > 1;
    for chain in &r.chains {
        if multi {
            h.push_str(&format!(
                "<h2>Chain <span class=\"sub\">{}</span></h2>\n",
                esc(&chain.name)
            ));
        }
        h.push_str(&direction(&chain.blocked, multi));
        h.push_str(&direction(&chain.allowed, multi));
        if !chain.structural.is_empty() {
            h.push_str(&structural(&chain.structural, multi));
        }
    }

    for n in &r.notes {
        h.push_str(&format!("<p class=\"warn\">{}</p>\n", esc(n)));
    }

    if !r.assertions.is_empty() {
        h.push_str(&intent(r));
    }

    h.push_str(&boundaries());

    h.push_str("<footer>\n");
    h.push_str(
        "Generated by fwdelta. This file is self-contained: no scripts, no external \
         stylesheets, no remote assets, no network access at any point.\n",
    );
    h.push_str("</footer>\n</main>\n</body>\n</html>\n");
    h
}

fn summary(r: &DiffReport) -> String {
    let blocked: u128 = r.chains.iter().map(|c| c.blocked.flows).sum();
    let allowed: u128 = r.chains.iter().map(|c| c.allowed.flows).sum();

    let mut h = String::from("<div class=\"cards\">\n");
    let card = |n: String, l: &str, cls: &str| {
        format!(
            "<div class=\"card\"><div class=\"n {cls}\">{n}</div><div class=\"l\">{l}</div></div>\n"
        )
    };
    h.push_str(&card(
        render::count(blocked),
        "flows newly blocked",
        if blocked > 0 { "fail" } else { "" },
    ));
    h.push_str(&card(render::count(allowed), "flows newly allowed", ""));
    if !r.assertions.is_empty() {
        h.push_str(&card(r.passed().to_string(), "assertions passed", "pass"));
        h.push_str(&card(
            r.failed().to_string(),
            "failed",
            if r.failed() > 0 { "fail" } else { "" },
        ));
        // Vacuous is its own card and never folded into passed: it held
        // trivially and established nothing.
        h.push_str(&card(
            r.vacuous().to_string(),
            "vacuous",
            if r.vacuous() > 0 { "vac" } else { "" },
        ));
    }
    h.push_str("</div>\n");
    h
}

fn direction(d: &DirectionReport, nested: bool) -> String {
    let (title, subtitle) = d.direction.heading();
    let tag = if nested { "h3" } else { "h2" };
    let mut h =
        format!("<{tag}>{} <span class=\"sub\">{}</span></{tag}>\n", esc(title), esc(subtitle));

    if d.is_empty() {
        h.push_str("<p class=\"none\">none</p>\n");
        return h;
    }

    if !d.qualifiers.is_empty() {
        h.push_str(&format!(
            "<p class=\"qual\">all entries: {}</p>\n",
            esc(&d.qualifiers.join(", "))
        ));
    }

    // Columns are emitted only when some row uses them, matching the text
    // renderer's behaviour of dropping a column nothing constrains.
    let any = |f: fn(&Row) -> &String| d.rows.iter().any(|r| !f(r).is_empty());
    let show_iif = any(|r| &r.iif);
    let show_oif = any(|r| &r.oif);
    let show_proto = any(|r| &r.proto);
    let show_dport = any(|r| &r.dport);

    h.push_str("<div class=\"scroll\">\n<table>\n<thead><tr>");
    if show_iif {
        h.push_str("<th>in</th>");
    }
    if show_oif {
        h.push_str("<th>out</th>");
    }
    if show_proto {
        h.push_str("<th>proto</th>");
    }
    h.push_str("<th>source</th><th>destination</th>");
    if show_dport {
        h.push_str("<th>port</th>");
    }
    h.push_str("<th>attribution</th></tr></thead>\n<tbody>\n");

    for row in &d.rows {
        h.push_str("<tr>");
        if show_iif {
            h.push_str(&format!("<td>{}</td>", esc(&row.iif)));
        }
        if show_oif {
            h.push_str(&format!("<td>{}</td>", esc(&row.oif)));
        }
        if show_proto {
            h.push_str(&format!("<td>{}</td>", esc(&row.proto)));
        }
        h.push_str(&format!(
            "<td class=\"wrap\">{}</td><td class=\"wrap\">{}</td>",
            esc(&row.src),
            esc(&row.dst)
        ));
        if show_dport {
            h.push_str(&format!("<td>{}</td>", esc(row.dport.trim_start_matches(':'))));
        }
        h.push_str(&format!("<td class=\"note wrap\">{}</td>", esc(&row.note)));
        h.push_str("</tr>\n");
    }
    h.push_str("</tbody>\n</table>\n</div>\n");

    // The projection is stated with the figure, exactly as the text renderer
    // states it. A count whose basis is not given cannot be calibrated.
    h.push_str(&format!(
        "<p class=\"total\"><b>{}</b> flows <span class=\"proj\">({})</span></p>\n",
        render::count(d.flows),
        esc(DirectionReport::PROJECTION)
    ));

    if d.omitted_rows > 0 {
        h.push_str(&format!(
            "<p class=\"note\">&hellip; {} further {} omitted, covering {} flows</p>\n",
            d.omitted_rows,
            if d.omitted_rows == 1 { "entry" } else { "entries" },
            render::count(d.omitted_flows)
        ));
    }
    if d.cells_truncated {
        h.push_str(
            "<p class=\"warn\">&hellip; attribution cell cap reached; some of the delta is not listed</p>\n",
        );
    }
    if d.incomplete {
        h.push_str(
            "<p class=\"warn\">Enumeration hit a work limit; the list above is incomplete.</p>\n",
        );
    }
    h
}

fn structural(rows: &[StructuralRow], nested: bool) -> String {
    let tag = if nested { "h3" } else { "h2" };
    let mut h = format!("<{tag}>Structural</{tag}>\n<div class=\"scroll\">\n<table>\n");
    h.push_str("<thead><tr><th>rule</th><th>change</th><th>detail</th></tr></thead>\n<tbody>\n");
    for r in rows {
        h.push_str(&format!(
            "<tr><td>{:02}</td><td>{}</td><td class=\"note wrap\">{}</td></tr>\n",
            r.number,
            esc(&r.what),
            esc(&r.why)
        ));
    }
    h.push_str("</tbody>\n</table>\n</div>\n");
    h
}

fn intent(r: &DiffReport) -> String {
    let mut h = String::from("<h2>Intent</h2>\n<div class=\"scroll\">\n<table>\n");
    h.push_str(
        "<thead><tr><th>outcome</th><th>assertion</th><th>kind</th><th>detail</th></tr></thead>\n<tbody>\n",
    );
    for a in &r.assertions {
        let cls = if a.is_pass() {
            "pass"
        } else if a.is_fail() {
            "fail"
        } else {
            "vac"
        };
        h.push_str(&format!(
            "<tr><td><span class=\"tag {cls}\">{}</span></td><td>{}</td><td class=\"note\">{}</td><td class=\"wrap\">{}</td></tr>\n",
            esc(&a.outcome),
            esc(&a.name),
            esc(&a.kind),
            esc(&a.detail)
        ));
    }
    h.push_str("</tbody>\n</table>\n</div>\n");

    h.push_str(&format!(
        "<p class=\"total\">{} assertions checked, {} passed, {} failed, {} vacuous.</p>\n",
        r.assertions.len(),
        r.passed(),
        r.failed(),
        r.vacuous()
    ));
    if r.vacuous() > 0 {
        h.push_str(
            "<p class=\"warn\">A vacuous assertion held trivially: nothing in the ruleset \
             decides the packets it describes, so it established nothing. It is not a pass.</p>\n",
        );
    }
    h
}

/// On the page, not in a footnote.
///
/// Anyone reading a report should be able to see what the analysis did not
/// cover without going and finding the documentation. An attestation that
/// carried only a verdict would overstate itself; so would this.
fn boundaries() -> String {
    let mut h =
        String::from("<h2>What this analysis did not cover</h2>\n<div class=\"bounds\">\n<dl>\n");
    for (name, text) in model_boundaries() {
        h.push_str(&format!("<dt>{}</dt>\n<dd>{}</dd>\n", esc(name), esc(text)));
    }
    h.push_str("</dl>\n<p><b>A passing run does not establish:</b></p>\n<ul>\n");
    for item in does_not_establish() {
        h.push_str(&format!("<li>{}</li>\n", esc(item)));
    }
    h.push_str("</ul>\n</div>\n");
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_covers_the_dangerous_characters() {
        assert_eq!(esc("<script>&\"'"), "&lt;script&gt;&amp;&quot;&#39;");
        assert_eq!(esc("10.0.0.0/8"), "10.0.0.0/8");
    }
}
