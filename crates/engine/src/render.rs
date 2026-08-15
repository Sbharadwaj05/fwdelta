//! Turning rectangles into the lines a reviewer actually reads.
//!
//! Two rendering choices carry most of the readability:
//!
//! * An address set is printed either as its minimal CIDR cover or as
//!   "enclosing prefix except holes", whichever needs fewer terms. A /16 with a
//!   /24 punched out is eight prefixes the first way and two the second.
//! * Columns are padded to content width, so addresses and ports line up and the
//!   eye can scan down a column instead of reading each line.

use crate::enumerate::Enumeration;
use soteria_ir::{Field, IntervalSet, SymbolTable, set_to_prefixes};

use crate::region::Region;

/// How much detail a line is allowed to carry.
///
/// The merge pass is deliberately aggressive: it will fold three hundred
/// unrelated source blocks into one rectangle, which is correct and unreadable.
/// Truncation therefore has to apply *inside* a dimension as well as across
/// rectangles. The text output is a summary with an explicit remainder; the
/// machine-readable output carries the complete set.
#[derive(Clone, Copy, Debug)]
pub struct Style {
    /// Maximum blocks or ranges printed for one dimension.
    pub max_terms: usize,
}

impl Default for Style {
    fn default() -> Self {
        Self { max_terms: 6 }
    }
}

impl Style {
    /// No truncation. Used by tests and by the JSON writer.
    pub fn full() -> Self {
        Self { max_terms: usize::MAX }
    }

    /// Join terms, replacing the tail beyond the cap with a count.
    fn join(&self, terms: Vec<String>) -> String {
        if terms.len() <= self.max_terms {
            return terms.join(",");
        }
        let hidden = terms.len() - self.max_terms;
        let head = terms[..self.max_terms].join(",");
        format!("{head} +{hidden} more")
    }
}

/// Dotted-quad.
pub fn ipv4(v: u64) -> String {
    format!("{}.{}.{}.{}", (v >> 24) & 0xff, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
}

/// A prefix, with `/32` elided because a bare host address reads faster.
pub fn cidr(v: u64, len: u32) -> String {
    if len == 32 { ipv4(v) } else { format!("{}/{}", ipv4(v), len) }
}

/// Render an address set, choosing the shorter of the two available forms.
pub fn addr_set(set: &IntervalSet, style: &Style) -> String {
    if set.is_empty() {
        return "<none>".to_string();
    }
    if set.is_full() {
        return "any".to_string();
    }

    let direct = set_to_prefixes(set);
    let direct_terms: Vec<String> = direct.iter().map(|&(v, l)| cidr(v, l)).collect();

    let Some((lo, hi)) = set.hull() else { return style.join(direct_terms) };
    let common = ((lo as u32) ^ (hi as u32)).leading_zeros();
    let enclosing = IntervalSet::prefix(32, lo, common);
    let holes = enclosing.difference(set);
    if holes.is_empty() {
        return style.join(direct_terms);
    }
    let hole_prefixes = set_to_prefixes(&holes);
    if 1 + hole_prefixes.len() < direct.len() {
        let base = enclosing.hull().map(|(l, _)| l).unwrap_or(lo);
        let hole_terms: Vec<String> = hole_prefixes.iter().map(|&(v, l)| cidr(v, l)).collect();
        format!("{} except {}", cidr(base, common), style.join(hole_terms))
    } else {
        style.join(direct_terms)
    }
}

/// Render a port set. `None` means unconstrained, which is printed as nothing.
pub fn port_set(set: &IntervalSet, style: &Style) -> Option<String> {
    if set.is_full() {
        return None;
    }
    if set.is_empty() {
        return Some("<none>".to_string());
    }
    let terms: Vec<String> = set
        .ranges()
        .iter()
        .map(|&(lo, hi)| if lo == hi { lo.to_string() } else { format!("{lo}-{hi}") })
        .collect();
    Some(style.join(terms))
}

fn proto_name(v: u64) -> String {
    match v {
        1 => "icmp".into(),
        2 => "igmp".into(),
        6 => "tcp".into(),
        17 => "udp".into(),
        41 => "ipv6".into(),
        47 => "gre".into(),
        50 => "esp".into(),
        51 => "ah".into(),
        58 => "icmpv6".into(),
        89 => "ospf".into(),
        112 => "vrrp".into(),
        132 => "sctp".into(),
        other => other.to_string(),
    }
}

/// Render a protocol set by name where a name exists.
pub fn proto_set(set: &IntervalSet, style: &Style) -> String {
    if set.is_full() {
        return "any".to_string();
    }
    if set.is_empty() {
        return "<none>".to_string();
    }
    // Naming every value is only readable for a handful; beyond that show ranges.
    if set.count() <= 6 {
        let mut names = Vec::new();
        for &(lo, hi) in set.ranges() {
            for v in lo..=hi {
                names.push(proto_name(v));
            }
        }
        return style.join(names);
    }
    let terms: Vec<String> = set
        .ranges()
        .iter()
        .map(|&(lo, hi)| if lo == hi { proto_name(lo) } else { format!("{lo}-{hi}") })
        .collect();
    style.join(terms)
}

/// Render an interface set by name. `None` means unconstrained.
///
/// The dimension spans all 256 symbols, of which only the names appearing in
/// the two rulesets are known. A set covering unnamed symbols therefore cannot
/// be listed positively and is shown as an exclusion instead, which is both
/// shorter and the way the rule was almost certainly written.
pub fn iface_set(set: &IntervalSet, syms: &SymbolTable, style: &Style) -> Option<String> {
    if set.is_full() {
        return None;
    }
    if set.is_empty() {
        return Some("<none>".to_string());
    }
    let named = |s: &IntervalSet| -> Vec<String> {
        s.ranges()
            .iter()
            .flat_map(|&(lo, hi)| lo..=hi)
            .map(|v| match syms.name_of(v as u8) {
                Some(n) => n.to_string(),
                None => format!("if#{v}"),
            })
            .collect()
    };

    if syms.all_named(set) && set.count() <= 8 {
        return Some(style.join(named(set)));
    }
    let complement = set.complement();
    if syms.all_named(&complement) && complement.count() <= 8 {
        return Some(format!("not {}", style.join(named(&complement))));
    }
    Some(format!("{} of 256 symbols", set.count()))
}

/// One rendered rectangle, split into columns before padding.
#[derive(Clone, Debug, Default)]
pub struct Row {
    pub iif: String,
    pub oif: String,
    pub proto: String,
    pub src: String,
    pub dst: String,
    pub dport: String,
    pub note: String,
}

/// Render a rectangle into columns. Source port rides with the source address,
/// since it is constrained rarely and never deserves its own column.
pub fn row(region: &Region, note: &str, syms: &SymbolTable, style: &Style) -> Row {
    let src = match port_set(region.get(Field::SrcPort), style) {
        Some(p) => format!("{}:{}", addr_set(region.get(Field::SrcAddr), style), p),
        None => addr_set(region.get(Field::SrcAddr), style),
    };
    Row {
        iif: iface_set(region.get(Field::IfIn), syms, style)
            .map(|s| format!("in {s}"))
            .unwrap_or_default(),
        oif: iface_set(region.get(Field::IfOut), syms, style)
            .map(|s| format!("out {s}"))
            .unwrap_or_default(),
        proto: proto_set(region.get(Field::Proto), style),
        src,
        dst: addr_set(region.get(Field::DstAddr), style),
        dport: port_set(region.get(Field::DstPort), style)
            .map(|p| format!(":{p}"))
            .unwrap_or_default(),
        note: note.to_string(),
    }
}

/// Pad columns to content width and join. Interface columns disappear entirely
/// when no row constrains them, which is the common case.
pub fn table(rows: &[Row], indent: &str) -> String {
    let width = |f: fn(&Row) -> &String| rows.iter().map(|r| f(r).len()).max().unwrap_or(0);
    let w_iif = width(|r| &r.iif);
    let w_oif = width(|r| &r.oif);
    let w_proto = width(|r| &r.proto);
    let w_src = width(|r| &r.src);
    let w_dst = width(|r| &r.dst);
    let w_dport = width(|r| &r.dport);

    let mut out = String::new();
    for r in rows {
        let mut line = String::from(indent);
        if w_iif > 0 {
            line.push_str(&format!("{:<w_iif$}  ", r.iif));
        }
        if w_oif > 0 {
            line.push_str(&format!("{:<w_oif$}  ", r.oif));
        }
        line.push_str(&format!(
            "{:<w_proto$}  {:<w_src$} -> {:<w_dst$} {:<w_dport$}  {}",
            r.proto, r.src, r.dst, r.dport, r.note
        ));
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

/// Compact packet counts. Exact below a billion, scientific above, because the
/// header space is 2^104 and nobody reads a 32-digit integer.
pub fn count(n: u128) -> String {
    if n < 1_000_000_000 {
        let s = n.to_string();
        let mut out = String::new();
        for (i, ch) in s.chars().enumerate() {
            if i > 0 && (s.len() - i) % 3 == 0 {
                out.push(',');
            }
            out.push(ch);
        }
        out
    } else {
        let mut mantissa = n;
        let mut exp = 0u32;
        while mantissa >= 10 {
            mantissa /= 10;
            exp += 1;
        }
        let lead = n / 10u128.pow(exp.saturating_sub(1).min(38));
        format!("{}.{}e{}", lead / 10, lead % 10, exp)
    }
}

/// Render a whole enumeration under a section heading.
pub fn section(
    title: &str,
    subtitle: &str,
    e: &Enumeration,
    note: &str,
    syms: &SymbolTable,
    style: &Style,
) -> String {
    let mut out = format!("{title}  {subtitle}\n");
    if e.regions.is_empty() {
        out.push_str("  none\n");
        return out;
    }
    let rows: Vec<Row> = e.regions.iter().map(|r| row(r, note, syms, style)).collect();
    out.push_str(&table(&rows, "  "));
    if e.omitted_regions > 0 || e.omitted_packets > 0 {
        out.push_str(&format!(
            "  ... {} further {} omitted, covering {} packets\n",
            e.omitted_regions,
            if e.omitted_regions == 1 { "entry" } else { "entries" },
            count(e.omitted_packets)
        ));
    }
    if e.incomplete {
        out.push_str("  WARNING: enumeration hit a work limit; the list above is incomplete\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_addresses_drop_the_slash_thirtytwo() {
        assert_eq!(cidr(0x0A00_050E, 32), "10.0.5.14");
        assert_eq!(cidr(0x0A01_0000, 16), "10.1.0.0/16");
    }

    #[test]
    fn a_sixteen_with_a_hole_prefers_the_except_form() {
        let base = IntervalSet::prefix(32, 0x0A05_0000, 16);
        let hole = IntervalSet::prefix(32, 0x0A05_0300, 24);
        let text = addr_set(&base.difference(&hole), &Style::default());
        assert_eq!(text, "10.5.0.0/16 except 10.5.3.0/24");
    }

    #[test]
    fn a_clean_prefix_stays_a_prefix() {
        let s = Style::default();
        assert_eq!(addr_set(&IntervalSet::prefix(32, 0x0A01_0000, 16), &s), "10.1.0.0/16");
        assert_eq!(addr_set(&IntervalSet::full(32), &s), "any");
    }

    #[test]
    fn disjoint_prefixes_list_directly() {
        let s = IntervalSet::prefix(32, 0x0A01_0000, 16)
            .union(&IntervalSet::prefix(32, 0x0A02_0000, 16));
        assert_eq!(addr_set(&s, &Style::default()), "10.1.0.0/16,10.2.0.0/16");
    }

    #[test]
    fn a_wide_scatter_is_truncated_with_a_remainder() {
        // Fifty unrelated blocks: correct to merge, impossible to read whole.
        let mut s = IntervalSet::empty(32);
        for i in 0..50u64 {
            s = s.union(&IntervalSet::prefix(32, (20 + i * 3) << 24, 24));
        }
        let text = addr_set(&s, &Style::default());
        assert!(text.ends_with("+44 more"), "unexpected: {text}");
        assert_eq!(text.matches(',').count(), 5);
        // The full style must still print everything, for the JSON path.
        assert!(!addr_set(&s, &Style::full()).contains("more"));
    }

    #[test]
    fn unconstrained_ports_render_as_nothing() {
        let s = Style::default();
        assert_eq!(port_set(&IntervalSet::full(16), &s), None);
        assert_eq!(port_set(&IntervalSet::point(16, 502), &s).unwrap(), "502");
        assert_eq!(port_set(&IntervalSet::range(16, 1024, 65535), &s).unwrap(), "1024-65535");
    }

    #[test]
    fn protocols_render_by_name() {
        let s = Style::default();
        assert_eq!(proto_set(&IntervalSet::point(8, 6), &s), "tcp");
        assert_eq!(
            proto_set(&IntervalSet::point(8, 6).union(&IntervalSet::point(8, 17)), &s),
            "tcp,udp"
        );
        assert_eq!(proto_set(&IntervalSet::full(8), &s), "any");
    }

    #[test]
    fn counts_are_grouped() {
        assert_eq!(count(1_000), "1,000");
        assert_eq!(count(65_280), "65,280");
    }
}
