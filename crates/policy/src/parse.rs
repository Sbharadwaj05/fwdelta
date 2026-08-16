//! Reading the assertion file.
//!
//! The shape is the flat property list blueprint §10 settles on, rather than an
//! expression grammar: easier to write, and harder to outgrow into something
//! that needs its own semantics document.
//!
//! ```toml
//! [zones]
//! vlan_corp = ["10.1.0.0/16"]
//! vlan_ot   = ["10.5.0.0/16"]
//!
//! [[assert]]
//! name  = "ot-cell-isolation"
//! kind  = "isolation"
//! from  = "vlan_corp"
//! to    = "vlan_ot"
//! proto = "tcp"
//! dport = 502
//! ```

use std::collections::BTreeMap;

use fwdelta_ir::{Field, IfMatch, IntervalSet};

/// What an assertion claims.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// No packet in the set may be permitted.
    Isolation,
    /// Every packet in the set must be permitted.
    Reachability,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Isolation => "isolation",
            Kind::Reachability => "reachability",
        }
    }
}

/// One end of an assertion: a zone name, or a literal address set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Endpoint {
    Zone(String),
    Literal(String),
}

impl Endpoint {
    pub fn label(&self) -> &str {
        match self {
            Endpoint::Zone(n) | Endpoint::Literal(n) => n,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Assertion {
    pub name: String,
    pub kind: Kind,
    pub from: Option<Endpoint>,
    pub to: Option<Endpoint>,
    pub proto: Option<IntervalSet>,
    pub sport: Option<IntervalSet>,
    pub dport: Option<IntervalSet>,
    /// Absent means every interface. See [`Assertion::iif_match`].
    pub iif: Option<String>,
    pub oif: Option<String>,
    pub chain: Option<String>,
    /// Human-readable restatement, for the report line.
    pub summary: String,
}

impl Assertion {
    /// An assertion silent on the input interface constrains **all 256 symbol
    /// values**, exactly as an unconstrained rule does. Reading silence as
    /// "interface index 0" would quietly scope the claim to whichever interface
    /// happened to sort first, which is both wrong and invisible.
    pub fn iif_match(&self) -> IfMatch {
        match &self.iif {
            None => IfMatch::Any,
            Some(n) => IfMatch::one(n.clone()),
        }
    }

    pub fn oif_match(&self) -> IfMatch {
        match &self.oif {
            None => IfMatch::Any,
            Some(n) => IfMatch::one(n.clone()),
        }
    }

    /// Interface names this assertion mentions, for the shared symbol table.
    ///
    /// These have to join the table even when no rule names them: "what happens
    /// to traffic arriving on eth7" is a real question with a real answer, given
    /// by whichever rules leave the interface unconstrained. Leaving the name
    /// out would resolve it to the empty set and make the assertion vacuous for
    /// the wrong reason.
    pub fn interface_names(&self) -> impl Iterator<Item = &str> {
        self.iif.iter().chain(self.oif.iter()).map(String::as_str)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub zones: BTreeMap<String, IntervalSet>,
    pub assertions: Vec<Assertion>,
}

impl Policy {
    pub fn interface_names(&self) -> impl Iterator<Item = &str> {
        self.assertions.iter().flat_map(Assertion::interface_names)
    }

    /// Resolve an endpoint to addresses, or say why it cannot be resolved.
    pub fn resolve(&self, e: &Endpoint) -> Result<IntervalSet, PolicyError> {
        match e {
            Endpoint::Zone(name) => self.zones.get(name).cloned().ok_or_else(|| {
                PolicyError::new(format!(
                    "no zone named `{name}`. Defined zones: {}",
                    if self.zones.is_empty() {
                        "none".to_string()
                    } else {
                        self.zones.keys().cloned().collect::<Vec<_>>().join(", ")
                    }
                ))
            }),
            Endpoint::Literal(text) => parse_addr(text),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyError {
    pub message: String,
    /// Where in the document, when the failure is structural.
    pub location: Option<String>,
}

impl PolicyError {
    pub fn new(message: impl Into<String>) -> Self {
        Self { message: message.into(), location: None }
    }
    pub fn at(mut self, location: impl Into<String>) -> Self {
        self.location = Some(location.into());
        self
    }
}

impl core::fmt::Display for PolicyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match &self.location {
            Some(l) => write!(f, "{l}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for PolicyError {}

// ------------------------------------------------------------------ scalars

fn parse_addr(text: &str) -> Result<IntervalSet, PolicyError> {
    let t = text.trim();
    if let Some((base, len)) = t.split_once('/') {
        let addr = parse_ipv4(base)?;
        let len: u32 = len
            .trim()
            .parse()
            .map_err(|_| PolicyError::new(format!("`{len}` is not a prefix length")))?;
        if len > 32 {
            return Err(PolicyError::new(format!("prefix length {len} exceeds 32")));
        }
        return Ok(IntervalSet::prefix(32, u64::from(addr), len));
    }
    if let Some((lo, hi)) = t.split_once('-') {
        let (lo, hi) = (parse_ipv4(lo)?, parse_ipv4(hi)?);
        if hi < lo {
            return Err(PolicyError::new(format!("range `{t}` runs backwards")));
        }
        return Ok(IntervalSet::range(32, u64::from(lo), u64::from(hi)));
    }
    Ok(IntervalSet::point(32, u64::from(parse_ipv4(t)?)))
}

fn parse_ipv4(text: &str) -> Result<u32, PolicyError> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.len() != 4 {
        return Err(PolicyError::new(format!("`{}` is not an IPv4 address", text.trim())));
    }
    let mut v: u32 = 0;
    for p in parts {
        let o: u32 = p.parse().map_err(|_| PolicyError::new(format!("`{p}` is not a number")))?;
        if o > 255 {
            return Err(PolicyError::new(format!("octet {o} is larger than 255")));
        }
        v = (v << 8) | o;
    }
    Ok(v)
}

fn proto_number(name: &str) -> Option<u64> {
    Some(match name {
        "icmp" => 1,
        "igmp" => 2,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
        "esp" => 50,
        "ah" => 51,
        "ospf" => 89,
        "vrrp" => 112,
        "sctp" => 132,
        _ => return None,
    })
}

/// `502`, `"1024-65535"`, `[22, 80, 443]`.
fn parse_ports(v: &toml::Value, what: &str) -> Result<IntervalSet, PolicyError> {
    let one = |v: &toml::Value| -> Result<IntervalSet, PolicyError> {
        match v {
            toml::Value::Integer(n) => {
                if !(0..=65535).contains(n) {
                    return Err(PolicyError::new(format!("port {n} is out of range")));
                }
                Ok(IntervalSet::point(16, *n as u64))
            }
            toml::Value::String(s) => {
                let (lo, hi) = s
                    .split_once('-')
                    .ok_or_else(|| PolicyError::new(format!("`{s}` is not a port range")))?;
                let lo: u64 = lo.trim().parse().map_err(|_| PolicyError::new("bad port"))?;
                let hi: u64 = hi.trim().parse().map_err(|_| PolicyError::new("bad port"))?;
                if lo > 65535 || hi > 65535 || hi < lo {
                    return Err(PolicyError::new(format!("`{s}` is not a valid port range")));
                }
                Ok(IntervalSet::range(16, lo, hi))
            }
            _ => Err(PolicyError::new(format!("{what} must be a number, range or list"))),
        }
    };
    match v {
        toml::Value::Array(items) => {
            let mut acc = IntervalSet::empty(16);
            for i in items {
                acc = acc.union(&one(i)?);
            }
            Ok(acc)
        }
        other => one(other),
    }
}

fn parse_protos(v: &toml::Value) -> Result<IntervalSet, PolicyError> {
    let one = |v: &toml::Value| -> Result<IntervalSet, PolicyError> {
        match v {
            toml::Value::Integer(n) if (0..=255).contains(n) => {
                Ok(IntervalSet::point(8, *n as u64))
            }
            toml::Value::Integer(n) => {
                Err(PolicyError::new(format!("protocol number {n} is out of range")))
            }
            toml::Value::String(s) => proto_number(s)
                .map(|n| IntervalSet::point(8, n))
                .ok_or_else(|| PolicyError::new(format!("unknown protocol `{s}`"))),
            _ => Err(PolicyError::new("proto must be a name, number or list")),
        }
    };
    match v {
        toml::Value::Array(items) => {
            let mut acc = IntervalSet::empty(8);
            for i in items {
                acc = acc.union(&one(i)?);
            }
            Ok(acc)
        }
        other => one(other),
    }
}

// ------------------------------------------------------------------ document

const ASSERT_KEYS: &[&str] =
    &["name", "kind", "from", "to", "proto", "sport", "dport", "iif", "oif", "chain"];

/// Parse an assertion document.
pub fn parse(source: &str) -> Result<Policy, PolicyError> {
    let doc: toml::Table = toml::from_str(source).map_err(|e| {
        let mut err = PolicyError::new(e.message().to_string());
        if let Some(span) = e.span() {
            let line = source[..span.start.min(source.len())].lines().count().max(1);
            err = err.at(format!("line {line}"));
        }
        err
    })?;

    let mut policy = Policy::default();

    if let Some(zones) = doc.get("zones") {
        let table = zones
            .as_table()
            .ok_or_else(|| PolicyError::new("`zones` must be a table").at("[zones]"))?;
        for (name, value) in table {
            let mut set = IntervalSet::empty(32);
            let items: Vec<&toml::Value> = match value {
                toml::Value::Array(a) => a.iter().collect(),
                other => vec![other],
            };
            for item in items {
                let text = item.as_str().ok_or_else(|| {
                    PolicyError::new("a zone member must be a quoted address or prefix")
                        .at(format!("zones.{name}"))
                })?;
                set = set.union(&parse_addr(text).map_err(|e| e.at(format!("zones.{name}")))?);
            }
            if set.is_empty() {
                return Err(PolicyError::new("a zone must contain at least one address")
                    .at(format!("zones.{name}")));
            }
            policy.zones.insert(name.clone(), set);
        }
    }

    let Some(asserts) = doc.get("assert") else {
        return Ok(policy);
    };
    let asserts = asserts
        .as_array()
        .ok_or_else(|| PolicyError::new("`assert` must be a list of tables").at("[[assert]]"))?;

    for (i, item) in asserts.iter().enumerate() {
        let t = item.as_table().ok_or_else(|| {
            PolicyError::new("each assertion must be a table").at(format!("assert[{i}]"))
        })?;

        let name = t
            .get("name")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                PolicyError::new("an assertion needs a `name`").at(format!("assert[{i}]"))
            })?
            .to_string();
        let here = format!("assertion `{name}`");

        // An unrecognised key is a typo, and a typo in a policy file silently
        // weakens the check it was meant to strengthen.
        for key in t.keys() {
            if !ASSERT_KEYS.contains(&key.as_str()) {
                return Err(PolicyError::new(format!(
                    "unknown field `{key}`. Known fields: {}",
                    ASSERT_KEYS.join(", ")
                ))
                .at(here));
            }
        }

        let kind = match t.get("kind").and_then(|v| v.as_str()) {
            Some("isolation") => Kind::Isolation,
            Some("reachability") => Kind::Reachability,
            Some(other) => {
                return Err(PolicyError::new(format!(
                    "unknown kind `{other}`; expected isolation or reachability"
                ))
                .at(here));
            }
            None => {
                return Err(PolicyError::new("an assertion needs a `kind`").at(here));
            }
        };

        let endpoint = |key: &str| -> Option<Endpoint> {
            t.get(key).and_then(|v| v.as_str()).map(|s| {
                if policy.zones.contains_key(s) {
                    Endpoint::Zone(s.to_string())
                } else if s.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                    Endpoint::Literal(s.to_string())
                } else {
                    // Not a zone and not address-shaped: almost certainly a
                    // misspelled zone name, and resolving it will say so.
                    Endpoint::Zone(s.to_string())
                }
            })
        };

        let from = endpoint("from");
        let to = endpoint("to");
        let proto = t.get("proto").map(parse_protos).transpose().map_err(|e| e.at(here.clone()))?;
        let sport = t
            .get("sport")
            .map(|v| parse_ports(v, "sport"))
            .transpose()
            .map_err(|e| e.at(here.clone()))?;
        let dport = t
            .get("dport")
            .map(|v| parse_ports(v, "dport"))
            .transpose()
            .map_err(|e| e.at(here.clone()))?;

        let str_field = |key: &str| t.get(key).and_then(|v| v.as_str()).map(str::to_string);

        let mut summary = String::new();
        summary.push_str(from.as_ref().map(Endpoint::label).unwrap_or("any"));
        summary.push_str(" -> ");
        summary.push_str(to.as_ref().map(Endpoint::label).unwrap_or("any"));
        if let Some(p) = t.get("dport") {
            let _ = std::fmt::Write::write_fmt(&mut summary, format_args!(":{p}"));
        }

        policy.assertions.push(Assertion {
            name,
            kind,
            from,
            to,
            proto,
            sport,
            dport,
            iif: str_field("iif"),
            oif: str_field("oif"),
            chain: str_field("chain"),
            summary,
        });
    }

    // Resolve every endpoint now, so a misspelled zone fails at load rather
    // than turning into a mysterious vacuous result later.
    for a in &policy.assertions {
        for e in [a.from.as_ref(), a.to.as_ref()].into_iter().flatten() {
            policy.resolve(e).map_err(|err| err.at(format!("assertion `{}`", a.name)))?;
        }
    }

    Ok(policy)
}

/// The address set an assertion covers on one side, as a match dimension.
pub fn endpoint_set(
    policy: &Policy,
    e: Option<&Endpoint>,
    field: Field,
) -> Result<IntervalSet, PolicyError> {
    match e {
        None => Ok(IntervalSet::full(field.bits())),
        Some(ep) => policy.resolve(ep),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOC: &str = r#"
[zones]
vlan_corp = ["10.1.0.0/16"]
vlan_ot   = ["10.5.0.0/16", "10.6.0.0/16"]
mgmt      = "10.9.0.0/24"

[[assert]]
name  = "ot-cell-isolation"
kind  = "isolation"
from  = "vlan_corp"
to    = "vlan_ot"
proto = "tcp"
dport = 502

[[assert]]
name  = "mgmt-plane-reachable"
kind  = "reachability"
from  = "mgmt"
to    = "vlan_ot"
proto = "tcp"
dport = 22
iif   = "eth1"
"#;

    #[test]
    fn a_document_parses_to_zones_and_assertions() {
        let p = parse(DOC).unwrap();
        assert_eq!(p.zones.len(), 3);
        assert_eq!(p.zones["vlan_corp"].count(), 65536);
        assert_eq!(p.zones["vlan_ot"].count(), 2 * 65536);
        assert_eq!(p.zones["mgmt"].count(), 256);
        assert_eq!(p.assertions.len(), 2);
        assert_eq!(p.assertions[0].kind, Kind::Isolation);
        assert_eq!(p.assertions[1].kind, Kind::Reachability);
        assert_eq!(p.assertions[0].dport.as_ref().unwrap().ranges(), &[(502, 502)]);
    }

    /// The requirement that keeps an assertion from being silently scoped to
    /// whichever interface happens to sort first.
    #[test]
    fn an_assertion_silent_on_interface_covers_all_256_symbols() {
        let p = parse(DOC).unwrap();
        let syms = fwdelta_ir::SymbolTable::from_names(["eth0", "eth1"]).unwrap();

        let silent = p.assertions[0].iif_match();
        assert_eq!(silent, IfMatch::Any);
        assert!(silent.resolve(&syms).is_full());
        assert_eq!(silent.resolve(&syms).count(), 256);

        let named = p.assertions[1].iif_match();
        assert_eq!(named.resolve(&syms).count(), 1);
    }

    /// Growing the symbol table must not move an assertion that says nothing
    /// about interfaces, for the same reason it must not move a rule.
    #[test]
    fn growing_the_table_does_not_move_a_silent_assertion() {
        let p = parse(DOC).unwrap();
        let narrow = fwdelta_ir::SymbolTable::from_names(["eth0"]).unwrap();
        let wide = fwdelta_ir::SymbolTable::from_names(["eth0", "eth1", "eth2", "wg0"]).unwrap();
        let m = p.assertions[0].iif_match();
        assert_eq!(m.resolve(&narrow), m.resolve(&wide));
    }

    #[test]
    fn assertion_interfaces_join_the_symbol_table() {
        let p = parse(DOC).unwrap();
        let names: Vec<&str> = p.interface_names().collect();
        assert_eq!(names, vec!["eth1"]);
    }

    #[test]
    fn a_misspelled_zone_fails_at_load() {
        let doc = "[zones]\na = [\"10.0.0.0/8\"]\n\n[[assert]]\nname = \"x\"\nkind = \"isolation\"\nfrom = \"typo\"\nto = \"a\"\n";
        let err = parse(doc).unwrap_err();
        assert!(err.to_string().contains("no zone named `typo`"), "{err}");
        assert!(err.to_string().contains("Defined zones: a"), "{err}");
    }

    #[test]
    fn an_unknown_field_is_a_typo_not_an_extension() {
        let doc = "[[assert]]\nname = \"x\"\nkind = \"isolation\"\ndport = 22\ndprot = 80\n";
        let err = parse(doc).unwrap_err();
        assert!(err.to_string().contains("unknown field `dprot`"), "{err}");
    }

    #[test]
    fn literal_endpoints_do_not_need_a_zone() {
        let doc = "[[assert]]\nname = \"x\"\nkind = \"isolation\"\nfrom = \"10.1.0.0/16\"\nto = \"10.5.0.14\"\n";
        let p = parse(doc).unwrap();
        assert_eq!(p.resolve(p.assertions[0].from.as_ref().unwrap()).unwrap().count(), 65536);
        assert_eq!(p.resolve(p.assertions[0].to.as_ref().unwrap()).unwrap().count(), 1);
    }

    #[test]
    fn ports_accept_a_number_a_range_or_a_list() {
        let doc = "[[assert]]\nname=\"a\"\nkind=\"isolation\"\ndport=502\n[[assert]]\nname=\"b\"\nkind=\"isolation\"\ndport=\"1024-2048\"\n[[assert]]\nname=\"c\"\nkind=\"isolation\"\ndport=[22,80,443]\n";
        let p = parse(doc).unwrap();
        assert_eq!(p.assertions[0].dport.as_ref().unwrap().count(), 1);
        assert_eq!(p.assertions[1].dport.as_ref().unwrap().count(), 1025);
        assert_eq!(p.assertions[2].dport.as_ref().unwrap().count(), 3);
    }

    #[test]
    fn bad_values_are_rejected_with_the_assertion_named() {
        for (doc, want) in [
            ("[[assert]]\nname=\"a\"\nkind=\"isolation\"\ndport=99999\n", "out of range"),
            (
                "[[assert]]\nname=\"a\"\nkind=\"isolation\"\nproto=\"frobnicate\"\n",
                "unknown protocol",
            ),
            ("[[assert]]\nname=\"a\"\nkind=\"nonsense\"\n", "unknown kind"),
            ("[[assert]]\nkind=\"isolation\"\n", "needs a `name`"),
            ("[zones]\nz = [\"10.0.0.300\"]\n", "octet 300"),
        ] {
            let err = parse(doc).unwrap_err();
            assert!(err.to_string().contains(want), "expected {want:?}, got: {err}");
        }
    }

    #[test]
    fn malformed_toml_reports_a_line() {
        let err = parse("[zones\nbroken").unwrap_err();
        assert!(err.location.is_some(), "{err}");
    }

    #[test]
    fn an_empty_document_is_an_empty_policy() {
        let p = parse("# nothing\n").unwrap();
        assert!(p.zones.is_empty() && p.assertions.is_empty());
    }
}
