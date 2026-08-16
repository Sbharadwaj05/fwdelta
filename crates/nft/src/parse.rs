//! Recursive-descent parser for the documented nftables subset.
//!
//! The boundary is `docs/NFTABLES-SUBSET.md`. Everything outside it is a hard
//! error carrying a file, line and column, because a construct the frontend
//! quietly drops produces a model that confidently disagrees with the kernel.
//!
//! Two rejections here exist for the *model* rather than the grammar, and are
//! the reason this file knows anything about semantics at all:
//!
//! * A port match must pin a protocol that has ports (SEMANTICS §4.2).
//! * A rule whose predicate can never hold is a typo, not a rule.

use soteria_ir::{Action, Chain, Field, Hook, IfMatch, IntervalSet, Match, Origin, Ruleset};
use std::collections::BTreeSet;

use crate::error::{Cause, ParseError};
use crate::lex::{Tok, Token, lex};

/// Protocols that carry ports. A port match on anything else is unsound.
const PORT_BEARING: [u64; 3] = [6, 17, 132];

fn proto_number(name: &str) -> Option<u64> {
    Some(match name {
        "icmp" => 1,
        "igmp" => 2,
        "tcp" => 6,
        "udp" => 17,
        "gre" => 47,
        "esp" => 50,
        "ah" => 51,
        "icmpv6" | "ipv6-icmp" => 58,
        "ospf" => 89,
        "vrrp" => 112,
        "sctp" => 132,
        "udplite" => 136,
        _ => return None,
    })
}

pub struct Parser<'a> {
    toks: Vec<Token>,
    pos: usize,
    file: String,
    src: &'a str,
}

impl<'a> Parser<'a> {
    pub fn new(file: &str, src: &'a str) -> Result<Self, ParseError> {
        let toks = lex(file, src).map_err(|e| e.with_source(src))?;
        Ok(Self { toks, pos: 0, file: file.to_string(), src })
    }

    // ------------------------------------------------------------- primitives

    fn peek(&self) -> &Tok {
        &self.toks[self.pos.min(self.toks.len() - 1)].tok
    }

    fn at(&self) -> (u32, u32) {
        let t = &self.toks[self.pos.min(self.toks.len() - 1)];
        (t.line, t.column)
    }

    fn bump(&mut self) -> Tok {
        let t = self.toks[self.pos.min(self.toks.len() - 1)].tok.clone();
        if self.pos < self.toks.len() - 1 {
            self.pos += 1;
        }
        t
    }

    fn err(&self, cause: Cause, message: impl Into<String>) -> ParseError {
        let (line, column) = self.at();
        ParseError::new(self.file.clone(), line, column, cause, message).with_source(self.src)
    }

    fn err_at(
        &self,
        line: u32,
        column: u32,
        cause: Cause,
        message: impl Into<String>,
    ) -> ParseError {
        ParseError::new(self.file.clone(), line, column, cause, message).with_source(self.src)
    }

    fn syntax(&self, message: impl Into<String>) -> ParseError {
        self.err(Cause::Syntax, message)
    }

    fn eat_sym(&mut self, c: char) -> bool {
        if *self.peek() == Tok::Sym(c) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect_sym(&mut self, c: char) -> Result<(), ParseError> {
        if self.eat_sym(c) {
            Ok(())
        } else {
            Err(self.syntax(format!("expected `{c}`, found {}", self.peek().describe())))
        }
    }

    fn eat_word(&mut self, w: &str) -> bool {
        if matches!(self.peek(), Tok::Word(x) if x == w) {
            self.bump();
            true
        } else {
            false
        }
    }

    fn expect_word(&mut self) -> Result<String, ParseError> {
        match self.bump() {
            Tok::Word(w) => Ok(w),
            other => Err(self.syntax(format!("expected a name, found {}", other.describe()))),
        }
    }

    fn expect_num(&mut self) -> Result<u64, ParseError> {
        match self.bump() {
            Tok::Num(n) => Ok(n),
            other => Err(self.syntax(format!("expected a number, found {}", other.describe()))),
        }
    }

    fn skip_breaks(&mut self) {
        while *self.peek() == Tok::Break {
            self.bump();
        }
    }

    // ------------------------------------------------------------- top level

    pub fn parse(&mut self) -> Result<Ruleset, ParseError> {
        let mut chains = Vec::new();
        self.skip_breaks();
        while *self.peek() != Tok::Eof {
            let (line, col) = self.at();
            match self.bump() {
                Tok::Word(w) if w == "table" => chains.extend(self.table()?),
                Tok::Word(w) if matches!(w.as_str(), "include" | "define" | "set" | "map" | "element") => {
                    return Err(self
                        .err_at(line, col, Cause::Unimplemented, format!("`{w}` is not supported"))
                        .with_hint(
                            "the subset covers literal matches only; see docs/NFTABLES-SUBSET.md",
                        ));
                }
                other => {
                    return Err(self.err_at(
                        line,
                        col,
                        Cause::Syntax,
                        format!("expected `table`, found {}", other.describe()),
                    ));
                }
            }
            self.skip_breaks();
        }
        Ok(Ruleset { label: self.file.clone(), chains })
    }

    fn table(&mut self) -> Result<Vec<Chain>, ParseError> {
        let (line, col) = self.at();
        let family = self.expect_word()?;
        match family.as_str() {
            "ip" => {}
            "ip6" | "inet" | "arp" | "bridge" | "netdev" => {
                return Err(self
                    .err_at(
                        line,
                        col,
                        Cause::OutOfScope,
                        format!("address family `{family}` is not supported"),
                    )
                    .with_hint(
                        "1.0 models IPv4 only; the header layout is 32-bit (SEMANTICS §4.4)",
                    ));
            }
            other => {
                return Err(self.err_at(
                    line,
                    col,
                    Cause::Syntax,
                    format!("unknown address family `{other}`"),
                ));
            }
        }
        let _name = self.expect_word()?;
        self.expect_sym('{')?;

        let mut chains = Vec::new();
        loop {
            self.skip_breaks();
            if self.eat_sym('}') {
                break;
            }
            let (line, col) = self.at();
            match self.bump() {
                Tok::Word(w) if w == "chain" => chains.push(self.chain()?),
                Tok::Word(w) if matches!(w.as_str(), "set" | "map" | "element" | "counter" | "quota") => {
                    return Err(self
                        .err_at(
                            line,
                            col,
                            Cause::Unimplemented,
                            format!("`{w}` declarations are not supported"),
                        )
                        .with_hint("see docs/NFTABLES-SUBSET.md"));
                }
                Tok::Eof => return Err(self.syntax("unexpected end of file inside `table`")),
                other => {
                    return Err(self.err_at(
                        line,
                        col,
                        Cause::Syntax,
                        format!("expected `chain`, found {}", other.describe()),
                    ));
                }
            }
        }
        Ok(chains)
    }

    fn chain(&mut self) -> Result<Chain, ParseError> {
        let (name_line, name_col) = self.at();
        let name = self.expect_word()?;
        self.expect_sym('{')?;
        self.skip_breaks();

        // Base chains declare a hook. A chain without one is a regular chain,
        // reachable only by jump or goto, which the subset excludes.
        if !self.eat_word("type") {
            return Err(self
                .err_at(
                    name_line,
                    name_col,
                    Cause::OutOfScope,
                    format!("chain `{name}` is a regular chain, with no hook"),
                )
                .with_hint(
                    "regular chains are only reachable by jump or goto, which 1.0 does not model",
                ));
        }

        let (tline, tcol) = self.at();
        let kind = self.expect_word()?;
        match kind.as_str() {
            "filter" => {}
            "nat" => {
                return Err(self
                    .err_at(tline, tcol, Cause::OutOfScope, "this is a NAT table")
                    .with_hint(
                        "address translation changes packet identity in transit and is a stated \
                         non-goal (blueprint §02); analysis of the whole file is refused because a \
                         filter result would describe packets that do not exist as analysed",
                    ));
            }
            other => {
                return Err(self.err_at(
                    tline,
                    tcol,
                    Cause::OutOfScope,
                    format!("chain type `{other}` is not supported"),
                ));
            }
        }

        if !self.eat_word("hook") {
            return Err(self.syntax("expected `hook` after the chain type"));
        }
        let (hline, hcol) = self.at();
        let hook_name = self.expect_word()?;
        let hook = match hook_name.as_str() {
            "input" => Hook::Input,
            "output" => Hook::Output,
            "forward" => Hook::Forward,
            "prerouting" | "postrouting" => {
                return Err(self
                    .err_at(
                        hline,
                        hcol,
                        Cause::OutOfScope,
                        format!("hook `{hook_name}` is not supported"),
                    )
                    .with_hint("only reachable with NAT or routing in scope, which 1.0 excludes"));
            }
            other => {
                return Err(self.err_at(
                    hline,
                    hcol,
                    Cause::Syntax,
                    format!("unknown hook `{other}`"),
                ));
            }
        };

        if self.eat_word("device") {
            self.bump();
        }
        if !self.eat_word("priority") {
            return Err(self.syntax("expected `priority` in the chain declaration"));
        }
        // Priority does not affect a single-chain analysis, but it has to parse.
        self.eat_sym('-');
        match self.peek() {
            Tok::Num(_) | Tok::Word(_) => {
                self.bump();
            }
            _ => return Err(self.syntax("expected a priority value")),
        }
        self.skip_breaks();

        // nftables defaults a base chain's policy to accept when none is given.
        let mut policy = Action::Accept;
        if self.eat_word("policy") {
            let (pline, pcol) = self.at();
            let v = self.expect_word()?;
            policy = match v.as_str() {
                "accept" => Action::Accept,
                "drop" => Action::Drop,
                other => {
                    return Err(self.err_at(
                        pline,
                        pcol,
                        Cause::Syntax,
                        format!("policy must be `accept` or `drop`, found `{other}`"),
                    ));
                }
            };
            self.skip_breaks();
        }

        let mut chain = Chain::new(name, hook, policy);
        loop {
            self.skip_breaks();
            if self.eat_sym('}') {
                break;
            }
            if *self.peek() == Tok::Eof {
                return Err(self.syntax("unexpected end of file inside `chain`"));
            }
            let (m, action, origin) = self.rule()?;
            chain.push(m, action, origin);
        }
        Ok(chain)
    }

    // ----------------------------------------------------------------- rules

    fn rule(&mut self) -> Result<(Match, Action, Origin), ParseError> {
        let (line, column) = self.at();
        let mut m = Match::any();
        let mut action: Option<Action> = None;
        let mut ports_constrained = false;

        loop {
            match self.peek().clone() {
                Tok::Break | Tok::Eof => break,
                Tok::Sym('}') => break,
                Tok::Sym('@') => {
                    return Err(self
                        .err(Cause::Unimplemented, "named sets are not supported")
                        .with_hint("inline the members, or see docs/NFTABLES-SUBSET.md"));
                }
                Tok::Word(w) => {
                    let (kline, kcol) = self.at();
                    self.bump();
                    match w.as_str() {
                        "ip" => m = self.ip_match(m)?,
                        "meta" => m = self.meta_match(m, kline, kcol)?,
                        "tcp" | "udp" => {
                            m = self.l4_match(m, &w, &mut ports_constrained)?;
                        }
                        "sctp" | "dccp" | "udplite" => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::Unimplemented,
                                    format!("`{w}` port matches are not supported yet"),
                                )
                                .with_hint(
                                    "the model has the protocol; the frontend has not been \
                                     exercised against the kernel for it",
                                ));
                        }
                        "iifname" => {
                            let s = self.if_spec()?;
                            m = m.with_iif(s);
                        }
                        "oifname" => {
                            let s = self.if_spec()?;
                            m = m.with_oif(s);
                        }
                        "iif" | "oif" => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::OutOfScope,
                                    format!("`{w}` matches the numeric interface index"),
                                )
                                .with_hint(format!(
                                    "an ifindex is assigned at runtime, so it is neither stable \
                                     across reloads nor comparable between two revisions of a \
                                     file; use `{w}name` instead",
                                )));
                        }
                        "ct" => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::OutOfScope,
                                    "connection tracking is outside the model",
                                )
                                .with_hint(
                                    "the model is stateless: forward-direction packets are \
                                     governed by the ruleset and return traffic for permitted \
                                     connections is assumed permitted (SEMANTICS §4.1)",
                                ));
                        }
                        "limit" | "quota" => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::OutOfScope,
                                    format!("`{w}` is not a function of the packet header"),
                                )
                                .with_hint("rate is state, and the header space has no room for it"));
                        }
                        "counter" => self.skip_counter(),
                        "comment" => {
                            if !matches!(self.peek(), Tok::Str(_)) {
                                return Err(self.syntax("expected a quoted comment"));
                            }
                            self.bump();
                        }
                        "log" => self.skip_log(),
                        "accept" => action = Some(self.set_action(action, Action::Accept, kline, kcol)?),
                        "drop" => action = Some(self.set_action(action, Action::Drop, kline, kcol)?),
                        "reject" => {
                            if self.eat_word("with") {
                                // `reject with icmp type port-unreachable` and friends.
                                while !matches!(self.peek(), Tok::Break | Tok::Eof | Tok::Sym('}'))
                                {
                                    self.bump();
                                }
                            }
                            action = Some(self.set_action(action, Action::Reject, kline, kcol)?);
                        }
                        "jump" | "goto" => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::OutOfScope,
                                    format!("`{w}` to another chain is not modelled"),
                                )
                                .with_hint("1.0 analyses one base chain at a time"));
                        }
                        "return" | "queue" | "dup" | "fwd" | "notrack" => {
                            return Err(self.err_at(
                                kline,
                                kcol,
                                Cause::OutOfScope,
                                format!("`{w}` is not a filtering verdict"),
                            ));
                        }
                        "snat" | "dnat" | "masquerade" | "redirect" => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::OutOfScope,
                                    format!("`{w}` performs address translation"),
                                )
                                .with_hint(
                                    "NAT is a stated non-goal (blueprint §02); the whole file is \
                                     refused because a filter analysis would describe packets that \
                                     do not exist as analysed",
                                ));
                        }
                        other => {
                            return Err(self
                                .err_at(
                                    kline,
                                    kcol,
                                    Cause::Unimplemented,
                                    format!("`{other}` is not in the supported subset"),
                                )
                                .with_hint("the full boundary is docs/NFTABLES-SUBSET.md"));
                        }
                    }
                }
                other => {
                    return Err(self.syntax(format!("unexpected {}", other.describe())));
                }
            }
        }

        let Some(action) = action else {
            return Err(self
                .err_at(line, column, Cause::OutOfScope, "this rule has no verdict")
                .with_hint(
                    "a rule that falls through is meaningful to nftables but ambiguous in a \
                     report; give it an explicit accept, drop or reject",
                ));
        };

        self.check_soundness(&m, ports_constrained, line, column)?;

        let origin = Origin {
            file: self.file.clone(),
            line,
            column,
            text: self.src.lines().nth(line.saturating_sub(1) as usize).unwrap_or("").trim().to_string(),
        };
        Ok((m, action, origin))
    }

    /// The two rejections that exist for the model rather than the grammar.
    fn check_soundness(
        &self,
        m: &Match,
        ports_constrained: bool,
        line: u32,
        column: u32,
    ) -> Result<(), ParseError> {
        if m.is_unsatisfiable() {
            return Err(self
                .err_at(line, column, Cause::Soundness, "this rule can never match a packet")
                .with_hint(
                    "the matches contradict each other. A rule matching nothing is \
                     indistinguishable in a report from one that was never written",
                ));
        }

        if ports_constrained {
            let proto = m.packet_dim(Field::Proto);
            let all_port_bearing = !proto.is_full()
                && proto
                    .ranges()
                    .iter()
                    .flat_map(|&(lo, hi)| lo..=hi)
                    .all(|p| PORT_BEARING.contains(&p));
            if !all_port_bearing {
                return Err(self
                    .err_at(
                        line,
                        column,
                        Cause::Soundness,
                        "a port match without a protocol that has ports",
                    )
                    .with_hint(
                        "the model gives every packet a source and destination port, including \
                         ICMP, which is sound only while port matches pin tcp, udp or sctp \
                         (SEMANTICS §4.2)",
                    ));
            }
        }
        Ok(())
    }

    fn set_action(
        &self,
        current: Option<Action>,
        new: Action,
        line: u32,
        column: u32,
    ) -> Result<Action, ParseError> {
        if let Some(existing) = current {
            return Err(self.err_at(
                line,
                column,
                Cause::Syntax,
                format!("this rule already has the verdict `{existing}`"),
            ));
        }
        Ok(new)
    }

    /// `counter`, optionally with the `packets N bytes N` that `nft list` emits.
    fn skip_counter(&mut self) {
        if self.eat_word("packets") {
            let _ = self.expect_num();
            if self.eat_word("bytes") {
                let _ = self.expect_num();
            }
        }
    }

    /// `log` with any of its options. It has no effect on the verdict.
    fn skip_log(&mut self) {
        loop {
            match self.peek().clone() {
                Tok::Word(w)
                    if matches!(w.as_str(), "prefix" | "level" | "flags" | "group" | "snaplen" | "queue-threshold") =>
                {
                    self.bump();
                    if matches!(self.peek(), Tok::Str(_) | Tok::Word(_) | Tok::Num(_)) {
                        self.bump();
                    }
                }
                _ => break,
            }
        }
    }

    // ------------------------------------------------------ match expressions

    fn ip_match(&mut self, m: Match) -> Result<Match, ParseError> {
        let (line, col) = self.at();
        let what = self.expect_word()?;
        match what.as_str() {
            "saddr" => {
                let set = self.addr_spec()?;
                Ok(m.constrain(Field::SrcAddr, &set))
            }
            "daddr" => {
                let set = self.addr_spec()?;
                Ok(m.constrain(Field::DstAddr, &set))
            }
            "protocol" => {
                let set = self.proto_spec()?;
                Ok(m.constrain(Field::Proto, &set))
            }
            other => Err(self
                .err_at(
                    line,
                    col,
                    Cause::Unimplemented,
                    format!("`ip {other}` is not in the supported subset"),
                )
                .with_hint("supported: `ip saddr`, `ip daddr`, `ip protocol`")),
        }
    }

    fn meta_match(&mut self, m: Match, line: u32, col: u32) -> Result<Match, ParseError> {
        let what = self.expect_word()?;
        match what.as_str() {
            "l4proto" => {
                let set = self.proto_spec()?;
                Ok(m.constrain(Field::Proto, &set))
            }
            "iifname" => {
                let s = self.if_spec()?;
                Ok(m.with_iif(s))
            }
            "oifname" => {
                let s = self.if_spec()?;
                Ok(m.with_oif(s))
            }
            other => Err(self
                .err_at(
                    line,
                    col,
                    Cause::Unimplemented,
                    format!("`meta {other}` is not in the supported subset"),
                )
                .with_hint("supported: `meta l4proto`, `meta iifname`, `meta oifname`")),
        }
    }

    fn l4_match(
        &mut self,
        m: Match,
        proto: &str,
        ports_constrained: &mut bool,
    ) -> Result<Match, ParseError> {
        let (line, col) = self.at();
        let what = self.expect_word()?;
        let field = match what.as_str() {
            "sport" => Field::SrcPort,
            "dport" => Field::DstPort,
            other => {
                return Err(self.err_at(
                    line,
                    col,
                    Cause::Unimplemented,
                    format!("`{proto} {other}` is not in the supported subset"),
                ));
            }
        };
        let ports = self.port_spec()?;
        *ports_constrained = true;
        // `tcp dport 22` implies the protocol, exactly as nftables does. This is
        // what keeps the SEMANTICS §4.2 obligation true by construction.
        let number = proto_number(proto).expect("caller passed a known protocol");
        Ok(m.constrain(Field::Proto, &IntervalSet::point(8, number)).constrain(field, &ports))
    }

    // ------------------------------------------------------------ value forms

    /// Named sets can appear wherever a literal value can, so the check belongs
    /// with the value parsers and not only at the start of a statement.
    fn reject_named_set(&mut self) -> Result<(), ParseError> {
        if *self.peek() == Tok::Sym('@') {
            return Err(self
                .err(Cause::Unimplemented, "named sets are not supported")
                .with_hint(
                    "a named set is defined elsewhere in the file, which needs a resolution \
                     pass the frontend does not have yet; inline the members",
                ));
        }
        Ok(())
    }

    /// `[!=] value`, returning whether the match was negated.
    fn negation(&mut self) -> bool {
        if *self.peek() == Tok::Sym('!') {
            self.bump();
            self.eat_sym('=');
            true
        } else {
            false
        }
    }

    fn addr_spec(&mut self) -> Result<IntervalSet, ParseError> {
        let negated = self.negation();
        self.reject_named_set()?;
        let set = self.addr_value()?;
        Ok(if negated { set.complement() } else { set })
    }

    fn addr_value(&mut self) -> Result<IntervalSet, ParseError> {
        if self.eat_sym('{') {
            let mut acc = IntervalSet::empty(32);
            loop {
                self.skip_breaks();
                acc = acc.union(&self.addr_atom()?);
                self.skip_breaks();
                if self.eat_sym(',') {
                    continue;
                }
                self.expect_sym('}')?;
                break;
            }
            return Ok(acc);
        }
        self.addr_atom()
    }

    fn addr_atom(&mut self) -> Result<IntervalSet, ParseError> {
        let (line, col) = self.at();
        let Tok::Ip(base) = self.bump() else {
            return Err(self.err_at(line, col, Cause::Syntax, "expected an IPv4 address"));
        };
        if self.eat_sym('/') {
            let len = self.expect_num()?;
            if len > 32 {
                return Err(self.err_at(
                    line,
                    col,
                    Cause::Syntax,
                    format!("prefix length {len} exceeds 32"),
                ));
            }
            return Ok(IntervalSet::prefix(32, u64::from(base), len as u32));
        }
        if self.eat_sym('-') {
            let (eline, ecol) = self.at();
            let Tok::Ip(hi) = self.bump() else {
                return Err(self.err_at(eline, ecol, Cause::Syntax, "expected an IPv4 address"));
            };
            if hi < base {
                return Err(self.err_at(line, col, Cause::Syntax, "range runs backwards"));
            }
            return Ok(IntervalSet::range(32, u64::from(base), u64::from(hi)));
        }
        Ok(IntervalSet::point(32, u64::from(base)))
    }

    fn port_spec(&mut self) -> Result<IntervalSet, ParseError> {
        let negated = self.negation();
        self.reject_named_set()?;
        let set = self.port_value()?;
        Ok(if negated { set.complement() } else { set })
    }

    fn port_value(&mut self) -> Result<IntervalSet, ParseError> {
        if self.eat_sym('{') {
            let mut acc = IntervalSet::empty(16);
            loop {
                self.skip_breaks();
                acc = acc.union(&self.port_atom()?);
                self.skip_breaks();
                if self.eat_sym(',') {
                    continue;
                }
                self.expect_sym('}')?;
                break;
            }
            return Ok(acc);
        }
        self.port_atom()
    }

    fn port_atom(&mut self) -> Result<IntervalSet, ParseError> {
        let (line, col) = self.at();
        if let Tok::Word(name) = self.peek().clone() {
            return Err(self
                .err_at(
                    line,
                    col,
                    Cause::OutOfScope,
                    format!("service name `{name}` cannot be resolved"),
                )
                .with_hint(
                    "resolving it depends on the host's /etc/services, which is not in the \
                     ruleset and would make the analysis depend on where it ran; write the number",
                ));
        }
        let lo = self.expect_num()?;
        if lo > 65535 {
            return Err(self.err_at(line, col, Cause::Syntax, format!("port {lo} exceeds 65535")));
        }
        if self.eat_sym('-') {
            let (hline, hcol) = self.at();
            let hi = self.expect_num()?;
            if hi > 65535 {
                return Err(self.err_at(
                    hline,
                    hcol,
                    Cause::Syntax,
                    format!("port {hi} exceeds 65535"),
                ));
            }
            if hi < lo {
                return Err(self.err_at(line, col, Cause::Syntax, "range runs backwards"));
            }
            return Ok(IntervalSet::range(16, lo, hi));
        }
        Ok(IntervalSet::point(16, lo))
    }

    fn proto_spec(&mut self) -> Result<IntervalSet, ParseError> {
        let negated = self.negation();
        self.reject_named_set()?;
        let set = if self.eat_sym('{') {
            let mut acc = IntervalSet::empty(8);
            loop {
                self.skip_breaks();
                acc = acc.union(&self.proto_atom()?);
                self.skip_breaks();
                if self.eat_sym(',') {
                    continue;
                }
                self.expect_sym('}')?;
                break;
            }
            acc
        } else {
            self.proto_atom()?
        };
        Ok(if negated { set.complement() } else { set })
    }

    fn proto_atom(&mut self) -> Result<IntervalSet, ParseError> {
        let (line, col) = self.at();
        match self.bump() {
            Tok::Num(n) if n <= 255 => Ok(IntervalSet::point(8, n)),
            Tok::Num(n) => Err(self.err_at(
                line,
                col,
                Cause::Syntax,
                format!("protocol number {n} exceeds 255"),
            )),
            Tok::Word(w) => match proto_number(&w) {
                Some(n) => Ok(IntervalSet::point(8, n)),
                None => Err(self
                    .err_at(line, col, Cause::Syntax, format!("unknown protocol `{w}`"))
                    .with_hint("write the IP protocol number if the name is unfamiliar")),
            },
            other => Err(self.err_at(
                line,
                col,
                Cause::Syntax,
                format!("expected a protocol, found {}", other.describe()),
            )),
        }
    }

    fn if_spec(&mut self) -> Result<IfMatch, ParseError> {
        let negated = self.negation();
        self.reject_named_set()?;
        let mut names = BTreeSet::new();
        if self.eat_sym('{') {
            loop {
                self.skip_breaks();
                names.insert(self.if_name()?);
                self.skip_breaks();
                if self.eat_sym(',') {
                    continue;
                }
                self.expect_sym('}')?;
                break;
            }
        } else {
            names.insert(self.if_name()?);
        }
        Ok(if negated { IfMatch::NoneOf(names) } else { IfMatch::OneOf(names) })
    }

    fn if_name(&mut self) -> Result<String, ParseError> {
        let (line, col) = self.at();
        let name = match self.bump() {
            Tok::Str(s) => s,
            Tok::Word(w) => w,
            other => {
                return Err(self.err_at(
                    line,
                    col,
                    Cause::Syntax,
                    format!("expected an interface name, found {}", other.describe()),
                ));
            }
        };
        // A wildcard is a claim about interfaces the tool has never seen.
        if name.contains('*') || *self.peek() == Tok::Sym('*') {
            return Err(self
                .err_at(
                    line,
                    col,
                    Cause::Soundness,
                    format!("interface wildcard `{name}` is not supported"),
                )
                .with_hint(
                    "interfaces are modelled as symbols drawn from the names in the two files \
                     being compared, so a wildcard would have to range over names the tool cannot \
                     observe; name each interface (decision D-02)",
                ));
        }
        Ok(name)
    }
}

/// Parse one nftables file into the IR.
pub fn parse(file: &str, source: &str) -> Result<Ruleset, ParseError> {
    Parser::new(file, source)?.parse()
}
