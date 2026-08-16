//! Tokeniser.
//!
//! Hand-written rather than built on a combinator library, per decision D-03.
//! nftables statement syntax is small and irregular rather than deeply nested,
//! precise `file:line:column` positions are easier to control directly, and
//! every dependency removed is one fewer entry to justify in the `cargo-deny`
//! allowlist that the air-gap claim rests on.
//!
//! Newlines are significant: nftables separates statements by newline or `;`.

use crate::error::{Cause, ParseError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Tok {
    /// An identifier or keyword.
    Word(String),
    Num(u64),
    /// A dotted quad, already packed.
    Ip(u32),
    /// A quoted string, without the quotes.
    Str(String),
    Sym(char),
    /// Statement separator: a newline or a `;`.
    Break,
    Eof,
}

impl Tok {
    /// How to name this token in an error message.
    pub fn describe(&self) -> String {
        match self {
            Tok::Word(w) => format!("`{w}`"),
            Tok::Num(n) => format!("`{n}`"),
            Tok::Ip(v) => {
                format!("`{}.{}.{}.{}`", v >> 24, (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
            }
            Tok::Str(s) => format!("`\"{s}\"`"),
            Tok::Sym(c) => format!("`{c}`"),
            Tok::Break => "end of statement".to_string(),
            Tok::Eof => "end of file".to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Token {
    pub tok: Tok,
    pub line: u32,
    pub column: u32,
}

struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
    col: u32,
    file: String,
}

impl<'a> Lexer<'a> {
    fn peek(&self) -> Option<u8> {
        self.src.get(self.pos).copied()
    }

    fn peek_at(&self, n: usize) -> Option<u8> {
        self.src.get(self.pos + n).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.pos += 1;
        if c == b'\n' {
            self.line += 1;
            self.col = 1;
        } else {
            self.col += 1;
        }
        Some(c)
    }

    fn err(&self, line: u32, col: u32, message: impl Into<String>) -> ParseError {
        ParseError::new(self.file.clone(), line, col, Cause::Syntax, message)
    }
}

/// Split source into tokens.
pub fn lex(file: &str, src: &str) -> Result<Vec<Token>, ParseError> {
    let mut lx = Lexer { src: src.as_bytes(), pos: 0, line: 1, col: 1, file: file.to_string() };
    let mut out: Vec<Token> = Vec::new();

    loop {
        // Whitespace, comments, and line continuations.
        loop {
            match lx.peek() {
                Some(b' ') | Some(b'\t') | Some(b'\r') => {
                    lx.bump();
                }
                Some(b'#') => {
                    while let Some(c) = lx.peek() {
                        if c == b'\n' {
                            break;
                        }
                        lx.bump();
                    }
                }
                Some(b'\\') if lx.peek_at(1) == Some(b'\n') => {
                    lx.bump();
                    lx.bump();
                }
                _ => break,
            }
        }

        let (line, column) = (lx.line, lx.col);
        let Some(c) = lx.peek() else {
            out.push(Token { tok: Tok::Eof, line, column });
            return Ok(out);
        };

        let tok = match c {
            b'\n' | b';' => {
                lx.bump();
                // Collapse runs of separators; blank lines are not statements.
                if matches!(out.last().map(|t| &t.tok), Some(Tok::Break) | None) {
                    continue;
                }
                Tok::Break
            }
            b'"' => {
                lx.bump();
                let mut s = String::new();
                loop {
                    match lx.bump() {
                        Some(b'"') => break,
                        Some(b'\\') => {
                            if let Some(n) = lx.bump() {
                                s.push(n as char);
                            }
                        }
                        Some(ch) => s.push(ch as char),
                        None => {
                            return Err(lx.err(line, column, "unterminated string"));
                        }
                    }
                }
                Tok::Str(s)
            }
            b'0'..=b'9' => scan_number_or_ip(&mut lx, line, column)?,
            c if c.is_ascii_alphabetic() || c == b'_' => {
                let mut w = String::new();
                while let Some(ch) = lx.peek() {
                    if ch.is_ascii_alphanumeric() || ch == b'_' || ch == b'-' || ch == b'.' {
                        // A trailing `-` before a digit is a range separator, not
                        // part of the word: `1024-65535` must not lex as a word.
                        if ch == b'-' && lx.peek_at(1).is_some_and(|n| n.is_ascii_digit()) {
                            break;
                        }
                        w.push(ch as char);
                        lx.bump();
                    } else {
                        break;
                    }
                }
                Tok::Word(w)
            }
            b'{' | b'}' | b',' | b'/' | b'-' | b'!' | b'=' | b'@' | b'*' | b'(' | b')' => {
                lx.bump();
                Tok::Sym(c as char)
            }
            other => {
                lx.bump();
                return Err(lx.err(
                    line,
                    column,
                    format!("unexpected character `{}`", other as char),
                ));
            }
        };
        out.push(Token { tok, line, column });
    }
}

/// A run of digits, or a dotted quad if dots follow.
fn scan_number_or_ip(lx: &mut Lexer<'_>, line: u32, column: u32) -> Result<Tok, ParseError> {
    let first = scan_u64(lx, line, column)?;
    if lx.peek() != Some(b'.') || !lx.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
        return Ok(Tok::Num(first));
    }

    let mut octets = vec![first];
    while lx.peek() == Some(b'.') && lx.peek_at(1).is_some_and(|c| c.is_ascii_digit()) {
        lx.bump();
        octets.push(scan_u64(lx, line, column)?);
    }
    if octets.len() != 4 {
        return Err(lx.err(
            line,
            column,
            format!("expected a dotted quad, found {} parts", octets.len()),
        ));
    }
    let mut v: u32 = 0;
    for o in &octets {
        if *o > 255 {
            return Err(lx.err(line, column, format!("octet {o} is larger than 255")));
        }
        v = (v << 8) | (*o as u32);
    }
    Ok(Tok::Ip(v))
}

fn scan_u64(lx: &mut Lexer<'_>, line: u32, column: u32) -> Result<u64, ParseError> {
    let mut n: u64 = 0;
    let mut any = false;
    while let Some(c) = lx.peek() {
        if !c.is_ascii_digit() {
            break;
        }
        any = true;
        n = n
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .ok_or_else(|| lx.err(line, column, "number too large"))?;
        lx.bump();
    }
    if !any {
        return Err(lx.err(line, column, "expected a number"));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn toks(src: &str) -> Vec<Tok> {
        lex("t.nft", src).unwrap().into_iter().map(|t| t.tok).collect()
    }

    #[test]
    fn dotted_quads_lex_as_one_token() {
        assert_eq!(toks("10.5.0.14")[0], Tok::Ip(0x0A05_000E));
        assert_eq!(toks("0.0.0.0")[0], Tok::Ip(0));
        assert_eq!(toks("255.255.255.255")[0], Tok::Ip(u32::MAX));
    }

    #[test]
    fn a_prefix_is_an_address_then_a_length() {
        assert_eq!(
            toks("10.1.0.0/16"),
            vec![Tok::Ip(0x0A01_0000), Tok::Sym('/'), Tok::Num(16), Tok::Eof]
        );
    }

    /// `1024-65535` must not lex as one word, and `veth-b` must not split.
    #[test]
    fn hyphens_separate_ranges_but_live_inside_names() {
        assert_eq!(
            toks("1024-65535"),
            vec![Tok::Num(1024), Tok::Sym('-'), Tok::Num(65535), Tok::Eof]
        );
        assert_eq!(toks("veth-b"), vec![Tok::Word("veth-b".into()), Tok::Eof]);
    }

    #[test]
    fn comments_and_blank_lines_disappear() {
        let t = toks("# leading comment\n\n\naccept # trailing\n\n");
        assert_eq!(t, vec![Tok::Word("accept".into()), Tok::Break, Tok::Eof]);
    }

    #[test]
    fn semicolons_and_newlines_both_break_statements() {
        assert_eq!(
            toks("a; b\nc"),
            vec![
                Tok::Word("a".into()),
                Tok::Break,
                Tok::Word("b".into()),
                Tok::Break,
                Tok::Word("c".into()),
                Tok::Eof
            ]
        );
    }

    #[test]
    fn strings_keep_their_contents() {
        assert_eq!(toks("\"eth0\"")[0], Tok::Str("eth0".into()));
        assert_eq!(toks("\"a b\"")[0], Tok::Str("a b".into()));
    }

    #[test]
    fn positions_track_lines_and_columns() {
        let t = lex("t.nft", "table\n  ip x\n").unwrap();
        assert_eq!((t[0].line, t[0].column), (1, 1));
        assert_eq!((t[2].line, t[2].column), (2, 3));
    }

    #[test]
    fn bad_octets_are_rejected() {
        assert!(lex("t.nft", "10.0.0.300").is_err());
        assert!(lex("t.nft", "\"unterminated").is_err());
    }
}
