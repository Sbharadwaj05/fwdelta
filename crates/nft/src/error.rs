//! Parse failures that point at the line responsible.
//!
//! Blueprint section 06 is explicit that an unmodellable construct must cause a
//! hard error naming the file and line, never a silent skip. The reasoning is
//! worth restating: a rule the frontend does not understand and drops produces a
//! model that confidently disagrees with the kernel, which is worse than no
//! model at all.
//!
//! Errors therefore carry a category. Grammar mistakes and deliberate
//! non-goals read very differently to whoever hits them, and a message saying
//! "NAT is out of scope, see the subset table" saves the reader working out
//! whether they typed something wrong.

use core::fmt;

/// Why a file was rejected.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cause {
    /// The input is not valid nftables as far as this parser can tell.
    Syntax,
    /// Valid nftables, outside the supported subset, and deliberately so.
    OutOfScope,
    /// Valid and modellable in principle, but not implemented yet.
    Unimplemented,
    /// Valid and parseable, but rejected because modelling it would be unsound.
    Soundness,
}

impl Cause {
    pub fn label(self) -> &'static str {
        match self {
            Cause::Syntax => "syntax error",
            Cause::OutOfScope => "out of scope",
            Cause::Unimplemented => "not supported yet",
            Cause::Soundness => "cannot be modelled soundly",
        }
    }
}

/// A rejection, with enough context to fix it without reading the source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub file: String,
    pub line: u32,
    pub column: u32,
    pub cause: Cause,
    pub message: String,
    /// The offending source line, quoted verbatim.
    pub snippet: String,
    /// What to do instead.
    pub hint: Option<String>,
}

impl ParseError {
    pub fn new(
        file: impl Into<String>,
        line: u32,
        column: u32,
        cause: Cause,
        message: impl Into<String>,
    ) -> Self {
        Self {
            file: file.into(),
            line,
            column,
            cause,
            message: message.into(),
            snippet: String::new(),
            hint: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    /// Attach the source line the position points at.
    pub fn with_source(mut self, source: &str) -> Self {
        if let Some(line) = source.lines().nth(self.line.saturating_sub(1) as usize) {
            self.snippet = line.to_string();
        }
        self
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            f,
            "{}:{}:{}: {}: {}",
            self.file,
            self.line,
            self.column,
            self.cause.label(),
            self.message
        )?;
        if !self.snippet.is_empty() {
            writeln!(f, "  {}", self.snippet)?;
            // Column is 1-based and the snippet is indented by two.
            let caret = " ".repeat(2 + self.column.saturating_sub(1) as usize);
            writeln!(f, "{caret}^")?;
        }
        if let Some(h) = &self.hint {
            write!(f, "  hint: {h}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rendered_error_points_at_the_column() {
        let src = "table ip filter {\n    ct state established accept\n}\n";
        let e = ParseError::new("f.nft", 2, 5, Cause::OutOfScope, "connection tracking")
            .with_source(src)
            .with_hint("rewrite statelessly");
        let text = e.to_string();
        assert!(text.starts_with("f.nft:2:5: out of scope: connection tracking"));
        assert!(text.contains("ct state established accept"));
        assert!(text.contains("hint: rewrite statelessly"));
        // The caret sits under the first column of the statement.
        let caret_line = text.lines().nth(2).unwrap();
        assert_eq!(caret_line.trim_end(), "      ^");
    }
}
