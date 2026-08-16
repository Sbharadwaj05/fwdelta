//! A minimal JSON writer.
//!
//! Hand-written, and D-08 records the line this sits on: writing a serialiser
//! for a schema this project defines has no "silently misreads the input"
//! failure mode, whereas hand-writing a parser for user input does. The
//! assertion reader uses a real TOML library for exactly that reason; this does
//! not need one.
//!
//! One deliberate choice: packet counts are emitted as **strings**. They run to
//! 2^120, and JSON numbers are IEEE 754 doubles in every consumer that matters,
//! so emitting them as numbers would silently round the figure the machine-
//! readable path exists to preserve.

use core::fmt::Write;

#[derive(Clone, Debug)]
pub enum Json {
    Null,
    Bool(bool),
    /// An integer small enough to survive a double. Emitted bare.
    Num(u64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn str(s: impl Into<String>) -> Json {
        Json::Str(s.into())
    }

    /// A count that may exceed 2^53. Emitted as a string, on purpose.
    pub fn big(v: u128) -> Json {
        Json::Str(v.to_string())
    }

    pub fn arr<I: IntoIterator<Item = Json>>(items: I) -> Json {
        Json::Arr(items.into_iter().collect())
    }

    pub fn obj<I: IntoIterator<Item = (&'static str, Json)>>(fields: I) -> Json {
        Json::Obj(fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// `None` renders as `null`, which is how an unconstrained dimension is
    /// distinguished from one constrained to everything.
    pub fn opt(v: Option<Json>) -> Json {
        v.unwrap_or(Json::Null)
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, 0);
        s.push('\n');
        s
    }

    fn write(&self, out: &mut String, depth: usize) {
        let pad = |out: &mut String, d: usize| {
            for _ in 0..d {
                out.push_str("  ");
            }
        };
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => {
                let _ = write!(out, "{b}");
            }
            Json::Num(n) => {
                let _ = write!(out, "{n}");
            }
            Json::Str(s) => escape(s, out),
            Json::Arr(items) if items.is_empty() => out.push_str("[]"),
            Json::Arr(items) => {
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    pad(out, depth + 1);
                    item.write(out, depth + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, depth);
                out.push(']');
            }
            Json::Obj(fields) if fields.is_empty() => out.push_str("{}"),
            Json::Obj(fields) => {
                out.push_str("{\n");
                for (i, (k, v)) in fields.iter().enumerate() {
                    pad(out, depth + 1);
                    escape(k, out);
                    out.push_str(": ");
                    v.write(out, depth + 1);
                    if i + 1 < fields.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                pad(out, depth);
                out.push('}');
            }
        }
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            // Control characters must be escaped; everything else is UTF-8 and
            // passes through, since JSON documents are UTF-8 by definition.
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_escaped() {
        let j = Json::str("a\"b\\c\nd\te\u{1}");
        // The control character becomes a \u escape, not a literal byte.
        assert_eq!(j.render().trim(), r#""a\"b\\c\nd\te\u0001""#);
    }

    #[test]
    fn unicode_passes_through_as_utf8() {
        assert_eq!(Json::str("vlan_ot →").render().trim(), "\"vlan_ot →\"");
    }

    /// The reason counts are strings: 2^120 does not survive a double.
    #[test]
    fn large_counts_do_not_lose_precision() {
        let n = (1u128 << 120) - 1;
        assert_eq!(Json::big(n).render().trim(), format!("\"{n}\""));
        assert!(Json::big(n).render().contains("1329227995784915872903807060280344575"));
    }

    #[test]
    fn empty_containers_stay_on_one_line() {
        assert_eq!(Json::Arr(vec![]).render().trim(), "[]");
        assert_eq!(Json::Obj(vec![]).render().trim(), "{}");
    }

    #[test]
    fn nesting_indents() {
        let j = Json::obj([("a", Json::arr([Json::Num(1), Json::Num(2)]))]);
        assert_eq!(j.render(), "{\n  \"a\": [\n    1,\n    2\n  ]\n}\n");
    }

    #[test]
    fn null_is_distinct_from_an_empty_array() {
        let j = Json::obj([("x", Json::opt(None)), ("y", Json::opt(Some(Json::arr([]))))]);
        let text = j.render();
        assert!(text.contains("\"x\": null"));
        assert!(text.contains("\"y\": []"));
    }
}
