//! End-to-end tests against the built binary.
//!
//! These exercise the thing a user and a CI system actually invoke, including
//! the exit codes, which are the entire interface as far as a pipeline is
//! concerned.

use std::path::PathBuf;
use std::process::{Command, Output};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures").join(name)
}

fn soteria(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_soteria")).args(args).output().expect("run soteria")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn base() -> String {
    fixture("cell-gateway-base.nft").to_string_lossy().into_owned()
}

fn head() -> String {
    fixture("cell-gateway-head.nft").to_string_lossy().into_owned()
}

#[test]
fn a_ruleset_against_itself_has_no_delta() {
    let b = base();
    let out = soteria(&["diff", "--base", &b, "--head", &b]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert_eq!(text.matches("  none\n").count(), 2, "{text}");
    assert!(!text.contains("STRUCTURAL"), "{text}");
}

#[test]
fn a_narrowing_edit_reports_lost_traffic_and_the_woken_rule() {
    let out = soteria(&["diff", "--base", &base(), "--head", &head()]);
    let text = stdout(&out);
    assert!(text.contains("NEWLY BLOCKED"), "{text}");
    assert!(text.contains("now denied by rule 05"), "{text}");
    assert!(text.contains("rule 05  now reachable"), "{text}");
    assert!(text.contains("flows  (src, dst, dport, proto"), "{text}");
}

/// The gate is opt-in. Most changes that remove access are deliberate, so a
/// non-empty newly-blocked set is surfaced rather than made to block a merge.
#[test]
fn losing_traffic_only_fails_the_build_when_asked() {
    let permissive = soteria(&["diff", "--base", &base(), "--head", &head()]);
    assert_eq!(permissive.status.code(), Some(0));
    assert!(stdout(&permissive).contains("does not block the build"));

    let strict =
        soteria(&["diff", "--base", &base(), "--head", &head(), "--fail-on-newly-blocked"]);
    assert_eq!(strict.status.code(), Some(1));
}

/// A ruleset the tool cannot model must never produce a green build.
#[test]
fn an_unsupported_construct_exits_two() {
    let dir = std::env::temp_dir().join("soteria-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("conntrack.nft");
    std::fs::write(
        &bad,
        "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    ct state established accept\n  }\n}\n",
    )
    .unwrap();

    let out = soteria(&["diff", "--base", &base(), "--head", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "unsupported input must not exit 0 or 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("connection tracking"), "{err}");
    assert!(err.contains("conntrack.nft:4:5"), "{err}");
}

#[test]
fn bad_arguments_exit_two() {
    assert_eq!(soteria(&["diff", "--base", &base()]).status.code(), Some(2));
    assert_eq!(soteria(&["frobnicate"]).status.code(), Some(2));
    assert_eq!(soteria(&["diff", "--nonsense"]).status.code(), Some(2));
    assert_eq!(
        soteria(&["diff", "--base", &base(), "--head", &head(), "--format", "yaml"]).status.code(),
        Some(2)
    );
}

#[test]
fn version_and_help_succeed() {
    assert_eq!(soteria(&["version"]).status.code(), Some(0));
    assert!(stdout(&soteria(&["version"])).starts_with("soteria "));
    assert!(stdout(&soteria(&["--help"])).contains("EXIT CODES"));
}

/// Delimiter-balance scan that respects strings and escapes. Enough to catch a
/// serialiser that forgets a comma or a brace.
fn well_formed(s: &str) -> bool {
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for c in s.chars() {
        if in_str {
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    depth == 0 && !in_str
}

#[test]
fn json_output_is_well_formed_and_complete() {
    let out = soteria(&["diff", "--base", &base(), "--head", &head(), "--format", "json"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);

    assert!(well_formed(&text), "unbalanced json:\n{text}");
    for key in [
        "\"tool\"",
        "\"base\"",
        "\"head\"",
        "\"chains\"",
        "\"newly_blocked\"",
        "\"structural\"",
        "\"flows\"",
        "\"interfaces\"",
    ] {
        assert!(text.contains(key), "missing {key} in:\n{text}");
    }
    // Attribution must survive into the machine-readable path.
    assert!(text.contains("\"was\""), "{text}");
    assert!(text.contains("\"now\""), "{text}");
}

/// Counts run to 2^120 and JSON numbers are doubles everywhere that matters,
/// so they are emitted as strings. A bare large number here would mean silent
/// rounding of the figure the JSON path exists to preserve.
#[test]
fn large_counts_are_quoted_in_json() {
    let out = soteria(&["diff", "--base", &base(), "--head", &head(), "--format", "json"]);
    let text = stdout(&out);
    let line = text.lines().find(|l| l.contains("\"packets\"")).expect("a packets field");
    let value = line.split(':').nth(1).unwrap().trim().trim_end_matches(',');
    assert!(value.starts_with('"') && value.ends_with('"'), "packets was not quoted: {line}");
}

#[test]
fn json_and_text_agree_on_the_exit_code() {
    for format in ["text", "json"] {
        let out = soteria(&[
            "diff",
            "--base",
            &base(),
            "--head",
            &head(),
            "--format",
            format,
            "--fail-on-newly-blocked",
        ]);
        assert_eq!(out.status.code(), Some(1), "format {format}");
    }
}

#[test]
fn check_reports_dead_rules_with_their_source_position() {
    let out = soteria(&["check", &base(), "--verify"]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    // Rule 5 (the modbus drop) is dead in the base revision: rule 4 already
    // accepts everything it would match.
    assert!(text.contains("rule 05 unreachable"), "{text}");
    assert!(text.contains("covered by rule 04"), "{text}");
    assert!(text.contains("cell-gateway-base.nft:"), "{text}");
}

#[test]
fn verify_runs_the_engine_self_checks() {
    let out = soteria(&["diff", "--base", &base(), "--head", &head(), "--verify"]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn selecting_a_missing_chain_is_an_error_not_an_empty_report() {
    let out = soteria(&["diff", "--base", &base(), "--head", &head(), "--chain", "nosuch"]);
    assert_eq!(out.status.code(), Some(2));
}
