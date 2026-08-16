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

fn fwdelta(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fwdelta")).args(args).output().expect("run fwdelta")
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
    let out = fwdelta(&["diff", "--base", &b, "--head", &b]);
    assert_eq!(out.status.code(), Some(0));
    let text = stdout(&out);
    assert_eq!(text.matches("  none\n").count(), 2, "{text}");
    assert!(!text.contains("STRUCTURAL"), "{text}");
}

#[test]
fn a_narrowing_edit_reports_lost_traffic_and_the_woken_rule() {
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head()]);
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
    let permissive = fwdelta(&["diff", "--base", &base(), "--head", &head()]);
    assert_eq!(permissive.status.code(), Some(0));
    assert!(stdout(&permissive).contains("does not block the build"));

    let strict =
        fwdelta(&["diff", "--base", &base(), "--head", &head(), "--fail-on-newly-blocked"]);
    assert_eq!(strict.status.code(), Some(1));
}

/// A ruleset the tool cannot model must never produce a green build.
#[test]
fn an_unsupported_construct_exits_two() {
    let dir = std::env::temp_dir().join("fwdelta-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let bad = dir.join("conntrack.nft");
    std::fs::write(
        &bad,
        "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    ct state established accept\n  }\n}\n",
    )
    .unwrap();

    let out = fwdelta(&["diff", "--base", &base(), "--head", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2), "unsupported input must not exit 0 or 1");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("connection tracking"), "{err}");
    assert!(err.contains("conntrack.nft:4:5"), "{err}");
}

#[test]
fn bad_arguments_exit_two() {
    assert_eq!(fwdelta(&["diff", "--base", &base()]).status.code(), Some(2));
    assert_eq!(fwdelta(&["frobnicate"]).status.code(), Some(2));
    assert_eq!(fwdelta(&["diff", "--nonsense"]).status.code(), Some(2));
    assert_eq!(
        fwdelta(&["diff", "--base", &base(), "--head", &head(), "--format", "yaml"]).status.code(),
        Some(2)
    );
}

#[test]
fn version_and_help_succeed() {
    assert_eq!(fwdelta(&["version"]).status.code(), Some(0));
    assert!(stdout(&fwdelta(&["version"])).starts_with("fwdelta "));
    assert!(stdout(&fwdelta(&["--help"])).contains("EXIT CODES"));
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
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--format", "json"]);
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
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--format", "json"]);
    let text = stdout(&out);
    let line = text.lines().find(|l| l.contains("\"packets\"")).expect("a packets field");
    let value = line.split(':').nth(1).unwrap().trim().trim_end_matches(',');
    assert!(value.starts_with('"') && value.ends_with('"'), "packets was not quoted: {line}");
}

#[test]
fn json_and_text_agree_on_the_exit_code() {
    for format in ["text", "json"] {
        let out = fwdelta(&[
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
    let out = fwdelta(&["check", &base(), "--verify"]);
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
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--verify"]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn selecting_a_missing_chain_is_an_error_not_an_empty_report() {
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--chain", "nosuch"]);
    assert_eq!(out.status.code(), Some(2));
}

// ------------------------------------------------------------------- M5

fn policy_file() -> String {
    fixture("cell-gateway.policy.toml").to_string_lossy().into_owned()
}

fn write_temp(name: &str, body: &str) -> String {
    let dir = std::env::temp_dir().join("fwdelta-cli-test");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, body).unwrap();
    p.to_string_lossy().into_owned()
}

#[test]
fn assertions_are_reported_with_kind_appropriate_wording() {
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--assert", &policy_file()]);
    let text = stdout(&out);
    assert!(text.contains("INTENT"), "{text}");
    // Isolation that fails names the packet that got through.
    assert!(text.contains("FAIL    ot-cell-isolation"), "{text}");
    assert!(text.contains(":502"), "{text}");
    // Reachability that passes must not say "no path", which is the opposite
    // of what passing means for that kind.
    assert!(text.contains("PASS    mgmt-plane-reachable"), "{text}");
    assert!(!text.contains("no path mgmt"), "wrong wording for reachability:\n{text}");
    assert!(text.contains("all permitted mgmt"), "{text}");
}

#[test]
fn a_failed_assertion_fails_the_build() {
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--assert", &policy_file()]);
    assert_eq!(out.status.code(), Some(1));
}

/// A ruleset that decides only one subnet, so an assertion pointed at any
/// other subnet is decided by nothing.
const NARROW: &str = "table ip filter {\n  chain input {\n    type filter hook input priority filter; policy drop;\n    meta l4proto tcp ip daddr 10.5.0.0/16 tcp dport 502 drop\n    meta l4proto tcp ip daddr 10.5.0.0/16 accept\n  }\n}\n";

/// The requirement: an assertion nothing in the ruleset decides must not read
/// as a pass. A slipped digit in a zone is how this happens in practice.
///
/// Worth noting what this test had to be built to show. In a ruleset carrying a
/// broad rule -- `iifname "lo" accept`, which nearly every real file has -- a
/// typo'd zone surfaces as a FAIL instead, because that rule genuinely permits
/// traffic to the mistyped addresses. Both outcomes are loud, which is what
/// matters; the silent one is the pass, and that is what this pins.
#[test]
fn an_assertion_nothing_decides_is_vacuous_not_passing() {
    let rules = write_temp("narrow.nft", NARROW);
    let doc = "[zones]\nvlan_corp = [\"10.1.0.0/16\"]\nvlan_ot = [\"10.50.0.0/16\"]\n\n[[assert]]\nname=\"ot-cell-isolation\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\nproto=\"tcp\"\ndport=502\n";
    let path = write_temp("typo.policy.toml", doc);

    let out = fwdelta(&["diff", "--base", &rules, "--head", &rules, "--assert", &path]);
    let text = stdout(&out);

    assert!(text.contains("VACUOUS"), "a zone nothing decides must not pass:\n{text}");
    assert!(!text.contains("PASS    ot-cell-isolation"), "{text}");
    assert!(text.contains("default policy"), "the reason should say why:\n{text}");
    assert!(text.contains("typo"), "and hint at the likely cause:\n{text}");
    assert!(text.contains("1 vacuous"), "{text}");
    // It must fail the build: a green result that establishes nothing is worse
    // than a red one, because green gets merged.
    assert_eq!(out.status.code(), Some(1));
}

/// The corrected zone must produce a real verdict, or the test above could be
/// satisfied by calling everything vacuous.
#[test]
fn the_same_assertion_with_the_right_zone_is_a_real_pass() {
    let rules = write_temp("narrow.nft", NARROW);
    let doc = "[zones]\nvlan_corp = [\"10.1.0.0/16\"]\nvlan_ot = [\"10.5.0.0/16\"]\n\n[[assert]]\nname=\"ot-cell-isolation\"\nkind=\"isolation\"\nfrom=\"vlan_corp\"\nto=\"vlan_ot\"\nproto=\"tcp\"\ndport=502\n";
    let path = write_temp("right.policy.toml", doc);

    let out = fwdelta(&["diff", "--base", &rules, "--head", &rules, "--assert", &path]);
    let text = stdout(&out);
    assert!(text.contains("PASS    ot-cell-isolation"), "{text}");
    assert!(!text.contains("VACUOUS"), "{text}");
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn vacuous_can_be_downgraded_deliberately() {
    let rules = write_temp("narrow.nft", NARROW);
    let doc = "[zones]\nz = [\"10.50.0.0/16\"]\n\n[[assert]]\nname=\"x\"\nkind=\"isolation\"\nto=\"z\"\nproto=\"tcp\"\ndport=502\n";
    let path = write_temp("vacuous.policy.toml", doc);

    let strict = fwdelta(&["diff", "--base", &rules, "--head", &rules, "--assert", &path]);
    assert_eq!(strict.status.code(), Some(1));

    let lenient = fwdelta(&[
        "diff",
        "--base",
        &rules,
        "--head",
        &rules,
        "--assert",
        &path,
        "--allow-vacuous",
    ]);
    assert!(stdout(&lenient).contains("VACUOUS"), "still reported");
    assert_eq!(lenient.status.code(), Some(0), "but no longer fatal");
}

/// An interface named only by an assertion still has to get a symbol, or the
/// assertion resolves to the empty set and is vacuous for the wrong reason.
#[test]
fn an_interface_named_only_in_an_assertion_still_resolves() {
    // wg0 appears in neither ruleset.
    let doc = "[zones]\nz = [\"10.5.0.0/16\"]\n\n[[assert]]\nname=\"x\"\nkind=\"isolation\"\nto=\"z\"\niif=\"wg0\"\nproto=\"tcp\"\ndport=502\n";
    let path = write_temp("wg0.policy.toml", doc);
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--assert", &path]);
    let text = stdout(&out);
    // The rules leave iif unconstrained, so they do decide wg0 traffic: this is
    // a real result, not "describes no packet".
    assert!(!text.contains("contradict"), "assertion collapsed to nothing:\n{text}");
    assert!(text.contains("FAIL") || text.contains("PASS"), "{text}");
}

#[test]
fn a_bad_assertion_file_exits_two() {
    let path = write_temp(
        "bad.policy.toml",
        "[[assert]]\nname=\"x\"\nkind=\"isolation\"\nfrom=\"nosuchzone\"\n",
    );
    let out = fwdelta(&["diff", "--base", &base(), "--head", &head(), "--assert", &path]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("no zone named `nosuchzone`"));
}

/// The attestation has to say what the check did not cover, or it overstates
/// itself the same way an unqualified PASS would.
#[test]
fn the_attestation_carries_the_model_boundaries() {
    let dest = write_temp("att.json", "");
    let out = fwdelta(&[
        "diff",
        "--base",
        &base(),
        "--head",
        &head(),
        "--assert",
        &policy_file(),
        "--attest",
        &dest,
    ]);
    assert_eq!(out.status.code(), Some(1), "the failed assertion still fails the build");

    let text = std::fs::read_to_string(&dest).unwrap();
    assert!(well_formed(&text), "attestation is not well-formed json:\n{text}");
    for expected in [
        "https://in-toto.io/Statement/v1",
        "modelBoundaries",
        "stateless",
        "IPv4 only",
        "doesNotEstablish",
        "unsigned by design",
        "\"sha256\"",
        "ot-cell-isolation",
        "counterexample",
    ] {
        assert!(text.contains(expected), "attestation missing {expected:?}");
    }
}

/// The digests must agree with the rest of the world, or the attestation
/// identifies nothing.
#[test]
fn attestation_digests_match_the_files() {
    let dest = write_temp("att2.json", "");
    fwdelta(&["diff", "--base", &base(), "--head", &head(), "--attest", &dest]);
    let text = std::fs::read_to_string(&dest).unwrap();

    let expected = Command::new("sha256sum").arg(head()).output().expect("sha256sum");
    let digest =
        String::from_utf8_lossy(&expected.stdout).split_whitespace().next().unwrap().to_string();
    assert_eq!(digest.len(), 64);
    assert!(text.contains(&digest), "attestation digest disagrees with sha256sum");
}
