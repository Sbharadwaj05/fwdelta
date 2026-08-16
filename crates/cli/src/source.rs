//! Resolving `--base` and `--head` to ruleset text.
//!
//! A path is read directly. Anything that is not an existing file is treated as
//! a git revision and resolved with `git show <rev>:<path>`, which is what makes
//! the blueprint's headline invocation work:
//!
//! ```text
//! soteria diff --base main --head HEAD --path cell-gateway.nft
//! ```
//!
//! **This is the only place the tool spawns a process**, and it only happens
//! when an argument is not a file. Passing two paths keeps the run to file reads
//! and standard I/O, which is the mode the syscall audit exercises. `git show`
//! reads the local object store and does not touch a network, but the honest
//! statement is that the audit covers the file path and this branch is opt-in by
//! the shape of the arguments.

use std::path::Path;
use std::process::Command;

/// Ruleset text with a label for the report header.
#[derive(Debug)]
pub struct Source {
    pub label: String,
    pub text: String,
}

pub fn load(spec: &str, path: Option<&str>) -> Result<Source, String> {
    if Path::new(spec).is_file() {
        let text = std::fs::read_to_string(spec).map_err(|e| format!("{spec}: {e}"))?;
        return Ok(Source { label: spec.to_string(), text });
    }

    let Some(path) = path else {
        return Err(format!(
            "`{spec}` is not a file. To read it as a git revision, also pass --path \
             <file within the repository>"
        ));
    };

    let target = format!("{spec}:{path}");
    let out = Command::new("git")
        .args(["show", &target])
        .output()
        .map_err(|e| format!("could not run git: {e}"))?;
    if !out.status.success() {
        return Err(format!("git show {target}: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    let text = String::from_utf8(out.stdout).map_err(|_| format!("{target}: not valid UTF-8"))?;

    // A short hash reads better in the report header than a branch name, and it
    // is what the reader needs to reproduce the run.
    let label = Command::new("git")
        .args(["rev-parse", "--short", spec])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| spec.to_string());

    Ok(Source { label, text })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_read_directly() {
        let dir = std::env::temp_dir().join("soteria-source-test");
        let _ = std::fs::create_dir_all(&dir);
        let file = dir.join("x.nft");
        std::fs::write(&file, "table ip filter {}\n").unwrap();

        let s = load(file.to_str().unwrap(), None).unwrap();
        assert_eq!(s.text, "table ip filter {}\n");
        assert_eq!(s.label, file.to_str().unwrap());
    }

    #[test]
    fn a_missing_file_without_a_path_explains_the_git_form() {
        let err = load("definitely-not-a-file-xyz", None).unwrap_err();
        assert!(err.contains("--path"), "unhelpful error: {err}");
    }
}
