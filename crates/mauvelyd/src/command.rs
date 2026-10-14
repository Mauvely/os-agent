//! Running an external program from an argv vector. Never through a shell.

use std::io::Write;
use std::process::{Command, Stdio};

use crate::Error;

/// Runs `argv[0]` with the rest as arguments, feeds `stdin` if given, and
/// returns stdout. A non-zero exit is an error carrying the tail of stderr.
pub fn run(argv: &[String], stdin: Option<&[u8]>) -> Result<Vec<u8>, Error> {
    let (program, args) = argv.split_first().expect("argv is never empty");
    let spawn_err = |e: std::io::Error| Error::Command {
        program: program.clone(),
        detail: e.to_string(),
    };
    let mut child = Command::new(program)
        .args(args)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(spawn_err)?;
    if let Some(input) = stdin {
        // Inputs are a few hundred bytes at most, well under a pipe buffer.
        let mut pipe = child.stdin.take().expect("stdin is piped");
        pipe.write_all(input).map_err(spawn_err)?;
    }
    let out = child.wait_with_output().map_err(spawn_err)?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(Error::Command {
            program: program.clone(),
            detail: format!("{}: {}", out.status, tail(stderr.trim(), 400)),
        });
    }
    Ok(out.stdout)
}

/// The last `max` bytes of `s`, on a character boundary.
fn tail(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut start = s.len() - max;
    while !s.is_char_boundary(start) {
        start += 1;
    }
    &s[start..]
}

/// Builds an argv from string slices.
pub(crate) fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

/// Rejects a value from the server that a program would read as an option.
pub(crate) fn operand(what: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() || value.starts_with('-') {
        return Err(Error::Invalid(format!("{what} {value:?} is not valid")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_without_a_shell() {
        // `$HOME` stays literal: no shell expands it.
        let out = run(&argv(&["echo", "$HOME", "a;b"]), None).unwrap();
        assert_eq!(out, b"$HOME a;b\n");
    }

    #[test]
    fn feeds_stdin_and_reports_failure() {
        assert_eq!(run(&argv(&["cat"]), Some(b"seed")).unwrap(), b"seed");
        let err = run(&argv(&["sh", "-c", "echo oops >&2; exit 3"]), None).unwrap_err();
        assert!(err.to_string().contains("oops"), "{err}");
        assert!(run(&argv(&["/nonexistent/tool"]), None).is_err());
    }

    #[test]
    fn operands_may_not_look_like_options() {
        assert!(operand("remote", "flathub").is_ok());
        assert!(operand("remote", "--no-gpg-verify").is_err());
        assert!(operand("remote", "").is_err());
    }
}
