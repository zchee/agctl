use clap::ValueEnum;

use super::run;
use crate::cli::CompletionsArgs;

/// Every subcommand `agctl` currently parses. Empirically, every
/// `clap_complete` generator spells a subcommand out as a literal word
/// somewhere in its script — a `case`/`switch` label, a quoted candidate, or
/// a `complete -a`/`-f -a` argument — so this list holds for all five
/// shells rather than needing a per-shell subset.
const SUBCOMMANDS: &[&str] = &[
    "claude",
    "status",
    "watch",
    "login",
    "doctor",
    "accounts",
    "import",
    "use",
    "exec",
    "env",
    "completions",
];

#[test]
fn every_shell_generates_a_non_empty_script_naming_every_subcommand() {
    for shell in clap_complete::Shell::value_variants() {
        let args = CompletionsArgs { shell: *shell };
        let mut out = Vec::new();
        run(&args, &mut out).unwrap_or_else(|err| panic!("{shell:?} should generate: {err}"));

        let script = String::from_utf8(out).unwrap_or_else(|err| panic!("{shell:?}: {err}"));
        assert!(!script.is_empty(), "{shell:?}: the generated script is empty");
        assert!(script.contains("agctl"), "{shell:?}: the binary name is missing");

        for name in SUBCOMMANDS {
            assert!(
                script.contains(name),
                "{shell:?}: subcommand `{name}` is missing from the generated script"
            );
        }
    }
}

#[test]
fn zsh_script_starts_with_the_compdef_header() {
    let args = CompletionsArgs { shell: clap_complete::Shell::Zsh };
    let mut out = Vec::new();
    run(&args, &mut out).expect("zsh should generate");
    let script = String::from_utf8(out).expect("the script is valid UTF-8");
    assert_eq!(script.lines().next(), Some("#compdef agctl"));
}

#[test]
fn a_write_error_other_than_a_closed_reader_is_reported() {
    /// A writer that always fails with an error other than `BrokenPipe`, to
    /// prove that only a closed reader is swallowed and any other I/O
    /// failure still surfaces as [`crate::error::AppError::Io`].
    struct AlwaysFails;

    impl std::io::Write for AlwaysFails {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let args = CompletionsArgs { shell: clap_complete::Shell::Bash };
    let err = run(&args, &mut AlwaysFails).expect_err("a non-broken-pipe write error must surface");
    assert!(matches!(err, crate::error::AppError::Io { .. }), "unexpected error: {err}");
}

#[test]
fn a_broken_pipe_write_error_is_swallowed() {
    /// A writer that reports every write as `BrokenPipe`, standing in for a
    /// reader that closed its end of the pipe — an ordinary, expected way to
    /// consume a completion script (`agctl completions zsh | head -1`).
    struct BrokenPipeWriter;

    impl std::io::Write for BrokenPipeWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::new(std::io::ErrorKind::BrokenPipe, "pipe closed"))
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let args = CompletionsArgs { shell: clap_complete::Shell::Zsh };
    run(&args, &mut BrokenPipeWriter).expect("a closed reader must not be reported as a failure");
}
