//! `agctl claude exec`/`env` — an isolated session's credentials, as an
//! environment delta or as a child process.
//!
//! Two variables carry the whole isolation (plan section 3.3): the
//! securestorage directory, whose *spelling* is what Claude Code hashes into
//! a keychain service name (fact F14), and the Claude Code config directory,
//! which is [`crate::commands::isolate::SessionDir::path`]. `env` can only
//! print an environment; `exec` can additionally spawn the child directly
//! and, because it owns the argv, hand it `--mcp-config` — `env`'s
//! equivalent is a shell alias, since fact F59 says the flag has no
//! environment-variable form.

use std::ffi::OsString;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::ExitStatus;
use std::time::Duration;
use std::time::Instant;

use crate::cli::EnvArgs;
use crate::cli::ExecArgs;
use crate::cli::Shell;
use crate::commands::isolate;
use crate::commands::isolate::SessionDir;
use crate::commands::isolate::SessionOptions;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgctlConfig;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::claude::namespace;
use crate::provider::claude::namespace::EnvView;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;

/// Environment variables an isolated session's child must never inherit.
///
/// `CLAUDE_CODE_OAUTH_TOKEN` short-circuits credential lookup entirely (fact
/// F19), which would defeat the whole point of pointing the child at an
/// isolated store.
pub const UNSET_VARS: &[&str] = &[namespace::OAUTH_TOKEN_ENV];

/// The environment (and, for `exec`, the argv addition) one isolated session
/// resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSpec {
    /// `export_spelling(ns)` verbatim — the value Claude Code would hash
    /// into a keychain service name (fact F14).
    pub securestorage_dir: String,
    /// The session's Claude Code config directory.
    pub config_dir: PathBuf,
    /// `Some(<session dir>/mcp.json)` unless the session omitted it.
    pub mcp_config: Option<PathBuf>,
}

/// Builds the export for one session, from the account record that names it.
///
/// Only an [`AccountKind::Owned`] account has an `export_spelling` to
/// export; `Live` and `ConfigDirReadOnly` are refused, naming the kind. Plan
/// AC50: the export is refused unless `sha8(export_spelling)` still equals
/// the recorded `export_sha8` and neither is empty — a namespace whose
/// spelling and hash have drifted apart would silently name the wrong
/// keychain item.
///
/// `paths` is accepted for parity with [`isolate::ensure_session`]'s
/// signature; nothing in this function reads it, since every value it needs
/// already lives on `rec` and `session`.
///
/// # Errors
///
/// Returns [`AppError::Config`] for a non-`Owned` account, an empty spelling
/// or hash, or a spelling that no longer hashes to the recorded value.
pub fn spec_for(
    _paths: &Paths,
    rec: &AccountRecord,
    session: &SessionDir,
) -> Result<ExportSpec, AppError> {
    let (export_spelling, export_sha8) = match &rec.kind {
        AccountKind::Owned { export_spelling, export_sha8 } => (export_spelling, export_sha8),
        other => {
            return Err(AppError::Config(format!(
                "only an account agctl owns can be exported into a session; `{}` is `{}`, whose \
                 credentials live outside agctl's own store",
                rec.account_uuid,
                other.name()
            )));
        }
    };

    if export_spelling.is_empty() || export_sha8.is_empty() {
        return Err(AppError::Config(format!(
            "`{}`'s registry record has an empty export spelling or hash, so no keychain service \
             can be derived for it; run `agctl claude login` again",
            rec.account_uuid
        )));
    }

    let recomputed = namespace::sha8(export_spelling);
    if recomputed != *export_sha8 {
        return Err(AppError::Config(format!(
            "`{}`'s export spelling `{export_spelling}` hashes to `{recomputed}`, not the \
             recorded `{export_sha8}`; the namespace may have moved — see `agctl claude \
             accounts show {}`",
            rec.account_uuid, rec.account_uuid
        )));
    }

    Ok(ExportSpec {
        securestorage_dir: export_spelling.clone(),
        config_dir: session.path.clone(),
        mcp_config: session.mcp_config.clone(),
    })
}

/// Renders `spec` as shell commands (plan AC51).
///
/// Deterministic and shell-specific: `zsh`/`bash` share `export`/`unset`/
/// `alias`; `fish` uses `set -gx`/`set -e` and a `function`. Every value is
/// single-quoted (already absolute and NFC, since [`ExportSpec::securestorage_dir`]
/// is `export_spelling` verbatim and [`ExportSpec::config_dir`] is a
/// directory agctl created); each [`UNSET_VARS`] entry is preceded by a
/// one-line comment stating why, and the `claude` alias — when
/// [`ExportSpec::mcp_config`] is `Some` — is followed by a one-line caveat
/// that an alias (or fish function) reaches only interactive shells (fact
/// F59: `--mcp-config` has no environment-variable form).
///
/// The alias/function's *whole body* is quoted, not just the path inside
/// it: an `alias` is a textual macro that the shell re-parses from scratch
/// when it is expanded, so a path sitting in double quotes inside a
/// single-quoted alias body still undergoes `$()`/`` ` ` ``/`$var`
/// expansion at that second parse, even though the definition line looked
/// safely quoted. Quoting the path once for its own position and once more
/// for the body it sits inside — `quote_posix(inner)` where `inner` already
/// contains a `quote_posix`-quoted path — means the stored macro text is
/// single-quoted at the position that matters, so the second parse expands
/// nothing (plan AC51's "single-quoted" clause, invariant-equivalent to
/// I19's "never re-interpret what agctl places").
#[must_use]
pub fn render_env(spec: &ExportSpec, shell: Shell) -> String {
    let mut lines = Vec::new();
    let config_dir = spec.config_dir.display().to_string();

    match shell {
        Shell::Fish => {
            lines.push(format!(
                "set -gx {} {}",
                namespace::SECURESTORAGE_ENV,
                quote_fish(&spec.securestorage_dir)
            ));
            lines.push(format!(
                "set -gx {} {}",
                namespace::CONFIG_DIR_ENV,
                quote_fish(&config_dir)
            ));
            for var in UNSET_VARS {
                lines.push(format!(
                    "# {var} would bypass this session's stored credential (fact F19)"
                ));
                lines.push(format!("set -e {var}"));
            }
            if let Some(mcp) = &spec.mcp_config {
                let path = quote_fish(&mcp.display().to_string());
                lines.push(format!(
                    "function claude\n    command claude --mcp-config {path} $argv\nend"
                ));
                lines.push(
                    "# a fish function only reaches an interactive shell; a script started from \
                     one will not inherit it"
                        .to_owned(),
                );
            }
        }
        Shell::Zsh | Shell::Bash => {
            lines.push(format!(
                "export {}={}",
                namespace::SECURESTORAGE_ENV,
                quote_posix(&spec.securestorage_dir)
            ));
            lines.push(format!(
                "export {}={}",
                namespace::CONFIG_DIR_ENV,
                quote_posix(&config_dir)
            ));
            for var in UNSET_VARS {
                lines.push(format!(
                    "# {var} would bypass this session's stored credential (fact F19)"
                ));
                lines.push(format!("unset {var}"));
            }
            if let Some(mcp) = &spec.mcp_config {
                let inner =
                    format!("claude --mcp-config {}", quote_posix(&mcp.display().to_string()));
                lines.push(format!("alias claude={}", quote_posix(&inner)));
                lines.push(
                    "# an alias only reaches an interactive shell; a script started from one \
                     will not inherit it"
                        .to_owned(),
                );
            }
        }
    }

    lines.join("\n")
}

/// Single-quotes `value` for `sh`-family shells, escaping embedded `'`.
fn quote_posix(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        if ch == '\'' { out.push_str("'\\''") } else { out.push(ch) }
    }
    out.push('\'');
    out
}

/// Single-quotes `value` for `fish`, escaping `\` and embedded `'`.
fn quote_fish(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for ch in value.chars() {
        match ch {
            '\'' => out.push_str("\\'"),
            '\\' => out.push_str("\\\\"),
            _ => out.push(ch),
        }
    }
    out.push('\'');
    out
}

/// Runs `argv` with `spec`'s environment delta, without a shell (plan AC52).
///
/// The child inherits agctl's own environment except for exactly the
/// delta: [`ExportSpec::securestorage_dir`] and [`ExportSpec::config_dir`]
/// are set, and every [`UNSET_VARS`] entry is removed. `--mcp-config
/// <path>` is appended to `argv` only when `argv[0]`'s basename is exactly
/// `claude` and [`ExportSpec::mcp_config`] is `Some` — an arbitrary command
/// must not be handed a flag it does not understand. The child is
/// registered with `ctx` so the pass coordinator's cancellation reaches it;
/// this function writes no credential of its own.
///
/// # Errors
///
/// Returns [`AppError::Config`] when `argv` is empty, [`AppError::Refused`]
/// when the run was cancelled before or during the child's lifetime, and
/// [`AppError::Io`] when the child cannot be started or waited for.
pub fn exec_command(
    spec: &ExportSpec,
    argv: &[OsString],
    ctx: &PassCtx,
    cancel: &Cancel,
) -> Result<ExitStatus, AppError> {
    let Some((program, rest)) = argv.split_first() else {
        return Err(AppError::Config("no command was given to run".to_owned()));
    };

    if cancel.is_cancelled() {
        return Err(AppError::Refused {
            reason: "cancelled before the command could start".to_owned(),
        });
    }

    let mut command = Command::new(program);
    command.args(rest);
    for var in UNSET_VARS {
        command.env_remove(var);
    }
    command.env(namespace::SECURESTORAGE_ENV, &spec.securestorage_dir);
    command.env(namespace::CONFIG_DIR_ENV, &spec.config_dir);

    let is_claude =
        Path::new(program).file_name().and_then(std::ffi::OsStr::to_str) == Some("claude");
    if is_claude && let Some(mcp) = &spec.mcp_config {
        command.arg("--mcp-config");
        command.arg(mcp);
    }

    let child = command.spawn().map_err(|err| AppError::Io {
        context: format!("could not start `{}`", Path::new(program).display()),
        source: err,
    })?;

    let token = ctx.register_child(child);
    match ctx.wait_child(token) {
        Ok(status) => Ok(status),
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            Err(AppError::Refused { reason: "cancelled while the command was running".to_owned() })
        }
        Err(err) => Err(AppError::Io {
            context: "could not wait for the command to exit".to_owned(),
            source: err,
        }),
    }
}

/// The process exit code a finished child should be reported as.
///
/// Signal deaths follow the common shell convention of `128 + signal`, so a
/// `claude` killed by `SIGTERM` is distinguishable from one that exited 15
/// on its own.
pub(crate) fn exit_code_of(status: ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    use std::os::unix::process::ExitStatusExt;
    status.signal().map_or(crate::error::EXIT_FATAL, |signal| 128 + signal)
}

/// A [`PassCtx`] for a command with no pass deadline of its own.
///
/// `exec`'s child can run indefinitely — an interactive `claude` session,
/// say — so it is waited on through [`PassCtx::wait_child`], which never
/// consults the deadline; a generous one is supplied only to satisfy the
/// constructor.
pub(crate) fn standalone_ctx(cancel: &Cancel) -> PassCtx {
    let now = Instant::now();
    let deadline = now.checked_add(Duration::from_secs(365 * 24 * 3600)).unwrap_or(now);
    PassCtx::standalone(cancel.clone(), deadline)
}

/// Resolves the account, builds its session and its export, shared by
/// `exec`, `env` and (through [`standalone_ctx`]) `use`.
pub(crate) fn prepare(
    config_dir: Option<&Path>,
    id: &str,
    claude_config_dir: Option<PathBuf>,
    fresh_context: bool,
    no_mcp: bool,
    cancel: &Cancel,
) -> Result<(SessionDir, ExportSpec, PassCtx), AppError> {
    let paths = Paths::resolve(config_dir)?;
    paths.ensure_dirs()?;
    let config = AgctlConfig::load(&paths)?;
    let record = config.resolve_id(id)?.clone();
    let env = EnvView::from_process();
    let opts = SessionOptions { claude_config_dir, fresh_context, no_mcp };
    let ctx = standalone_ctx(cancel);

    let session = isolate::ensure_session(&paths, &record, &opts, &env, &ctx)?;
    let spec = spec_for(&paths, &record, &session)?;
    Ok((session, spec, ctx))
}

/// `agctl claude exec <id> -- <command> [args...]`.
///
/// Returns the child's own exit code (plan AC52) rather than agctl's
/// usual 0/1/2 contract, which is why `main`'s dispatch treats this arm
/// differently from every other command.
///
/// # Errors
///
/// Returns [`AppError`] when the account cannot be resolved, the session
/// cannot be prepared, or the command cannot be started or waited for.
pub fn run_exec(
    config_dir: Option<&Path>,
    args: &ExecArgs,
    cancel: &Cancel,
) -> Result<i32, AppError> {
    let (_session, spec, ctx) = prepare(
        config_dir,
        &args.id,
        args.claude_config_dir.clone(),
        args.fresh_context,
        args.no_mcp,
        cancel,
    )?;
    let status = exec_command(&spec, &args.command, &ctx, cancel)?;
    Ok(exit_code_of(status))
}

/// `agctl claude env <id>`.
///
/// # Errors
///
/// Returns [`AppError`] when the account cannot be resolved or the session
/// cannot be prepared.
pub fn run_env(config_dir: Option<&Path>, args: &EnvArgs, cancel: &Cancel) -> Result<(), AppError> {
    let (_session, spec, _ctx) = prepare(
        config_dir,
        &args.id,
        args.claude_config_dir.clone(),
        args.fresh_context,
        args.no_mcp,
        cancel,
    )?;
    println!("{}", render_env(&spec, args.shell));
    Ok(())
}

#[cfg(test)]
#[path = "export_tests.rs"]
mod tests;
