//! `agentctl claude use` — an isolated session, launched.
//!
//! Bare `use <id>` is exactly `isolate::ensure_session` followed by
//! `export::exec_command` against `claude` on `PATH`, with the same
//! environment delta `exec`/`env` compute. `--live`, `--undo` and `--forget`
//! are parsed (plan section 3.2) but not yet implemented: W4a/W4b (S22) land
//! the first two, and S16 lands `--forget` alongside the seeding it removes.

use std::ffi::OsString;
use std::path::Path;

use crate::cli::UseArgs;
use crate::commands::export;
use crate::error::AppError;
use crate::runtime::coordinator::Cancel;

/// `agentctl claude use [<id>] [--live] [--claude-config-dir <PATH>]
/// [--fresh-context] [--no-mcp] [--yes] [--json]` · `use --undo [--yes]` ·
/// `use --forget <id> [--yes]`.
///
/// Returns the launched `claude`'s own exit code for the bare-`use` shape
/// (plan AC52's contract, shared with `exec`), which is why `main`'s
/// dispatch treats this arm like `exec` rather than like every other
/// command.
///
/// # Errors
///
/// Returns [`AppError::not_implemented`] for `--live`, `--undo` and
/// `--forget`, which `clap`'s conflict groups guarantee are never combined
/// with each other or with an id; [`AppError::Config`] when no id was given
/// and none of those three was either, or when the account cannot be
/// resolved; and whatever [`export::prepare`] or [`export::exec_command`]
/// return otherwise.
pub fn run(config_dir: Option<&Path>, args: &UseArgs, cancel: &Cancel) -> Result<i32, AppError> {
    if args.live {
        return Err(AppError::not_implemented("claude use --live"));
    }
    if args.undo {
        return Err(AppError::not_implemented("claude use --undo"));
    }
    if args.forget.is_some() {
        return Err(AppError::not_implemented("claude use --forget"));
    }
    // `--new-only` is accepted as a synonym naming the default behaviour it
    // already asks for; there is nothing else for it to select.
    let _ = args.new_only;

    let Some(id) = &args.id else {
        return Err(AppError::Config(
            "an account id is required unless one of --undo or --forget is given".to_owned(),
        ));
    };

    let (session, spec, ctx) = export::prepare(
        config_dir,
        id,
        args.claude_config_dir.clone(),
        args.fresh_context,
        args.no_mcp,
        cancel,
    )?;

    if args.json {
        print_session_json(&session, &spec)?;
    }
    // `--yes` is accepted for forward compatibility: nothing on this path
    // prompts yet. S22 adds the `--live` confirmation it is meant for.
    let _ = args.yes;

    let argv = vec![OsString::from("claude")];
    let status = export::exec_command(&spec, &argv, &ctx, cancel)?;
    Ok(export::exit_code_of(status))
}

/// `--json`: the session's details, printed before `claude` launches.
fn print_session_json(
    session: &crate::commands::isolate::SessionDir,
    spec: &export::ExportSpec,
) -> Result<(), AppError> {
    let doc = serde_json::json!({
        "securestorage_dir": spec.securestorage_dir,
        "config_dir": spec.config_dir,
        "session_path": session.path,
        "mcp_config": session.mcp_config,
    });
    let text = serde_json::to_string_pretty(&doc)
        .map_err(|err| AppError::Config(format!("could not render the session as JSON: {err}")))?;
    println!("{text}");
    Ok(())
}

#[cfg(test)]
#[path = "use_tests.rs"]
mod tests;
