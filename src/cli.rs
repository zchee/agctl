//! Command-line surface, parsed with `clap`'s derive API.
//!
//! The shape here is fixed by plan section 3.2. Two details are worth stating
//! because they are not obvious from the struct definitions:
//!
//! **`--config-dir` is a global option and names the agentctl store.** It is
//! accepted before or after the subcommand (`agentctl claude status
//! --config-dir DIR`), and `AGENTCTL_CONFIG_DIR` is its environment form. The
//! foreign Claude Code directories that `import --from keychain` scans are a
//! different thing and are spelled `--claude-config-dir` so the two never
//! collide inside `clap` (a global option propagates into every subcommand).
//!
//! **Only production environment variables are read here.** Plan section 3.2
//! also lists test-only variables — the keychain backend and binary
//! overrides, the three endpoint URL overrides, and the fault-injection
//! switch. Those are compiled in solely under the `testing` feature by the
//! modules that own them, never by this one: a production-visible token-URL
//! override would be an exfiltration vector (plan section 3.9, AC37).

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::Duration;

use clap::Args;
use clap::Parser;
use clap::Subcommand;
use clap::ValueEnum;
use thiserror::Error;

/// The slowest polling `watch` will accept, so agentctl stays a good API
/// citizen (plan principle P4, AC13).
pub const WATCH_INTERVAL_FLOOR: Duration = Duration::from_secs(60);

/// Why a duration argument could not be parsed.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum DurationParseError {
    /// The argument was empty or entirely whitespace.
    #[error("expected a duration such as `10s`, `5m` or `300`, but the value was empty")]
    Empty,

    /// The argument did not start with a digit.
    #[error(
        "expected a duration such as `10s`, `5m` or `300`, but `{0}` does not start with a number"
    )]
    NoDigits(String),

    /// The numeric part did not fit, or the unit conversion did not fit.
    #[error("duration `{0}` is too large to represent")]
    Overflow(String),

    /// The unit suffix is not one this parser knows.
    #[error(
        "unknown duration unit `{unit}` in `{input}`; use `s`, `m`, `h`, or no suffix for seconds"
    )]
    UnknownUnit {
        /// The unrecognised suffix.
        unit: String,
        /// The whole argument, for context.
        input: String,
    },
}

/// Parses a duration written as `10s`, `5m`, `2h`, or a bare `300` meaning
/// seconds.
///
/// All arithmetic is checked. This is load-bearing rather than defensive: this
/// project builds with `-C overflow-checks=off` in every profile, so a
/// multiplication that overflowed would wrap silently and hand back a
/// plausible-looking short duration instead of failing.
///
/// # Errors
///
/// Returns a [`DurationParseError`] when the value is empty, carries no
/// leading number, uses an unknown unit, or does not fit in a [`Duration`].
///
/// # Examples
///
/// ```ignore
/// assert_eq!(parse_duration("5m")?, Duration::from_secs(300));
/// assert_eq!(parse_duration("300")?, Duration::from_secs(300));
/// assert!(parse_duration("99999999999999999999s").is_err());
/// ```
pub fn parse_duration(input: &str) -> Result<Duration, DurationParseError> {
    let text = input.trim();
    if text.is_empty() {
        return Err(DurationParseError::Empty);
    }

    let split = text.find(|c: char| !c.is_ascii_digit()).unwrap_or(text.len());
    let (digits, unit) = text.split_at(split);
    if digits.is_empty() {
        return Err(DurationParseError::NoDigits(text.to_owned()));
    }

    // `str::parse` rejects values above `u64::MAX` by returning an error, so
    // an absurd literal fails here rather than wrapping.
    let value: u64 = digits.parse().map_err(|_| DurationParseError::Overflow(text.to_owned()))?;

    let seconds = match unit {
        "" | "s" => value,
        "m" => {
            value.checked_mul(60).ok_or_else(|| DurationParseError::Overflow(text.to_owned()))?
        }
        "h" => {
            value.checked_mul(3600).ok_or_else(|| DurationParseError::Overflow(text.to_owned()))?
        }
        other => {
            return Err(DurationParseError::UnknownUnit {
                unit: other.to_owned(),
                input: text.to_owned(),
            });
        }
    };

    Ok(Duration::from_secs(seconds))
}

/// `clap` adapter for a plain duration argument.
fn duration_value_parser(input: &str) -> Result<Duration, String> {
    parse_duration(input).map_err(|err| err.to_string())
}

/// `clap` adapter for `watch --interval`, which additionally enforces the
/// 60 s floor (AC13).
fn watch_interval_value_parser(input: &str) -> Result<Duration, String> {
    let interval = parse_duration(input).map_err(|err| err.to_string())?;
    if interval < WATCH_INTERVAL_FLOOR {
        return Err(format!(
            "interval `{input}` is below the 60s floor; agentctl will not poll the usage API more often than once every 60 seconds"
        ));
    }
    Ok(interval)
}

/// Manage AI coding agents.
#[derive(Debug, Parser)]
#[command(name = "agentctl", version, about, long_about = None)]
pub struct Cli {
    /// Use this agentctl configuration directory instead of the default.
    #[arg(long, value_name = "DIR", env = "AGENTCTL_CONFIG_DIR", global = true)]
    pub config_dir: Option<PathBuf>,

    /// The subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Work with Claude subscription accounts.
    Claude {
        /// The `claude` subcommand to run.
        #[command(subcommand)]
        command: ClaudeCommand,
    },
    /// Print a shell completion script for agentctl to stdout.
    Completions(CompletionsArgs),
}

/// Arguments for `agentctl completions`.
#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Which shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Subcommands under `agentctl claude`.
#[derive(Debug, Subcommand)]
pub enum ClaudeCommand {
    /// Show subscription usage for every known account.
    Status(StatusArgs),
    /// Watch subscription usage in a terminal UI.
    Watch(WatchArgs),
    /// Log in to an Anthropic account and store its credentials.
    Login(LoginArgs),
    /// Inspect and manage the accounts agentctl knows about.
    Accounts {
        /// The `accounts` subcommand to run.
        #[command(subcommand)]
        command: AccountsCommand,
    },
    /// Record accounts that other Claude Code config directories hold.
    Import(ImportArgs),
    /// Report on store health, locks, and stray files.
    Doctor(DoctorArgs),
    /// Start (or manage) an isolated Claude Code session for one account.
    Use(UseArgs),
    /// Run one command with an account's credentials, without a shell.
    Exec(ExecArgs),
    /// Print shell commands that put an account's credentials in your environment.
    Env(EnvArgs),
}

/// Arguments for `agentctl claude status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Emit the report as JSON instead of a table.
    #[arg(long)]
    pub json: bool,

    /// Include the untouched upstream response body in the output.
    #[arg(long)]
    pub raw: bool,

    /// Refresh expired credentials even when a cached value would do.
    #[arg(long)]
    pub refresh: bool,

    /// Ignore the on-disk usage cache for this run.
    #[arg(long)]
    pub no_cache: bool,

    /// Show rows that are hidden by default, such as stale siblings.
    #[arg(long)]
    pub all: bool,

    /// Fold the live credential into the row of the account that owns it, and
    /// add a Kind column saying so. Table only; --json is unaffected.
    #[arg(long)]
    pub by_identity: bool,

    /// Limit the report to this account; repeat to name several.
    #[arg(long = "account", value_name = "ID")]
    pub account: Vec<String>,

    /// Per-request HTTP timeout, such as `10s` or `5m`.
    #[arg(long, value_name = "DUR", default_value = "10s", value_parser = duration_value_parser)]
    pub timeout: Duration,
}

/// Arguments for `agentctl claude watch`.
#[derive(Debug, Args)]
pub struct WatchArgs {
    /// How often to refetch usage; must be at least 60s.
    #[arg(long, value_name = "DUR", default_value = "300s", value_parser = watch_interval_value_parser)]
    pub interval: Duration,
}

/// Arguments for `agentctl claude login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Paste the `code#state` value by hand instead of using a loopback
    /// redirect.
    #[arg(long)]
    pub manual: bool,

    /// Give the resulting account a human-readable label.
    #[arg(long, value_name = "NAME")]
    pub label: Option<String>,
}

/// Subcommands under `agentctl claude accounts`.
#[derive(Debug, Subcommand)]
pub enum AccountsCommand {
    /// List known accounts.
    List {
        /// Include rows that are hidden by default.
        #[arg(long)]
        all: bool,
    },
    /// Show one account in full.
    Show {
        /// Account id, or `uuid/org-uuid` when the uuid is ambiguous.
        id: String,
    },
    /// Forget an account, optionally deleting its stored credentials.
    Remove {
        /// Account id, or `uuid/org-uuid` when the uuid is ambiguous.
        id: String,
        /// Also delete the credential file agentctl wrote for this account.
        #[arg(long)]
        delete_secret: bool,
        /// Do not prompt for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Move an account's namespace to its real organization directory.
    Relocate {
        /// Account id, or `uuid/org-uuid` when the uuid is ambiguous.
        id: String,
        /// Do not prompt for confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Hide a discovered keychain service from reports.
    Forget {
        /// The keychain service name to hide.
        service: String,
    },
    /// Stop hiding a previously forgotten keychain service.
    Unforget {
        /// The keychain service name to reveal again.
        service: String,
    },
}

/// Where `agentctl claude import` should read accounts from.
///
/// One source, still spelled as a value rather than as a bare flag: the
/// keychain is not the only place accounts could come from, and a command
/// line that already says *which* source it read does not change shape when a
/// second one arrives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ImportSource {
    /// Claude Code credential services discovered in the login keychain.
    Keychain,
}

/// Arguments for `agentctl claude import`.
#[derive(Debug, Args)]
pub struct ImportArgs {
    /// Which source to import from.
    #[arg(long = "from", value_name = "SOURCE")]
    pub from: ImportSource,

    /// A Claude Code config directory to scan; repeat to name several.
    #[arg(long = "claude-config-dir", value_name = "DIR")]
    pub claude_config_dir: Vec<PathBuf>,

    /// Report what would be imported without changing anything.
    #[arg(long)]
    pub dry_run: bool,
}

/// Arguments for `agentctl claude doctor`.
#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Remove one stale Claude Code lock artefact, named by absolute path.
    #[arg(long, value_name = "LOCK-PATH")]
    pub remove_stale: Option<PathBuf>,

    /// Do not prompt for confirmation.
    #[arg(long)]
    pub yes: bool,
}

/// Which login shell [`EnvArgs`] should print for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Shell {
    /// `export VAR=value`, `unset VAR`, `alias`.
    Zsh,
    /// Identical to [`Shell::Zsh`]: both read the same `export`/`unset`/`alias` syntax.
    Bash,
    /// `set -gx VAR value`, `set -e VAR`, a `function`.
    Fish,
}

/// Arguments for `agentctl claude use`.
///
/// Three shapes share this struct, distinguished by which fields are set:
/// `use [<id>] [--live] [--claude-config-dir <PATH>] [--fresh-context]
/// [--no-mcp] [--yes] [--json]`, `use --undo [--yes]`, and `use --forget <id>
/// [--yes]`.
#[derive(Debug, Args)]
pub struct UseArgs {
    /// Account selector: the same syntax `accounts remove` accepts.
    #[arg(value_name = "ID", conflicts_with_all = ["undo", "forget"])]
    pub id: Option<String>,

    /// Hot-swap the live Claude Code credential instead of starting an
    /// isolated session (decision D-018).
    #[arg(long, conflicts_with_all = ["new_only", "undo", "forget"])]
    pub live: bool,

    /// Accepted as a synonym for the default (isolated-session) behaviour.
    #[arg(long)]
    pub new_only: bool,

    /// Undo the most recent `--live` swap.
    #[arg(long, conflicts_with = "forget")]
    pub undo: bool,

    /// Remove the session directory created by an earlier `use <id>`.
    #[arg(long, value_name = "ID")]
    pub forget: Option<String>,

    /// Use this directory as the session's Claude Code config directory
    /// instead of a generated one. Must be an absolute path.
    #[arg(long, value_name = "PATH")]
    pub claude_config_dir: Option<PathBuf>,

    /// Do not symlink the directories that hold resumable work (tier 2).
    #[arg(long)]
    pub fresh_context: bool,

    /// Omit the MCP symlink, the `--mcp-config` flag and the shell alias
    /// together.
    #[arg(long)]
    pub no_mcp: bool,

    /// Do not prompt for confirmation.
    #[arg(long)]
    pub yes: bool,

    /// Print the session's details as JSON before launching.
    #[arg(long)]
    pub json: bool,
}

/// Arguments for `agentctl claude exec <id> -- <command> [args...]`.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Account selector: the same syntax `accounts remove` accepts.
    pub id: String,

    /// Use this directory as the session's Claude Code config directory
    /// instead of a generated one. Must be an absolute path.
    #[arg(long, value_name = "PATH")]
    pub claude_config_dir: Option<PathBuf>,

    /// Do not symlink the directories that hold resumable work (tier 2).
    #[arg(long)]
    pub fresh_context: bool,

    /// Omit the MCP symlink and the `--mcp-config` flag together.
    #[arg(long)]
    pub no_mcp: bool,

    /// The command to run, and any arguments to give it.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

/// Arguments for `agentctl claude env <id>`.
#[derive(Debug, Args)]
pub struct EnvArgs {
    /// Account selector: the same syntax `accounts remove` accepts.
    pub id: String,

    /// Use this directory as the session's Claude Code config directory
    /// instead of a generated one. Must be an absolute path.
    #[arg(long, value_name = "PATH")]
    pub claude_config_dir: Option<PathBuf>,

    /// Do not symlink the directories that hold resumable work (tier 2).
    #[arg(long)]
    pub fresh_context: bool,

    /// Omit the MCP symlink, the `--mcp-config` flag and the shell alias
    /// together.
    #[arg(long)]
    pub no_mcp: bool,

    /// Which shell's syntax to print.
    #[arg(long, value_enum, default_value_t = Shell::Zsh)]
    pub shell: Shell,
}

#[cfg(test)]
#[path = "cli_tests.rs"]
mod tests;
