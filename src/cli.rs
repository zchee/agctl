//! Command-line surface, parsed with `clap`'s derive API.
//!
//! The shape here is fixed by plan section 3.2. Two details are worth stating
//! because they are not obvious from the struct definitions:
//!
//! **`--config-dir` is a global option and names the agctl store.** It is
//! accepted before or after the subcommand (`agctl claude status
//! --config-dir DIR`), and `AGCTL_CONFIG_DIR` is its environment form. The
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

/// The slowest polling `watch` will accept, so agctl stays a good API
/// citizen (plan principle P4, AC13).
pub const WATCH_INTERVAL_FLOOR: Duration = Duration::from_secs(60);

/// `claude use --live`'s refusal exit codes (plan AC67, ruling OQ4).
///
/// AC67 is literal: each refusal gets **its own message and its own exit
/// code**, so a script can act on one without parsing English. They live here
/// because `cli.rs` is the single CLI contract — the flags, and now what the
/// process returns.
///
/// **The block starts at 10 because 0, 1 and 2 are taken.**
/// [`EXIT_OK`](crate::error::EXIT_OK) is 0,
/// [`EXIT_FATAL`](crate::error::EXIT_FATAL) is 1,
/// [`EXIT_PARTIAL`](crate::error::EXIT_PARTIAL) is 2 — and `clap` also exits
/// 2 for a usage error, so a swap code of 2 would be ambiguous between "the
/// item changed under the hold" and "you misspelled a flag". Every code below
/// is therefore ≥ 3, and in practice ≥ 10 so the block reads as one.
///
/// | code | meaning |
/// |---|---|
/// | 0 | `applied`, `already_active`, and refusal **B**'s warning line |
/// | 10–21 | plan section 3.4's refusals and outcomes |
/// | 22–24 | the live store's own three, added by W4b |
///
/// Refusal **B** — a secure-storage backend is active or of unknown kind — is
/// deliberately **not** here: decision D-020 degraded it to a warning line
/// and exit 0, because no storage-V5 backend exists in this build.
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "`ALL` is the totality the exit-code tests check, and nothing in the shipped \
                  binary reads the table as a table"
    )
)]
pub mod swap_exit {
    /// Refusal **A**: the lock agctl holds is compromised — its mtime
    /// moved under us, so the protocol was already violated and nothing may
    /// be written.
    pub const REFUSED_A: i32 = 10;
    /// Refusal **C**: `CLAUDE_CODE_OAUTH_TOKEN` is set in agctl's own
    /// environment, which short-circuits every store (fact F19).
    pub const REFUSED_C: i32 = 11;
    /// Refusal **D**: the credential does not fit fact F42's 4 032-byte
    /// keychain stdin line.
    pub const REFUSED_D: i32 = 12;
    /// Refusal **E**: `CLAUDE_SECURESTORAGE_CONFIG_DIR` holds a non-empty
    /// value, so this shell names a **namespace** rather than the live store
    /// — and the pass was asked for the live one.
    ///
    /// Reachable only through `use --undo` of a live-target audit entry: the
    /// forward path's scope gate *partitions* the two targets on the same
    /// variable, so a forward `use --live` can never reach the live subject
    /// build with it set (W4b §D1, ruling G1). A reversal takes its target
    /// from the audit log instead, so the two can disagree — which is the
    /// state this refuses.
    pub const REFUSED_E: i32 = 13;
    /// Refusal **F**: the outgoing credential cannot be adopted, so the swap
    /// would lose it.
    pub const REFUSED_F: i32 = 14;
    /// The inherited `CLAUDE_SECURESTORAGE_CONFIG_DIR` names no store
    /// agctl owns (ruling OQ1). Not one of the lettered refusals — it is
    /// decided before Phase A begins — so `--json` gives it `reason:
    /// "not_owned"` and no `refusal` member.
    pub const PRECONDITION: i32 = 15;
    /// Another process holds the store's Claude Code locks and agctl did
    /// not break them.
    pub const BUSY: i32 = 16;
    /// The item changed under the hold, so the refreshed credential was
    /// thrown away rather than written over a newer one.
    pub const DISCARDED: i32 = 17;
    /// The write child was killed on a timeout and the verifying read did not
    /// settle it. Means "re-run `status`", not "failed".
    pub const UNKNOWN: i32 = 18;
    /// The write child ran and exited non-zero: `security(1)` refused the
    /// write and the item is demonstrably untouched.
    ///
    /// **Not** [`REFUSED_A`], which it used to share. A refusal letter is a
    /// security signal — **A** means somebody moved a lock agctl was
    /// holding — and an ordinary write failure is not that. Sharing the code
    /// also made the exit code contradict the audit line, which records this
    /// case as `"outcome":"failed"`. `--json` gives it `outcome: "failed"`
    /// and **no** `refusal` member.
    pub const WRITE_FAILED: i32 = 19;
    /// Nobody agreed to the swap: the confirmation was declined, or there was
    /// no terminal to ask at and `--yes` was not given.
    ///
    /// **Not** refusal **F**, which it used to share. **F** means *the
    /// outgoing credential cannot be adopted, so the swap would lose it* — a
    /// fact about the store that a person cannot talk agctl out of — and a
    /// script that saw exit 14 could not tell it from an operator answering
    /// "no". `--json` gives this `outcome: "cancelled"` and **no** `refusal`
    /// member, the same shape [`WRITE_FAILED`] takes.
    pub const CANCELLED: i32 = 20;
    /// The incoming account's credential has expired and its store has
    /// migrated into the keychain, so the swap will not refresh it.
    ///
    /// A refresh rotates the server's refresh token away from whatever holds
    /// the old one, so it may only be done by something that can save the
    /// result. The swap can save a refreshed credential back into a plaintext
    /// `.credentials.json`; it cannot write a *second* keychain item inside
    /// one hold, so for a migrated store the refresh would be spent and
    /// thrown away — which is what left the incoming account needing a fresh
    /// `login`. `agctl claude status` refreshes that item in place and
    /// persists it, so the message says to run it and try again.
    ///
    /// `--json` gives this `outcome: "needs_refresh"` and **no** `refusal`
    /// member: nothing is wrong with the store, and nothing was written.
    pub const NEEDS_REFRESH: i32 = 21;
    /// The audit log cannot be appended to, so a **live**-store swap is
    /// refused rather than performed unrecorded (W4b §D6, ruling G2).
    ///
    /// Invariant I16 makes the audit line the only durable evidence that
    /// agctl broke a lock in the user's own `~/.claude`, and the failure is
    /// attacker-selectable: one `ln -s` at the log's name, or one `chmod
    /// 0644`. A control whose only failure mode is *the adversary switches it
    /// off and the privileged action proceeds* is not a control, so the live
    /// swap stops instead. The denial of service that buys is loud, names
    /// itself in `doctor`'s `audit log` row and is one `chmod` from fixed;
    /// the alternative is a silent, unrecorded mutation of the live store.
    ///
    /// Unlettered: plan section 3.4's **A**–**F** is canonical and **E** is
    /// spoken for, so `--json` carries `outcome: "refused"` with `reason:
    /// "audit_refused"` and **no** `refusal` member. Namespace swaps keep
    /// W4a's behaviour — a refused log is logged and the swap carries on.
    pub const AUDIT_REFUSED: i32 = 22;
    /// The live store could not be resolved: nothing is at the path this
    /// environment names, or the symbolic link there dangles (W4b §D3,
    /// ruling G3).
    ///
    /// Split out of refusal **A**, which every acquire error used to collapse
    /// into. **A** means *somebody moved a lock agctl was holding* — a
    /// security signal — and a `~/.claude` that is not there is a
    /// configuration fact decided in Phase A with nothing held. `--json`
    /// gives it `reason: "live_unreachable"` and no `refusal` member.
    pub const LIVE_UNREACHABLE: i32 = 23;
    /// The live keychain item is absent, so the live store has not migrated
    /// and its credential is still in `~/.claude/.credentials.json` (W4b §D5,
    /// ruling G4).
    ///
    /// W4a's first-write path *removes* that plaintext file once the write
    /// applies (finding N-2), which against the live store would be a
    /// deletion inside the user's own `~/.claude` — a write invariant I11′
    /// does not price. So the swap refuses instead, and **no file under the
    /// live store is ever written or removed**: the W4b relaxation stays
    /// exactly "the three lock artefacts plus the item". The condition is
    /// transient and self-healing — migration is the steady state — so the
    /// message says to run `claude` once. `--json` gives it `reason:
    /// "live_item_absent"` and no `refusal` member.
    pub const LIVE_ITEM_ABSENT: i32 = 24;

    /// Every code above, for the exhaustiveness and uniqueness tests.
    pub const ALL: [(&str, i32); 15] = [
        ("refused_a", REFUSED_A),
        ("refused_c", REFUSED_C),
        ("refused_d", REFUSED_D),
        ("refused_e", REFUSED_E),
        ("refused_f", REFUSED_F),
        ("precondition", PRECONDITION),
        ("busy", BUSY),
        ("discarded", DISCARDED),
        ("unknown", UNKNOWN),
        ("write_failed", WRITE_FAILED),
        ("cancelled", CANCELLED),
        ("needs_refresh", NEEDS_REFRESH),
        ("audit_refused", AUDIT_REFUSED),
        ("live_unreachable", LIVE_UNREACHABLE),
        ("live_item_absent", LIVE_ITEM_ABSENT),
    ];
}

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
            "interval `{input}` is below the 60s floor; agctl will not poll the usage API more often than once every 60 seconds"
        ));
    }
    Ok(interval)
}

/// Manage AI coding agents.
#[derive(Debug, Parser)]
#[command(name = "agctl", version, about, long_about = None)]
pub struct Cli {
    /// Use this agctl configuration directory instead of the default.
    #[arg(long, value_name = "DIR", env = "AGCTL_CONFIG_DIR", global = true)]
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
    /// Print a shell completion script for agctl to stdout.
    Completions(CompletionsArgs),
}

/// Arguments for `agctl completions`.
#[derive(Debug, Args)]
pub struct CompletionsArgs {
    /// Which shell to generate a completion script for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

/// Subcommands under `agctl claude`.
#[derive(Debug, Subcommand)]
pub enum ClaudeCommand {
    /// Show subscription usage for every known account.
    Status(StatusArgs),
    /// Watch subscription usage in a terminal UI.
    Watch(WatchArgs),
    /// Log in to an Anthropic account and store its credentials.
    Login(LoginArgs),
    /// Inspect and manage the accounts agctl knows about.
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

/// Arguments for `agctl claude status`.
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

/// Arguments for `agctl claude watch`.
#[derive(Debug, Args)]
pub struct WatchArgs {
    /// How often to refetch usage; must be at least 60s.
    #[arg(long, value_name = "DUR", default_value = "300s", value_parser = watch_interval_value_parser)]
    pub interval: Duration,
}

/// Arguments for `agctl claude login`.
#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Paste the `code#state` value by hand instead of using a loopback
    /// redirect.
    #[arg(long)]
    pub manual: bool,

    /// Give the resulting account a human-readable label.
    #[arg(long, value_name = "NAME")]
    pub label: Option<String>,

    /// Refuse, instead of minting a second session, when the account
    /// authorized is the one Claude Code is already signed in as.
    #[arg(long)]
    pub no_duplicate: bool,
}

/// Subcommands under `agctl claude accounts`.
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
        /// Also delete the credential file agctl wrote for this account.
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

/// Where `agctl claude import` should read accounts from.
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

/// Arguments for `agctl claude import`.
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

/// Arguments for `agctl claude doctor`.
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

/// Arguments for `agctl claude use`.
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

/// Arguments for `agctl claude exec <id> -- <command> [args...]`.
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

/// Arguments for `agctl claude env <id>`.
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
