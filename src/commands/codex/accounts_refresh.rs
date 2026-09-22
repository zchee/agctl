//! `agctl codex accounts set` and `agctl codex accounts refresh` — the two
//! subcommands that change refresh policy and the one that sends a refresh
//! token because a person asked for it (plan AC127, decision D-035, U44).
//!
//! # Why these two live away from `accounts.rs`
//!
//! Everything in `accounts.rs` reads the registry or unlinks files agctl
//! wrote. These two can reach the token host, and the capability that lets
//! them — [`PostPermit`] — is pinned by path: `scripts/phase3-greps.sh` names
//! this file, and only this file, in the consent, refresh-driver, POST-permit
//! and permit-mint allow-lists. Keeping them here is what makes
//! "`accounts list` cannot POST" a property of the file layout rather than of
//! a reviewer's attention.
//!
//! # The one POST a person can ask for
//!
//! `refresh --resend` is D-035's single override. Every gate that decides
//! whether the send happens — the marker must say `refresh outcome unknown`
//! for *this* grant, an hour must have passed since that send, the marker's
//! one re-send must be unspent, no staged temporary may be lying in the
//! namespace, no Codex daemon may be using it — lives in
//! [`refresh::run`](crate::provider::codex::refresh::run) under the namespace
//! lock, where the state it judges cannot change under it. This module adds
//! none of them and re-implements none of them: it takes the user's
//! confirmation, turns it into a [`ResendConsent`], and says in words what the
//! driver decided.
//!
//! # The confirmation, and why `--yes` is not a way around it
//!
//! [`ResendConsent::after_confirmation`] refuses when stdin is not a terminal,
//! `--yes` included, so a re-send cannot be scheduled by cron or CI: a second
//! send of a refresh token the host may already have consumed is a reuse
//! event the vendor may answer by revoking the grant (risk R63), and that is a
//! cost a person takes, not a job. The question is therefore asked only when
//! there *is* a terminal and no `--yes`, and the consent type is what proves
//! the rule held — a refusal returns `Err` before any
//! [`SendMode::Resend`](crate::provider::codex::refresh::SendMode::Resend)
//! exists to be sent.
//!
//! # `set` never opens the namespace
//!
//! `set --refresh never|auto` is a registry field, written under
//! `.config.lock` and nothing else (plan AC127). It does not create the Codex
//! tree, take the namespace lock or read `auth.json`: a user who wants agctl
//! to stop sending a token must not have to let agctl touch the store to say
//! so. The effect is the next pass's, where a `never` row is
//! `RefreshStep::Disabled` — 0 POSTs — and goes `expired (run agctl codex
//! login)` when its access token runs out.

use std::io::IsTerminal;
use std::time::Duration;
use std::time::Instant;

use jiff::Timestamp;
use jiff::tz::TimeZone;

use crate::cli::RefreshMode;
use crate::commands::Prompt;
use crate::config::AgctlConfig;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::auth_store::OwnedNamespace;
use crate::provider::codex::lock;
use crate::provider::codex::lock::LockBudget;
use crate::provider::codex::permit::PostPermit;
use crate::provider::codex::proof;
use crate::provider::codex::proof::OwnedRecord;
use crate::provider::codex::refresh;
use crate::provider::codex::refresh::AdoptReason;
use crate::provider::codex::refresh::ConsentRefusal;
use crate::provider::codex::refresh::NeedsLoginReason;
use crate::provider::codex::refresh::REFRESH_POST_BUDGET;
use crate::provider::codex::refresh::RefreshNote;
use crate::provider::codex::refresh::RefreshReport;
use crate::provider::codex::refresh::RefreshStep;
use crate::provider::codex::refresh::ResendBlock;
use crate::provider::codex::refresh::ResendConsent;
use crate::provider::codex::refresh::ResetConsent;
use crate::provider::codex::refresh::SendMode;
use crate::provider::codex::refresh::StaleReason;
use crate::provider::codex::refresh::WRITE_ALLOWANCE;
use crate::runtime::coordinator::Cancel;

use super::accounts;

/// How long either subcommand waits for the namespace lock.
///
/// A command budget, not a pass budget: a person is waiting, and another
/// agctl holding the namespace is a reason to say so rather than to block.
const LOCK_BUDGET: Duration = Duration::from_secs(5);

/// The slack between the deadline this command sets and the budget
/// [`refresh::run`] checks against it.
///
/// The driver requires `remaining >= lock budget + POST budget + write
/// allowance`, measured from a clock that has already advanced past the line
/// that set the deadline. Without slack an exactly-sized budget loses that
/// race and the send is refused as `stale` for no reason the user can see.
const SLACK: Duration = Duration::from_secs(1);

/// One `refresh` invocation's arguments.
pub struct Request<'a> {
    /// The id, email or label the user typed.
    pub id: &'a str,
    /// Send the stored refresh token once more.
    pub resend: bool,
    /// Lift the terminal 401 state.
    pub reset_floor: bool,
    /// Whether the confirmation was given up front.
    pub yes: bool,
}

/// `agctl codex accounts set <id> --refresh <auto|never>`.
///
/// Registry only, under `.config.lock`: no namespace is opened, no lock is
/// taken and no credential is read (plan AC127).
///
/// # Errors
///
/// As [`accounts::resolve`]; [`AppError::Refused`] for a row agctl stores no
/// credential for, plus whatever the registry update reports.
pub fn set(
    paths: &Paths,
    id: &str,
    mode: RefreshMode,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let policy = match mode {
        RefreshMode::Auto => RefreshPolicy::Auto,
        RefreshMode::Never => RefreshPolicy::Never,
    };
    let config = AgctlConfig::load(paths)?;
    let record = accounts::resolve(&config.codex_accounts, id)?;
    let shown = accounts::key(record);

    // A `Live` or `HomeReadOnly` row is never refreshed by agctl at all
    // (invariant I21), so there is no policy on it to change. Said by name
    // rather than recorded as a field nothing reads.
    match &record.kind {
        CodexKind::Owned { refresh, .. } if *refresh == policy => {
            io.tell(&format!("{shown} is already `{}`", word(policy)));
            return Ok(());
        }
        CodexKind::Owned { .. } => {}
        CodexKind::Live | CodexKind::HomeReadOnly { .. } => {
            return Err(AppError::Refused {
                reason: format!(
                    "agctl never refreshes `{shown}`: its credential belongs to a Codex home \
                     agctl did not create, and only the account's own client refreshes it"
                ),
            });
        }
    }

    let (user, acct) = (record.chatgpt_user_id.clone(), record.chatgpt_account_id.clone());
    AgctlConfig::update(paths, |config| {
        if let Some(row) = accounts::find_mut(config, &user, &acct)
            && let CodexKind::Owned { refresh, .. } = &mut row.kind
        {
            *refresh = policy;
        }
    })?;

    io.tell(&match policy {
        RefreshPolicy::Auto => {
            format!("{shown}: agctl may refresh this grant again when its access token expires")
        }
        RefreshPolicy::Never => format!(
            "{shown}: agctl will never send this refresh token; the row reads `expired (run \
             agctl codex login)` once its access token runs out"
        ),
    });
    Ok(())
}

/// `agctl codex accounts refresh <id> [--resend|--reset-floor] [--yes]`.
///
/// # Errors
///
/// [`AppError::Config`] when neither action was named, as
/// [`accounts::resolve`] for the id, and [`AppError::Refused`] for a row agctl
/// stores no credential for or a send the driver declined.
pub fn refresh(
    paths: &Paths,
    request: &Request<'_>,
    cancel: &Cancel,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    // Read once, here: every seam below takes it as a value, so a test
    // chooses what a terminal would have said without one.
    refresh_with(paths, request, std::io::stdin().is_terminal(), cancel, io)
}

/// [`refresh`] over a chosen `stdin_is_tty`.
fn refresh_with(
    paths: &Paths,
    request: &Request<'_>,
    stdin_is_tty: bool,
    cancel: &Cancel,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    if !request.resend && !request.reset_floor {
        return Err(AppError::Config(
            "`agctl codex accounts refresh` needs `--resend` (send the stored refresh token \
             once more) or `--reset-floor` (lift a terminal 401 state)"
                .to_owned(),
        ));
    }

    let config = AgctlConfig::load(paths)?;
    let record = accounts::resolve(&config.codex_accounts, request.id)?.clone();
    let shown = accounts::key(&record);
    let Some(owned) = proof::owned(&record) else {
        return Err(AppError::Refused {
            reason: format!(
                "agctl stores no credential for `{shown}`, so it has no refresh state to act on; \
                 `agctl codex login` adds one"
            ),
        });
    };

    if request.resend {
        // The permit is minted here and nowhere else in this command: a
        // `--reset-floor` run holds no capability to POST at all.
        let permit = PostPermit::from_env();
        resend(paths, &permit, owned, &shown, request, stdin_is_tty, cancel, io)
    } else {
        reset_floor(paths, owned, &shown, request, stdin_is_tty, cancel, io)
    }
}

/// `--resend`: the one audited re-send of a grant whose outcome is unknown.
#[expect(clippy::too_many_arguments, reason = "each is a distinct input the send needs")]
fn resend(
    paths: &Paths,
    permit: &PostPermit,
    owned: OwnedRecord<'_>,
    shown: &str,
    request: &Request<'_>,
    stdin_is_tty: bool,
    cancel: &Cancel,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let question = format!(
        "send `{shown}`'s stored refresh token once more? agctl does not know whether the token \
         host consumed the first send, and a reuse can be answered by revoking the grant (risk \
         R63); this is the only re-send agctl will make for it"
    );
    let Some(consent) =
        consent(io, stdin_is_tty, request.yes, &question, ResendConsent::after_confirmation)?
    else {
        io.tell("nothing was sent");
        return Ok(());
    };

    let fault = crate::commands::status::current_fault();
    let ctx = refresh::RefreshCtx {
        paths,
        deadline: deadline(),
        lock_budget: LockBudget::Command(LOCK_BUDGET),
        cancel,
        fault: &fault,
    };
    let report = refresh::run(permit, owned, SendMode::Resend(consent), &ctx);
    tracing::debug!(step = ?report.step, "codex accounts refresh --resend");
    report_resend(io, shown, &report)
}

/// `--reset-floor`: lift the terminal 401 state, and nothing else.
fn reset_floor(
    paths: &Paths,
    owned: OwnedRecord<'_>,
    shown: &str,
    request: &Request<'_>,
    stdin_is_tty: bool,
    cancel: &Cancel,
    io: &mut dyn Prompt,
) -> Result<(), AppError> {
    let question = format!(
        "lift the refresh floor for `{shown}`, so agctl may send its refresh token again after \
         three that did not help?"
    );
    let Some(consent) =
        consent(io, stdin_is_tty, request.yes, &question, ResetConsent::after_confirmation)?
    else {
        io.tell("nothing was changed");
        return Ok(());
    };

    let fault = crate::commands::status::current_fault();
    let guard = lock::acquire_codex(paths, owned, LockBudget::Command(LOCK_BUDGET), cancel, &fault)
        .map_err(|err| AppError::Refused { reason: err.to_string() })?;
    let ns = OwnedNamespace::open(paths, owned, &guard)
        .map_err(|err| AppError::Refused { reason: err.to_string() })?;
    refresh::reset_floor(paths, &ns, consent)?;
    io.tell(&format!(
        "{shown}: the 401 floor and the `refresh did not help` count are back to their defaults; \
         no token was sent"
    ));
    Ok(())
}

/// Asks the question, and turns the answer into the consent `build` makes.
///
/// `Ok(None)` is "the person said no": nothing is sent and the command
/// succeeds, because declining is an answer rather than a failure. The
/// question is put only when there is a terminal to put it at and no `--yes`;
/// whether that was enough is `build`'s decision, never this function's, so
/// the terminal rule lives beside the consent type it protects.
fn consent<T>(
    io: &mut dyn Prompt,
    stdin_is_tty: bool,
    yes: bool,
    question: &str,
    build: impl Fn(&str, bool, bool) -> Result<T, ConsentRefusal>,
) -> Result<Option<T>, AppError> {
    let answer =
        if stdin_is_tty && !yes { if io.confirm(question)? { "yes" } else { "no" } } else { "" };
    match build(answer, stdin_is_tty, yes) {
        Ok(consent) => Ok(Some(consent)),
        Err(ConsentRefusal::NotConfirmed) => Ok(None),
        Err(refusal @ ConsentRefusal::NotATerminal) => {
            Err(AppError::Refused { reason: format!("{question} — {refusal}") })
        }
    }
}

/// What the command gives the driver: the lock wait, the POST budget, the
/// write allowance and [`SLACK`].
fn deadline() -> Instant {
    let now = Instant::now();
    let budget = LOCK_BUDGET
        .checked_add(REFRESH_POST_BUDGET)
        .and_then(|budget| budget.checked_add(WRITE_ALLOWANCE))
        .and_then(|budget| budget.checked_add(SLACK));
    budget.and_then(|budget| now.checked_add(budget)).unwrap_or(now)
}

/// Says what the driver decided, and whether the row is usable now.
///
/// `Ok` only when the account can be read again: a rotated grant, or one
/// another writer had already put in place. A refusal the driver took before
/// sending is [`AppError::Refused`]; a send that happened and left the row
/// degraded is [`AppError::Partial`], which is what that exit status means
/// (`error.rs`) — the command printed the row's state and the row is not
/// healthy.
fn report_resend(io: &mut dyn Prompt, shown: &str, report: &RefreshReport) -> Result<(), AppError> {
    for note in &report.notes {
        io.tell(&format!("note: {}", note_line(*note)));
    }
    match &report.step {
        RefreshStep::Refreshed { parked } => {
            io.tell(&if *parked {
                format!(
                    "{shown}: the token host answered with a new grant; it is parked as pending \
                     and the next pass puts it in place"
                )
            } else {
                format!("{shown}: the token host answered with a new grant, and it is stored")
            });
            Ok(())
        }
        RefreshStep::Adopted(reason) => {
            io.tell(&format!("{shown}: nothing was sent — {}", adopted(*reason)));
            Ok(())
        }
        RefreshStep::ResendRefused(block) => {
            Err(AppError::Refused { reason: format!("{shown}: {}", refused(shown, block)) })
        }
        RefreshStep::Busy => Err(AppError::Refused {
            reason: format!(
                "another agctl holds `{shown}`'s namespace; nothing was sent. Try again when it \
                 has finished"
            ),
        }),
        RefreshStep::Disabled => Err(AppError::Refused {
            reason: format!(
                "`{shown}` is set to `never` refresh; `agctl codex accounts set {shown} \
                 --refresh auto` is what re-arms it"
            ),
        }),
        RefreshStep::SessionDetected(pid) => Err(AppError::Refused {
            reason: format!(
                "a Codex process ({pid}) is using `{shown}`'s namespace; agctl refreshes a grant \
                 only when nothing else has it open"
            ),
        }),
        RefreshStep::StateUnavailable(reason) => Err(AppError::Refused {
            reason: format!(
                "`{shown}`'s refresh marker could not be read or written, so nothing was sent: \
                 {reason}"
            ),
        }),
        RefreshStep::NotBefore(at) => Err(AppError::Refused {
            reason: format!(
                "the token host asked for no refresh of `{shown}`'s grant before {}",
                local(*at)
            ),
        }),
        RefreshStep::UnauthorizedFloor { until } => Err(AppError::Refused {
            reason: format!(
                "`{shown}` is inside its 401 refresh floor until {}; nothing was sent",
                local(*until)
            ),
        }),
        RefreshStep::UnauthorizedTerminal => Err(AppError::Refused {
            reason: format!(
                "three sent refreshes did not help `{shown}`; `agctl codex accounts refresh \
                 {shown} --reset-floor` lifts that, and `agctl codex login` replaces the grant"
            ),
        }),
        RefreshStep::Stale(reason) => Err(AppError::Refused {
            reason: format!("nothing was sent for `{shown}`: {}", stale(reason)),
        }),
        RefreshStep::OutcomeUnknown { since, class, .. } => {
            io.tell(&format!(
                "{shown}: the re-send was answered with `{}`, so its outcome is still unknown \
                 (since {}). Its one re-send is spent; `agctl codex login` replaces the grant",
                class.label(),
                local(*since)
            ));
            Err(AppError::Partial { failed: 1 })
        }
        RefreshStep::NeedsLogin(reason) => {
            io.tell(&format!("{shown}: {}", needs_login(*reason)));
            Err(AppError::Partial { failed: 1 })
        }
        RefreshStep::RacedExternal => {
            io.tell(&format!(
                "{shown}: the token host called the grant that was sent dead while another \
                 writer's newer one was in the file; the newer grant was kept"
            ));
            Err(AppError::Partial { failed: 1 })
        }
        RefreshStep::DiscardedExternal => {
            io.tell(&format!(
                "{shown}: another writer's grant was in the file, so the response was discarded"
            ));
            Err(AppError::Partial { failed: 1 })
        }
        RefreshStep::Failed(reason) => {
            Err(AppError::Refused { reason: format!("`{shown}`'s re-send did not run: {reason}") })
        }
    }
}

/// Why the driver refused a `--resend`.
///
/// [`ResendBlock::StrayTmp`] carries no file name — the driver saw one while
/// holding the lock this command no longer holds — so the refusal names the
/// namespace it is in and sends the reader to `doctor`, which lists the
/// namespace and is the one command allowed to spell a store file's name
/// (`scripts/phase3-greps.sh`, `auth_json`).
fn refused(shown: &str, block: &ResendBlock) -> String {
    match block {
        ResendBlock::NotUnknown => "its last refresh outcome is not unknown, so there is nothing \
             to re-send. agctl re-sends a refresh token only when it does not know what its own \
             last send did"
            .to_owned(),
        ResendBlock::AlreadyResent => "its one re-send is already spent. agctl sends a grant at \
             most twice — once on its own and once because you asked — so `agctl codex login` is \
             what remains"
            .to_owned(),
        ResendBlock::TooEarly(at) => format!(
            "agctl waits an hour after a send whose outcome it does not know, in case an answer \
             is still on its way; `{shown}` becomes eligible at {}",
            local(*at)
        ),
        ResendBlock::StrayTmp => format!(
            "a staged temporary is lying in `{shown}`'s namespace and may hold a grant the token \
             host already rotated. `agctl codex doctor` names the file; nothing was sent until \
             it is dealt with"
        ),
    }
}

/// Why no POST was needed.
fn adopted(reason: AdoptReason) -> &'static str {
    match reason {
        AdoptReason::Fresh => "the stored access token is not due for a refresh",
        AdoptReason::ExternalAccess => {
            "another writer had already refreshed this grant, and agctl adopted it"
        }
        AdoptReason::ChangedBeforePost => {
            "the credential changed before the send, and the grant now in it is fresh"
        }
    }
}

/// Why nothing was sent, for a row that stays as it was.
fn stale(reason: &StaleReason) -> String {
    match reason {
        StaleReason::NotEnoughTime => {
            "there was not enough time left for the lock, the request and the write".to_owned()
        }
        StaleReason::Cancelled => "the command was cancelled before the send".to_owned(),
        StaleReason::Torn => "the credential was being rewritten and stayed unreadable".to_owned(),
        StaleReason::DaemonRecordUnreadable => {
            "a Codex daemon's record exists and cannot be read, so agctl cannot tell whether \
             the namespace is in use"
                .to_owned()
        }
        StaleReason::ChangedBeforePost => {
            "the credential changed between the read and the send".to_owned()
        }
        StaleReason::PreSend(reason) => {
            format!("the request never left this machine ({reason}), so the grant is untouched")
        }
        StaleReason::Rejected(status) => format!(
            "the token host answered {status} before processing the request, so the grant is \
             taken as unused"
        ),
    }
}

/// Why the row needs a login.
fn needs_login(reason: NeedsLoginReason) -> &'static str {
    match reason {
        NeedsLoginReason::Absent => {
            "agctl holds no credential for it; `agctl codex login` adds one"
        }
        NeedsLoginReason::NoRefreshToken => {
            "its stored credential carries no refresh token; `agctl codex login` replaces it"
        }
        NeedsLoginReason::Dead => {
            "the token host called this grant dead; `agctl codex login` replaces it"
        }
        NeedsLoginReason::ResendRejected(_) => {
            "the token host refused the re-send, and the re-send is spent; `agctl codex login` \
             replaces the grant"
        }
    }
}

/// What a note says.
fn note_line(note: RefreshNote) -> &'static str {
    match note {
        RefreshNote::AuditLogRefused => {
            "the audit log refused an entry; the write it describes still happened"
        }
        RefreshNote::CodexSession(_) => "a Codex session is using this namespace",
        RefreshNote::IdentityDrift => "the new id token names another account",
        RefreshNote::IdTokenUnreadable => {
            "the new id token could not be decoded, and the stored one was kept"
        }
        RefreshNote::PendingReplayed => "a parked credential was put in place first",
        RefreshNote::PendingDiscarded => "a parked credential was discarded first",
        RefreshNote::StaleMarkerCleared => "a marker for an older grant was cleared",
    }
}

/// The policy's own word, as `--refresh` spells it.
fn word(policy: RefreshPolicy) -> &'static str {
    match policy {
        RefreshPolicy::Auto => "auto",
        RefreshPolicy::Never => "never",
    }
}

/// `at` in the reader's own time zone, to the minute.
fn local(at: Timestamp) -> String {
    at.to_zoned(TimeZone::system()).strftime("%Y-%m-%d %H:%M %Z").to_string()
}

#[cfg(test)]
#[path = "accounts_refresh_tests.rs"]
mod tests;
