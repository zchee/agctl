//! `agentctl claude login` — mint a credential agentctl owns.
//!
//! The flow is plan section 3.7: PKCE, an authorize URL the user opens, a code
//! that comes back either through a loopback listener or by hand, an exchange,
//! and then a write into `<config_dir>/claude/<acct>/<org>/.credentials.json`.
//!
//! # What makes the ordering load-bearing
//!
//! Everything that touches the filesystem happens **after** the exchange has
//! returned and the identity is known, and everything that touches *this*
//! namespace happens under its lock (invariant I3). Two consequences are worth
//! naming because they are what the tests pin down:
//!
//! - A wrong `state` fails before the exchange, so a mismatched callback
//!   leaves nothing behind at all — not a directory, not a record (AC12).
//! - Logging the same `(account, organization)` in twice overwrites under the
//!   lock, and only after an interactive confirmation. There is no `--yes` on
//!   this command in phase 1, so a non-interactive run refuses rather than
//!   silently replacing a credential another process may be refreshing
//!   (AC41).
//!
//! # Terminal interaction is a seam
//!
//! Prompting, reading a pasted code, and opening a browser go through
//! [`LoginIo`] rather than straight to `std::io`. That is what lets the unit
//! tests drive a complete login — mock token endpoint, temporary config
//! directory, scripted paste — and assert on the bytes that reach disk,
//! instead of testing the flow only through a subprocess that cannot be given
//! a fake terminal.

use std::io::IsTerminal;
use std::io::Write;
use std::path::Path;
use std::time::Instant;

use crate::cli::LoginArgs;
use crate::config::AccountKind;
use crate::config::AccountRecord;
use crate::config::AgentctlConfig;
use crate::config::new_record;
use crate::config::paths::Paths;
use crate::config::paths::UNKNOWN_ORG;
use crate::config::paths::validate_segment;
use crate::error::AppError;
use crate::provider::claude;
use crate::provider::claude::credentials::Credentials;
use crate::provider::claude::credentials::Digests;
use crate::provider::claude::namespace;
use crate::provider::claude::oauth;
use crate::provider::claude::oauth::OauthClient;
use crate::provider::claude::oauth::OauthError;
use crate::provider::claude::oauth::Redirect;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::fault::Fault;
use crate::secret::file_store;
use crate::secret::file_store::ReadOutcome;
use crate::secret::file_store::WriteOutcome;
use crate::secret::file_store::WriteRequest;
use crate::secret::namespace_lock;
use crate::secret::namespace_lock::COMMAND_LOCK_TIMEOUT;

/// One login, with everything it needs from the command line.
pub struct Login<'a> {
    /// The store to write into.
    pub paths: &'a Paths,
    /// Paste the `code#state` by hand instead of listening on a loopback port.
    pub manual: bool,
    /// The label to record on the account.
    pub label: Option<&'a str>,
    /// The process-wide cancellation flag.
    pub cancel: &'a Cancel,
}

/// The parts of a login that need a human at a terminal.
pub trait LoginIo {
    /// Writes a line the user is meant to read.
    fn tell(&mut self, message: &str);

    /// Tries to open `url` in a browser. Failure is not an error: the URL has
    /// already been printed, and a headless machine is a normal place to run
    /// this.
    fn open_browser(&mut self, url: &str);

    /// Prompts and reads one line.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Io`] when the prompt cannot be written or the line
    /// cannot be read.
    fn read_line(&mut self, prompt: &str) -> Result<String, AppError>;

    /// Asks a yes/no question that must be answered by a person.
    ///
    /// # Errors
    ///
    /// Returns [`AppError::Config`] when there is no terminal to ask at, which
    /// is how a non-interactive run refuses to overwrite (AC41).
    fn confirm(&mut self, question: &str) -> Result<bool, AppError>;
}

/// Suppresses the browser launch, so the end-to-end suite can drive a real
/// `login` without opening a window on the developer's desktop.
///
/// Test seam only, and compiled out without the `testing` feature (plan
/// section 3.9): a release build must not be talkable out of showing the user
/// the URL it is asking them to authorize.
#[cfg(feature = "testing")]
pub const NO_BROWSER_ENV: &str = "AGENTCTL_NO_BROWSER";

/// The real terminal.
pub struct Terminal;

impl LoginIo for Terminal {
    fn tell(&mut self, message: &str) {
        println!("{message}");
    }

    fn open_browser(&mut self, url: &str) {
        // The URL has already been printed, so suppressing the launch costs
        // the user nothing but a click.
        #[cfg(feature = "testing")]
        if std::env::var_os(NO_BROWSER_ENV).is_some() {
            tracing::debug!("not opening a browser: the test seam is set");
            return;
        }

        // Detached: `open(1)` returns immediately on macOS, but a Linux
        // desktop opener can live as long as the browser it started, and
        // waiting for that would hang the login.
        if let Err(err) = open::that_detached(url) {
            tracing::debug!("could not open a browser ({err}); the URL was printed instead");
        }
    }

    fn read_line(&mut self, prompt: &str) -> Result<String, AppError> {
        print!("{prompt}");
        std::io::stdout().flush().map_err(|err| AppError::Io {
            context: "could not write the login prompt".to_owned(),
            source: err,
        })?;
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map_err(|err| AppError::Io {
            context: "could not read the pasted authorization code".to_owned(),
            source: err,
        })?;
        Ok(line)
    }

    fn confirm(&mut self, question: &str) -> Result<bool, AppError> {
        if !std::io::stdin().is_terminal() {
            return Err(AppError::Config(format!(
                "{question} — refusing: `login` overwrites stored credentials only after an \
                 interactive confirmation, and standard input is not a terminal"
            )));
        }
        let answer = self.read_line(&format!("{question} [y/N] "))?;
        Ok(matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes"))
    }
}

/// Runs `agentctl claude login`.
///
/// # Errors
///
/// Returns [`AppError`] for every failure. All of them are fatal (exit 1):
/// this command either logs an account in or it does not, and there are no
/// rendered rows for the partial exit status to describe.
pub fn run(config_dir: Option<&Path>, args: &LoginArgs, cancel: &Cancel) -> Result<(), AppError> {
    let paths = Paths::resolve(config_dir)?;
    let client = OauthClient::from_env(&claude::user_agent())?;
    let login = Login { paths: &paths, manual: args.manual, label: args.label.as_deref(), cancel };
    run_with(&login, &client, &mut Terminal)
}

/// The login flow, with the OAuth client and the terminal supplied.
///
/// # Errors
///
/// See [`run`].
pub fn run_with(
    login: &Login<'_>,
    client: &OauthClient,
    io: &mut dyn LoginIo,
) -> Result<(), AppError> {
    let pkce = oauth::pkce();
    let scopes = oauth::requested_scopes();

    // Bound before the URL is built: the port is part of the redirect URI, and
    // the redirect URI the authorize URL carries must be byte-identical to the
    // one the exchange sends.
    let listener = if login.manual { None } else { Some(oauth::listen_loopback().map_err(fatal)?) };
    let redirect = match &listener {
        Some(listener) => {
            Redirect::Loopback { port: oauth::loopback_port(listener).map_err(fatal)? }
        }
        None => Redirect::Manual,
    };

    let url = oauth::authorize_url(client, &pkce, &redirect, &scopes).map_err(fatal)?;
    io.tell(&format!("Open this URL to authorize agentctl:\n\n  {url}\n"));
    io.open_browser(url.as_str());

    let code = match listener {
        Some(listener) => {
            let now = Instant::now();
            let deadline = now.checked_add(oauth::LOOPBACK_TIMEOUT).unwrap_or(now);
            io.tell("Waiting for the browser to come back…");
            oauth::loopback_wait(listener, &pkce.state, deadline, login.cancel).map_err(fatal)?
        }
        None => {
            let pasted = io.read_line("Paste the `code#state` value the page shows: ")?;
            let (code, state) = oauth::parse_manual_code(&pasted).map_err(fatal)?;
            oauth::verify_state(&pkce.state, &state).map_err(fatal)?;
            code
        }
    };

    let response = oauth::exchange(client, &code, &pkce.state, &pkce, &redirect, login.cancel)
        .map_err(fatal)?;
    let now_ms = jiff::Timestamp::now().as_millisecond();
    let mut credentials =
        oauth::to_credentials(response, now_ms, &scopes).map_err(|err| fatal(err.into()))?;

    if credentials.identity().is_none() {
        // Fact F26's fallback. A failure here is not a failed login: it just
        // leaves the identity as unknown as it already was, and the check
        // below is what turns that into an error.
        match oauth::profile(client, &credentials, login.cancel) {
            Ok(document) => apply_profile(&mut credentials, &document),
            Err(err) => tracing::warn!("could not read the account profile: {err}"),
        }
    }

    let Some(identity) = credentials.identity() else {
        return Err(AppError::Config(
            "the login succeeded but named no account, so agentctl cannot tell which account \
             these credentials belong to; nothing was written"
                .to_owned(),
        ));
    };
    let account_uuid = identity.account_uuid.clone();
    let organization_uuid =
        identity.organization_uuid.clone().unwrap_or_else(|| UNKNOWN_ORG.to_owned());
    validate_segment(&account_uuid)?;
    validate_segment(&organization_uuid)?;

    if AgentctlConfig::load(login.paths)?.get(&account_uuid, &organization_uuid).is_some() {
        let question = format!(
            "`{account_uuid}/{organization_uuid}` is already logged in. Replace its stored \
             credentials?"
        );
        if !io.confirm(&question)? {
            return Err(AppError::Config("login cancelled; nothing was written".to_owned()));
        }
    }

    login.paths.ensure_dirs()?;
    let ns_dir = login.paths.namespace_dir(&account_uuid, &organization_uuid);

    let now = Instant::now();
    let lock_deadline = now.checked_add(COMMAND_LOCK_TIMEOUT).unwrap_or(now);
    let guard = namespace_lock::acquire(
        login.paths,
        &account_uuid,
        &organization_uuid,
        lock_deadline,
        login.cancel,
        fault(),
    )
    .map_err(|err| AppError::Config(format!("could not take the namespace lock: {err}")))?;

    // Invariant I9: a pending file from an earlier failed write describes
    // credentials this login has just superseded, and a stray temporary file
    // holds token material at rest (risk R24).
    clear_stale_files(login.paths, &ns_dir)?;

    let prior = prior_digests(&ns_dir);
    let blob = credentials.to_blob_json();
    let write_now = Instant::now();
    let ctx = PassCtx::standalone(
        login.cancel.clone(),
        write_now.checked_add(oauth::TOKEN_TIMEOUT).unwrap_or(write_now),
    );
    let request = WriteRequest {
        paths: login.paths,
        ns_dir: &ns_dir,
        blob_json: &blob,
        prior: prior.as_ref(),
        new_expires_at_ms: credentials.expires_at_ms,
        fault: fault(),
    };
    let outcome = file_store::write_credentials(&request, &ctx)
        .map_err(|err| AppError::Config(format!("could not store the credentials: {err}")))?;

    // The record is written even when the rename failed, deliberately: a
    // pending file whose namespace has no account record is one nothing will
    // ever come back for, whereas a recorded account replays it on the next
    // pass (plan section 3.3, first-write row).
    let export_spelling = namespace::export_spelling(&ns_dir);
    let export_sha8 = namespace::sha8(&export_spelling);
    let mut record = new_record(
        account_uuid.clone(),
        organization_uuid.clone(),
        AccountKind::Owned { export_spelling, export_sha8 },
    )?;
    record.email = identity.email.clone();
    record.org_name = identity.org_name.clone();
    record.label = login.label.map(str::to_owned);
    record_owned(login.paths, record)?;

    drop(guard);

    if let WriteOutcome::SavedToPending { error } = &outcome {
        tracing::warn!("the credential file could not be replaced ({error}); saved as pending");
        io.tell(
            "The credentials could not be written into place and were saved as pending; the \
             next `agentctl claude status` will finish the job.",
        );
    }

    // Re-read rather than reuse a copy from before the write: the identifier
    // shown here is `<acct>` or `<acct>/<org>` depending on what else is in
    // the registry, so it has to be derived from what is actually stored now.
    let id = AgentctlConfig::load(login.paths)
        .ok()
        .and_then(|config| {
            config
                .get(&account_uuid, &organization_uuid)
                .map(|rec| rec.display_id(&config.accounts))
        })
        .unwrap_or_else(|| account_uuid.clone());
    match identity.email.as_deref() {
        Some(email) => io.tell(&format!("Logged in as {email} ({id}).")),
        None => io.tell(&format!("Logged in ({id}).")),
    }
    Ok(())
}

/// Writes one account into the registry.
///
/// **Every registry mutation this command makes goes through here**, and this
/// is the only place that is allowed to. A registry write is a
/// read-modify-write of a file two `agentctl` processes may be touching at
/// once, so the read, the mutation and the write have to happen under one
/// hold of `.config.lock` — which is why the sequence is confined to a
/// function small enough to be swapped for a single call that does exactly
/// that.
///
/// A caller must **not** take `.config.lock` around this. `flock` is per
/// open-file-description, so a caller holding it would be waiting on itself
/// and would get `Busy` at the deadline. The namespace lock is a different
/// file and is unaffected; it stays held across this call so the credential
/// file and the record that points at it land together.
///
/// # Errors
///
/// Returns whatever the registry write reports: [`AppError::Refused`] when
/// the configuration lock cannot be taken, [`AppError::Io`] for a filesystem
/// failure.
fn record_owned(paths: &Paths, record: AccountRecord) -> Result<(), AppError> {
    AgentctlConfig::update(paths, |config| config.upsert(record))
}

/// Turns any OAuth failure into a fatal application error.
///
/// A `login` that did not log in produced nothing to render, so it exits 1
/// rather than 2 whatever went wrong along the way. The OAuth messages are
/// already user-facing sentences and already redacted, so they are carried
/// through verbatim.
fn fatal(err: OauthError) -> AppError {
    AppError::Config(err.to_string())
}

/// The fault set this process should honour.
///
/// Always empty without the `testing` feature, which is what keeps the
/// injection points unreachable in a release build (plan section 3.9).
fn fault() -> Fault {
    #[cfg(feature = "testing")]
    {
        Fault::from_env()
    }
    #[cfg(not(feature = "testing"))]
    {
        Fault::none()
    }
}

/// Fills in an identity from a profile response (fact F26).
///
/// The document's exact shape was never captured on the wire, so every field
/// is optional and a document that carries none of them simply leaves the
/// credentials as they were. Both the nested spelling Claude Code's exchange
/// uses and a flat top-level `uuid`/`email_address` are accepted.
fn apply_profile(credentials: &mut Credentials, document: &serde_json::Value) {
    let account = document.get("account").unwrap_or(document);
    let organization = document.get("organization");

    let uuid = account.get("uuid").and_then(serde_json::Value::as_str);
    let email = account.get("email_address").and_then(serde_json::Value::as_str);
    let org_uuid = organization.and_then(|o| o.get("uuid")).and_then(serde_json::Value::as_str);
    let org_name = organization.and_then(|o| o.get("name")).and_then(serde_json::Value::as_str);
    if uuid.is_none() && email.is_none() && org_uuid.is_none() {
        return;
    }

    let token_account = credentials.token_account.get_or_insert_with(Default::default);
    if let Some(uuid) = uuid {
        token_account.uuid = Some(uuid.to_owned());
    }
    if let Some(email) = email {
        token_account.email_address = Some(email.to_owned());
    }
    if let Some(org_uuid) = org_uuid {
        token_account.organization_uuid = Some(org_uuid.to_owned());
    }
    if let Some(org_name) = org_name {
        token_account.organization_name = Some(org_name.to_owned());
    }
}

/// Removes a superseded pending file and any leftover temporary file.
///
/// Shared with [`accounts::relocate`](crate::commands::accounts::relocate),
/// which supersedes a namespace's contents in exactly the same way and is
/// bound by the same clause of invariant I9 ("`login`/`relocate`/`remove`
/// delete any pending first").
///
/// # Errors
///
/// Returns [`AppError::Config`] when `ns_dir` is not inside this store — the
/// same refusal [`file_store::write_credentials`] makes, applied before
/// anything is unlinked rather than after — and [`AppError::Io`] when a file
/// that exists cannot be removed.
pub fn clear_stale_files(paths: &Paths, ns_dir: &Path) -> Result<(), AppError> {
    if !paths.is_under_namespace_root(ns_dir) {
        return Err(AppError::Config(format!(
            "`{}` is outside the agentctl namespace root; refusing to touch it",
            ns_dir.display()
        )));
    }

    let mut targets =
        vec![ns_dir.join(file_store::PENDING_FILE), ns_dir.join(file_store::PENDING_META)];
    targets.extend(file_store::list_stray_tmp(ns_dir).map_err(|err| AppError::Io {
        context: format!("could not list `{}`", ns_dir.display()),
        source: err,
    })?);

    for target in targets {
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(AppError::Io {
                    context: format!("could not remove `{}`", target.display()),
                    source: err,
                });
            }
        }
    }
    Ok(())
}

/// The digests of the credentials already in this namespace, if any.
///
/// Recorded in the pending metadata so a failed rename can be replayed only
/// against the file it was derived from. `None` means a first write, which is
/// the normal case for a login.
fn prior_digests(ns_dir: &Path) -> Option<Digests> {
    match file_store::read_credentials(ns_dir) {
        Ok(ReadOutcome::Present { bytes, .. }) => {
            Credentials::parse_blob(&bytes).ok().map(|creds| creds.digests())
        }
        _ => None,
    }
}

#[cfg(test)]
#[path = "login_tests.rs"]
mod tests;
