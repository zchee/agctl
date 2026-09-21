//! `agctl codex doctor` — what is on this machine for Codex, and nothing
//! else.
//!
//! The report is plan section 3.3's `doctor` paragraph, item for item: the
//! resolved home and the links walked to reach it, the store mode and whether
//! agctl reads the file, the four Codex variables this process carries, the
//! live credential's shape, the daemon evidence, the Codex credentials on this
//! machine that are not agctl's, every owned namespace with its lock, its
//! stray files and its refresh marker, what the tree holds that no record
//! explains, and the write log's last lines.
//!
//! # It diagnoses; it does not repair, and it does not create
//!
//! There is no `--remove-stale` here and no repair of any kind: no Codex lock
//! is agctl's to remove (plan section 3.2), so this command has no write path
//! at all. It does not even create a directory. That is not a matter of care
//! but of route: [`OwnedNamespace::open`](crate::provider::codex::auth_store::OwnedNamespace::open)
//! creates the namespace directory it opens, so this file never calls it, and
//! reaches a namespace only through `symlink_metadata`, `read_dir`,
//! [`auth_store::read_live`] and [`RefreshStateFile::load`] — reads whose
//! failure mode is a report line, not a missing directory (the C3 carry,
//! ledger #469). `ensure_codex_dirs` is not called either, so running
//! `doctor` on a machine that has never run `agctl codex login` leaves it
//! exactly as it was.
//!
//! # Nothing that came out of a file is printed back
//!
//! Every string this command puts into the report is an identifier agctl
//! validated, a path agctl derived, a word compiled into this build, or a
//! number. A `config.toml` that does not parse is reported by **line number**
//! (invariant I31, plan AC116); a store mode or an auth mode this build does
//! not know is reported as `unknown` rather than as the spelling found; the
//! fact F61 field-set comparison names the members that are **missing** —
//! those names are this crate's — and **counts** the rest (premortem PM22);
//! a `codex-switcher:` keychain item is counted and never named. The reason
//! is uniform: a member name, a configuration value or a keychain account can
//! carry a credential someone pasted into the wrong place, and no sanitizer
//! can tell that from a field name.

use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use jiff::Timestamp;

use crate::cli::Cli;
use crate::cli::CodexDoctorArgs;
use crate::commands::codex::codex_env_from_process;
use crate::config::AgctlConfig;
use crate::config::codex::CodexAccountRecord;
use crate::config::codex::CodexKind;
use crate::config::codex::RefreshPolicy;
use crate::config::paths::Paths;
use crate::error::AppError;
use crate::provider::codex::audit;
use crate::provider::codex::auth_store;
use crate::provider::codex::auth_store::CodexResolved;
use crate::provider::codex::auth_store::RefreshState;
use crate::provider::codex::auth_store::RefreshStateFile;
use crate::provider::codex::auth_store::RefreshStateRead;
use crate::provider::codex::credentials::AuthMode;
use crate::provider::codex::credentials::Credentials;
use crate::provider::codex::discovery;
use crate::provider::codex::discovery::Orphan;
use crate::provider::codex::home;
use crate::provider::codex::home::ConfigNote;
use crate::provider::codex::home::DaemonEvidence;
use crate::provider::codex::home::FileInEffect;
use crate::provider::codex::home::KeyringProbe;
use crate::provider::codex::home::StoreMode;
use crate::provider::codex::home::is_home_account;
use crate::provider::codex::proof;
use crate::provider::codex::refresh;
use crate::render::codex_doctor::CodexDoctorReport;
use crate::render::codex_doctor::EnvVar;
use crate::render::codex_doctor::ForeignSection;
use crate::render::codex_doctor::HomeSection;
use crate::render::codex_doctor::LiveSection;
use crate::render::codex_doctor::LockSection;
use crate::render::codex_doctor::MarkerSection;
use crate::render::codex_doctor::NamespaceSection;
use crate::render::codex_doctor::OrphanEntry;
use crate::render::codex_doctor::StoreSection;
use crate::render::codex_doctor::VERSION;
use crate::runtime::coordinator::Cancel;
use crate::runtime::coordinator::PassCtx;
use crate::runtime::proc;
use crate::secret::KeychainReader;
use crate::secret::ServiceEntry;
use crate::secret::namespace_lock;

/// The keychain service prefix a Codex account switcher uses, the Codex twin
/// of [`SWITCHER_SERVICE_PREFIX`](crate::secret::SWITCHER_SERVICE_PREFIX).
///
/// Items under it are **counted** and never named: the rest of the service
/// name is a person's address.
pub const SWITCHER_PREFIX: &str = "codex-switcher:";

/// The directory a Codex home keeps several logins in (open question U32).
///
/// Its presence is reported; it is never listed and never read.
pub const MULTI_AUTH_DIR: &str = "multi-auth";

/// The Codex variables whose presence in agctl's own environment is worth
/// knowing, because a Codex session started with one of them may not be using
/// the credential this report describes.
pub const REPORTED_ENV: [&str; 4] = [
    "CODEX_API_KEY",
    "CODEX_ACCESS_TOKEN",
    "CODEX_REFRESH_TOKEN_URL_OVERRIDE",
    "CODEX_APP_SERVER_LOGIN_CLIENT_ID",
];

/// How many of the write log's last lines the report carries (invariant I30).
pub const AUDIT_LINES: usize = 10;

/// How long the keychain listings may take before the report goes on without
/// them.
const LISTING_BUDGET: Duration = Duration::from_secs(15);

/// The permission bits a credential file must have.
const REQUIRED_MODE: u32 = 0o600;

/// The parked pending write's metadata file, which writer 2 leaves beside the
/// pending credential (plan section 3.3, `accounts remove`).
const PENDING_META: &str = "auth.pending.meta";

/// Runs `agctl codex doctor`.
///
/// # Errors
///
/// [`AppError`] when the registry cannot be read, or when the Codex tree
/// exists and cannot be listed. A home that cannot be resolved, a marker that
/// cannot be read and a log that cannot be opened are each **reported**, not
/// returned: a diagnosis that refuses to print because one of the things it
/// diagnoses is broken is the one case it exists for.
pub fn run(cli: &Cli, args: &CodexDoctorArgs, cancel: &Cancel) -> Result<(), AppError> {
    let paths = Paths::resolve(cli.config_dir.as_deref())?;
    let config = AgctlConfig::load(&paths)?;
    let env_view = EnvView::from_process();
    let listings = Listings::take(cancel);
    let report = build(&paths, &config.codex_accounts, &env_view, &listings, cancel)?;

    if args.json {
        let document = serde_json::to_string_pretty(&report).map_err(|err| {
            AppError::Config(format!("the report could not be serialized: {err}"))
        })?;
        println!("{document}");
    } else {
        print!("{}", crate::render::codex_doctor::render(&report));
    }
    Ok(())
}

/// What this process's environment says, read once.
///
/// A view rather than a read at each use, so the unit tests build one from
/// literals and `home.rs` keeps its rule that it never names the environment
/// (invariant I25).
#[derive(Debug, Clone, Default)]
pub struct EnvView {
    /// The two inputs a Codex home resolves from.
    pub codex: home::CodexEnv,
    /// Which of [`REPORTED_ENV`] are set. **Never their values.**
    pub set: Vec<&'static str>,
}

impl EnvView {
    /// The view of the process agctl is running in.
    #[must_use]
    pub fn from_process() -> Self {
        Self {
            codex: codex_env_from_process(),
            set: REPORTED_ENV.into_iter().filter(|name| std::env::var_os(name).is_some()).collect(),
        }
    }
}

/// The two read-only keychain listings the report needs.
///
/// Taken once, before anything else: they are the only `security` calls this
/// command makes, and both read attributes only (plan AC109, ledger #121).
#[derive(Debug, Clone, Default)]
pub struct Listings {
    /// The `Codex Auth` items, or `None` when the listing could not be taken.
    pub codex_auth: Option<Vec<ServiceEntry>>,
    /// How many `codex-switcher:` items are listed.
    pub switcher: Option<usize>,
}

impl Listings {
    /// Both listings, through the reader this build has.
    #[must_use]
    pub fn take(cancel: &Cancel) -> Self {
        let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + LISTING_BUDGET);
        let reader = crate::secret::default_reader(&ctx);
        Self::from_reader(reader.as_ref())
    }

    /// Both listings, through a reader a test can replace.
    #[must_use]
    pub fn from_reader(reader: &dyn KeychainReader) -> Self {
        let codex_auth = reader.list_services(home::KEYRING_SERVICE).ok();
        let switcher = reader.list_services(SWITCHER_PREFIX).ok().map(|items| items.len());
        Self { codex_auth, switcher }
    }

    /// What the listing says about `home`'s item (fact F94).
    fn probe(&self, home_dir: &Path) -> KeyringProbe {
        let Some(entries) = &self.codex_auth else { return KeyringProbe::Unknown };
        let account = home::keyring_account(home_dir);
        let listed = entries.iter().any(|entry| {
            entry.service == home::KEYRING_SERVICE
                && entry.account.as_deref().is_none_or(|listed| listed == account)
        });
        if listed { KeyringProbe::ItemPresent } else { KeyringProbe::NoItem }
    }

    /// Whether any listed `Codex Auth` entry has no account column, so an item
    /// can only be matched by service name.
    fn coarse(&self) -> bool {
        self.codex_auth.as_ref().is_some_and(|entries| {
            entries
                .iter()
                .any(|entry| entry.service == home::KEYRING_SERVICE && entry.account.is_none())
        })
    }
}

/// Builds the report. The whole command apart from rendering it.
///
/// # Errors
///
/// [`AppError`] when the Codex tree exists and cannot be listed.
pub fn build(
    paths: &Paths,
    accounts: &[CodexAccountRecord],
    env: &EnvView,
    listings: &Listings,
    cancel: &Cancel,
) -> Result<CodexDoctorReport, AppError> {
    let resolved = home::codex_home(&env.codex);
    let home_dir = resolved.as_ref().ok().cloned();
    let store = store_section(home_dir.as_deref(), listings);
    let live = live_section(home_dir.as_deref(), &store.read, accounts, paths, cancel);
    let namespaces = namespace_sections(paths, accounts, cancel);
    let orphans = orphan_entries(paths, accounts)?;
    // A log that cannot be read explains nothing, so it explains no keychain
    // item either: the failure costs removal commands, never adds one. The
    // reader still sees the log's own error in the `audit` section.
    let caused = audit::gained_keychain_accounts(paths).unwrap_or_default();

    Ok(CodexDoctorReport {
        version: VERSION,
        home: HomeSection {
            path: home_dir.as_ref().map(|dir| dir.display().to_string()),
            symlink_chain: home_dir.as_deref().map(symlink_chain).unwrap_or_default(),
            error: resolved.err().map(|err| err.to_string()),
        },
        store,
        environment: REPORTED_ENV
            .into_iter()
            .map(|name| EnvVar { name, present: env.set.contains(&name) })
            .collect(),
        live,
        foreign: foreign_section(home_dir.as_deref(), listings, &caused),
        namespaces,
        orphans,
        audit: audit_lines(paths),
        notes: Vec::new(),
    })
}

/// The symbolic links walked to reach `dir`, outermost first.
///
/// Each hop is `<link> -> <target>`, both of them paths — a link's target is
/// not file content in the sense invariant I24 guards, and a home reached
/// through a link is exactly what a reader needs to see.
fn symlink_chain(dir: &Path) -> Vec<String> {
    let mut chain = Vec::new();
    let mut prefix = PathBuf::new();
    for component in dir.components() {
        prefix.push(component);
        let Ok(meta) = fs::symlink_metadata(&prefix) else { continue };
        if !meta.file_type().is_symlink() {
            continue;
        }
        if let Ok(target) = fs::read_link(&prefix) {
            chain.push(format!("{} -> {}", prefix.display(), target.display()));
        }
    }
    chain
}

/// Where this home keeps its credentials, and whether agctl reads them.
fn store_section(home_dir: Option<&Path>, listings: &Listings) -> StoreSection {
    let Some(dir) = home_dir else {
        return StoreSection {
            mode: "file".to_owned(),
            read: "not read".to_owned(),
            coarse_match: false,
            profiles_consulted: false,
            base_url: None,
            config_note: None,
        };
    };
    let (mode, note) = home::store_mode(dir);
    let effect = home::file_in_effect(&mode, || listings.probe(dir));
    let read = match &effect {
        FileInEffect::Read { note: Some(note) } => (*note).to_owned(),
        FileInEffect::Read { note: None } => "file".to_owned(),
        FileInEffect::NotRead(_) => "not read".to_owned(),
    };
    StoreSection {
        mode: mode_word(&mode).to_owned(),
        read,
        coarse_match: matches!(mode, StoreMode::Auto) && listings.coarse(),
        profiles_consulted: false,
        base_url: home::base_url(dir),
        config_note: note.map(config_note),
    }
}

/// The store mode as a word this build compiled in.
///
/// A mode this build does not know is `unknown`: its spelling came out of
/// `config.toml` and is never echoed.
fn mode_word(mode: &StoreMode) -> &'static str {
    match mode {
        StoreMode::File => "file",
        StoreMode::Keyring => "keyring",
        StoreMode::Auto => "auto",
        StoreMode::Ephemeral => "ephemeral",
        StoreMode::Unknown(_) => "unknown",
    }
}

/// What was wrong with `config.toml`: the line number, never the line
/// (invariant I31, plan AC116).
fn config_note(note: ConfigNote) -> String {
    match note {
        ConfigNote::Unparseable { line: Some(line) } => {
            format!("unparseable config.toml (line {line})")
        }
        ConfigNote::Unparseable { line: None } => "unparseable config.toml".to_owned(),
        ConfigNote::Unreadable => "config.toml could not be read".to_owned(),
    }
}

/// The live home's credential file, read only when the store mode says it is
/// the one in effect.
fn live_section(
    home_dir: Option<&Path>,
    read: &str,
    accounts: &[CodexAccountRecord],
    paths: &Paths,
    cancel: &Cancel,
) -> LiveSection {
    let empty = LiveSection {
        state: "no home",
        auth_mode: None,
        mode_bits: None,
        mode_warning: None,
        size: None,
        access_expiry: None,
        last_refresh: None,
        matches_namespace: None,
        daemon: "none",
        missing_known_members: Vec::new(),
        unknown_member_count: 0,
    };
    let Some(dir) = home_dir else { return empty };
    let daemon = daemon_word(home::daemon_evidence(dir, cancel));
    if read == "not read" {
        return LiveSection { state: "not read", daemon, ..empty };
    }

    let path = dir.join(auth_store::shown_name());
    let (mode_bits, mode_warning, size) = file_facts(&path);
    let (state, credentials) = match auth_store::read_live(dir) {
        CodexResolved::Credentials(credentials) => ("credentials", Some(credentials)),
        CodexResolved::Absent => ("absent", None),
        CodexResolved::Torn => ("torn", None),
        CodexResolved::Transient(_) => ("unusable", None),
    };
    let now = Timestamp::now();
    LiveSection {
        state,
        auth_mode: credentials.as_ref().map(|found| auth_mode_word(found.auth_mode())),
        mode_bits,
        mode_warning,
        size,
        access_expiry: credentials
            .as_ref()
            .and_then(|found| found.access_expires_at())
            .and_then(|at| Timestamp::from_second(at).ok())
            .map(|at| relative(at, now)),
        last_refresh: credentials
            .as_ref()
            .and_then(|found| found.last_refresh())
            .map(|at| relative(at, now)),
        matches_namespace: credentials
            .as_ref()
            .and_then(|found| same_grant(found, accounts, paths)),
        daemon,
        missing_known_members: credentials
            .as_ref()
            .map(|found| found.missing_known_members())
            .unwrap_or_default(),
        unknown_member_count: credentials.as_ref().map_or(0, |found| found.unknown_member_count()),
    }
}

/// The permission bits, the warning when they are not 0600, and the size.
fn file_facts(path: &Path) -> (Option<String>, Option<String>, Option<u64>) {
    use std::os::unix::fs::MetadataExt;

    let Ok(meta) = fs::symlink_metadata(path) else { return (None, None, None) };
    let bits = meta.mode() & 0o7777;
    let warning = (bits != REQUIRED_MODE).then(|| {
        format!(
            "warning: `{}` is mode {bits:04o}; a credential file should be {REQUIRED_MODE:04o}",
            path.display()
        )
    });
    (Some(format!("{bits:04o}")), warning, Some(meta.size()))
}

/// The auth mode as a word this build compiled in.
fn auth_mode_word(mode: &AuthMode) -> &'static str {
    match mode {
        AuthMode::ApiKey => "apikey",
        AuthMode::ChatGpt => "chatgpt",
        AuthMode::ChatGptAuthTokens => "chatgptauthtokens",
        AuthMode::Headers => "headers",
        AuthMode::AgentIdentity => "agentidentity",
        AuthMode::PersonalAccessToken => "personalaccesstoken",
        AuthMode::BedrockApiKey => "bedrockapikey",
        AuthMode::BedrockAccessKeys => "bedrockaccesskeys",
        AuthMode::Unknown(_) => "unknown",
    }
}

/// The owned namespace holding the same grant as the live credential, by
/// refresh-digest equality (plan section 3.3 step 2's fold).
fn same_grant(
    live: &Credentials,
    accounts: &[CodexAccountRecord],
    paths: &Paths,
) -> Option<String> {
    let digest = live.refresh_digest8()?;
    accounts.iter().filter_map(proof::owned).find_map(|owned| {
        let dir = paths.codex_namespace_dir(owned.user(), owned.acct()).ok()?;
        let CodexResolved::Credentials(found) = auth_store::read_live(&dir) else { return None };
        (found.refresh_digest8()? == digest).then(|| format!("{}+{}", owned.user(), owned.acct()))
    })
}

/// What the home says about a Codex daemon using it.
fn daemon_word(evidence: DaemonEvidence) -> &'static str {
    match evidence {
        DaemonEvidence::None => "none",
        DaemonEvidence::PidAlive(_) => "a daemon is running",
        DaemonEvidence::Recycled(_) => "a recycled process id, not the daemon",
        DaemonEvidence::ArtefactOnly => "artefacts only",
        DaemonEvidence::RecordUnreadable => "a daemon record cannot be read",
    }
}

/// The Codex credentials on this machine that are not agctl's.
///
/// `caused` are the accounts agctl's own write log records a refused login
/// child as having gained ([`audit::gained_keychain_accounts`]).
///
/// # Why only those get a removal command
///
/// A `Codex Auth` item whose account is not this home's is very often nothing
/// to do with agctl: it is how Codex stores the credential of **another** of
/// the user's Codex homes. Printing a paste-me `security
/// delete-generic-password` line for every one of them invites a person to
/// destroy a working login of theirs, which is the data loss the plan avoids
/// by scoping the command to "a `Codex Auth` keychain item agctl's login
/// child caused and refused (`listing gained` in the audit)" (plan §3.3,
/// ledger #186). An item agctl cannot show it caused is therefore only
/// counted, and the reader is told where to look.
fn foreign_section(
    home_dir: Option<&Path>,
    listings: &Listings,
    caused: &[String],
) -> ForeignSection {
    let multi_auth_present = home_dir.is_some_and(|dir| {
        fs::symlink_metadata(dir.join(MULTI_AUTH_DIR)).is_ok_and(|meta| meta.is_dir())
    });
    let entries = listings.codex_auth.as_deref().unwrap_or_default();
    let expected = home_dir.map(home::keyring_account);
    let foreign = entries
        .iter()
        .filter(|entry| entry.service == home::KEYRING_SERVICE)
        .filter_map(|entry| entry.account.as_deref())
        .filter(|account| expected.as_deref() != Some(account));

    let mut unexplained_removals = Vec::new();
    let mut unexplained_items = 0usize;
    let mut unnameable_items = 0usize;
    for account in foreign {
        // Both halves, in this order: the spelling check decides whether the
        // string may be rendered at all, the log decides whether agctl may
        // claim it. A string the log names but the check rejects is still
        // never printed.
        if !is_home_account(account) {
            unnameable_items += 1;
        } else if caused.iter().any(|caused| caused == account) {
            unexplained_removals.push(format!(
                "security delete-generic-password -s \"{}\" -a \"{account}\"",
                home::KEYRING_SERVICE
            ));
        } else {
            unexplained_items += 1;
        }
    }

    ForeignSection {
        multi_auth_present,
        switcher_items: listings.switcher.unwrap_or(0),
        codex_auth_items: entries.len(),
        unexplained_removals,
        unexplained_items,
        unnameable_items,
    }
}

/// One section per owned namespace, in registry order.
fn namespace_sections(
    paths: &Paths,
    accounts: &[CodexAccountRecord],
    cancel: &Cancel,
) -> Vec<NamespaceSection> {
    accounts
        .iter()
        .filter_map(|record| Some((record, proof::owned(record)?)))
        .filter_map(|(record, owned)| {
            let dir = paths.codex_namespace_dir(owned.user(), owned.acct()).ok()?;
            let (artefacts, credentials_present) = artefacts(&dir);
            let marker = marker_section(paths, owned.user(), owned.acct());
            let mut notes = Vec::new();
            if artefacts.iter().any(|line| line.starts_with("stray tmp")) {
                notes.push(
                    "`accounts refresh --resend` is refused while a stray temporary file is there"
                        .to_owned(),
                );
            }
            Some(NamespaceSection {
                user: owned.user().to_owned(),
                acct: owned.acct().to_owned(),
                path: dir.display().to_string(),
                credentials_present,
                refresh_policy: policy_word(&record.kind),
                lock: lock_section(paths, owned.user(), owned.acct(), cancel),
                artefacts,
                marker,
                notes,
            })
        })
        .collect()
}

/// The record's refresh policy as a word.
fn policy_word(kind: &CodexKind) -> &'static str {
    match kind {
        CodexKind::Owned { refresh: RefreshPolicy::Never, .. } => "never",
        _ => "auto",
    }
}

/// What a namespace directory holds besides its credential, by kind, and
/// whether the credential itself is there.
///
/// Read-only: the directory is listed, never opened for write and never
/// created. A name found here is classified into one of this build's own
/// sentences and never printed back (invariant I24).
fn artefacts(dir: &Path) -> (Vec<String>, bool) {
    let mut lines = Vec::new();
    let mut credentials_present = false;
    let mut stray_tmp = 0usize;
    let mut session = 0usize;

    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return (lines, false),
        Err(err) => {
            lines.push(format!("the namespace directory could not be listed: {}", err.kind()));
            return (lines, false);
        }
    };
    // The four names agctl's own writers use, derived from the one place the
    // credential file is named (`auth_store::shown_name`), so this file holds
    // no second spelling of it (invariant I23, `scripts/phase3-greps.sh`).
    let credentials = auth_store::shown_name();
    let pending = format!("{credentials}.pending");
    let staged = format!("{credentials}.tmp.");
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name == credentials {
            credentials_present = true;
        } else if name == pending {
            lines.push("a parked pending write is there".to_owned());
        } else if name == PENDING_META {
            // The pending write's own metadata, not an artefact of its own.
        } else if name.starts_with(&staged) {
            // A `Complete` write whose process exited between the create and
            // the rename leaves one of these.
            stray_tmp += 1;
        } else {
            session += 1;
        }
    }
    if stray_tmp > 0 {
        lines.push(format!("stray tmp (rotated grant?): {stray_tmp} file(s)"));
    }
    if session > 0 {
        lines.push(format!("codex session artefacts present: {session} entry(s)"));
    }
    lines.sort();
    (lines, credentials_present)
}

/// Who holds agctl's own lock for this namespace, when anybody does.
fn lock_section(paths: &Paths, user: &str, acct: &str, cancel: &Cancel) -> Option<LockSection> {
    let path = paths.codex_lock_path(user, acct).ok()?;
    let body = namespace_lock::read_body(&path)?;
    // A recycled process id is the failure this comparison exists for: the pid
    // may be in use again by something unrelated, and naming it as the holder
    // sends a user after the wrong process.
    let recycled = body
        .pid_start_time
        .as_ref()
        .is_some_and(|recorded| proc::start_time(body.pid, cancel).as_ref() != Some(recorded));
    let holder = if recycled {
        "dead (pid recycled)"
    } else if proc::holder(body.pid, cancel) == proc::Holder::Dead {
        "dead (holder gone)"
    } else {
        "held"
    };
    Some(LockSection { pid: body.pid, acquired_at: body.acquired_at, holder })
}

/// One namespace's refresh marker, read without opening the namespace.
fn marker_section(paths: &Paths, user: &str, acct: &str) -> MarkerSection {
    let absent = MarkerSection {
        state: "absent",
        unavailable: None,
        inflight_digest8: None,
        inflight_age: None,
        class: None,
        floor_min: None,
        did_not_help: None,
        resent: None,
        ambiguous_since: None,
        resend_eligible: None,
    };
    let file = match RefreshStateFile::new(paths, user, acct) {
        Ok(file) => file,
        Err(err) => {
            return MarkerSection {
                state: "unavailable",
                unavailable: Some(err.to_string()),
                ..absent
            };
        }
    };
    match file.load() {
        RefreshStateRead::Absent => absent,
        RefreshStateRead::Unavailable(reason) => {
            MarkerSection { state: "unavailable", unavailable: Some(reason), ..absent }
        }
        RefreshStateRead::Present(state) => present_marker(&state),
    }
}

/// A marker that is there, field by field.
fn present_marker(state: &RefreshState) -> MarkerSection {
    let now = Timestamp::now();
    let resend_eligible = state.ambiguous_since.and_then(|since| {
        let class = state.class?;
        Some(!state.resent && refresh::resend_eligible_at(since, class, state.retry_after) <= now)
    });
    MarkerSection {
        state: "present",
        unavailable: None,
        inflight_digest8: state.inflight.as_ref().map(|flight| flight.sent_digest8.clone()),
        inflight_age: state.inflight.as_ref().map(|flight| elapsed(flight.sent_at, now)),
        class: state.class.map(auth_store::UnknownClass::label),
        floor_min: Some(state.floor_min),
        did_not_help: Some(state.did_not_help),
        resent: Some(state.resent),
        ambiguous_since: state.ambiguous_since.map(|since| elapsed(since, now)),
        resend_eligible,
    }
}

/// Everything under the Codex tree that no record explains.
fn orphan_entries(
    paths: &Paths,
    accounts: &[CodexAccountRecord],
) -> Result<Vec<OrphanEntry>, AppError> {
    let found = discovery::orphans(paths, accounts, SystemTime::now())
        .map_err(|err| AppError::Config(format!("the Codex tree could not be listed: {err}")))?;
    Ok(found
        .into_iter()
        .map(|orphan| match orphan {
            Orphan::NamespaceWithoutRecord { user, acct } => OrphanEntry {
                kind: "namespace without record".to_owned(),
                subject: format!("{user}+{acct}"),
                age: None,
            },
            Orphan::RecordWithoutCredentials { user, acct } => OrphanEntry {
                kind: format!("record without {}", auth_store::shown_name()),
                subject: format!("{user}+{acct}"),
                age: None,
            },
            Orphan::StaleScratch { name, age } => OrphanEntry {
                kind: "stale scratch".to_owned(),
                subject: name,
                age: Some(words(age)),
            },
        })
        .collect())
}

/// The write log's last [`AUDIT_LINES`] lines, oldest first.
///
/// A log that cannot be read is one line saying so, not a refusal: the log is
/// one of the things being diagnosed.
fn audit_lines(paths: &Paths) -> Vec<String> {
    match audit::read(paths) {
        Ok(None) => Vec::new(),
        Ok(Some(text)) => {
            let lines: Vec<&str> = text.lines().filter(|line| !line.trim().is_empty()).collect();
            lines
                .iter()
                .skip(lines.len().saturating_sub(AUDIT_LINES))
                .map(|line| (*line).to_owned())
                .collect()
        }
        Err(err) => vec![format!("the Codex write log could not be read: {err}")],
    }
}

/// A timestamp as `expired 3m ago` or `in 2h13m`.
fn relative(at: Timestamp, now: Timestamp) -> String {
    if at <= now {
        format!("expired {} ago", crate::usage::model::render_countdown(at, now))
    } else {
        format!("in {}", crate::usage::model::render_countdown(now, at))
    }
}

/// How long ago `at` was.
fn elapsed(at: Timestamp, now: Timestamp) -> String {
    crate::usage::model::render_countdown(at.min(now), now)
}

/// A duration in the same words the countdown uses.
fn words(age: Duration) -> String {
    let now = Timestamp::now();
    let then = jiff::SignedDuration::try_from(age)
        .ok()
        .and_then(|age| now.checked_sub(age).ok())
        .unwrap_or(now);
    crate::usage::model::render_countdown(then, now)
}

#[cfg(test)]
#[path = "doctor_tests.rs"]
mod tests;
