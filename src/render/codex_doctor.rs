//! The `agctl codex doctor` report: what it holds, and how it reads.
//!
//! The report is built in [`commands::codex::doctor`](crate::commands::codex::doctor)
//! and rendered here, in the two shapes plan section 3.2 names — a table for a
//! person and a version-1 document for a program, validated against
//! `schemas/codex-doctor.v1.json`.
//!
//! # Nothing here came out of a credential file
//!
//! Every string this module renders is one of four things: an identifier agctl
//! validated (a namespace segment, a `cli|<16 hex>` keychain account), a path
//! agctl derived, a fixed word this crate compiled in, or a number — a count,
//! a size, a mode, an age. No member name, no configuration value and no line
//! of `config.toml` reaches a field, because "sanitized" cannot tell a
//! token-shaped key from a field name (invariant I24, invariant I31, plan
//! AC116). Where the plan asks for a comparison against a file's shape — the
//! fact F61 field set, premortem PM22 — the report carries the **missing**
//! names, which come from this crate's own list, and a **count** of the rest.
//!
//! An email address and a plan type are the two exceptions, and they are not
//! exceptions to that rule: both are allowlisted claims (invariant I24), and
//! both are already on every `agctl codex status` row.

use serde::Serialize;

/// The version this build emits, and the only one
/// `schemas/codex-doctor.v1.json` accepts.
pub const VERSION: u32 = 1;

/// The one-line warning that removing the marker directory re-arms a send
/// (risk R68).
///
/// The directory is named by role rather than by path: the marker's path is
/// spelled in `config/paths.rs` and `provider/codex/auth_store.rs` and nowhere
/// else (`scripts/phase3-greps.sh`, rule `state_path`), and a renderer that
/// repeated it would be a second spelling to keep in step. A reader who needs
/// the path has it: an unreadable marker is reported with it.
pub const STATE_WARNING: &str = "removing agctl's Codex refresh-marker directory re-arms one refresh send per \
     namespace; agctl cannot tell a deleted marker from a refresh that was never \
     sent";

/// The whole report.
#[derive(Debug, Clone, Serialize)]
pub struct CodexDoctorReport {
    /// The report version. A consumer must refuse one it does not know.
    pub version: u32,
    /// The Codex home this machine resolves to.
    pub home: HomeSection,
    /// What that home says about where its credentials are kept.
    pub store: StoreSection,
    /// The Codex variables set in agctl's own environment, presence only.
    pub environment: Vec<EnvVar>,
    /// What the live home's credential file is.
    pub live: LiveSection,
    /// What else on this machine holds Codex credentials.
    pub foreign: ForeignSection,
    /// One entry per owned namespace, in registry order.
    pub namespaces: Vec<NamespaceSection>,
    /// What agctl's own tree holds that no record explains.
    pub orphans: Vec<OrphanEntry>,
    /// How many further entries it holds under a name agctl would not have
    /// written.
    ///
    /// A **count**: an entry's name is a directory name read off disk, and
    /// anything running as the user can create one, escape bytes and all
    /// (review S35 C3).
    pub unnameable_orphans: usize,
    /// The audit log's last lines, oldest first.
    pub audit: Vec<String>,
    /// Sentences that belong to the report as a whole.
    pub notes: Vec<String>,
}

/// The resolved Codex home and how it was reached.
#[derive(Debug, Clone, Serialize)]
pub struct HomeSection {
    /// The resolved home, absent when it could not be resolved.
    pub path: Option<String>,
    /// The symbolic links walked to reach it, in order; empty when there are
    /// none. Each entry is `<link> -> <target>`.
    pub symlink_chain: Vec<String>,
    /// Why the home could not be resolved (fact F86's sentence).
    pub error: Option<String>,
}

/// Where the home keeps its credentials, and whether agctl reads them.
#[derive(Debug, Clone, Serialize)]
pub struct StoreSection {
    /// The mode `config.toml` configures: `file`, `keyring`, `auto`,
    /// `ephemeral`, or `unknown` for a value this build does not know —
    /// the value itself is file content and is never rendered.
    pub mode: String,
    /// What agctl does about it: `file`, `auto (file in effect)`, or
    /// `not read`.
    pub read: String,
    /// Whether the keychain listing had no account column, so a `Codex Auth`
    /// item could only be matched by service name (plan section 3.3).
    pub coarse_match: bool,
    /// Always false: a profile cannot set the store key (fact F84), so
    /// `doctor` says out loud that none was consulted.
    pub profiles_consulted: bool,
    /// `chatgpt_base_url`, when it is a plain URL carrying no credential.
    pub base_url: Option<String>,
    /// What was wrong with `config.toml`: the line number only, never its
    /// text (invariant I31, plan AC116).
    pub config_note: Option<String>,
}

/// One environment variable agctl's own process carries.
#[derive(Debug, Clone, Serialize)]
pub struct EnvVar {
    /// The variable's name.
    pub name: &'static str,
    /// Whether it is set. **Never its value.**
    pub present: bool,
}

/// The live home's credential file.
#[derive(Debug, Clone, Serialize)]
pub struct LiveSection {
    /// `credentials`, `absent`, `torn`, `unusable`, or `not read`.
    pub state: &'static str,
    /// The authentication mode, or `unknown` for one this build does not
    /// know.
    pub auth_mode: Option<&'static str>,
    /// The file's permission bits, as four octal digits.
    pub mode_bits: Option<String>,
    /// Set when the bits are not 0600.
    pub mode_warning: Option<String>,
    /// The file's size in bytes.
    pub size: Option<u64>,
    /// The access token's expiry as a relative time.
    pub access_expiry: Option<String>,
    /// `last_refresh` as a relative time.
    pub last_refresh: Option<String>,
    /// The owned namespace whose credential is the same grant, as
    /// `<user>+<acct>`.
    pub matches_namespace: Option<String>,
    /// What the home says about a Codex daemon using it.
    pub daemon: &'static str,
    /// Members of fact F61's field set the document does not have.
    pub missing_known_members: Vec<&'static str>,
    /// How many members it has that are not in that set. A **count**: the
    /// names are file content (premortem PM22).
    pub unknown_member_count: usize,
}

/// Codex credentials on this machine that are not agctl's and are never read.
#[derive(Debug, Clone, Serialize)]
pub struct ForeignSection {
    /// Whether the live home has a `multi-auth/` directory (open question
    /// U32). Its contents are never listed and never read.
    pub multi_auth_present: bool,
    /// How many `codex-switcher:` keychain items are listed. **A count**: a
    /// switcher item's account names a person.
    pub switcher_items: usize,
    /// How many `Codex Auth` keychain items are listed.
    pub codex_auth_items: usize,
    /// The removal command for each listed `Codex Auth` item that agctl's own
    /// write log records a refused login child as having gained, so an item
    /// agctl caused can be cleaned up by hand. Empty when the listing could
    /// not be taken, and empty when the log could not be read.
    pub unexplained_removals: Vec<String>,
    /// How many further `Codex Auth` items are listed under an account that
    /// is spelled the way Codex spells one but that agctl's write log does
    /// not explain.
    ///
    /// A **count**, and never a command: such an item is most often the
    /// working credential of another Codex home of the user's, and a
    /// paste-me removal line for it would be an invitation to destroy a
    /// login (plan §3.3, ledger #186).
    pub unexplained_items: usize,
    /// How many further `Codex Auth` items are listed under an account agctl
    /// would not have written.
    ///
    /// A **count**: any application can create a `Codex Auth` item with any
    /// account string, and that string is never rendered — least of all into a
    /// command a reader would paste into a shell (review S35 C1).
    pub unnameable_items: usize,
}

/// One owned namespace.
#[derive(Debug, Clone, Serialize)]
pub struct NamespaceSection {
    /// The namespace's ChatGPT user id.
    pub user: String,
    /// The namespace's ChatGPT account id.
    pub acct: String,
    /// The namespace directory agctl derives from those two ids.
    pub path: String,
    /// Whether `auth.json` is there.
    pub credentials_present: bool,
    /// `auto` or `never`.
    pub refresh_policy: &'static str,
    /// Who holds the namespace lock, when anybody does.
    pub lock: Option<LockSection>,
    /// What else the directory holds: a parked pending write, a stray
    /// temporary file, Codex session artefacts.
    pub artefacts: Vec<String>,
    /// The refresh marker.
    pub marker: MarkerSection,
    /// Sentences about this namespace.
    pub notes: Vec<String>,
}

/// agctl's own namespace lock, as its body spells it.
#[derive(Debug, Clone, Serialize)]
pub struct LockSection {
    /// The holder's process id.
    pub pid: u32,
    /// When the lock was taken, RFC 3339.
    pub acquired_at: String,
    /// `held`, `dead (holder gone)` or `dead (pid recycled)`.
    pub holder: &'static str,
}

/// This namespace's refresh marker.
#[derive(Debug, Clone, Serialize)]
pub struct MarkerSection {
    /// `absent`, `present` or `unavailable`.
    pub state: &'static str,
    /// Why it could not be read, as `<path> (<reason>)`.
    pub unavailable: Option<String>,
    /// The digest prefix of the refresh token a send is outstanding for.
    pub inflight_digest8: Option<String>,
    /// How long that send has been outstanding.
    pub inflight_age: Option<String>,
    /// The class of an unknown outcome, including `interrupted`.
    pub class: Option<&'static str>,
    /// The 401 floor, in minutes.
    pub floor_min: Option<u32>,
    /// How many refreshes in a row did not lift a 401.
    pub did_not_help: Option<u8>,
    /// Whether the user's one re-send has been spent.
    pub resent: Option<bool>,
    /// How long an ambiguous outcome has been outstanding.
    pub ambiguous_since: Option<String>,
    /// Whether `accounts refresh <id> --resend` would be accepted now.
    pub resend_eligible: Option<bool>,
}

/// One thing agctl's own tree holds that no record explains.
#[derive(Debug, Clone, Serialize)]
pub struct OrphanEntry {
    /// `namespace without record`, `record without auth.json` or
    /// `stale scratch`.
    ///
    /// Owned rather than static only because the second one is built from
    /// `auth_store::shown_name()`, the one place the credential file is
    /// named. Every value is still this build's own words.
    pub kind: String,
    /// The directory name or `<user>+<acct>` pair it concerns.
    pub subject: String,
    /// How old a stale scratch directory is.
    pub age: Option<String>,
}

/// The report as a person reads it.
///
/// Sections in the order the plan lists them, each headed by its name and
/// indented by two spaces, so a section with nothing to say is one line
/// rather than a gap.
#[must_use]
pub fn render(report: &CodexDoctorReport) -> String {
    let mut out = String::new();
    home_section(&mut out, report);
    store_section(&mut out, report);
    environment_section(&mut out, report);
    live_section(&mut out, report);
    foreign_section(&mut out, report);
    namespaces_section(&mut out, report);
    orphans_section(&mut out, report);
    audit_section(&mut out, report);
    for note in &report.notes {
        push(&mut out, 0, note);
    }
    out
}

/// One line at `indent` levels of two spaces.
fn push(out: &mut String, indent: usize, line: &str) {
    for _ in 0..indent {
        out.push_str("  ");
    }
    out.push_str(line);
    out.push('\n');
}

fn home_section(out: &mut String, report: &CodexDoctorReport) {
    push(out, 0, "codex home");
    match (&report.home.path, &report.home.error) {
        (Some(path), _) => push(out, 1, path),
        (None, Some(error)) => push(out, 1, error),
        (None, None) => push(out, 1, "unresolved"),
    }
    for hop in &report.home.symlink_chain {
        push(out, 1, &format!("via {hop}"));
    }
}

fn store_section(out: &mut String, report: &CodexDoctorReport) {
    let store = &report.store;
    push(out, 0, "credential store");
    push(out, 1, &format!("mode {} ({})", store.mode, store.read));
    if store.coarse_match {
        push(out, 1, "coarse match: the keychain listing has no account column");
    }
    if !store.profiles_consulted {
        push(out, 1, "profiles not consulted");
    }
    if let Some(url) = &store.base_url {
        push(out, 1, &format!("chatgpt_base_url {url}"));
    }
    if let Some(note) = &store.config_note {
        push(out, 1, note);
    }
}

fn environment_section(out: &mut String, report: &CodexDoctorReport) {
    push(out, 0, "environment");
    for var in &report.environment {
        let state = if var.present { "present" } else { "unset" };
        push(out, 1, &format!("{} {state}", var.name));
    }
    if report.environment.iter().any(|var| var.present) {
        push(out, 1, "a Codex session started with these may not be using the row above");
    }
}

fn live_section(out: &mut String, report: &CodexDoctorReport) {
    let live = &report.live;
    push(out, 0, "live credential");
    push(out, 1, live.state);
    if let Some(mode) = live.auth_mode {
        push(out, 1, &format!("auth_mode {mode}"));
    }
    if let (Some(bits), Some(size)) = (&live.mode_bits, live.size) {
        push(out, 1, &format!("mode {bits}, {size} bytes"));
    }
    if let Some(warning) = &live.mode_warning {
        push(out, 1, warning);
    }
    if let Some(expiry) = &live.access_expiry {
        push(out, 1, &format!("access token {expiry}"));
    }
    if let Some(last) = &live.last_refresh {
        push(out, 1, &format!("last refresh {last}"));
    }
    if let Some(namespace) = &live.matches_namespace {
        push(out, 1, &format!("the same grant as the owned namespace {namespace}"));
    }
    push(out, 1, &format!("daemon evidence: {}", live.daemon));
    if !live.missing_known_members.is_empty() {
        push(out, 1, &format!("fields absent: {}", live.missing_known_members.join(", ")));
    }
    if live.unknown_member_count > 0 {
        push(
            out,
            1,
            &format!(
                "{} field(s) this build does not know; a Codex upgrade may have added them",
                live.unknown_member_count
            ),
        );
    }
}

fn foreign_section(out: &mut String, report: &CodexDoctorReport) {
    let foreign = &report.foreign;
    push(out, 0, "other credentials on this machine (never read)");
    push(out, 1, &format!("`multi-auth/` {}", present_or_not(foreign.multi_auth_present)));
    push(out, 1, &format!("codex-switcher keychain items: {}", foreign.switcher_items));
    push(out, 1, &format!("`Codex Auth` keychain items: {}", foreign.codex_auth_items));
    for command in &foreign.unexplained_removals {
        push(out, 1, &format!("left by a refused agctl login; remove it yourself with: {command}"));
    }
    if foreign.unexplained_items > 0 {
        push(
            out,
            1,
            &format!(
                "{} further `Codex Auth` item(s) are not this home's and are not agctl's doing; \
                 one of them is likely another Codex home of yours, so agctl offers no removal \
                 command for it",
                foreign.unexplained_items
            ),
        );
    }
    if foreign.unnameable_items > 0 {
        push(
            out,
            1,
            &format!(
                "{} further `Codex Auth` item(s) are listed under an account agctl would not \
                 have written; open Keychain Access and look at them yourself — agctl will not \
                 print an account string it did not make",
                foreign.unnameable_items
            ),
        );
    }
}

fn present_or_not(present: bool) -> &'static str {
    if present { "present" } else { "absent" }
}

fn namespaces_section(out: &mut String, report: &CodexDoctorReport) {
    push(out, 0, "owned namespaces");
    if report.namespaces.is_empty() {
        push(out, 1, "none");
        return;
    }
    for namespace in &report.namespaces {
        push(out, 1, &format!("{}+{}", namespace.user, namespace.acct));
        push(out, 2, &namespace.path);
        push(
            out,
            2,
            &format!(
                "credentials {}, refresh {}",
                present_or_not(namespace.credentials_present),
                namespace.refresh_policy
            ),
        );
        if let Some(lock) = &namespace.lock {
            push(
                out,
                2,
                &format!("lock: pid {} since {}, {}", lock.pid, lock.acquired_at, lock.holder),
            );
        }
        for artefact in &namespace.artefacts {
            push(out, 2, artefact);
        }
        marker_lines(out, &namespace.marker);
        for note in &namespace.notes {
            push(out, 2, note);
        }
    }
    push(out, 1, STATE_WARNING);
}

fn marker_lines(out: &mut String, marker: &MarkerSection) {
    match marker.state {
        "absent" => push(out, 2, "refresh marker: none"),
        "unavailable" => push(
            out,
            2,
            &format!(
                "refresh state unavailable: {}",
                marker.unavailable.as_deref().unwrap_or("the marker could not be read")
            ),
        ),
        _ => push(out, 2, "refresh marker:"),
    }
    if let (Some(digest8), Some(age)) = (&marker.inflight_digest8, &marker.inflight_age) {
        push(out, 3, &format!("send outstanding for {digest8}, {age} ago"));
    }
    if let Some(class) = marker.class {
        push(out, 3, &format!("class {class}"));
    }
    if let Some(since) = &marker.ambiguous_since {
        push(out, 3, &format!("ambiguous refresh outstanding since {since}"));
    }
    if let Some(floor) = marker.floor_min {
        push(out, 3, &format!("401 floor {floor} min"));
    }
    if let Some(count) = marker.did_not_help {
        push(out, 3, &format!("refresh did not help {count} time(s)"));
    }
    if let Some(resent) = marker.resent {
        push(out, 3, &format!("re-send spent: {resent}"));
    }
    if marker.resend_eligible == Some(true) {
        push(out, 3, "--resend eligible");
    }
}

fn orphans_section(out: &mut String, report: &CodexDoctorReport) {
    push(out, 0, "left behind");
    if report.orphans.is_empty() && report.unnameable_orphans == 0 {
        push(out, 1, "nothing");
        return;
    }
    for orphan in &report.orphans {
        match &orphan.age {
            Some(age) => push(out, 1, &format!("{} ({}, {age})", orphan.kind, orphan.subject)),
            None => push(out, 1, &format!("{} ({})", orphan.kind, orphan.subject)),
        }
    }
    if report.unnameable_orphans > 0 {
        push(
            out,
            1,
            &format!(
                "{} further entr(y/ies) are named in a way agctl would not have written; list \
                 the Codex directory yourself — agctl will not print a name it did not make",
                report.unnameable_orphans
            ),
        );
    }
}

fn audit_section(out: &mut String, report: &CodexDoctorReport) {
    push(out, 0, "write log");
    if report.audit.is_empty() {
        push(out, 1, "no Codex write has been recorded");
        return;
    }
    for line in &report.audit {
        push(out, 1, line);
    }
}

/// The published schema, compiled into the test binary.
#[cfg(test)]
pub const SCHEMA: &str = include_str!("../../schemas/codex-doctor.v1.json");

/// Validates a [`CodexDoctorReport`] against [`SCHEMA`], naming every failure.
///
/// A sibling of `json::assert_valid_doctor` rather than a case it grows into:
/// that one is normatively scoped to `schemas/doctor.v1.json`, which plan AC98
/// pins unmodified.
///
/// # Panics
///
/// Panics when the document does not validate, which is the assertion.
#[cfg(test)]
pub fn assert_valid(report: &CodexDoctorReport) {
    let schema: serde_json::Value =
        serde_json::from_str(SCHEMA).expect("the published Codex doctor schema is valid JSON");
    let validator =
        jsonschema::validator_for(&schema).expect("the published Codex doctor schema compiles");
    let instance = serde_json::to_value(report).expect("a Codex doctor report serializes");

    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|err| format!("{}: {err}", err.instance_path()))
        .collect();
    assert!(
        errors.is_empty(),
        "the emitted document does not match schemas/codex-doctor.v1.json:\n{}\n\ndocument:\n{}",
        errors.join("\n"),
        serde_json::to_string_pretty(&instance).unwrap_or_default()
    );
}

#[cfg(test)]
#[path = "codex_doctor_tests.rs"]
mod tests;
