//! OpenAI's Codex CLI: its credential file, its home directory, and the
//! types that decide which of agctl's writes may touch either.
//!
//! Phase 3 (plan section 3.1). The modules follow the data:
//!
//! - [`home`] resolves `CODEX_HOME` from an injected environment and reads the
//!   two `config.toml` keys agctl needs — never the process environment, so a
//!   test cannot reach the developer's own Codex home (invariant I25).
//! - [`claims`] reads the id token's payload against an allowlist.
//! - [`credentials`] holds one `auth.json` as a document: every member it
//!   does not understand is kept where it was, every token is kept in a
//!   `SecretString`, and the module's private `exposed` is the second and last
//!   place in the crate a token's plaintext is taken out (invariant I20).
//! - [`proof`] holds the values that prove a write is allowed: an owned
//!   registry record, a verified login, a held namespace lock. Their fields
//!   are private and their constructors `pub(super)`, so nothing outside this
//!   module tree can forge one (invariant I22, plan AC119/AC122).
//! - [`lock`] takes a namespace lock and is the only producer of the lock
//!   proof.
//! - [`auth_store`] is the only module that opens an `auth.json`, and the
//!   only one that writes one: the three named writers, the refresh marker,
//!   and the receipts every write returns.
//! - [`account`] is the row vocabulary: states and credits.
//!
//! Nothing in this tree is reachable from a command before S33/S34; until
//! then every item is exercised by its sibling tests.

#![cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "the Codex commands that call this tree land at S31 (usage), S32 (refresh), \
                  S33 (status/watch) and S34 (login/import/accounts)"
    )
)]

pub mod account;
pub mod auth_store;
pub mod claims;
pub mod credentials;
pub mod home;
pub mod lock;
pub mod proof;
pub mod usage;

#[cfg(test)]
#[path = "testkit_tests.rs"]
mod testkit;

/// The environment variable that replaces
/// [`USER_AGENT_DEFAULT`](crate::provider::USER_AGENT_DEFAULT) for Codex.
///
/// Production-visible on purpose (plan section 3.2): if the vendor starts
/// refusing the honest agent, the user can supply its own client's without
/// waiting for a release. The Claude twin is
/// [`claude::USER_AGENT_ENV`](crate::provider::claude::USER_AGENT_ENV).
pub const USER_AGENT_ENV: &str = "AGCTL_CODEX_USER_AGENT";

/// The plan types this build knows by name (fact F63), as the wire spells
/// them.
///
/// Used to decide whether a claim's plan is shown as-is or as `unknown`; a
/// value outside this list is not an error, because the vendor adds tiers
/// without notice, but it is also not echoed verbatim into the registry.
pub const PLAN_TYPES: [&str; 22] = [
    "guest",
    "free",
    "go",
    "plus",
    "pro",
    "prolite",
    "free_workspace",
    "team",
    "self_serve_business_prolite",
    "self_serve_business_usage_based",
    "business",
    "ent26",
    "enterprise_cbp_automation",
    "enterprise_cbp_usage_based",
    "education",
    "quorum",
    "k12",
    "enterprise",
    "edu",
    "edu_plus",
    "edu_pro",
    "unknown",
];

/// Whether `plan` is one of [`PLAN_TYPES`].
pub fn is_known_plan(plan: &str) -> bool {
    PLAN_TYPES.contains(&plan)
}

#[cfg(test)]
#[path = "mod_tests.rs"]
mod tests;
