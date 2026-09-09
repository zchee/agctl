//! Tests for the `use` dispatch: the S22/S16 refusals and the id
//! requirement. The successful launch path is exercised at the `export`
//! unit-test and e2e layers, which is where a controllable `PATH` lives —
//! `run` resolves `claude` through the *process's own* `PATH`, which a unit
//! test cannot safely override (`std::env::set_var` is `unsafe` in this
//! edition and would race every other test in the binary).

use super::*;
use crate::runtime::coordinator::Cancel;

fn args(id: Option<&str>) -> UseArgs {
    UseArgs {
        id: id.map(str::to_owned),
        live: false,
        new_only: false,
        undo: false,
        forget: None,
        claude_config_dir: None,
        fresh_context: false,
        no_mcp: false,
        yes: false,
        json: false,
    }
}

#[test]
fn refuses_live_as_not_implemented() {
    let mut a = args(Some("someone"));
    a.live = true;
    let err = run(None, &a, &Cancel::new()).expect_err("--live is not implemented yet");
    assert!(err.to_string().contains("--live"), "{err}");
}

#[test]
fn refuses_undo_as_not_implemented() {
    let mut a = args(None);
    a.undo = true;
    let err = run(None, &a, &Cancel::new()).expect_err("--undo is not implemented yet");
    assert!(err.to_string().contains("--undo"), "{err}");
}

#[test]
fn refuses_forget_as_not_implemented() {
    let mut a = args(None);
    a.forget = Some("someone".to_owned());
    let err = run(None, &a, &Cancel::new()).expect_err("--forget is not implemented yet");
    assert!(err.to_string().contains("--forget"), "{err}");
}

#[test]
fn requires_an_id_without_undo_or_forget() {
    let a = args(None);
    let err = run(None, &a, &Cancel::new())
        .expect_err("no id and neither --undo nor --forget is refused");
    assert!(matches!(err, AppError::Config(_)));
}

#[test]
fn accepts_new_only_as_an_inert_synonym() {
    // `--new-only` alone still requires an id (it changes nothing about the
    // id requirement); this proves the field is read rather than rejected by
    // some accidental exhaustiveness check, without needing a `claude` on
    // `PATH`.
    let mut a = args(None);
    a.new_only = true;
    let err = run(None, &a, &Cancel::new()).expect_err("an id is still required");
    assert!(matches!(err, AppError::Config(_)));
}
