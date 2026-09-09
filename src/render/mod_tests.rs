use super::*;

fn ts() -> Timestamp {
    "2026-09-08T00:00:00Z".parse::<Timestamp>().expect("a valid RFC 3339 literal")
}

fn row(account: &str, visible: bool) -> StatusRow {
    StatusRow {
        account: account.to_owned(),
        org: "Acme".to_owned(),
        plan: "max".to_owned(),
        state: "ok".to_owned(),
        note: None,
        usage: None,
        visible_by_default: visible,
        same_identity_as_live: false,
        kind: "owned",
    }
}

/// A row with no numbers, in the given state.
fn empty_row(account: &str, state: &str) -> StatusRow {
    StatusRow {
        account: account.to_owned(),
        org: String::new(),
        plan: String::new(),
        state: state.to_owned(),
        note: None,
        usage: None,
        visible_by_default: true,
        same_identity_as_live: false,
        kind: "owned",
    }
}

#[test]
fn hidden_rows_are_counted_but_not_shown_by_default() {
    let report = Report {
        rows: vec![row("alice", true), row("sibling", false), row("switcher", false)],
        now: ts(),
        tz: TimeZone::UTC,
        show_all: false,
        by_identity: false,
    };

    let shown: Vec<&str> = report.shown().iter().map(|row| row.account.as_str()).collect();
    assert_eq!(shown, vec!["alice"]);
    assert_eq!(report.hidden_count(), 2);
}

#[test]
fn all_shows_every_row_and_reports_nothing_hidden() {
    // UTC because nothing here renders a reset; a fixed zone keeps the row
    // arithmetic under test independent of where the suite runs.
    let report = Report {
        rows: vec![row("alice", true), row("sibling", false)],
        now: ts(),
        tz: TimeZone::UTC,
        show_all: true,
        by_identity: false,
    };

    assert_eq!(report.shown().len(), 2);
    assert_eq!(report.hidden_count(), 0, "nothing is hidden once --all is given");
}

#[test]
fn a_note_is_appended_to_the_state_in_parentheses() {
    let mut row = row("alice", true);
    assert_eq!(row.state_cell(), "ok");

    row.note = Some("keychain service `Claude Code-credentials`".to_owned());
    assert_eq!(row.state_cell(), "ok (keychain service `Claude Code-credentials`)");

    row.note = Some(String::new());
    assert_eq!(row.state_cell(), "ok", "an empty note adds no empty parentheses");
}

#[test]
fn the_same_identity_note_joins_the_row_s_own_note_rather_than_replacing_it() {
    // `agentctl-p3-login-live-identity-warning-b90`: a row can be both in a
    // state that needs explaining and the live account's twin, and a reader
    // who is told only one of the two has been told the less useful half.
    let mut row = row("alice", true);
    assert_eq!(row.state_cell(), "ok");

    row.same_identity_as_live = true;
    assert_eq!(row.state_cell(), format!("ok ({SAME_IDENTITY_NOTE})"));

    row.note = Some("the stored credential is gone".to_owned());
    assert_eq!(
        row.state_cell(),
        format!("ok (the stored credential is gone; {SAME_IDENTITY_NOTE})"),
        "the row's own note comes first: it is about this row, the marker is about two"
    );

    row.same_identity_as_live = false;
    assert_eq!(
        row.state_cell(),
        "ok (the stored credential is gone)",
        "an unmarked row renders exactly as it did before the marker existed"
    );
}

#[test]
fn an_empty_row_carries_a_state_and_nothing_else() {
    let row = empty_row("alice", "needs login");
    assert_eq!(row.state_cell(), "needs login");
    assert!(row.usage.is_none());
    assert!(row.visible_by_default, "a row with no numbers is still the user's business");
}
