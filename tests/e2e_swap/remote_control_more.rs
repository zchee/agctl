use super::*;

#[test]
fn ac157_restart_preserves_existing_plan_and_outcome_members() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let plain =
        run_channel(&fixture, &["claude", "use", "--live", EMAIL_T, "--json"], true, |_, _| {
            Reply::No
        });
    assert_eq!(plain.output.code(), 20);
    let mut remaining = plain.output.stderr.as_str();
    let mut plain_documents = Vec::new();
    while let Some(at) = remaining.find("{\n") {
        let mut stream = serde_json::Deserializer::from_str(&remaining[at..]).into_iter::<Value>();
        plain_documents.push(stream.next().unwrap().unwrap());
        remaining = &remaining[at + stream.byte_offset()..];
    }
    let flagged = run(&fixture, &forward(), |_, _| Reply::No);
    assert_eq!(flagged.output.code(), 20);
    let flagged_documents: Vec<Value> = serde_json::Deserializer::from_str(&flagged.output.stdout)
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(plain_documents.len(), 2);
    assert_eq!(flagged_documents.len(), 2);
    assert_eq!(plain_documents[0], flagged_documents[0], "D7: plan keys and values are unchanged");
    let mut outcome = flagged_documents[1].clone();
    assert_counts(&outcome);
    outcome.as_object_mut().unwrap().remove("remote_control");
    assert_eq!(
        plain_documents[1], outcome,
        "D7: no unrelated outcome member changes under the flag"
    );
    assert!(calls(&fixture).is_empty());
}

#[test]
fn ac147_restart_is_opt_in_and_bulk_yes_is_a_parser_error() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let before = fixture.keychain_items();
    let config = fs::read(fixture.home().join(".claude.json")).unwrap();
    for mode in ["--live", "--undo"] {
        let output = fixture
            .raw()
            .args(["claude", "use", mode, "--restart-remote-control", "--yes", "--json"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(calls(&fixture).is_empty());
        assert_unchanged(&fixture, &before, &config);
    }
    let output = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes", "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(calls(&fixture).is_empty());
    assert!(
        outcome_doc(&String::from_utf8(output.stdout).unwrap()).get("remote_control").is_none()
    );
}

#[test]
fn ac147_restart_namespace_undo_types_nothing() {
    let server = MockServer::start();
    let (mut fixture, _) = two_accounts(&server, common::fresh_at());
    fixture.set("AGCTL_TMUX_BIN", fixture.scratch("must-not-execute").to_str().unwrap());
    let (code, stdout, stderr) = swap(&fixture, &["--json"]);
    assert_eq!(code, 0, "{stdout}{stderr}");
    let result = run(
        &fixture,
        &["claude", "use", "--undo", "--restart-remote-control", "--json"],
        |_, _| Reply::Yes,
    );
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert!(result.output.stderr.contains("does not act on a namespace target"));
    assert!(calls(&fixture).is_empty());
    assert_counts(&doc(&result));
}

#[test]
fn ac152_restart_13a_needs_refresh_has_no_tmux_call() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let token = token_ok(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::expired_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let service = common::migration_service(&fixture.ns_dir(ACCT_T, ORG_T));
    fixture.keychain_item(
        &service,
        &common::identified_blob(
            "sk-ant-oat01-incoming",
            "sk-ant-ort01-incoming",
            common::expired_at(),
            ACCT_T,
            Some(ORG_T),
        ),
    );
    let result = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(result.output.code(), 21, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["outcome"], "needs_refresh");
    assert!(calls(&fixture).is_empty());
    assert_eq!(token.calls(), 0);
}

#[test]
fn ac153_restart_rejects_a_live_background_group_on_the_same_real_pty() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::spawn(&fixture, 7, true);
    setup(&mut fixture, &[&session], &resolved);
    let result = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(result.output.code(), 30, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["remote_control"]["skipped"], 1);
    assert_eq!(sends(&fixture), 0);
    assert!(result.output.stderr.contains("not_in_foreground"));
}

#[test]
fn ac153_restart_two_pane_preflight_is_all_or_nothing() {
    for failure in ["second bad", "duplicate", "gone"] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let first = Session::new(&fixture, 7);
        let mut second = Session::new(&fixture, 8);
        setup(&mut fixture, &[&first, &second], &resolved);
        if failure == "second bad" {
            let mut document = second.document.clone();
            document["version"] = json!("2.1.0");
            second.save(&document);
        }
        if failure == "duplicate" {
            let mut document = second.document.clone();
            document["tmux"] = first.document["tmux"].clone();
            second.save(&document);
        }
        let result = run(&fixture, &forward(), |index, _| {
            if index == 0 && failure == "gone" {
                second.child.kill().unwrap();
                second.child.wait().unwrap();
                // The remaining session independently declines: the dead entry
                // must be gone, not a static skip or a restore target.
                Reply::Yes
            } else if failure == "gone" {
                Reply::No
            } else {
                Reply::Yes
            }
        });
        assert_eq!(result.output.code(), 30);
        assert_eq!(sends(&fixture), 0);
        let count = &doc(&result)["remote_control"];
        if failure == "gone" {
            assert_eq!(count["gone"], 1);
            assert_eq!(count["skipped"], 0);
        } else {
            assert_eq!(count["skipped"], if failure == "duplicate" { 2 } else { 1 });
        }
    }
}

#[test]
fn ac153_restart_a_dead_only_candidate_allows_the_swap_without_input() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let mut session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let result = run(&fixture, &forward(), |index, _| {
        assert_eq!(index, 0);
        session.child.kill().unwrap();
        session.child.wait().unwrap();
        Reply::Yes
    });
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["remote_control"]["gone"], 1);
    assert!(calls(&fixture).is_empty());
}

#[test]
fn ac154_restart_timeout_restores_only_the_disconnected_session() {
    let server = MockServer::start();
    let (p, t) = live_profiles(&server);
    let token = token_ok(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let first = Session::new(&fixture, 7);
    let second = Session::new(&fixture, 8);
    setup(&mut fixture, &[&first, &second], &resolved);
    let delays = fixture.scratch("delays");
    fs::write(&delays, format!("{} 300\n{} never\n", first.child.id(), second.child.id())).unwrap();
    fixture.set("AGCTL_FAKE_TMUX_NULL_AFTER_MS", delays.to_str().unwrap());
    fixture.set("AGCTL_RC_BUDGET_MS", "30000");
    let before = fixture.keychain_items();
    let config = fs::read(fixture.home().join(".claude.json")).unwrap();
    let result = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(result.output.code(), 30, "{}{}", result.output.stdout, result.output.stderr);
    let counts = &doc(&result)["remote_control"];
    assert_eq!(counts["disconnected"], 1);
    assert_eq!(counts["not_disconnected"], 1);
    assert_eq!(counts["restored"], 1);
    assert_eq!(sends(&fixture), 5);
    assert_unchanged(&fixture, &before, &config);
    assert_released(&fixture, &resolved);
    assert_eq!(p.calls(), 1);
    assert_eq!(t.calls(), 0);
    assert_eq!(token.calls(), 0);
    let all = calls(&fixture);
    assert!(all[..2].iter().all(|call| call[0] == "display-message"));
    assert_eq!(all.last().unwrap()[2], "%7", "only the disconnected pane is restored");
}

#[test]
fn ac171_restart_observes_the_first_bridge_while_the_next_attestation_is_open() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let first = Session::new(&fixture, 7);
    let second = Session::new(&fixture, 8);
    setup(&mut fixture, &[&first, &second], &resolved);
    let mut first_reconnect = None;
    let result = run(&fixture, &forward(), |index, question| {
        if index == 5 {
            first_reconnect = Some(if question.contains("in %7:") {
                first.path.clone()
            } else {
                second.path.clone()
            });
        }
        if index == 6 {
            // Another actor drops and re-establishes the first bridge while the
            // second pane's question is open. Polling only after all answers
            // would miss this drop and incorrectly report two stable bridges.
            let path = first_reconnect.as_ref().unwrap();
            let mut state: Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            let bridge = state["bridgeSessionId"].clone();
            assert!(bridge.is_string());
            state["bridgeSessionId"] = Value::Null;
            fs::write(path, state.to_string()).unwrap();
            std::thread::sleep(Duration::from_secs(1));
            state["bridgeSessionId"] = bridge;
            fs::write(path, state.to_string()).unwrap();
        }
        Reply::Yes
    });
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["remote_control"]["reconnected"], 1);
    assert_eq!(doc(&result)["remote_control"]["not_confirmed"], 1);
    assert_eq!(sends(&fixture), 6);
}

#[test]
fn ac171_restart_two_reconnects_require_fresh_answers_outside_the_locks() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let first = Session::new(&fixture, 7);
    let second = Session::new(&fixture, 8);
    setup(&mut fixture, &[&first, &second], &resolved);
    let result = run(&fixture, &forward(), |index, question| {
        let connecting = question.contains("for reconnect");
        for (acct, org) in [(ACCT, ORG), (ACCT_T, ORG_T)] {
            assert_eq!(
                common::lock_is_held(&fixture.lock_path(acct, org)),
                !connecting,
                "question {index}"
            );
        }
        Reply::Yes
    });
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["remote_control"]["reconnected"], 2);
    assert_eq!(result.questions.len(), 7);
    assert_eq!(sends(&fixture), 6);
    let all = calls(&fixture);
    assert!(all[..2].iter().all(|call| call[0] == "display-message"));
    assert_released(&fixture, &resolved);
}

#[test]
fn ac171_restart_reconnect_decline_and_eof_preserve_the_applied_exit() {
    for (reply, field) in [(Reply::No, "attestation_declined"), (Reply::Eof, "not_attested")] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        let result =
            run(&fixture, &forward(), |index, _| if index == 3 { reply } else { Reply::Yes });
        assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
        assert_eq!(doc(&result)["remote_control"][field], 1);
        assert_eq!(doc(&result)["remote_control"]["not_confirmed"], 1);
        assert_eq!(sends(&fixture), 2);
    }
}

#[test]
fn ac171_restart_restore_requires_fresh_answer_after_second_pane_decline() {
    for (reply, declined, not_attested) in [(Reply::No, 2, 0), (Reply::Eof, 1, 1)] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let first = Session::new(&fixture, 7);
        let second = Session::new(&fixture, 8);
        setup(&mut fixture, &[&first, &second], &resolved);
        let result = run(&fixture, &forward(), |index, _| match index {
            3 => Reply::No,
            4 => reply,
            _ => Reply::Yes,
        });
        assert_eq!(result.output.code(), 30, "{}{}", result.output.stdout, result.output.stderr);
        let counts = &doc(&result)["remote_control"];
        assert_eq!(counts["disconnected"], 1);
        assert_eq!(counts["not_confirmed"], 1);
        assert_eq!(counts["attestation_declined"], declined);
        assert_eq!(counts["not_attested"], not_attested);
        assert_eq!(sends(&fixture), 2);
        assert!(result.questions[4].contains("for restore"));
    }
}

#[test]
fn ac151_restart_never_toggles_a_bridge_reestablished_before_reconnect() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    fixture.set("AGCTL_FAKE_TMUX_REBRIDGE_AFTER_MS", "2000");
    let result = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["remote_control"]["already_connected"], 1);
    assert_eq!(doc(&result)["remote_control"]["reconnected"], 0);
    assert_eq!(sends(&fixture), 2);
    assert_eq!(result.questions.len(), 3);
}

#[test]
fn ac165_restart_catch_up_preserves_the_hint_but_never_types() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let initial = fixture
        .raw()
        .args(["claude", "use", "--live", EMAIL_T, "--yes", "--json"])
        .output()
        .unwrap();
    assert!(initial.status.success());
    fixture.live_claude_json_js(&normal_config());
    let result = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["outcome"], "already_active");
    assert_eq!(doc(&result)["config"]["outcome"], "applied");
    assert!(result.output.stderr.contains("does not act on a catch-up"));
    assert!(result.questions[0].contains("answer n, run `/remote-control`"));
    assert!(!result.questions[0].contains("With --restart-remote-control"));
    assert!(calls(&fixture).is_empty());
}

#[test]
fn ac156_restart_applied_without_config_update_never_reconnects() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let result = run(&fixture, &forward(), |index, _| {
        if index == 2 {
            fs::remove_file(fixture.home().join(".claude.json")).unwrap();
        }
        Reply::Yes
    });
    assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
    assert_eq!(doc(&result)["config"]["reason"], "absent");
    assert_eq!(doc(&result)["remote_control"]["not_confirmed"], 1);
    assert_eq!(sends(&fixture), 2);
    assert!(doc(&result)["warnings"].to_string().contains("config recovery"));
}

#[test]
fn ac156_restart_never_set_or_dropping_bridge_stays_not_confirmed_without_retry() {
    for (knob, value) in
        [("AGCTL_FAKE_TMUX_SET_AFTER_MS", "never"), ("AGCTL_FAKE_TMUX_DROP_AFTER_MS", "500")]
    {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        fixture.set(knob, value);
        fixture.set("AGCTL_RC_BUDGET_MS", "60000");
        let result = run(&fixture, &forward(), |_, _| Reply::Yes);
        assert_eq!(result.output.code(), 0, "{}{}", result.output.stdout, result.output.stderr);
        assert_eq!(doc(&result)["remote_control"]["not_confirmed"], 1);
        assert_eq!(doc(&result)["remote_control"]["reconnected"], 0);
        assert_eq!(sends(&fixture), 3);
    }
}

#[test]
fn ac158_restart_window_and_nonpane_hint_are_both_in_the_initial_question() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let first = Session::new(&fixture, 7);
    let second = Session::new(&fixture, 8);
    setup(&mut fixture, &[&first], &resolved);
    let mut nonpane = second.document.clone();
    nonpane.as_object_mut().unwrap().remove("tmux");
    second.save(&nonpane);
    fixture.set("AGCTL_SWAP_DEADLINE_MS", "70000");
    let result = run(&fixture, &forward(), |_, _| Reply::No);
    assert_eq!(result.output.code(), 20);
    assert_eq!(sends(&fixture), 0);
    let question = &result.questions[0];
    assert!(question.contains("rc-e2e-8"));
    assert!(question.contains("answer n, run `/remote-control`"));
    let secs = question
        .split("wait up to ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse::<u64>()
        .unwrap();
    assert!(secs <= 18);
}

#[test]
fn ac173_ac174_restart_config_and_capture_guards_reject_even_with_yes_available() {
    for (screen, reason) in [
        ("draft_visible.txt", "draft_visible"),
        ("stash_visible.txt", "stash_visible"),
        ("mode_visible.txt", "mode_visible"),
        ("dialog_conflict.txt", "dialog_conflict"),
        ("capture_ambiguous.txt", "capture_ambiguous"),
        ("capture_invalid.bin", "capture_invalid"),
    ] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        fixture.set(
            "AGCTL_FAKE_TMUX_SCREEN",
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("fixtures/rc-screens")
                .join(screen)
                .to_str()
                .unwrap(),
        );
        let result = run(&fixture, &forward(), |_, _| Reply::Yes);
        assert_eq!(result.output.code(), 30);
        assert_eq!(sends(&fixture), 0);
        assert_eq!(result.questions.len(), 1);
        assert!(result.output.stderr.contains(reason));
    }
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&common::live_config_document());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let result = run(&fixture, &forward(), |_, _| Reply::Yes);
    assert_eq!(result.output.code(), 30);
    assert_eq!(sends(&fixture), 0);
    assert!(result.output.stderr.contains("config_mode_rejected"));
}

#[test]
fn ac163_ac174_restart_fault_output_is_counts_only_and_audit_neutral() {
    let cases: BTreeMap<_, _> = [
        ("control", (None, None)),
        ("spawn", (Some("pane_unreadable"), Some("Spawn"))),
        ("timeout", (Some("capture_failed"), Some("Timeout"))),
        ("nonzero", (Some("capture_failed"), Some("Nonzero"))),
        ("invalid", (Some("capture_invalid"), None)),
        ("ambiguous", (Some("capture_ambiguous"), None)),
        ("oversize", (Some("capture_too_large"), Some("TooLarge"))),
    ]
    .into();
    for (case, (reason, transport_failure)) in cases {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        fixture.set("RUST_LOG", "agctl=debug");
        match case {
            "control" => {}
            "spawn" => {
                // Resolution succeeds; exec fails on the synthetic interpreter,
                // so this exercises Failure::Spawn, not only Unavailable.
                fs::write(
                    fixture.scratch("tmux-test"),
                    format!("#!{}\n", fixture.scratch("missing-interpreter").display()),
                )
                .unwrap();
            }
            "timeout" => {
                let bin = fixture.scratch("tmux-test");
                let script = fs::read_to_string(&bin).unwrap().replacen("#!/bin/sh\n", "#!/bin/sh\nif [ \"$1\" != capture-pane ]; then unset AGCTL_FAKE_TMUX_SLEEP; fi\n", 1);
                fs::write(bin, script).unwrap();
                fixture.set("AGCTL_FAKE_TMUX_SLEEP", "5");
            }
            "nonzero" => {
                fixture.set("AGCTL_FAKE_TMUX_CAPTURE_EXIT", "9");
            }
            "invalid" | "ambiguous" => {
                let name =
                    if case == "invalid" { "capture_invalid.bin" } else { "capture_ambiguous.txt" };
                fixture.set(
                    "AGCTL_FAKE_TMUX_SCREEN",
                    fixture.scratch("rc-screens").join(name).to_str().unwrap(),
                );
            }
            "oversize" => {
                fixture.set("AGCTL_FAKE_TMUX_CAPTURE_BYTES", "65537");
            }
            _ => unreachable!(),
        }
        let (baseline, _) = live_accounts(&server, common::fresh_at());
        baseline.live_claude_json_js(&normal_config());
        let receipt_count = |fixture: &Fixture| {
            fs::read_to_string(fixture.audit_log_path()).unwrap_or_default().lines().count()
        };
        let baseline_before = receipt_count(&baseline);
        let plain = run_channel(
            &baseline,
            &["claude", "use", "--live", EMAIL_T, "--json"],
            true,
            |_, _| {
                if reason.is_some() { Reply::No } else { Reply::Yes }
            },
        );
        assert_eq!(plain.output.code(), if reason.is_some() { 20 } else { 0 }, "{case}: baseline");
        let expected_receipts = receipt_count(&baseline) - baseline_before;
        let audit_before = receipt_count(&fixture);
        let result = run(&fixture, &forward(), |_, _| Reply::Yes);
        assert_eq!(
            result.output.code(),
            if reason.is_some() { 30 } else { 0 },
            "{case}: {}{}",
            result.output.stdout,
            result.output.stderr
        );
        assert_eq!(
            receipt_count(&fixture) - audit_before,
            expected_receipts,
            "{case}: AC163 no keystroke receipts, including refusal"
        );
        let counts = &doc(&result)["remote_control"];
        assert_counts(&doc(&result));
        let events = log_events(&result);
        assert!(events.contains("DEBUG"), "{case}: capture actual debug events");
        let stages: Vec<_> =
            events.lines().filter(|line| line.contains("Remote Control stage")).collect();
        assert_eq!(
            stages.len(),
            if reason.is_some() { 1 } else { 2 },
            "{case}: exactly one info event per stage: {events}"
        );
        assert!(stages.iter().all(|line| line.contains("INFO")));
        assert_eq!(
            stages.iter().filter(|line| line.contains("stage=\"disconnect\"")).count(),
            1,
            "{case}: disconnect stage identity: {events}"
        );
        if let Some(reason) = reason {
            assert!(result.output.stderr.contains(reason), "{case}: {events}");
            assert_eq!(counts["skipped"], 1, "{case}");
            assert_eq!(counts["not_disconnected"], 1, "{case}");
            assert_eq!(sends(&fixture), 0, "{case}");
        } else {
            assert_eq!(counts["reconnected"], 1);
            assert_eq!(sends(&fixture), 3);
        }
        if let Some(failure) = transport_failure {
            assert!(
                events.contains(&format!("Some({failure})")),
                "{case}: closed transport reason: {events}"
            );
            if ["Spawn", "Timeout"].contains(&failure) {
                assert_eq!(
                    events
                        .lines()
                        .filter(|line| line.contains("WARN")
                            && line.contains("tmux call did not complete"))
                        .count(),
                    1,
                    "{case}: closed warning"
                );
            }
        }
        assert_released(&fixture, &resolved);
    }
}

#[test]
fn ac168_ac176_restart_sigint_during_an_open_question_never_sends_that_group() {
    for group in [1, 3] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        let result =
            run(
                &fixture,
                &forward(),
                |index, _| if index == group { Reply::Interrupt } else { Reply::Yes },
            );
        assert_eq!(result.output.code(), 130, "{}{}", result.output.stdout, result.output.stderr);
        assert_eq!(sends(&fixture), group - 1);
        assert!(result.output.stderr.contains(&format!(
            "Remote Control was not confirmed reconnected in {} session(s)",
            if group == 1 { 0 } else { 1 }
        )));
        let documents: Vec<Value> = serde_json::Deserializer::from_str(&result.output.stdout)
            .into_iter()
            .map(Result::unwrap)
            .collect();
        assert!(documents.iter().all(|document| document["kind"] != "outcome"));
        assert_released(&fixture, &resolved);
    }
}

#[test]
fn ac170_ac171_restart_tty_loss_never_changes_the_original_swap_outcome() {
    for group in [1, 2, 3] {
        let server = MockServer::start();
        let (_p, _t) = live_profiles(&server);
        let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
        fixture.live_claude_json_js(&normal_config());
        let session = Session::new(&fixture, 7);
        setup(&mut fixture, &[&session], &resolved);
        let result =
            run(
                &fixture,
                &forward(),
                |index, _| if index == group { Reply::LoseTty } else { Reply::Yes },
            );
        assert_eq!(
            result.output.code(),
            if group == 3 { 0 } else { 30 },
            "group {group}: {}{}",
            result.output.stdout,
            result.output.stderr
        );
        assert_eq!(doc(&result)["remote_control"]["not_attested"], 1);
        assert_eq!(sends(&fixture), group - 1);
        if group == 3 {
            assert_eq!(doc(&result)["remote_control"]["not_confirmed"], 1);
        } else {
            assert_eq!(doc(&result)["remote_control"]["not_disconnected"], 1);
        }
    }
}

#[test]
fn ac152_restart_required_field_loss_after_discovery_refuses_before_input() {
    for field in
        ["pid", "sessionId", "version", "status", "tmux", "statusUpdatedAt", "bridgeSessionId"]
    {
        for missing in [true, false] {
            let server = MockServer::start();
            let (_p, t) = live_profiles(&server);
            let token = token_ok(&server);
            let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
            fixture.live_claude_json_js(&normal_config());
            let session = Session::new(&fixture, 7);
            setup(&mut fixture, &[&session], &resolved);
            let before = fixture.keychain_items();
            let config = fs::read(fixture.home().join(".claude.json")).unwrap();
            let result = run(&fixture, &forward(), |index, _| {
                assert_eq!(index, 0);
                let mut changed = session.document.clone();
                if missing {
                    changed.as_object_mut().unwrap().remove(field);
                } else {
                    changed[field] = json!([]);
                }
                session.save(&changed);
                Reply::Yes
            });
            assert_eq!(
                result.output.code(),
                30,
                "{field} missing={missing}: {}{}",
                result.output.stdout,
                result.output.stderr
            );
            assert_eq!(sends(&fixture), 0);
            assert_unchanged(&fixture, &before, &config);
            assert_eq!(t.calls(), 0);
            assert_eq!(token.calls(), 0);
        }
    }
}

#[test]
fn ac176_restart_a_registry_change_invalidates_a_fresh_yes() {
    let server = MockServer::start();
    let (_p, _t) = live_profiles(&server);
    let (mut fixture, resolved) = live_accounts(&server, common::fresh_at());
    fixture.live_claude_json_js(&normal_config());
    let session = Session::new(&fixture, 7);
    setup(&mut fixture, &[&session], &resolved);
    let result = run(&fixture, &forward(), |index, _| {
        if index == 1 {
            let mut changed = session.document.clone();
            changed["statusUpdatedAt"] = json!(2);
            session.save(&changed);
        }
        Reply::Yes
    });
    assert_eq!(result.output.code(), 30);
    assert_eq!(sends(&fixture), 0);
    assert!(result.output.stderr.contains("attestation_stale"));
}
