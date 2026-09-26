#![cfg(all(feature = "testing", target_os = "linux"))]

//! The opt-in flag refuses Linux before it reads a store or inspects the TTY.

mod common;

use common::Fixture;
use serde_json::Value;

#[test]
fn remote_control_unsupported_platform_precedes_tty_and_store_reads() {
    let fixture = Fixture::new();
    for mode in ["--live", "--undo"] {
        let mut command = fixture.raw();
        command.args(["claude", "use", mode, "--restart-remote-control", "--json"]);
        if mode == "--live" {
            command.arg("unresolved-account");
        }
        let output = command.output().unwrap();
        assert_eq!(output.status.code(), Some(30));
        let document: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(document["outcome"], "refused");
        assert_eq!(document["reason"], "remote_control_unsupported_platform");
        assert!(document.get("refusal").is_none());
        let counts = document["remote_control"].as_object().unwrap();
        assert_eq!(counts.len(), 11);
        assert!(counts.values().all(|value| value.as_u64() == Some(0)));
        assert!(!fixture.config_file().exists());
        assert!(!fixture.security_log_path().exists());
    }
}
