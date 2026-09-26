use super::*;

#[test]
fn state_and_exact_name_rules_need_no_process_table() {
    for state in b"Tt" {
        assert_eq!(state_holder(*state), Some(Holder::Stopped));
    }
    for state in b"ZX" {
        assert_eq!(state_holder(*state), Some(Holder::Dead));
    }
    for state in b"RSDIWKP" {
        assert_eq!(state_holder(*state), Some(Holder::Alive));
    }
    for state in [0, 255, b'?', b'x'] {
        assert_eq!(state_holder(state), None);
    }
    assert!(is_claude(42, 42, "claude"));
    assert!(!is_claude(42, 43, "claude"));
    for name in ["Claude", "claude-code", "Claude Helper", "2.1.282", "claude ", "claude\0"] {
        assert!(!is_claude(42, 42, name), "{name:?}");
    }
}
