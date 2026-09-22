//! The facts of this module itself: the plan vocabulary and the user-agent
//! override's environment variable. Everything else `provider::codex` owns is
//! tested beside the file that implements it.

use super::*;

#[test]
fn the_plan_type_vocabulary_is_fact() {
    assert_eq!(PLAN_TYPES.len(), 22);
    assert!(is_known_plan("pro") && is_known_plan("free_workspace") && is_known_plan("unknown"));
    assert!(!is_known_plan("Pro") && !is_known_plan(""));
    assert_eq!(USER_AGENT_ENV, "AGCTL_CODEX_USER_AGENT");
}
