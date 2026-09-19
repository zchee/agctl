use super::*;

#[test]
fn an_install_and_an_overwrite_are_described_differently() {
    assert_eq!(describe(WriteKind::LoginInstall { overwrote: false }), "a new grant");
    assert_eq!(
        describe(WriteKind::LoginInstall { overwrote: true }),
        "replacing the grant that was there"
    );
}

#[test]
fn a_refusal_carries_the_underlying_sentence_unchanged() {
    // Every early exit in `run` is wrapped by `refused`, so the sentence the
    // user reads is the one the failing step wrote, not a generic one.
    let err = refused("the scratch root `/x` is a symbolic link");
    assert_eq!(err.to_string(), "refused: the scratch root `/x` is a symbolic link");
}
