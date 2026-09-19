use std::ffi::OsStr;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;

use rustix::fs::FlockOperation;
use rustix::fs::Mode;
use rustix::io::Errno;

use super::*;

/// Turns `(name, value)` string pairs into what [`allowed_env`] consumes.
fn parent(pairs: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
    pairs.iter().map(|(k, v)| (OsString::from(*k), OsString::from(*v))).collect()
}

/// Runs [`allowed_env`] over `pairs` and returns the result as strings.
fn env_of(pairs: &[(&str, &str)], scratch: &Path) -> Vec<(String, String)> {
    let owned = parent(pairs);
    let iter = owned.iter().map(|(k, v)| (k.as_os_str(), v.as_os_str()));
    allowed_env(iter, scratch)
        .into_iter()
        .map(|(k, v)| (k.to_string_lossy().into_owned(), v.to_string_lossy().into_owned()))
        .collect()
}

/// The names [`allowed_env`] let through, sorted.
fn names_of(pairs: &[(&str, &str)], scratch: &Path) -> Vec<String> {
    let mut names: Vec<String> = env_of(pairs, scratch).into_iter().map(|(k, _)| k).collect();
    names.sort();
    names
}

#[test]
fn ac105_the_child_environment_is_exactly_the_allowlist_and_no_decoy_survives() {
    // Plan AC105 and decision D-037: the child's environment is built, not
    // inherited. Every name below that is not on the list is a decoy a real
    // developer environment could plausibly carry.
    let scratch = Path::new("/store/codex/.scratch/agctl-codex-login-0badf00d");
    let names = names_of(
        &[
            ("HOME", "/Users/someone"),
            ("PATH", "/usr/bin:/bin"),
            ("TMPDIR", "/var/folders/tmp/"),
            ("LANG", "en_US.UTF-8"),
            ("TERM", "xterm-256color"),
            // Decoys, every one of which must be dropped.
            ("KACHE_S3_SECRET_ACCESS_KEY", "decoy"),
            ("KACHE_S3_ACCESS_KEY_ID", "decoy"),
            ("CODEX_API_KEY", "decoy"),
            ("CODEX_ACCESS_TOKEN", "decoy"),
            ("CODEX_SQLITE_HOME", "/Users/someone/.codex"),
            ("AWS_SECRET_ACCESS_KEY", "decoy"),
            ("AGCTL_CODEX_USAGE_URL", "decoy"),
            ("SSH_AUTH_SOCK", "/private/tmp/ssh"),
            ("XDG_CONFIG_HOME", "/Users/someone/.config"),
        ],
        scratch,
    );

    assert_eq!(names, ["CODEX_HOME", "HOME", "LANG", "PATH", "TERM", "TMPDIR"]);
}

#[test]
fn ac105_an_inherited_codex_home_never_reaches_the_child() {
    // The single most important line in the module: the live home must not be
    // handed to a child that is about to write a credential.
    let scratch = Path::new("/store/codex/.scratch/agctl-codex-login-0badf00d");
    let env = env_of(&[("CODEX_HOME", "/Users/someone/.codex"), ("PATH", "/bin")], scratch);

    let homes: Vec<&(String, String)> = env.iter().filter(|(k, _)| k == "CODEX_HOME").collect();
    assert_eq!(homes.len(), 1, "exactly one CODEX_HOME reaches the child: {env:?}");
    assert_eq!(homes[0].1, scratch.to_string_lossy(), "and it is the scratch home");
    assert!(
        !env.iter().any(|(_, v)| v.contains(".codex")),
        "no inherited home survives anywhere in the environment: {env:?}"
    );
}

#[test]
fn the_locale_rule_is_a_prefix_not_a_substring() {
    // `LC_*` is passed through wholesale, so the rule has to be a prefix
    // match: a name that merely contains `LC_` is not a locale variable.
    let scratch = Path::new("/scratch");
    let names = names_of(
        &[
            ("LC_ALL", "en_US.UTF-8"),
            ("LC_CTYPE", "en_US.UTF-8"),
            ("LCD_BRIGHTNESS", "40"),
            ("MY_LC_THING", "decoy"),
            ("LC_", "empty name after the prefix"),
        ],
        scratch,
    );

    assert_eq!(names, ["CODEX_HOME", "LC_ALL", "LC_CTYPE"]);
}

#[test]
fn the_proxy_and_ca_names_pass_through_when_set_and_are_absent_when_not() {
    // Architect L9 / critic m14 (ledger #171): a user behind a proxy cannot
    // reach the authorization endpoint without these, and a login that cannot
    // happen is not a safer login.
    let scratch = Path::new("/scratch");
    let six = [
        ("HTTP_PROXY", "http://proxy:3128"),
        ("HTTPS_PROXY", "http://proxy:3128"),
        ("NO_PROXY", "localhost"),
        ("ALL_PROXY", "socks5://proxy:1080"),
        ("SSL_CERT_FILE", "/etc/ssl/cert.pem"),
        ("SSL_CERT_DIR", "/etc/ssl/certs"),
    ];
    let with = names_of(&six, scratch);
    assert_eq!(
        with,
        [
            "ALL_PROXY",
            "CODEX_HOME",
            "HTTPS_PROXY",
            "HTTP_PROXY",
            "NO_PROXY",
            "SSL_CERT_DIR",
            "SSL_CERT_FILE"
        ]
    );

    let without = names_of(&[("PATH", "/bin")], scratch);
    assert_eq!(without, ["CODEX_HOME", "PATH"], "an unset proxy is absent, not empty");
}

#[test]
fn user_logname_and_shell_are_not_passed_through() {
    // Not in D-037's list and not in S28's measured set. Adding one needs
    // evidence and a numbered deviation, so this test is the pin that makes
    // adding one deliberate.
    let scratch = Path::new("/scratch");
    let names =
        names_of(&[("USER", "someone"), ("LOGNAME", "someone"), ("SHELL", "/bin/zsh")], scratch);

    assert_eq!(names, ["CODEX_HOME"]);
}

#[test]
fn open_scratch_root_accepts_the_directory_ensure_codex_dirs_creates() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("chmod");

    open_scratch_root(root.path()).expect("a 0700 directory this uid owns is accepted");
}

#[test]
fn open_scratch_root_refuses_a_root_other_users_can_enter() {
    // `Paths::ensure_codex_dirs` creates the root 0700 when it is absent and
    // trusts it when it is present, so a root that was already there at 0755
    // would otherwise go unexamined — and the scratch leaf's whole privacy
    // argument rests on the parent's mode, not on the name's 32 bits.
    let root = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).expect("chmod");

    let err = open_scratch_root(root.path()).expect_err("a 0755 root is refused");
    let text = err.to_string();
    assert!(text.contains("0755"), "the refusal names the mode it found: {text}");
    assert!(text.contains("0700"), "and the mode it wanted: {text}");

    // Refused, never repaired: a silent chmod would hide how it got that way.
    let mode = fs::metadata(root.path()).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode, 0o755, "the root is left exactly as it was found");
}

#[test]
fn open_scratch_root_refuses_a_symlinked_root() {
    // `Path::is_dir` follows links, which is precisely how a redirected root
    // would pass unnoticed; this is why the check uses `symlink_metadata`.
    let home = tempfile::tempdir().expect("tempdir");
    let real = home.path().join("real");
    fs::create_dir(&real).expect("mkdir");
    fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).expect("chmod");
    let link = home.path().join("link");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");

    let err = open_scratch_root(&link).expect_err("a symlinked root is refused");
    assert!(err.to_string().contains("symbolic link"), "{err}");
}

#[test]
fn open_scratch_root_refuses_what_is_not_there() {
    let home = tempfile::tempdir().expect("tempdir");

    let err = open_scratch_root(&home.path().join("absent")).expect_err("refused");
    assert!(err.to_string().contains("cannot be opened"), "{err}");
}

/// Fails loudly under root, which ignores mode bits.
///
/// These tests make something unreadable or unwritable and assert what agctl
/// does about it; as root the `chmod` changes nothing and the test would pass
/// or fail for the wrong reason. The suite runs unprivileged (the developer's
/// own account, and CI as a normal user), so this is a guard with a stated
/// reason, not a skip.
fn unprivileged() {
    assert_ne!(
        rustix::process::geteuid().as_raw(),
        0,
        "this test changes mode bits, which root ignores; run the suite unprivileged"
    );
}

/// A 0700 root this uid owns, as `ensure_codex_dirs` would leave it.
fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("chmod");
    root
}

/// A scratch home made exactly the way `login.rs` makes one.
fn make_scratch(root: &Path) -> Scratch {
    let fd = open_scratch_root(root).expect("the root verifies");
    Scratch::create(root, fd).expect("a scratch home is created")
}

/// Runs `f` with the process umask set to `mask`, restoring it afterwards.
///
/// The umask is process-wide. nextest runs every test in its own process, so
/// this cannot leak into another test there; under `cargo test`'s shared
/// process it could, which is why the suite is run through nextest.
fn with_umask<T>(mask: rustix::fs::RawMode, f: impl FnOnce() -> T) -> T {
    let previous = rustix::process::umask(Mode::from_raw_mode(mask));
    let result = f();
    rustix::process::umask(previous);
    result
}

#[test]
fn a_scratch_home_is_created_0700_whatever_the_umask() {
    // `mkdirat`'s mode is masked by the umask downwards only, so a permissive
    // umask cannot widen 0700 and a restrictive one cannot narrow it below
    // the owner's bits — but the assertion is on the mode that resulted, under
    // both, rather than on that reasoning.
    let masks: [rustix::fs::RawMode; 3] = [0o000, 0o022, 0o077];
    for mask in masks {
        let root = private_root();
        let scratch = with_umask(mask, || make_scratch(root.path()));

        let mode = fs::metadata(scratch.path()).expect("metadata").permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "umask {mask:03o}: the scratch home is 0700");

        let name = scratch.path().file_name().and_then(OsStr::to_str).expect("a name");
        assert!(is_scratch_name(name), "AC105's `agctl-codex-login-<8hex>`: {name}");
    }
}

#[test]
fn two_scratch_homes_are_different_directories() {
    let root = private_root();

    let first = make_scratch(root.path());
    let second = make_scratch(root.path());

    assert_ne!(first.path(), second.path(), "each login gets its own home");
}

#[test]
fn an_existing_leaf_name_is_eexist_and_never_reused() {
    // `mkdirat` fails on a name that exists — the directory equivalent of
    // `O_EXCL`. Mutant: a builder that creates parents or tolerates an
    // existing directory; it would silently reuse a leaf somebody else made.
    let root = private_root();
    let fd = open_scratch_root(root.path()).expect("verifies");
    let name = "agctl-codex-login-0badf00d";
    fs::create_dir(root.path().join(name)).expect("pre-created by somebody else");

    assert_eq!(mkdir_leaf(&fd, name), Err(Errno::EXIST), "an existing name is refused");
}

#[test]
fn a_permissive_root_is_refused_before_anything_is_created() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o777)).expect("chmod");

    let err = open_scratch_root(root.path()).expect_err("refused");
    assert!(matches!(err, LoginChildError::ScratchRoot { .. }), "{err}");

    let entries = fs::read_dir(root.path()).expect("read_dir").count();
    assert_eq!(entries, 0, "nothing was created in a root that was refused");
}

/// Creates `<dir>/<name>` as an empty file and returns its path.
fn touch(dir: &Path, name: &str) -> PathBuf {
    let path = dir.join(name);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("mkdir -p");
    }
    fs::write(&path, b"").expect("write");
    path
}

#[test]
fn f81_the_residue_a_normal_login_leaves_is_not_a_survivor() {
    // Fact F81, measured at S28 with alpha.12: a NORMAL, successful
    // `codex login` leaves an unheld `tmp/arg0/codex-arg0<rand>/.lock`, three
    // symlinks and a log behind. Reporting a lock file because it EXISTS
    // would therefore refuse every real login — the trap ledger #310 names.
    //
    // Mutant to try: fill `held_locks` by existence instead of by the probe.
    // This test, and the happy-path e2e, must both go red.
    let scratch = tempfile::tempdir().expect("tempdir");
    let arg0 = scratch.path().join("tmp/arg0/codex-arg01a2b3c4d");
    fs::create_dir_all(&arg0).expect("mkdir -p");
    fs::write(arg0.join(".lock"), b"").expect("the 0-byte lock a normal login leaves");
    for name in ["apply_patch", "applypatch", "codex-execve-wrapper"] {
        std::os::unix::fs::symlink("/usr/bin/true", arg0.join(name)).expect("symlink");
    }
    touch(scratch.path(), "log/codex-login.log");
    touch(scratch.path(), "auth.json");

    let found = survey(scratch.path());

    assert!(!found.daemon_dir, "a normal login starts no daemon");
    assert!(found.held_locks.is_empty(), "an unheld lock is residue: {:?}", found.held_locks);
    assert!(found.odd_locks.is_empty(), "the residue has no odd lock: {:?}", found.odd_locks);
    assert!(!found.truncated, "and the whole residue was walked");

    // The assertion above is empty either because the lock is unheld — the
    // point — or because the survey never saw the file at all, which is a way
    // of passing that would hide the check being dead. So the same file is
    // held and surveyed again: it must now be reported. (It really was dead
    // once: `Path::extension` returns `None` for a name like `.lock`, because
    // a leading dot makes the whole name the file stem, so matching on the
    // extension missed the one lock file a real login leaves.)
    let lock = arg0.join(".lock");
    let holder = std::fs::File::open(&lock).expect("open");
    rustix::fs::flock(&holder, FlockOperation::NonBlockingLockExclusive).expect("hold it");
    let now_held = survey(scratch.path()).held_locks;
    assert_eq!(now_held, vec![lock], "the survey can see this file; it simply was not held");
    drop(holder);
}

#[test]
fn a_lock_something_still_holds_is_a_survivor() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let path = touch(scratch.path(), "tmp/arg0/codex-arg0deadbeef/.lock");

    // Held for the duration of the survey by a descriptor this test owns,
    // which is what a surviving child would look like from the outside.
    let holder = std::fs::File::open(&path).expect("open");
    rustix::fs::flock(&holder, FlockOperation::NonBlockingLockExclusive).expect("take the lock");

    let held = survey(scratch.path()).held_locks;

    assert_eq!(held, vec![path], "a held lock is reported");
    drop(holder);
}

#[test]
fn a_shared_holder_also_reads_as_a_survivor() {
    // `LOCK_SH` blocks an exclusive probe, so a reader-only survivor reads as
    // held. Deliberate, and the conservative direction: the cost is a refused
    // login, not an installed credential from a home somebody else is using.
    let scratch = tempfile::tempdir().expect("tempdir");
    let path = touch(scratch.path(), "held.lock");

    let holder = std::fs::File::open(&path).expect("open");
    rustix::fs::flock(&holder, FlockOperation::NonBlockingLockShared).expect("take a shared lock");

    let held = survey(scratch.path()).held_locks;

    assert_eq!(held, vec![path], "a shared holder is still a holder");
    drop(holder);
}

#[test]
fn the_probe_leaves_no_lock_behind_it() {
    // The probe acquires to answer "is it held", so it must release in every
    // case: a lock agctl still held would make the next caller wait on a
    // question that was already answered.
    let scratch = tempfile::tempdir().expect("tempdir");
    let path = touch(scratch.path(), "free.lock");

    let held = survey(scratch.path()).held_locks;
    assert!(held.is_empty());

    let after = std::fs::File::open(&path).expect("open");
    rustix::fs::flock(&after, FlockOperation::NonBlockingLockExclusive)
        .expect("the probe released whatever it took");
}

#[test]
fn a_symlinked_lock_can_never_deny_a_login() {
    // A link planted in the scratch must not be followed, and its refusal must
    // read as "not held" rather than as "held" — otherwise planting one would
    // be enough to stop every login.
    let scratch = tempfile::tempdir().expect("tempdir");
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let target = elsewhere.path().join("real.lock");
    fs::write(&target, b"").expect("write");
    let holder = std::fs::File::open(&target).expect("open");
    rustix::fs::flock(&holder, FlockOperation::NonBlockingLockExclusive).expect("held");

    std::os::unix::fs::symlink(&target, scratch.path().join("planted.lock")).expect("symlink");

    let held = survey(scratch.path()).held_locks;

    assert!(held.is_empty(), "a symlink is not followed and is not a survivor: {held:?}");
    drop(holder);
}

#[test]
fn a_daemon_directory_is_a_survivor_and_a_daemon_file_is_not() {
    // AC105's refusal is directory-based (decision D32 landed the two pid file
    // names for the LIVE home's session detection; the scratch's question is a
    // different one).
    let scratch = tempfile::tempdir().expect("tempdir");
    fs::create_dir_all(scratch.path().join("app-server-daemon")).expect("mkdir");
    let daemon_dir = survey(scratch.path()).daemon_dir;
    assert!(daemon_dir);

    let other = tempfile::tempdir().expect("tempdir");
    fs::write(other.path().join("app-server-daemon"), b"").expect("a file, not a directory");
    let as_file = survey(other.path()).daemon_dir;
    assert!(!as_file, "a file by that name is not a daemon directory");
}

#[test]
fn nothing_below_the_depth_bound_is_ever_probed() {
    // The survey stops at `SURVEY_MAX_DEPTH`: a held lock buried below it is
    // not reached. That is only safe because reaching the bound is itself a
    // refusal — see `a_home_too_deep_to_survey_completely_is_not_reported_as_clean`,
    // which is this test's positive control.
    let scratch = tempfile::tempdir().expect("tempdir");
    let mut deep = scratch.path().to_path_buf();
    for level in 0..(SURVEY_MAX_DEPTH + 4) {
        deep = deep.join(format!("d{level}"));
    }
    fs::create_dir_all(&deep).expect("mkdir -p");
    fs::write(deep.join("buried.lock"), b"").expect("write");

    let found = survey(scratch.path());

    assert!(found.held_locks.is_empty(), "nothing below the depth bound is reached");
    assert!(found.truncated, "and not reaching it is recorded");
}

#[test]
fn a_symlink_loop_is_never_followed() {
    // A link back to an ancestor would make a following walk loop forever.
    // The survey examines entries with `symlink_metadata` and never enters a
    // link, so it terminates, and the loop is not "unreadable" either.
    let scratch = tempfile::tempdir().expect("tempdir");
    let dir = scratch.path().join("a");
    fs::create_dir(&dir).expect("mkdir");
    std::os::unix::fs::symlink(scratch.path(), dir.join("back-to-the-top")).expect("symlink");

    let found = survey(scratch.path());

    assert!(!found.truncated, "a link is skipped, not counted as unreadable");
    assert!(found.held_locks.is_empty() && found.odd_locks.is_empty());
}

#[test]
fn gained_entries_names_only_what_the_second_listing_added() {
    let before = vec!["cli|aaaa".to_owned(), "cli|bbbb".to_owned()];
    let after = vec!["cli|aaaa".to_owned(), "cli|bbbb".to_owned(), "cli|cccc".to_owned()];

    assert_eq!(gained_entries(&before, &after), vec!["cli|cccc".to_owned()]);
    assert!(gained_entries(&before, &before).is_empty(), "an unchanged listing gains nothing");
    assert!(
        gained_entries(&after, &before).is_empty(),
        "an item that went away is not a gain; agctl deletes no keychain item"
    );
}

#[test]
fn a_fifo_named_like_a_lock_is_an_anomaly_and_is_never_probed() {
    // Only regular files are probed. A FIFO named `*.lock` is not normal vendor
    // residue (S28's contains none), so it is recorded as an anomaly, and
    // `flock` is never called on it.
    //
    // A CORRECTION to what this test used to say (ledger #333): opening a FIFO
    // here cannot block. `home::open_readonly_nofollow` carries `O_NONBLOCK`
    // (`home.rs:90-91`), so even without the type check the open would return
    // at once. The earlier version ran the survey on a thread with a five
    // second bound against a hang that could not happen; reviewer C1a showed
    // the guard-removed mutant going red in 0.019 s on the `odd_locks`
    // assertion below, not on the bound. So there is no thread and no timeout:
    // the assertion is the pin. Mutant: probe before establishing the entry
    // is a regular file — `odd_locks` stays empty and this test goes red.
    let scratch = tempfile::tempdir().expect("tempdir");
    let path = scratch.path().join("wedge.lock");
    let c = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).expect("a c string");
    // SAFETY: `c` is a valid NUL-terminated C string that outlives the call,
    // and the path is inside a directory this test owns.
    let made = unsafe { libc::mkfifo(c.as_ptr(), 0o600) };
    assert_eq!(made, 0, "the fixture could not create a FIFO");

    let found = survey(scratch.path());

    assert!(found.held_locks.is_empty(), "a FIFO is never probed, so it is never `held`");
    assert_eq!(found.odd_locks, vec![path], "it is reported as an anomaly instead");
}

#[test]
fn a_directory_named_like_a_lock_is_an_anomaly_and_is_not_descended_into() {
    let scratch = tempfile::tempdir().expect("tempdir");
    let path = scratch.path().join("pretend.lock");
    fs::create_dir(&path).expect("mkdir");
    fs::write(path.join("buried.lock"), b"").expect("write");

    let found = survey(scratch.path());

    assert_eq!(found.odd_locks, vec![path], "the directory itself is the anomaly");
    assert!(found.held_locks.is_empty());
}

#[test]
fn a_home_too_deep_to_survey_completely_is_not_reported_as_clean() {
    // A bound that is hit silently would turn "we did not look" into "we
    // looked and found nothing", which is the one answer this survey must
    // never give.
    let scratch = tempfile::tempdir().expect("tempdir");
    let mut deep = scratch.path().to_path_buf();
    for level in 0..(SURVEY_MAX_DEPTH + 2) {
        deep = deep.join(format!("d{level}"));
    }
    fs::create_dir_all(&deep).expect("mkdir -p");

    let found = survey(scratch.path());

    assert!(found.truncated, "hitting the depth bound is recorded, not ignored");
}

#[test]
fn a_root_owned_by_another_user_is_refused() {
    // The owner branch cannot be reached by making a directory somebody else
    // owns without privileges, so the predicate is exercised directly. Mutant:
    // delete the owner comparison in `root_verdict` — this test goes red,
    // where "every other test passes through the comparison" would not.
    let mine = geteuid().as_raw();
    let theirs = mine.wrapping_add(1);

    let err = root_verdict(theirs, 0o40700, mine).expect_err("a foreign owner is refused");
    assert_eq!(err, "is owned by another user");

    root_verdict(mine, 0o40700, mine).expect("this uid at 0700 is accepted");
}

#[test]
fn a_permissive_root_is_refused_by_the_predicate_and_the_message_names_both_modes() {
    let mine = geteuid().as_raw();

    let err = root_verdict(mine, 0o40755, mine).expect_err("0755 is refused");
    assert!(err.contains("0755"), "{err}");
    assert!(err.contains("0700"), "{err}");

    let group = root_verdict(mine, 0o40740, mine).expect_err("a group bit alone is refused");
    assert!(group.contains("0740"), "{group}");
}

#[test]
fn the_entry_bound_is_a_refusal_not_a_clean_answer() {
    // `SURVEY_MAX_ENTRIES` + 1 entries: the walk stops, and says so. Mutant:
    // return the survey as it stands when the budget runs out — it would read
    // clean with thousands of entries unexamined.
    let scratch = tempfile::tempdir().expect("tempdir");
    for index in 0..=SURVEY_MAX_ENTRIES {
        fs::write(scratch.path().join(format!("f{index}")), b"").expect("write");
    }

    let found = survey(scratch.path());

    assert!(found.truncated, "a home too large to walk has not been shown clean");
}

#[test]
fn a_directory_the_survey_cannot_list_makes_it_incomplete() {
    unprivileged();
    // Plan finding C1a F6: "could not look" must not read as "found nothing".
    // A 0000 subdirectory hides whatever is inside it, a held lock included.
    let scratch = tempfile::tempdir().expect("tempdir");
    let hidden = scratch.path().join("hidden");
    fs::create_dir(&hidden).expect("mkdir");
    fs::write(hidden.join("inside.lock"), b"").expect("write");
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let found = survey(scratch.path());

    // Restored before asserting, so the temporary directory can be removed
    // whatever the outcome.
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o700)).expect("chmod back");
    assert!(found.truncated, "an unlistable directory leaves the survey incomplete");
}

#[test]
fn a_lock_whose_state_cannot_be_asked_makes_the_survey_incomplete() {
    unprivileged();
    // A 0000 lock file cannot be opened, so whether it is held cannot be
    // asked. That is `EACCES`, not "free".
    let scratch = tempfile::tempdir().expect("tempdir");
    let lock = scratch.path().join("sealed.lock");
    fs::write(&lock, b"").expect("write");
    fs::set_permissions(&lock, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let found = survey(scratch.path());

    fs::set_permissions(&lock, fs::Permissions::from_mode(0o600)).expect("chmod back");
    assert!(found.held_locks.is_empty(), "an unopenable lock is not claimed as held");
    assert!(found.truncated, "but it is not claimed as free either");
}

/// Ages `path` by `age`.
fn age(path: &Path, age: Duration) {
    let when = SystemTime::now().checked_sub(age).expect("a representable time");
    fs::File::open(path)
        .expect("opens")
        .set_times(fs::FileTimes::new().set_modified(when))
        .expect("mtime is settable");
}

#[test]
fn the_sweep_removes_only_aged_homes_with_the_exact_scratch_name() {
    // Plan AC105: a stale scratch older than 15 minutes is swept; one aged
    // 9 minutes is not. And only a name `Scratch::create` could have made is
    // considered at all — a directory a user put in the root is never touched,
    // however old.
    let root = private_root();
    let old = root.path().join("agctl-codex-login-0000dead");
    let young = root.path().join("agctl-codex-login-0000beef");
    let foreign = root.path().join("agctl-codex-login-NOTHEX00");
    let unrelated = root.path().join("my-notes");
    for dir in [&old, &young, &foreign, &unrelated] {
        fs::create_dir(dir).expect("mkdir");
        fs::write(dir.join("content"), b"x").expect("write");
    }
    age(&old, Duration::from_secs(16 * 60));
    age(&young, Duration::from_secs(9 * 60));
    age(&foreign, Duration::from_secs(60 * 60));
    age(&unrelated, Duration::from_secs(60 * 60));

    let fd = open_scratch_root(root.path()).expect("verifies");
    sweep_stale_at(&fd, root.path(), Duration::from_secs(15 * 60), &mut Vec::new());

    assert!(!old.exists(), "an aged scratch home is swept");
    assert!(young.exists(), "one aged nine minutes is not");
    assert!(foreign.exists(), "a name that is not exactly `<prefix><8 lowercase hex>` survives");
    assert!(unrelated.exists(), "and an unrelated directory is never touched");
}

#[test]
fn the_sweep_never_follows_a_symlinked_leaf() {
    // An aged entry with a scratch-shaped name that is a LINK to somewhere
    // else: examined with `statat(AT_SYMLINK_NOFOLLOW)`, it is not a
    // directory, so nothing behind it is removed.
    let root = private_root();
    let elsewhere = tempfile::tempdir().expect("tempdir");
    let precious = elsewhere.path().join("precious");
    fs::write(&precious, b"keep").expect("write");
    let link = root.path().join("agctl-codex-login-0000cafe");
    std::os::unix::fs::symlink(elsewhere.path(), &link).expect("symlink");

    let fd = open_scratch_root(root.path()).expect("verifies");
    sweep_stale_at(&fd, root.path(), Duration::ZERO, &mut Vec::new());

    assert!(precious.exists(), "nothing behind a link is swept");
}

#[test]
fn a_symlinked_scratch_root_is_refused_so_nothing_behind_it_is_swept() {
    // Reviewer C1a's probe (F1), kept as the regression test. `login.rs`
    // sweeps only through a descriptor `open_scratch_root` returned, and a
    // link at the root is refused there, so a root redirected to `$HOME` can
    // never have its old subdirectories deleted. The ordering itself is
    // structural: the sweep takes the verified descriptor as its argument, so
    // it cannot be called before the verification that produces one.
    let target = tempfile::tempdir().expect("tempdir");
    let aged = target.path().join("agctl-codex-login-0000d00d");
    fs::create_dir(&aged).expect("mkdir");
    age(&aged, Duration::from_secs(60 * 60));
    let holder = tempfile::tempdir().expect("tempdir");
    let link = holder.path().join(".scratch");
    std::os::unix::fs::symlink(target.path(), &link).expect("symlink");

    let refused = open_scratch_root(&link);

    assert!(refused.is_err(), "a symlinked root is refused");
    assert!(aged.exists(), "and so nothing in the link's target is swept");
}

#[test]
fn dropping_a_scratch_removes_the_credential_and_the_home_and_nothing_beside_them() {
    // The `p3-s30-review2` carry, now a property of the type: every path out of
    // a login drops its `Scratch`. A sibling beside the leaf survives, so the
    // removal cannot reach past the directory it created.
    let root = private_root();
    let sibling = root.path().join("sibling-must-survive");
    fs::write(&sibling, b"x").expect("write");
    let scratch = make_scratch(root.path());
    let leaf = scratch.path().to_path_buf();
    fs::write(leaf.join("auth.json"), b"{}").expect("write");
    fs::create_dir_all(leaf.join("tmp/arg0/codex-arg01")).expect("residue");
    fs::write(leaf.join("tmp/arg0/codex-arg01/.lock"), b"").expect("residue");

    drop(scratch);

    assert!(!leaf.exists(), "the scratch home and everything in it is gone");
    assert!(sibling.exists(), "nothing outside the leaf is removed");
    assert!(root.path().exists(), "and certainly not the scratch root");
}

#[test]
fn a_leaf_swapped_for_a_symlink_never_makes_agctl_unlink_behind_it() {
    // Reviewer C1a F10 / order B11. A same-uid actor — the vendor child
    // included — replaces the scratch leaf with a symlink to the live Codex
    // home. A path-based cleanup would then unlink the LIVE `auth.json`
    // through it, making agctl the actor of an I21 violation. The cleanup acts
    // through the descriptors taken at creation, so the decoy survives.
    let root = private_root();
    let live = tempfile::tempdir().expect("tempdir");
    let live_auth = live.path().join("auth.json");
    fs::write(&live_auth, b"the live grant").expect("write");

    let scratch = make_scratch(root.path());
    let leaf = scratch.path().to_path_buf();
    let moved = root.path().join("moved-away");
    fs::rename(&leaf, &moved).expect("the leaf is moved aside");
    std::os::unix::fs::symlink(live.path(), &leaf).expect("and a link takes its name");

    drop(scratch);

    assert!(live_auth.exists(), "the live `auth.json` behind the link is untouched");
    assert_eq!(fs::read(&live_auth).expect("readable"), b"the live grant");
}

/// A stand-in `codex` that writes a credential into its home, then does `tail`.
fn stand_in(dir: &Path, tail: &str) -> PathBuf {
    let bin = dir.join("codex");
    fs::write(&bin, format!("#!/bin/sh\nprintf '{{}}' >\"$CODEX_HOME/auth.json\"\n{tail}\n"))
        .expect("write");
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).expect("chmod");
    bin
}

/// A pass context whose cancel the test can pull.
fn context() -> (crate::runtime::coordinator::Cancel, PassCtx) {
    let cancel = crate::runtime::coordinator::Cancel::new();
    let ctx = PassCtx::standalone(cancel.clone(), Instant::now() + Duration::from_secs(60));
    (cancel, ctx)
}

#[test]
fn a_cancelled_run_leaves_no_credential_behind_and_says_it_was_cancelled() {
    // Reviewer C1a's probe (F2), kept as the pin. The child writes a full
    // grant and then hangs; the login is cancelled. The error is worded as a
    // cancel, and dropping the scratch — which every caller does — removes the
    // credential the child wrote.
    let root = private_root();
    let bins = tempfile::tempdir().expect("tempdir");
    let bin = stand_in(bins.path(), "exec sleep 30");
    let scratch = make_scratch(root.path());
    let (cancel, ctx) = context();

    let puller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(300));
        cancel.cancel();
    });
    let result = run(&scratch, &bin, &ctx, &[], || Ok(Vec::new()));
    puller.join().expect("the canceller finishes");

    assert!(matches!(result, Err(LoginChildError::Cancelled)), "{result:?}");
    let credential = scratch.path().join("auth.json");
    // The positive control: the child really did write a credential, so the
    // absence asserted below is the drop's doing, not the child's.
    assert!(credential.exists(), "the stand-in wrote a credential before it hung");
    drop(scratch);
    assert!(!credential.exists(), "a cancelled run leaves no credential behind");
}

#[test]
fn a_child_that_cannot_be_started_leaves_no_scratch_behind() {
    let root = private_root();
    let scratch = make_scratch(root.path());
    let (_cancel, ctx) = context();

    let result = run(&scratch, Path::new("/nonexistent/codex"), &ctx, &[], || Ok(Vec::new()));

    assert!(matches!(result, Err(LoginChildError::Spawn { .. })), "{result:?}");
    drop(scratch);
    assert_eq!(fs::read_dir(root.path()).expect("read_dir").count(), 0, "no leaf is left");
}

#[test]
fn a_keychain_that_cannot_be_read_after_the_login_is_a_refusal() {
    // Order A3. The second listing is the check that catches a child that put
    // its credential in the keychain despite being asked not to (fact F95), so
    // a listing that could not be taken must refuse — never read as "nothing
    // gained". Mutant: `unwrap_or_default` on the second listing.
    let root = private_root();
    let bins = tempfile::tempdir().expect("tempdir");
    let bin = stand_in(bins.path(), "exit 0");
    let scratch = make_scratch(root.path());
    let (_cancel, ctx) = context();

    let result =
        run(&scratch, &bin, &ctx, &[], || Err("the keychain is locked (exit 36)".to_owned()));

    let err = result.expect_err("an unreadable second listing refuses");
    assert!(matches!(err, LoginChildError::KeychainAfter(_)), "{err:?}");
    assert!(err.to_string().contains("exit 36"), "the reason is named: {err}");
}

#[test]
fn the_child_runs_in_its_scratch_home_not_in_agctls_directory() {
    // Order A4. Codex resolves a `.codex/` Project config layer (fact F95)
    // from its working directory; a repository the user stands in must not
    // configure the login. Mutant: no `current_dir`.
    let root = private_root();
    let bins = tempfile::tempdir().expect("tempdir");
    let record = bins.path().join("cwd");
    let bin = stand_in(bins.path(), &format!("pwd -P >'{}'", record.display()));
    let scratch = make_scratch(root.path());
    let (_cancel, ctx) = context();

    run(&scratch, &bin, &ctx, &[], || Ok(Vec::new())).expect("the child runs");

    let cwd = fs::read_to_string(&record).expect("the child recorded its cwd");
    let want = fs::canonicalize(scratch.path()).expect("canonical");
    assert_eq!(Path::new(cwd.trim()), want, "the child starts in its own home");
}

#[test]
fn the_sweep_leaves_an_aged_regular_file_with_a_scratch_name_alone() {
    // Order D3: the round-1 pin that went missing. Only a DIRECTORY with the
    // exact scratch name is swept; a regular file that happens to have the
    // name, however old, is left where it is.
    let root = private_root();
    let file = root.path().join("agctl-codex-login-0000abcd");
    fs::write(&file, b"not a home").expect("write");
    age(&file, Duration::from_secs(60 * 60));

    let fd = open_scratch_root(root.path()).expect("verifies");
    let mut report = Vec::new();
    sweep_stale_at(&fd, root.path(), Duration::from_secs(15 * 60), &mut report);

    assert!(file.exists(), "a regular file is never swept");
    // And never even attempted: without the directory check the sweep would
    // try `AT_REMOVEDIR` on it and report `ENOTDIR` about a file it had no
    // business touching. Mutant: drop the sweep's `Directory` check.
    assert!(report.is_empty(), "nothing to report: {}", String::from_utf8_lossy(&report));
}

#[test]
fn a_child_that_makes_its_home_read_only_still_loses_its_credential() {
    // Order C2 / reviewer probe P-SILENT. A same-uid child `chmod 500`s its
    // home, which would make the credential's unlink fail with EACCES on this
    // login and on every sweep after it. The drop resets the leaf's mode on
    // its own descriptor first. Mutant: no `fchmod` — the credential survives.
    unprivileged();
    let root = private_root();
    let bins = tempfile::tempdir().expect("tempdir");
    let bin = stand_in(bins.path(), "chmod 500 \"$CODEX_HOME\"");
    let mut scratch = make_scratch(root.path());
    let (_cancel, ctx) = context();

    run(&scratch, &bin, &ctx, &[], || Ok(Vec::new())).expect("the child exits 0");
    let credential = scratch.path().join("auth.json");
    assert!(credential.exists(), "the child wrote a credential into a home it then sealed");

    let mut report = Vec::new();
    scratch.discard(&mut report);

    assert!(!credential.exists(), "the credential is removed despite the sealed home");
    assert!(
        report.is_empty(),
        "and nothing needed reporting: {}",
        String::from_utf8_lossy(&report)
    );
}

#[test]
fn a_removal_that_still_fails_is_reported_by_path_and_never_kept_silently() {
    // Order C2 (b). When a removal fails even after the mode reset, the user is
    // told where and why, in one line, with no byte of the file — and the test
    // reads that line from a writer it owns, not from the process's stderr.
    // The scratch ROOT made read-only is a failure the leaf's `fchmod` cannot
    // cure: the leaf itself can no longer be removed from it.
    unprivileged();
    let root = private_root();
    let mut scratch = make_scratch(root.path());
    let leaf = scratch.path().to_path_buf();
    fs::write(leaf.join("auth.json"), b"{\"secret\":\"never printed\"}").expect("write");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o500)).expect("seal the root");

    let mut report = Vec::new();
    scratch.discard(&mut report);

    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("unseal");
    let line = String::from_utf8(report).expect("utf-8");
    assert!(line.contains(&leaf.display().to_string()), "the path is named: {line}");
    assert!(line.contains("remove it by hand"), "and what to do: {line}");
    assert!(!line.contains("never printed"), "and no byte of the credential: {line}");
    assert_eq!(line.lines().count(), 1, "one line: {line}");
}

#[test]
fn a_link_inside_the_scratch_is_removed_as_a_link_and_never_followed() {
    // Order C3 / reviewer mutant N07b. The child writes this tree, and F81's
    // residue already contains links. A link planted INSIDE the leaf pointing
    // at a live home must be unlinked as a link: following it would make agctl
    // empty the live home. Mutant: `remove_tree_at` follows inner links.
    let root = private_root();
    let live = tempfile::tempdir().expect("tempdir");
    let live_auth = live.path().join("auth.json");
    fs::write(&live_auth, b"the live grant").expect("write");

    let scratch = make_scratch(root.path());
    let nested = scratch.path().join("tmp/arg0");
    fs::create_dir_all(&nested).expect("mkdir -p");
    std::os::unix::fs::symlink(live.path(), nested.join("inner")).expect("an inner link");
    let leaf = scratch.path().to_path_buf();

    drop(scratch);

    assert!(!leaf.exists(), "the scratch home is gone");
    assert_eq!(
        fs::read(&live_auth).expect("still there"),
        b"the live grant",
        "nothing behind the link moved"
    );
}

#[test]
fn the_sweep_never_follows_a_link_inside_an_aged_home() {
    // The same property through `sweep_stale_at`: an aged home left by a
    // killed login may hold a link to the live home.
    let root = private_root();
    let live = tempfile::tempdir().expect("tempdir");
    let live_auth = live.path().join("auth.json");
    fs::write(&live_auth, b"the live grant").expect("write");
    let aged = root.path().join("agctl-codex-login-0000feed");
    fs::create_dir(&aged).expect("mkdir");
    std::os::unix::fs::symlink(live.path(), aged.join("inner")).expect("an inner link");
    age(&aged, Duration::from_secs(60 * 60));

    let fd = open_scratch_root(root.path()).expect("verifies");
    sweep_stale_at(&fd, root.path(), Duration::from_secs(15 * 60), &mut Vec::new());

    assert!(!aged.exists(), "the aged home is swept");
    assert_eq!(
        fs::read(&live_auth).expect("still there"),
        b"the live grant",
        "nothing behind the link moved"
    );
}

#[test]
fn the_sweep_removes_an_aged_home_its_child_sealed_read_only() {
    // Order E2 (a). The sweep is the backstop for a login that aborted: its
    // scratch home, and the credential in it, wait for a later login. A child
    // that `chmod 500`ed its home would make every later sweep fail with EACCES
    // unless the sweep, too, resets the mode first. Mutant: the sweep without
    // `fchmod(&leaf)` — the aged credential survives every sweep.
    unprivileged();
    let root = private_root();
    let aged = root.path().join("agctl-codex-login-0000c0de");
    fs::create_dir(&aged).expect("mkdir");
    fs::write(aged.join("auth.json"), b"{}").expect("write");
    fs::set_permissions(&aged, fs::Permissions::from_mode(0o500)).expect("seal it");
    age(&aged, Duration::from_secs(60 * 60));

    let fd = open_scratch_root(root.path()).expect("verifies");
    let mut report = Vec::new();
    sweep_stale_at(&fd, root.path(), Duration::from_secs(15 * 60), &mut report);

    assert!(!aged.exists(), "the sealed aged home and its credential are swept");
    assert!(report.is_empty(), "nothing needed reporting: {}", String::from_utf8_lossy(&report));
}

#[test]
fn the_sweep_reports_an_aged_home_it_cannot_empty_in_exactly_one_line() {
    // Order E2 (b). A 0500 subdirectory can be opened but not written, so the
    // file inside it cannot be unlinked and the home cannot be removed. That
    // is reported, once, by path — never silently kept. Mutant: the sweep
    // without its report line.
    unprivileged();
    let root = private_root();
    let aged = root.path().join("agctl-codex-login-0000dead");
    let stuck = aged.join("stuck");
    fs::create_dir_all(&stuck).expect("mkdir -p");
    fs::write(stuck.join("left.txt"), b"x").expect("write");
    fs::set_permissions(&stuck, fs::Permissions::from_mode(0o500)).expect("seal the subdirectory");
    age(&aged, Duration::from_secs(60 * 60));

    let fd = open_scratch_root(root.path()).expect("verifies");
    let mut report = Vec::new();
    sweep_stale_at(&fd, root.path(), Duration::from_secs(15 * 60), &mut report);

    fs::set_permissions(&stuck, fs::Permissions::from_mode(0o700)).expect("unseal for cleanup");
    let text = String::from_utf8(report).expect("utf-8");
    assert_eq!(text.lines().count(), 1, "exactly one line: {text}");
    assert!(text.contains(&aged.display().to_string()), "the path is named: {text}");
    assert!(text.contains("remove it by hand"), "and what to do: {text}");
}

#[test]
fn a_subdirectory_the_child_made_unreadable_is_still_removed() {
    // Order E2 (c). A 0000 subdirectory cannot be opened, so its contents would
    // be left and the leaf would stay. The walk resets its mode — on the entry
    // itself, never through a link — and removes it. Mutant: `open_subdir`
    // without the `chmodat` fallback.
    unprivileged();
    let root = private_root();
    let mut scratch = make_scratch(root.path());
    let leaf = scratch.path().to_path_buf();
    let hidden = leaf.join("hidden");
    fs::create_dir(&hidden).expect("mkdir");
    fs::write(hidden.join("inside.txt"), b"x").expect("write");
    fs::set_permissions(&hidden, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let mut report = Vec::new();
    scratch.discard(&mut report);

    if leaf.exists() {
        // Only reached under the mutant; restores the tree so the tempdir can go.
        let _ = fs::set_permissions(&hidden, fs::Permissions::from_mode(0o700));
    }
    assert!(!leaf.exists(), "the leaf and the unreadable subdirectory are removed");
    assert!(report.is_empty(), "nothing needed reporting: {}", String::from_utf8_lossy(&report));
}

#[test]
fn a_credential_that_was_made_a_directory_is_removed_and_not_reported() {
    // Order E3. A child that made `auth.json` a directory fails the plain
    // unlink (`EPERM` on Darwin), and the tree walk then removes it. The
    // report must not tell the user to remove by hand something already gone.
    let root = private_root();
    let mut scratch = make_scratch(root.path());
    let leaf = scratch.path().to_path_buf();
    fs::create_dir(leaf.join("auth.json")).expect("a directory where the credential goes");
    fs::write(leaf.join("auth.json").join("inside"), b"x").expect("write");

    let mut report = Vec::new();
    scratch.discard(&mut report);

    assert!(!leaf.exists(), "removed by the walk");
    assert!(report.is_empty(), "and not reported: {}", String::from_utf8_lossy(&report));
}

#[cfg(target_os = "macos")]
#[test]
fn a_credential_that_genuinely_cannot_be_removed_is_reported() {
    // Order E3, the other half. After the leaf's mode reset, nothing a same-uid
    // user can do stops the unlink of a file in it — except the user-settable
    // immutable flag, which the owner may set without privileges on macOS.
    // Then the credential really stays, and must be reported. Mutant: the
    // credential arm without its report.
    let root = private_root();
    let mut scratch = make_scratch(root.path());
    let credential = scratch.path().join("auth.json");
    fs::write(&credential, b"{\"secret\":\"never printed\"}").expect("write");
    let c = std::ffi::CString::new(credential.as_os_str().as_encoded_bytes()).expect("a c string");
    // SAFETY: `c` is a valid NUL-terminated C string that outlives the call,
    // naming a file inside a directory this test owns.
    let sealed = unsafe { libc::chflags(c.as_ptr(), libc::UF_IMMUTABLE) };
    assert_eq!(sealed, 0, "the fixture could not set the immutable flag");

    let mut report = Vec::new();
    scratch.discard(&mut report);

    // SAFETY: as above; clearing the flag so the tempdir can be removed.
    let _ = unsafe { libc::chflags(c.as_ptr(), 0) };
    let text = String::from_utf8(report).expect("utf-8");
    assert!(credential.exists(), "the immutable credential really stayed");
    assert!(text.contains("the credential `auth.json`"), "and it is reported by name: {text}");
    assert!(!text.contains("never printed"), "with no byte of the file: {text}");
}
