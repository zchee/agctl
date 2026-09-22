---
name: check
description: Run the full local gate for agctl — rustfmt, clippy with warnings denied, and the nextest suite — through direnv with the shared dev target-dir this repo requires. Use before declaring any change complete, before committing, or when asked to verify that the tree is clean.
---

# Local gate

Run all three checks. Do not stop at the first failure — collect every failure, then report
them together, most blocking first.

`direnv exec .` is mandatory: `.envrc` is `layout rust_stable`, which exports the tuned
stable `RUSTFLAGS` this project builds against. `--config ~/.config/rust/config.dev.toml`
redirects dev/test artifacts to `~/.cache/rust/target`; it is correct for clippy and tests,
and wrong for release builds meant to populate `./target`.

```sh
direnv exec . cargo fmt --check
direnv exec . cargo --config ~/.config/rust/config.dev.toml clippy --all-targets --all-features -- -D warnings
direnv exec . cargo --config ~/.config/rust/config.dev.toml nextest run --all-features
```

`--all-features` is not optional. The `testing` feature compiles the test seams — the fake
keychain backend, the endpoint URL overrides, the fault-injection switch — and
`tests/feature_guard.rs` fails the build with a `compile_error!` without it, so a run that
omits the flag does not quietly skip the e2e suite.

Tests that spawn the binary — `tests/cli_smoke.rs` and every `tests/e2e_*.rs` — must reach
it through `env!("CARGO_BIN_EXE_agctl")`. Never `assert_cmd::Command::cargo_bin`: that
resolves to `./target/debug`, and with `--config ~/.config/rust/config.dev.toml` redirecting
the build to the shared dev target dir (then `/Volumes/tmpfs/target`, now `~/.cache/rust/target`),
it has already found a **stale artifact** on this
machine and tested a binary nobody had just built. A suite that passes against the wrong
binary is worse than one that fails.

## The two separate gates

**AC38** and **AC37/AC78** are deliberately not folded into the three commands above. Check
both whenever you touch the feature gating or the test seams. `scripts/release-gate.sh` also
carries the two documentation gates (**AC77**, **AC83**), so run it whenever you touch
`README.md`, `docs/` or `scripts/` as well — see "The documentation gates" below.

**AC38** — the no-feature build must fail loudly rather than silently skipping the e2e
suite:

```sh
direnv exec . cargo --config ~/.config/rust/config.dev.toml check --tests --keep-going
```

Expected: it *fails*, and the only error listed is `tests/feature_guard.rs`'s
`compile_error!`. Any other error means a test file lost its `#![cfg(feature = "testing")]`.

**AC37 / AC78** — a default-feature release artifact must contain no test-only
environment-variable name, and must still contain the production ones. Run the script:

```sh
scripts/release-gate.sh
```

It runs `scripts/docs-gate.sh` first (no build needed, so a prose failure is reported in
seconds), then builds `cargo build --release` (default features, no `--config`, into a scratch
`--target-dir` that is never `./target` and never the shared `~/.cache/rust/target`) and
greps the artifact for two lists. The seam names are the ones in `scripts/release-gate.sh`:
one representative name per seam-owning module, and only names a `testing` build of the
binary can carry as a string (the fake stand-ins' knob names and the fake `codex` prefix
cannot, so they are not listed). **The seam names, every one of which must be absent:**

| name | owner |
|------|-------|
| `AGCTL_FAULT` | `src/runtime/fault.rs` |
| `AGCTL_FAULT_RESUME` | `src/runtime/fault.rs` |
| `AGCTL_KEYCHAIN_BACKEND` | `src/secret/mod.rs` |
| `AGCTL_SECURITY_BIN` | declared `src/secret/mod.rs`; read by `src/secret/keychain_write.rs` (the write path) and `src/secret/mod.rs` (the read path) |
| `AGCTL_CLAUDE_USAGE_URL` | `src/provider/claude/usage.rs` |
| `AGCTL_CLAUDE_TOKEN_URL` | `src/provider/claude/oauth.rs` |
| `AGCTL_CLAUDE_AUTHORIZE_URL` | `src/provider/claude/oauth.rs` |
| `AGCTL_CLAUDE_PROFILE_URL` | `src/provider/claude/oauth.rs` (the live swap's profile GET) |
| `AGCTL_NO_BROWSER` | `src/commands/login.rs` |
| `AGCTL_CODEX_BIN` | `src/provider/codex/login_child.rs` (phase 3; listed from S29b, which introduces the name — the module that reads it lands at S34, and `scripts/phase3-greps.sh` pins it to that one file) |
| `AGCTL_CODEX_USAGE_URL` | `src/provider/codex/usage.rs` (phase 3, S31; `scripts/phase3-greps.sh` pins it to that one file) |
| `AGCTL_CODEX_TOKEN_URL` | `src/provider/codex/oauth.rs` (phase 3, S32; `scripts/phase3-greps.sh` pins it to that one file) |
| `codex_login_before_install` | `src/commands/codex/login.rs` (phase 3, S34: the pause point between `verify_login` and `install`) |
| `agctl lock order violated: ` | `src/runtime/lock_order.rs` (phase 3, S34: the prefix of the lock-order witness's three messages) |

Not in this table: `agctl unaudited write receipt` (S34 C2-a's `UNAUDITED_RECEIPT`, in
`src/provider/codex/auth_store.rs`). Removed at S37: measured absent from an all-features
release build, flags cleared and with this project's own build flags applied, 2026-09-22 —
its absence here proved nothing, since nothing a release build produces was ever shown to
carry it. The guards that remain: the drop check itself under `cargo nextest
run --all-features`, and `scripts/phase3-greps.sh`'s `receipt_check`/`reached_audit` rules.

**Four production names, every one of which must be present:** `AGCTL_CONFIG_DIR`,
`AGCTL_CLAUDE_USER_AGENT`, `AGCTL_CLAUDE_OAUTH_SCOPES`, and — from S33, once
`agctl codex status` builds the Codex usage client — `AGCTL_CODEX_USER_AGENT`. (The presence half is there so
a build that somehow embedded no strings at all cannot pass by accident.)

A seam in a release artifact is not a style problem. `AGCTL_CLAUDE_TOKEN_URL` in a
production binary means a refresh token goes wherever an environment variable points it.
If the gate fails, the build enabled `testing` — never `cargo build --release
--all-features`, never `cargo install --all-features`.

One representative name per seam-owning module: a new seam-owning module adds its
representative to the `seams` array in `scripts/release-gate.sh` **and** to the table
above, in the same change that introduces it. Some `AGCTL_*` names in the tree are
deliberately outside the array, for two different reasons. `AGCTL_LOCK_CHILD_ROLE` and
`AGCTL_LOCK_CHILD_DIR` live only in a `#[cfg(test)]` sibling and are covered more strongly by
`tests/e2e_lock.rs`; `AGCTL_E2E_MARKER` is set on a child by a test and the crate never reads
it — none of the three shows up in a `src`-only sweep at all, since all three live in
`*_tests.rs` files. Eleven more are dead code in every binary this crate ships (the
`AGCTL_FAKE_SECURITY_*` family and `AGCTL_FAKE_CODEX_`, added since `e6c00e9`; see below for
why): `rg -o --no-filename 'AGCTL_[A-Z0-9_]+' src --glob '!*_tests.rs' | sort -u | wc -l`
finds **27** distinct names outside `*_tests.rs`, of which 4 are the production list above
and 12 are in the `seams` array, leaving **11** genuinely outside both by that measure. The
script says so in its own comments; do not "tidy" any of them in.

`AGCTL_FAKE_CODEX_` is outside the array for a different reason: it is only ever a
`starts_with` argument, so no build carries it as a string at all and an artifact grep
could not fail for it. `scripts/phase3-greps.sh` guards it with a source rule,
`fake_prefix`, that pins the single spelling and the `#[cfg(feature = "testing")]`
directly above it. The drop check's prefix has a second guard of the same shape,
`receipt_check`, **as well as** its entry in the array above.

## The documentation gates

`scripts/docs-gate.sh` runs on its own as well as from the release gate, and needs no build:

```sh
scripts/docs-gate.sh
```

**AC77** — `README.md` must not carry the retired absolute claim that agctl never writes the
keychain (true in phase 1, false from the moment `use --live` landed), and must name both
`WriteTarget` constructors, `WriteTarget::migrated` and `WriteTarget::live`. Naming them is
what makes the claim checkable: the set of keychain items agctl can write is exactly the set
those two can name, so the README can be diffed against `src/secret/keychain_write.rs` by
anyone who doubts it. Rewording that paragraph without keeping both names fails the gate.

**AC83** — the two development wrappers this file documents (the direnv invocation and the
dev-profile cargo config) must appear in **no** reader-facing surface: not `README.md`, not
`docs/`, not `scripts/`, not `src/`. They belong here and in `AGENTS.md` (which `CLAUDE.md`
symlinks to), and nowhere else: `.envrc` is untracked, so a fresh clone has no layout and no
`RUSTFLAGS`, and a reader who copies a wrapped command gets an error rather than a build.

Two things about that script a reviewer will want to "fix" and must not:

- Its two patterns are spelled with a bracketed space and an escaped dot rather than as
  plain literals. The script lives under `scripts/`, which AC83 scans, so a literal would
  match itself and the gate could never pass.
- The AC83 check runs **first against a planted temp file** that contains both strings and is
  required to fail. That self-test is there because an earlier spelling of this rule joined
  its two patterns with a backslash-pipe — an escaped literal pipe in ripgrep's regex, not
  alternation — so the gate searched for a string containing a pipe character, found it
  nowhere, and passed unconditionally. A gate that has never been seen to fail is not a gate.

Benchmarks are not part of this gate. When you do run them, run them **bare** — `cargo bench`
with no direnv — because `layout rust_stable` pins `-C target-cpu` to the host CPU.

## Reading the results

- **`the option 'Z' is only accepted on the nightly compiler`** means a nightly `RUSTFLAGS`
  leaked in — usually `.envrc` switched to `layout rust_nightly`, or a parent shell exported
  the nightly flag set. This project is on stable; fix the environment, not the code.
- **Clippy is gated at `-D warnings`.** There is no `clippy.toml` and no `[lints]` table, so
  the default lint set is the whole policy. Fix the lint; do not reach for `#[allow]` when
  `#[expect(..., reason = "...")]` will do.
- **A test that passes suspiciously** may be leaning on a check that is compiled out:
  `layout rust_stable` sets `-C debug-assertions=off -C overflow-checks=off`, so
  `debug_assert!` is inert and overflow wraps silently. Assert with real assertions.
- **`nextest` reporting `no tests to run`** is a failure now: the crate carries unit tests
  in sibling `*_tests.rs` files and the `tests/` suite, so an empty run means the wrong
  target dir, a missing `--all-features`, or a broken test discovery — not a clean tree.

## Reporting

State plainly which of the three passed and which failed, and paste the actual failing output
rather than summarizing it. If all three pass, say so in one line — do not pad it. Say
separately whether you ran the AC37 and AC38 gates, and paste `scripts/release-gate.sh`'s
output verbatim when you did.
