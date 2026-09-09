---
name: check
description: Run the full local gate for agentctl — rustfmt, clippy with warnings denied, and the nextest suite — through direnv with the shared dev target-dir this repo requires. Use before declaring any change complete, before committing, or when asked to verify that the tree is clean.
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
it through `env!("CARGO_BIN_EXE_agentctl")`. Never `assert_cmd::Command::cargo_bin`: that
resolves to `./target/debug`, and with `--config ~/.config/rust/config.dev.toml` redirecting
the build to the shared dev target dir (then `/Volumes/tmpfs/target`, now `~/.cache/rust/target`),
it has already found a **stale artifact** on this
machine and tested a binary nobody had just built. A suite that passes against the wrong
binary is worse than one that fails.

## The two separate gates

**AC38** and **AC37** are deliberately not folded into the three commands above. Check both
whenever you touch the feature gating or the test seams.

**AC38** — the no-feature build must fail loudly rather than silently skipping the e2e
suite:

```sh
direnv exec . cargo --config ~/.config/rust/config.dev.toml check --tests --keep-going
```

Expected: it *fails*, and the only error listed is `tests/feature_guard.rs`'s
`compile_error!`. Any other error means a test file lost its `#![cfg(feature = "testing")]`.

**AC37** — a default-feature release artifact must contain no test-only environment-variable
name, and must still contain the production ones. Run the script:

```sh
scripts/release-gate.sh
```

It builds `cargo build --release` (default features, no `--config`, into a scratch
`--target-dir` that is never `./target` and never the shared `~/.cache/rust/target`) and
greps the artifact for two lists. The ten seam names are one representative name per
seam-owning module, not the whole test-only surface — `fixtures/fake-security.sh` alone
defines ten `AGENTCTL_FAKE_SECURITY_*` names on its own. The fake's **write** knob is the
one exception to "one per owner": the keychain write path is the only seam that can change
a keychain, so it is gated by name rather than by family. **Ten seam names, every one of
which must be absent:**

| name | owner |
|------|-------|
| `AGENTCTL_FAULT` | `src/runtime/fault.rs` |
| `AGENTCTL_FAULT_RESUME` | `src/runtime/fault.rs` |
| `AGENTCTL_KEYCHAIN_BACKEND` | `src/secret/mod.rs` |
| `AGENTCTL_SECURITY_BIN` | `src/secret/mod.rs` |
| `AGENTCTL_CLAUDE_USAGE_URL` | `src/provider/claude/usage.rs` |
| `AGENTCTL_CLAUDE_TOKEN_URL` | `src/provider/claude/oauth.rs` |
| `AGENTCTL_CLAUDE_AUTHORIZE_URL` | `src/provider/claude/oauth.rs` |
| `AGENTCTL_FAKE_SECURITY_LOG` | `fixtures/fake-security.sh` |
| `AGENTCTL_FAKE_SECURITY_WRITE_EXIT` | `fixtures/fake-security.sh` (the `-i` write path) |
| `AGENTCTL_NO_BROWSER` | `src/commands/login.rs` |

**Three production names, every one of which must be present:** `AGENTCTL_CONFIG_DIR`,
`AGENTCTL_CLAUDE_USER_AGENT`, `AGENTCTL_CLAUDE_OAUTH_SCOPES`. (The presence half is there so
a build that somehow embedded no strings at all cannot pass by accident.)

A seam in a release artifact is not a style problem. `AGENTCTL_CLAUDE_TOKEN_URL` in a
production binary means a refresh token goes wherever an environment variable points it.
If the gate fails, the build enabled `testing` — never `cargo build --release
--all-features`, never `cargo install --all-features`.

One representative name per seam-owning module: a new seam-owning module adds its
representative to the `seams` array in `scripts/release-gate.sh` **and** to the table
above, in the same change that introduces it.

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
