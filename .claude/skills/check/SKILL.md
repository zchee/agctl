---
name: check
description: Run the full local gate for agentctl — rustfmt, clippy with warnings denied, and the nextest suite — through direnv with the tmpfs target-dir this repo requires. Use before declaring any change complete, before committing, or when asked to verify that the tree is clean.
---

# Local gate

Run all three checks. Do not stop at the first failure — collect every failure, then report
them together, most blocking first.

`direnv exec .` is mandatory: `.envrc` is `layout rust_stable`, which exports the tuned
stable `RUSTFLAGS` this project builds against. `--config ~/.config/rust/config.dev.toml`
redirects dev/test artifacts to `/Volumes/tmpfs/target`; it is correct for clippy and tests,
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

Two acceptance criteria are separate gates, deliberately not folded into the three commands
above: **AC38** requires that `direnv exec . cargo --config ~/.config/rust/config.dev.toml
check --tests` (no features) *fails* with that `compile_error!`, and **AC37** requires that a
default-feature `cargo build --release` produces an artifact containing no test-only
environment-variable name, while the `--all-features` build does contain them. Check both when
touching the feature gating or the test seams.

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
rather than summarizing it. If all three pass, say so in one line — do not pad it.
