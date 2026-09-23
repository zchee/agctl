# AGENTS.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`agctl` is a CLI for managing AI coding agents. Binary-only, single crate, no public
library API. Phase 1 added Claude, phase 2 added switching which account Claude Code uses,
and phase 3 added a second provider, Codex — the module layout follows the data as it moves
and now has one copy per provider where the two differ: `cli.rs` parses (every flag lives
there and nowhere else) and `main.rs` dispatches one arm per command into `commands/`
(`status`, `watch`, `login`, `accounts`, `import`, `doctor`, `completions`, `isolate`,
`export`, `use` for Claude; `commands/codex/` holds the Codex twins of `status`, `watch`,
`login`, `accounts`, `import`, `doctor`, plus `accounts_refresh` and the shared pass
coordination in `pass.rs`); `config/` owns the account registry and `config/paths.rs`
derives every path agctl is allowed to write, for both providers; `provider/claude/` and
`provider/codex/` each hold one provider's knowledge behind the shared `provider` traits —
namespace and keychain-service naming, credential blobs, discovery, OAuth, the usage
request — and `provider/codex/` alone additionally carries what phase 3's login mechanism
and refresh policy need: `login_child.rs` (the child process that spawns the real `codex
login` and reports what it did), `auth_store.rs` plus `refresh.rs` (the D-035 owned-refresh
state machine and its write-ahead marker in `.state/`), and `audit.rs` (the write-receipt
audit log every keychain-affecting write must reach); `secret/` is the only code that
touches credentials on disk (`security_cli.rs` reads the keychain and never writes it,
`file_store.rs` writes the 0600 store, `namespace_lock.rs` and `foreign_activity.rs` decide
whether writing is allowed at all) and is shared by both providers; `usage/` parses and
caches responses; `runtime/` carries the pass coordinator, cancellation, child-process
cleanup and the fault-injection seam; and `render/` plus `tui/` are the two presentations,
table/JSON and the `watch` UI, each with a Codex row renderer alongside Claude's. The
`testing` feature compiles every test seam — both providers' endpoint overrides, the fake
keychain and fake `codex` stand-ins, the fault-injection switch — and must never reach a
release artifact: `scripts/release-gate.sh` proves that. Three more gates are phase-3
specific and run beside it: `scripts/phase3-greps.sh` (AC120 — pattern pins over `src/`,
never the `*_tests.rs` siblings; every check runs twice, once against a snapshot with one
violation planted, where it must fail, then against the real tree, where it must pass),
`scripts/phase3-structural.sh` (AC122 — invariants the compiler enforces rather than a
test, such as a private field or a `pub(super)` constructor: it plants the violating code in
a temporary-index snapshot of the working tree and requires `cargo check` to reject it at
the planted file and line), and `scripts/phase3-version-gate.sh` (AC99 — builds the phase-2
`agctl` from an older commit and proves it refuses a version-2 account registry outright,
writing nothing, while still reading a version-1 one; it builds no Codex binary and reads no
installed `codex`).

On each Claude Code version bump, re-run the route-A′ checklist `.omc/handoffs/rc-hint-a-prime-check.md`: the session registry schema and bridge behaviour are Claude Code internals, and the Remote Control hint degrades silently if they change.

## Run cargo through direnv

```sh
direnv exec . cargo build
```

`.envrc` is `layout rust_stable`, a direnv layout defined in `~/.config/direnv/direnvrc`
that exports a machine-tuned, stable-safe `RUSTFLAGS`:

```
-C target-cpu=<host cpu> -C target-feature=+neon -C opt-level=3 -C codegen-units=1
-C force-frame-pointers=on -C debug-assertions=off -C overflow-checks=off
-C llvm-args=-unroll-threshold=500 -C llvm-args=-enable-dfa-jump-thread
-C link-arg=-Wl,-dead_strip
```

Two consequences worth holding in mind:

- **Debug assertions and overflow checks are off in every build, tests included.**
  `debug_assert!` is inert and integer overflow wraps silently rather than panicking. Do not
  rely on either as a safety net; write real assertions and use checked arithmetic.
- **`.envrc` is untracked** (it matches a global `*.envrc*` ignore), so a fresh clone has no
  `.envrc` and no flags at all. Do not write code whose correctness depends on them.

The sibling layout `layout_rust_nightly` in the same direnvrc carries `-Z` flags. Do not
switch `.envrc` to it: this project is on stable, and stable rustc rejects `-Z` outright with
`the option 'Z' is only accepted on the nightly compiler`, failing every build.

### Benchmarks run bare

Benchmarks are the exception — run them **without** direnv:

```sh
cargo bench
```

`layout rust_stable` pins `-C target-cpu` to the host CPU, which makes results
non-comparable across machines and across runs on a changed host. Let `[profile.bench]`
govern instead.

### Dev and test artifacts go to a shared cache directory

For dev and test profiles, add the dev config so artifacts land in `~/.cache/rust/target`
instead of `./target`:

```sh
direnv exec . cargo --config ~/.config/rust/config.dev.toml nextest run --all-features
direnv exec . cargo --config ~/.config/rust/config.dev.toml clippy --all-targets --all-features -- -D warnings
```

Omit `--config` for release builds meant to populate `./target`.

## Toolchain: stable

`rust-toolchain.toml` pins `channel = "stable"`; `rust-version = "1.98"` is the MSRV and is
honored, not aspirational.

## Testing

- `panic = "abort"` is set on the dev and release profiles, so the shipped and `cargo run`
  binaries abort on panic. Cargo ignores the setting for the **test** profile, so test
  binaries unwind and `#[should_panic]` and `catch_unwind` work normally.
- Unit tests live in a sibling file, never inline. `foo.rs` ends with the declaration below
  and the test body goes in `foo_tests.rs` next to it (`main.rs` → `main_tests.rs`).
  Integration tests go under `tests/`.

  ```rust
  #[cfg(test)]
  #[path = "foo_tests.rs"]
  mod tests;
  ```

  Under `src/bin/`, cargo would autodiscover `*_tests.rs` as binary targets; set
  `autobins = false` and list binaries explicitly in `[[bin]]` if that directory is added.

## Formatting and imports

Run `direnv exec . cargo fmt`. `rustfmt.toml` is all stable options now, so two things it
used to claim to enforce are **conventions you must hold by hand**:

- One `use` per module — do not collapse imports into a nested `use std::{…}` block. The flat
  shape keeps parallel agent lanes editing different lines so their imports merge cleanly.
- Group imports as std, then external crates, then this crate, separated by blank lines.

`use_small_heuristics = "Max"` means anything fitting in 100 columns stays on one line, so
adding a single argument can re-flow an entire call. Expect diffs larger than the edit.

## Issue tracking

Work items live in beads (`br`), issue prefix `agctl`. Use `br ready` to find actionable
work, `br create` to file it, `br update` to move it. The JSONL export (`.beads/issues.jsonl`)
is the git-tracked source of truth; `.beads/beads.db` is not.

<!-- br-agent-instructions-v1 -->

---

## Beads Workflow Integration

This project uses [beads_rust](https://github.com/Dicklesworthstone/beads_rust) (`br`/`bd`) for issue tracking. Issues are stored in `.beads/` and tracked in git.

### Essential Commands

```bash
# View ready issues (open, unblocked, not deferred)
br ready              # or: bd ready

# List and search
br list --status=open # All open issues
br show <id>          # Full issue details with dependencies
br search "keyword"   # Full-text search

# Create and update
br create --title="..." --description="..." --type=task --priority=2
br update <id> --status=in_progress
br close <id> --reason="Completed"
br close <id1> <id2>  # Close multiple issues at once

# Sync with git
br sync --flush-only  # Export DB to JSONL
br sync --status      # Check sync status
```

### Workflow Pattern

1. **Start**: Run `br ready` to find actionable work
2. **Claim**: Use `br update <id> --status=in_progress`
3. **Work**: Implement the task
4. **Complete**: Use `br close <id>`
5. **Sync**: Always run `br sync --flush-only` at session end

### Key Concepts

- **Dependencies**: Issues can block other issues. `br ready` shows only open, unblocked work.
- **Priority**: P0=critical, P1=high, P2=medium, P3=low, P4=backlog (use numbers 0-4, not words)
- **Types**: task, bug, feature, epic, chore, docs, question
- **Blocking**: `br dep add <issue> <depends-on>` to add dependencies

### Session Protocol

**Before ending any session, run this checklist:**

```bash
git status              # Check what changed
git add <files>         # Stage code changes
br sync --flush-only    # Export beads changes to JSONL
git commit -m "..."     # Commit everything
git push                # Push to remote
```

### Best Practices

- Check `br ready` at session start to find available work
- Update status as you work (in_progress → closed)
- Create new issues with `br create` when you discover tasks
- Use descriptive titles and set appropriate priority/type
- Always sync before ending session

<!-- end-br-agent-instructions -->
