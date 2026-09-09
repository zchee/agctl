# agentctl

`agentctl` shows the subscription rate-limit utilization of **several Claude accounts at
once** — the 5-hour window, the weekly window, the weekly per-model window (Fable), and
usage credits — in one table or one terminal UI, without running `claude` and without
disturbing a Claude Code session that is already running.

Phase 1 is **Claude only**. Later phases add other providers and account switching; see
[Scope](#scope).

```
 Account           | Org  | Plan | 5h  | Weekly | Fable (weekly) | Credits                   | Next reset | State
-------------------+------+------+-----+--------+----------------+---------------------------+------------+-------
 alice@example.com | Acme | max  | 21% | 35%    | 56%            | n/a                       | 2h13m      | ok
 bob@example.com   | Acme | max  | 4%  | 12%    | 30%            | $219.56 / $5000.00 (4%)   | 2h13m      | ok
```

The `Credits` cell reads `n/a` when the account has no usage credits, `off` when they are
disabled, `<used> / <limit> (<pct>%)` when capped, and `<used> / Unlimited` when not.

## Build

macOS only in phase 1: account discovery reads the login keychain through `security(1)`.

```sh
cargo build --release
./target/release/agentctl claude status
```

There is no published crate and no installer yet. If you install by hand, install the
**default-feature** binary:

```sh
# correct
cargo build --release
install -m 0755 target/release/agentctl ~/.local/bin/agentctl
```

> **Never build or install with `--all-features`.**
> The `testing` feature compiles the test seams into the artifact, including overrides for
> the OAuth **token endpoint**. A production binary that honours
> `AGENTCTL_CLAUDE_TOKEN_URL` would send your refresh token wherever an environment
> variable pointed it. `cargo install --all-features` and
> `cargo build --release --all-features` are both wrong for anything you intend to run.
> `scripts/release-gate.sh` builds the release artifact the correct way and proves it
> carries none of those seams.

## Commands

Every command lives under `agentctl claude`. `--config-dir DIR` is global and names
*agentctl's* store; it is accepted before or after the subcommand.

### `status` — the table

```sh
agentctl claude status
agentctl claude status --json | jq '.rows[] | {id, state, windows}'
agentctl claude status --account 8ff4… --account bob@example.com
agentctl claude status --all --refresh --timeout 30s
```

| flag | effect |
|------|--------|
| `--json` | the report as JSON instead of a table; the shape is fixed by `schemas/status.v1.json` |
| `--raw` | include the untouched upstream response body under `raw` |
| `--refresh` | refresh expired credentials agentctl owns, and bypass the usage cache |
| `--no-cache` | bypass the usage cache without forcing a token refresh |
| `--all` | also show the rows hidden by default (stale siblings, foreign items, forgotten services) |
| `--account <ID>` | limit the report to one account; repeat for several |
| `--timeout <DUR>` | per-HTTP-request timeout, default `10s` (`10s`, `5m`, `2h`, or a bare number of seconds) |

`<ID>` is the account UUID when that is unambiguous, `<account-uuid>/<organization-uuid>`
when it is not, and the email address when that is unique. A keychain item with no
identity is addressed by its service name.

### `watch` — the same table, live

```sh
agentctl claude watch
agentctl claude watch --interval 10m
```

`--interval` defaults to `300s` and **will not go below 60s** — agentctl declines to poll
an undocumented endpoint faster than that. Keys: `q`, `Esc`, `Ctrl-C` or `Ctrl-D` quit;
`r` refreshes now; arrows or `j`/`k` move the selection. (`Ctrl-C` is bound explicitly
because raw mode swallows the terminal's own interrupt.)

Three things about `watch` that are not visible from the flags:

- A **scheduled** pass may be served from the 300 s usage cache and make no request at
  all. `r` always goes to the wire.
- `watch` has no `--timeout`; every request in a pass uses the 10 s `status` default. An
  `--interval` so large that the schedule arithmetic overflows simply schedules nothing,
  and only `r` fetches.
- `watch` has no `--all`. The footer counts the hidden rows and points at
  `agentctl claude status --all` to see them.

### `login` — mint a credential agentctl owns

```sh
agentctl claude login --label work
agentctl claude login --manual          # paste `code#state` instead of using the loopback
```

The browser goes to Anthropic's authorize page; the code comes back either to a loopback
listener on `127.0.0.1` or, with `--manual`, by paste. Only after the exchange returns —
so only once the account and organization are known — does anything reach disk, and it
reaches `<config-dir>/claude/<account-uuid>/<organization-uuid>/.credentials.json` under
that namespace's lock. A mismatched `state` fails before the exchange and leaves nothing
behind at all.

Logging the same `(account, organization)` in twice overwrites, and only after an
interactive confirmation. There is no `--yes` on `login`, so a non-interactive re-login
refuses rather than replacing a credential another process may be refreshing.

### `accounts` — inspect and edit what agentctl knows

```sh
agentctl claude accounts list [--all]
agentctl claude accounts show <id>
agentctl claude accounts remove <id> [--delete-secret] [--yes]
agentctl claude accounts relocate <id> [--yes]
agentctl claude accounts forget <keychain-service>
agentctl claude accounts unforget <keychain-service>
```

`remove` and `relocate` mutate a namespace and therefore wait for that namespace's lock
before touching anything; both refuse a row agentctl does not own. `forget` and
`unforget` flip one flag in agentctl's own registry — the keychain item they hide is
never read, never written and never removed. `relocate` moves a namespace that was
created as `_unknown-org` into its real organization directory once the organization is
known.

### `import --from keychain` — record what another config directory already has

```sh
agentctl claude import --from keychain --dry-run
agentctl claude import --from keychain --claude-config-dir ~/work/.claude
```

An import **records what is already true and changes nothing else**: it reads Claude Code
credential items belonging to other configuration directories, once, to learn who they
belong to, and files them in agentctl's registry as read-only rows. No credential is
written, moved or deleted; an account already in the registry is reported and left alone,
so a second import is a no-op. `--dry-run` prints the plan and writes nothing at all.

`--claude-config-dir` names a *Claude Code* configuration directory to scan; repeat it for
several. It is deliberately spelled differently from the global `--config-dir`, which
always means agentctl's own store.

### `doctor` — what is actually on this machine

```sh
agentctl claude doctor
agentctl claude doctor --remove-stale ~/.config/agentctl/claude/<acct>/<org>/.oauth_refresh.lock --yes
```

The report covers the keychain preflight, every discovered row with its token expiries,
credentials on this machine that belong to something else and are never read, the
namespace locks and who holds them, the Claude Code locks agentctl is holding itself, the
artefacts a Claude Code session leaves behind, the files a failed write leaves behind, and
the four situations that are not failures but are worth knowing about: a stale sibling, a
forgotten service, two rows holding the same credential, and a namespace still called
`_unknown-org`.

**`--remove-stale` is the only thing in agentctl that deletes anything Claude Code
created, and deleting a lock that is not actually stale can corrupt a running Claude Code
session's credential store.** It is fenced accordingly. The path must:

1. spell a location under `<config-dir>/claude/`, or be named by a held-lock record whose
   process is gone — see below;
2. not be in `.locks/` — those are agentctl's own locks, which nothing ever unlinks;
3. be named `.oauth_refresh.lock`, `.storage-write`, or a legacy `<namespace>.lock`;
4. be a **directory**, reached without following a symbolic link: Claude Code takes every
   one of its locks with `mkdir` and releases it with `rmdir`, so a directory is the only
   shape a lapsed lock has. A regular file at one of those names was written by something
   else; the report calls it anomalous and nothing removes it;
5. be older than 60 s;
6. show the **same modification time in two samples 12 s apart** — Claude Code's lock
   holders heartbeat every five seconds and derive "the holder is alive" from exactly that
   comparison, so an unchanged mtime across twelve seconds is the evidence that nobody is
   holding it;
7. and be confirmed with `--yes`, after the risk has been printed.

Anything else is refused, including a path that satisfies six of the seven. The command
takes about twelve seconds because of step 6.

Step 1 has one exception, and it is the only way `--remove-stale` reaches outside
`<config-dir>/claude/`. When agentctl takes Claude Code's locks itself it records what it
took before taking it, and a crash leaves that record naming directories nothing else will
ever remove. So a path outside the store is accepted when a record in
`<config-dir>/claude/held-locks/` names **that exact path** and the process that wrote it
is gone. A live process, a record naming some other path, and no record at all are each
refused. `doctor` lists those records, and prints the removal command for the ones that
leaked.

## How accounts are discovered

Three sources, and what separates them is who is allowed to write the credential:

1. **The live keychain item** — the credentials the `claude` you run right now is using.
   agentctl reads it and never refreshes or writes it. Identity comes from the blob's own
   `tokenAccount`, or from `.claude.json` for this row only.
2. **Per-configuration-directory keychain items** — a Claude Code credential item named
   after some *other* config directory, recorded by `import --from keychain`. Read once,
   read-only forever.
3. **agentctl-owned namespaces** — `<config-dir>/claude/<account-uuid>/<organization-uuid>/.credentials.json`,
   created by `login`. These are the only credentials agentctl will ever refresh or write.

A keychain item is named after a *directory spelling*, not after an account, so the same
account can appear under several names and two names can point at one directory. agentctl
therefore folds two entries into one row only when their token digests match, never by
path. Two items naming one physical directory but holding different credentials are a
**stale sibling of live**: real, not actionable, hidden by default and counted in the
footer. A blob that names nobody is `identity unknown` and stays visible, because logging
in fixes it. An unrecognised Claude Code item is `unclaimed` and shown; `accounts forget`
hides it.

By default the table shows Live, Owned, `unclaimed` and `identity unknown` rows. Stale
siblings, third-party (`claude-switcher:*`) items and forgotten services are hidden and
counted; `--all` shows them.

## Security posture

- **agentctl never writes the keychain.** The only `security(1)` subcommands it issues are
  `show-keychain-info`, `find-generic-password` and `dump-keychain` — all reads. There is
  no code path that adds, updates or deletes a keychain item.
- **agentctl never writes under a live Claude Code configuration directory, and never
  touches `.claude.json`.** Every file it creates is under its own configuration
  directory.
- **Refresh tokens sit at rest in 0600 files** —
  `~/.config/agentctl/claude/<acct>/<org>/.credentials.json`, in a directory tree created
  at 0700. This is the same posture as Claude Code's own plaintext fallback store, which
  holds the same material in the same shape at the same mode. It is not the keychain, and
  it is not encrypted: anything running as your user can read it.
- **The namespace lock lives outside the namespace** —
  `~/.config/agentctl/claude/.locks/<acct>.<org>.lock` — is created once, and is never
  unlinked, not even by the command that deletes the namespace it protects. `flock` locks
  an inode, so a lock file that can be deleted and recreated is a lock two processes can
  hold at the same time.
- **Claude Code activity in a namespace is detected and the refresh is refused.** Before a
  refresh POST, agentctl checks the write target, takes the lock, re-checks for a Claude
  Code session under the lock, and re-checks once more immediately before the rename. Any
  surprise at any of those points ends in a refusal. There is no flag that overrides it: a
  row reading `claude session detected — refresh refused` is the system working.
- **A row agentctl does not own is never refreshed and, when expired, is not even
  fetched.** Its owner refreshes it; agentctl reports.
- `doctor --remove-stale` is the single exception to "agentctl removes nothing", and it is
  fenced by the seven conditions — and the one record-attested exception to the first of
  them — listed under
  [`doctor`](#doctor--what-is-actually-on-this-machine).

## The usage endpoint

The numbers come from `GET https://api.anthropic.com/api/oauth/usage`, the endpoint
Claude Code's own `/usage` command reads. **It is undocumented.** It is not part of
Anthropic's published API, it carries no compatibility promise, and it may change shape or
disappear in any Claude Code release — which is what
[`docs/re-verify.md`](docs/re-verify.md) is for.

agentctl sends an honest `User-Agent`: `agentctl/<version>`. It does not pretend to be
Claude Code. A client that lies about who it is cannot be rate-limited, deprecated or
excluded separately from the product it is impersonating, which is bad for both sides. If
Anthropic ever starts refusing the honest agent, `AGENTCTL_CLAUDE_USER_AGENT` replaces the
string without waiting for a release.

Reading your own subscription usage with your own credentials is the same operation
`/usage` performs, but you are responsible for your own use of Anthropic's services under
their terms. agentctl reads usage figures and refreshes tokens it owns; it sends no
inference requests and consumes no quota.

**Caching and polling.** A usage response is cached for **300 s** per account, at
`<config-dir>/cache/claude/<acct>.<org>.<sha8>.json`. Inside that window a repeated
`status` answers from disk and makes no request. `--refresh` and `--no-cache` bypass it.
`watch --interval` will not go below **60 s**. When a fetch fails — a 429, a dead network,
a keychain that went away — the last good numbers are shown with the row marked `stale` or
`rate-limited`, rather than a blank cell.

## One switcher at a time

agentctl coexists with Claude Code. It does **not** coexist with another tool that rewrites
the same credentials.

- A third-party menu-bar account switcher (for example `claude-account-switcher`) works by
  deleting and recreating the live keychain item on every switch. agentctl lists those
  tools' `claude-switcher:*` items and never reads or writes them, but it cannot stop the
  live item from being replaced underneath it. Run one switcher, not two.
- `/logout` inside a Claude Code session that is pointed at an agentctl namespace
  **deletes that namespace's credential store**. Claude Code's logout clears both the
  keychain item and the plaintext file. Nothing is corrupted, but that account needs a new
  `agentctl claude login`.
- Two agentctl stores with different `--config-dir` values have independent locks. Logging
  the same account into both makes two independent holders of one refresh chain, and each
  will eventually invalidate the other's token. Use one store per account.

## Environment variables

| variable | meaning |
|----------|---------|
| `AGENTCTL_CONFIG_DIR` | the environment form of `--config-dir`. Default: the XDG configuration directory plus `agentctl`, i.e. `~/.config/agentctl` |
| `AGENTCTL_CLAUDE_USER_AGENT` | replaces the `agentctl/<version>` `User-Agent` on the usage and token endpoints |
| `AGENTCTL_CLAUDE_OAUTH_SCOPES` | replaces the space-separated scope set requested at login. A diagnostic: the server grants the same five scopes whatever is asked for |
| `RUST_LOG` | tracing filter for the diagnostics on stderr. Unset or unparseable means `warn`. `RUST_LOG=agentctl=trace` is the useful setting; no token material is ever logged at any level |

Those four are the whole `AGENTCTL_*` surface agentctl defines. Every other `AGENTCTL_*`
name you may find in the source is a test seam compiled only under the `testing` feature
and absent from a release build — see [Build](#build) and `scripts/release-gate.sh`.

### Read, but owned by Claude Code

agentctl also reads a handful of variables it does not define, because they decide what
Claude Code itself would do:

| variable | meaning |
|----------|---------|
| `CLAUDE_CONFIG_DIR`, `CLAUDE_SECURESTORAGE_CONFIG_DIR` | read on every run by `EnvView::from_process` in `src/provider/claude/namespace.rs`; together they decide which keychain service name agentctl rebuilds — see [docs/re-verify.md](docs/re-verify.md) section 1 |
| `CLAUDE_CODE_OAUTH_TOKEN` | short-circuits Claude Code's own credential lookup; agentctl reports that row read-only and never refreshes it |
| `HOME` | locates the live store |
| `USER`, `LOGNAME` | the `acct` attribute every `find-generic-password` is keyed on (`src/secret/mod.rs`); an unexpected value finds nothing rather than erroring |

## Exit codes

| code | meaning |
|------|---------|
| `0` | the run produced a complete, healthy result |
| `1` | the run failed outright and produced nothing useful — a bad configuration, an I/O failure, a refused command |
| `2` | the run produced output, but at least one **shown** row is degraded: expired, `needs login`, rate-limited, stale, keychain-locked, busy, or refused |

Exit 2 is about rows you can see. A row hidden by default cannot change the exit status,
because you did not ask about it. A pending credential that was replayed successfully is
not a degraded row and exits 0.

## Development

The gate is three commands, and `--all-features` is not optional for the last two — the
test suite fails to compile without it, on purpose:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
```

See `.claude/skills/check/SKILL.md` for what each one is guarding and how to read a
failure, and `AGENTS.md` for the build environment (the whole crate builds with
`-C debug-assertions=off -C overflow-checks=off`, so `debug_assert!` is inert and integer
overflow wraps silently).

Unit tests live in a sibling `foo_tests.rs` beside each `foo.rs`; the end-to-end suite is
`tests/e2e_*.rs`, all of it behind `#![cfg(feature = "testing")]`. Two of those tests are
deliberately slow — one waits out `doctor`'s 12 s stale-sampling interval, one waits out
the 5 s command lock timeout — so the whole suite takes about twelve seconds of wall clock.
No test may touch the real keychain, the real `$HOME`, or the network.

Before releasing an artifact, run `scripts/release-gate.sh`: it builds a default-feature
release into a scratch directory and proves the binary contains no test seam.

After a Claude Code upgrade, work through
[**docs/re-verify.md**](docs/re-verify.md) — agentctl's correctness depends on four
contracts read out of Claude Code's own binary, and an upgrade can change any of them.

## Scope

| phase | scope |
|-------|-------|
| 1 (this) | `status`, `watch`, `login`, `accounts`, `import` (read-only), `doctor` — Claude only, macOS only |
| 2 | switching the account Claude Code uses, without running `claude` |
| 3+ | other providers: Codex, Cursor, Copilot, and the rest |

## License

Apache-2.0. See [LICENSE](LICENSE).
