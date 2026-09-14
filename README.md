# agctl

`agctl` shows the subscription rate-limit utilization of **several Claude accounts at
once** — the 5-hour window, the weekly window, the weekly per-model window (Fable), and
usage credits — in one table or one terminal UI, without running `claude` and without
disturbing a Claude Code session that is already running.

It also switches which account Claude Code uses, among the accounts agctl owns — the ones
`agctl claude login` created. `use <id>`, `exec` and `env` prepare an isolated Claude Code
session for one account — `use` starts `claude` in it, `exec` runs one command in it, `env`
points your shell at it — and leave the account your running Claude Code uses alone.
`use --live <id>` hot-swaps the credential your running Claude Code reads, without running
`claude`, and `use --undo` puts the previous one back.

Phases 1 and 2 are **Claude only** and **macOS only**. Later phases add other providers;
see [Scope](#scope).

```
 Account           | Org  | Plan | 5h  | Weekly | Fable (weekly) | Credits                 | 5h reset        | Weekly reset         | State
-------------------+------+------+-----+--------+----------------+-------------------------+-----------------+----------------------+-------
 alice@example.com | Acme | max  | 21% | 35%    | 56%            | n/a                     | 1h12m (4:15 PM) | 2d22h (Sun 02:00 PM) | ok
 bob@example.com   | Acme | max  | 4%  | 12%    | 30%            | $219.56 / $5000.00 (4%) | 2h13m (5:16 PM) | 2d22h (Sun 02:00 PM) | ok
```

The `Credits` cell reads `n/a` when the account has no usage credits, `off` when they are
disabled, `<used> / <limit> (<pct>%)` when capped, and `<used> / Unlimited` when not.

The two reset columns say **when** each window rolls over as well as how long is left: the
5-hour window in `5h reset`, the seven-day all-models window in `Weekly reset`. Each cell
leads with the countdown and follows it with the absolute local time in parentheses, and
within a column every countdown lines up flush left and every closing parenthesis lines up
flush right, so `2d22h` and a shorter countdown in the same column still end at the same
right edge. The absolute time carries as much of the date as it takes to name the day —
nothing for a reset later today (`4:15 PM`), the weekday for another day this week
(`Sun 02:00 PM`), the date from a week out (`Sep 16 02:00 PM`) — and the hour is zero-padded
once a weekday or a date joins it, so every absolute time inside one of those two shapes is
the same width; today's bare clock time keeps the un-padded hour. A reset that has already
passed reads `now (11:59 PM)`, and a window agctl has no reset for is an em dash. A per-model
weekly window other than Fable gets a continuation row of its own, and its reset appears in
`Weekly reset`.

## Build

macOS only: account discovery reads the login keychain through `security(1)`.

```sh
cargo build --release
./target/release/agctl claude status
```

There is no published crate and no installer yet. If you install by hand, install the
**default-feature** binary:

```sh
# correct
cargo build --release
install -m 0755 target/release/agctl ~/.local/bin/agctl
```

> **Never build or install with `--all-features`.**
> The `testing` feature compiles the test seams into the artifact, including overrides for
> the OAuth **token endpoint** and the **profile endpoint**. A production binary that
> honours `AGCTL_CLAUDE_TOKEN_URL` would send your refresh token wherever an environment
> variable pointed it, and one that honours `AGCTL_CLAUDE_PROFILE_URL` would do the same
> with the live item's access token. `cargo install --all-features` and
> `cargo build --release --all-features` are both wrong for anything you intend to run.
> `scripts/release-gate.sh` builds the release artifact the correct way and proves it
> carries none of those seams.

### Shell completions

```sh
# zsh — add to ~/.zshrc, after compinit (the script calls compdef, which
# only exists once the completion system is loaded)
autoload -Uz compinit && compinit
eval "$(agctl completions zsh)"
# or install the file once into a directory you own and put on fpath:
mkdir -p ~/.zfunc && agctl completions zsh > ~/.zfunc/_agctl
fpath=(~/.zfunc $fpath)   # before compinit in ~/.zshrc
# bash — add to ~/.bashrc
eval "$(agctl completions bash)"
# fish
agctl completions fish > ~/.config/fish/completions/agctl.fish
```

`elvish` and `powershell` are also accepted. The script is generated from the same
`clap` definition the binary parses, so it never drifts from the real flag set. On
bash older than 4.4 (macOS ships 3.2) the candidates come back sorted alphabetically
rather than in the order the help text lists them; everything else is the same.

## Commands

Every provider command lives under `agctl claude`; the one top-level command is
`agctl completions`, above. `--config-dir DIR` is global and names *agctl's* store; it
is accepted before or after the subcommand.

### `status` — the table

```sh
agctl claude status
agctl claude status --json | jq '.rows[] | {id, state, windows}'
agctl claude status --account 8ff4… --account bob@example.com
agctl claude status --all --refresh --timeout 30s
```

| flag | effect |
|------|--------|
| `--json` | the report as JSON instead of a table; the shape is fixed by `schemas/status.v1.json` |
| `--raw` | include the untouched upstream response body under `raw` |
| `--refresh` | refresh expired credentials agctl owns, and bypass the usage cache |
| `--no-cache` | bypass the usage cache without forcing a token refresh |
| `--all` | also show the rows hidden by default (stale siblings, foreign items, forgotten services) |
| `--by-identity` | fold the live credential into the row of the account that owns it, and add a `Kind` column; table only |
| `--account <ID>` | limit the report to one account; repeat for several |
| `--timeout <DUR>` | per-HTTP-request timeout, default `10s` (`10s`, `5m`, `2h`, or a bare number of seconds) |

`<ID>` is the account UUID when that is unambiguous, `<account-uuid>/<organization-uuid>`
when it is not, and the email address when that is unique. A keychain item with no
identity is addressed by its service name.

One address can legitimately appear on two rows — a credential agctl owns and the one
Claude Code is signed in as can be the same account with two independent token pairs. The
owned row says so, with `same identity as live` in its `State` column and
`"same_identity_as": "live"` in `--json`; the rows stay separate, because each pair
expires, refreshes and can be revoked on its own.

`--by-identity` collapses that pair into one table row instead, with a `Kind` column
reading `live+owned`. The owned row is the one that survives, because it is the one
agctl can refresh, relocate or forget. It is a table flag: `--json` still emits one
object per credential source, so the two row counts differ under it, and a live row in a
failing state is never folded away.

For an account agctl owns, the `Plan` column comes from `GET /api/oauth/profile`, and it is
filled at two points only: at `login`, and when `status` or `watch` next refreshes a
credential that has none — which they do only once it has expired, `--refresh` included.
Once the plan and the rate-limit tier are both recorded, it is not asked again, so a plan
that changes later shows after the next `agctl claude login`. The cell is Claude Code's own
word — `max`, `pro`, `team` or `enterprise`. An organization type Claude Code does not map
leaves it `—`, and agctl asks again at each refresh. A pass with too little time left, such
as one under a very short `--timeout`, skips the question for that refresh rather than delay
saving the credential.

### `watch` — the same table, live

```sh
agctl claude watch
agctl claude watch --interval 10m
```

`--interval` defaults to `300s` and **will not go below 60s** — agctl declines to poll
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
  `agctl claude status --all` to see them.

### `login` — mint a credential agctl owns

```sh
agctl claude login --label work
agctl claude login --manual          # paste `code#state` instead of using the loopback
agctl claude login --no-duplicate    # refuse if this account is already the live one
```

The browser goes to Anthropic's authorize page; the code comes back either to a loopback
listener on `127.0.0.1` or, with `--manual`, by paste. Only after the exchange returns —
so only once the account and organization are known — does anything reach disk, and it
reaches `<config-dir>/claude/<account-uuid>/<organization-uuid>/.credentials.json` under
that namespace's lock. A mismatched `state` fails before the exchange and leaves nothing
behind at all.

After the exchange, `login` asks `GET /api/oauth/profile` once, with the new access token,
and stores the account's plan and rate-limit tier with the credential; that is what fills
the `Plan` column. The profile never changes which account or organization the exchange
named, and a tier that is not in Claude Code's own shape is not recorded. When the request
fails and the exchange did name the account, the login succeeds without a plan and the next
refresh asks again.

Logging the same `(account, organization)` in twice overwrites, and only after an
interactive confirmation. There is no `--yes` on `login`, so a non-interactive re-login
refuses rather than replacing a credential another process may be refreshing.

Logging in as the account Claude Code is *already* signed in as is allowed, and prints a
one-line notice on standard error saying both sessions stay valid: two independent token
pairs for one account is a supported setup. `--no-duplicate` refuses that case instead,
exits 1 and writes nothing; its message names the `.claude.json` the claim came from, so a
stale one can be checked. To change which account Claude Code itself uses, that is
`agctl claude use --live <id>`, not a second login.

### `accounts` — inspect and edit what agctl knows

```sh
agctl claude accounts list [--all]
agctl claude accounts show <id>
agctl claude accounts remove <id> [--delete-secret] [--yes]
agctl claude accounts relocate <id> [--yes]
agctl claude accounts forget <keychain-service>
agctl claude accounts unforget <keychain-service>
```

`remove` and `relocate` mutate a namespace and therefore wait for that namespace's lock
before touching anything; both refuse a row agctl does not own. `forget` and
`unforget` flip one flag in agctl's own registry — the keychain item they hide is
never read, never written and never removed. `relocate` moves a namespace that was
created as `_unknown-org` into its real organization directory once the organization is
known.

### `import --from keychain` — record what another config directory already has

```sh
agctl claude import --from keychain --dry-run
agctl claude import --from keychain --claude-config-dir ~/work/.claude
```

An import **records what is already true and changes nothing else**: it reads Claude Code
credential items belonging to other configuration directories, once, to learn who they
belong to, and files them in agctl's registry as read-only rows. No credential is
written, moved or deleted; an account already in the registry is reported and left alone,
so a second import is a no-op. `--dry-run` prints the plan and writes nothing at all.

`--claude-config-dir` names a *Claude Code* configuration directory to scan; repeat it for
several. It is deliberately spelled differently from the global `--config-dir`, which
always means agctl's own store.

### `doctor` — what is actually on this machine

```sh
agctl claude doctor
agctl claude doctor --remove-stale ~/.config/agctl/claude/<acct>/<org>/.oauth_refresh.lock --yes
```

The report covers the keychain preflight, every discovered row with its token expiries,
credentials on this machine that belong to something else and are never read, the
namespace locks and who holds them, the Claude Code locks agctl is holding itself, the
artefacts a Claude Code session leaves behind, the files a failed write leaves behind, the
credential a `use --live` parked in a namespace, every isolated session directory with the
state of its links and the keys it was seeded with, and the four situations that are not
failures but are worth knowing about: a stale sibling, a forgotten service, two rows holding
the same credential, and a namespace still called `_unknown-org`.

Its `store` block names the audit log and whether agctl can append to it, and has one
`claude config` row: the configuration file `use --live` rewrites and the lock beside it,
both as literal paths, then what the newest config write recorded:

- `no config write recorded`;
- `the newest live write (<audit id>) has no config write after it`, which is what a
  crash between a swap and its config step leaves;
- `last config write …` with its outcome, reason and audit ids, then whether its account
  `agrees with the file`, `differs from the file`, or cannot be compared with it.

The row prints audit ids, outcome words and those fixed phrases, never an account id or an
email.

**`--remove-stale` is the only thing in agctl that deletes anything Claude Code
created, and deleting a lock that is not actually stale can corrupt a running Claude Code
session's credential store.** It is fenced accordingly. The path must:

1. spell a location under `<config-dir>/claude/`, or be named by a held-lock record whose
   process is gone — see below;
2. not be in `.locks/` — those are agctl's own locks, which nothing ever unlinks;
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
`<config-dir>/claude/`. When agctl takes Claude Code's locks itself it records what it
took before taking it, and a crash leaves that record naming directories nothing else will
ever remove. So a path outside the store is accepted when a record in
`<config-dir>/claude/held-locks/` names **that exact path** and the process that wrote it
is gone. A live process, a record naming some other path, and no record at all are each
refused. `doctor` lists those records, and prints the removal command for the ones that
leaked. A `use --live` killed while it held the live store's three locks leaves exactly
such a record, and this is how those lock artefacts are removed.

### `use` — an isolated Claude Code session for one account

```sh
agctl claude use bob@example.com
agctl claude use bob@example.com --fresh-context --no-mcp
agctl claude use bob@example.com --json
agctl claude use --forget bob@example.com
```

`use <id>` starts `claude` from your `PATH` as that account, in a Claude Code configuration
directory of its own, and exits with `claude`'s exit code. It does not change which account
the Claude Code you already run is using: the session has its own credential store, named
by the environment below. Only an account agctl owns can be isolated. `--new-only` is
accepted as another name for this default.

The session directory is `<config-dir>/claude-sessions/<account-uuid>/<organization-uuid>/`,
created at 0700. Each run places what is missing and leaves what is already correct alone:

- **Tier 1** — `settings.json`, `CLAUDE.md` and `skills` are symbolic links into your live
  Claude Code configuration directory (`~/.claude`, or `CLAUDE_CONFIG_DIR`), so the session
  behaves the way your own does.
- **Tier 2** — `projects`, `shell-snapshots`, `file-history`, `sessions` and `session-env`
  are directory links too, so the session can resume your work. `--fresh-context` leaves
  them out.
- **`mcp.json`** links to the live `~/.claude.json`, and `claude` is started with
  `--mcp-config` pointing at it, so the session has your MCP servers. `--no-mcp` leaves out
  the link and the flag.
- **`.claude.json`** is the session's own Claude Code configuration, seeded once at 0600
  with your onboarding and editor preferences from the live file — `theme`, `editorMode`,
  `autoUpdates` and a dozen more — and never an account, cache, project or MCP key. agctl
  never rewrites it after the first run.

`history.jsonl` is never linked, because it has a lock of its own. An entry your live
directory does not have is skipped. Anything agctl did not put at one of these names is
refused, naming the path, and nothing after it is touched. The seed is read from the live
file under Claude Code's own config lock when that lock is free — one read; agctl never
waits on that lock and never breaks it — and otherwise read twice and compared, up to four
times, so a file Claude Code is halfway through writing is never copied.

`claude` gets your environment with three changes: `CLAUDE_SECURESTORAGE_CONFIG_DIR` names
the account's namespace, whose spelling Claude Code hashes into the name of the keychain
item it uses; `CLAUDE_CONFIG_DIR` names the session directory; and `CLAUDE_CODE_OAUTH_TOKEN`
is removed, because it would bypass the stored credential.

| flag | effect |
|------|--------|
| `--claude-config-dir <PATH>` | use this session directory instead of the generated one |
| `--fresh-context` | leave out the tier 2 links |
| `--no-mcp` | leave out the MCP link and the `--mcp-config` flag |
| `--json` | print the session's paths as JSON before `claude` starts |
| `--forget <ID>` | remove that account's session directory instead of starting one |
| `--yes` | do not ask before `--forget` removes anything |

A `--claude-config-dir` path must be absolute, with no `.` or `..` in it, and may not be the
live Claude Code configuration directory itself. `--json` prints `securestorage_dir`,
`config_dir`, `session_path` and `mcp_config`.

`use --forget <id>` removes the generated session directory and everything in it — its
links (never their targets), its seed, and whatever Claude Code wrote there, such as the
session's own `history.jsonl` and, for a `--fresh-context` session, its transcripts — after
a confirmation. The account's credentials and its namespace are left alone, and a
`--claude-config-dir` directory is not removed.

### `exec` — one command as an account

```sh
agctl claude exec bob@example.com -- claude
agctl claude exec bob@example.com -- env
```

`exec` prepares the same session directory as `use` and runs the command directly — no
shell — with the same three changes to your environment, then exits with that command's
exit code (`128 + n` when signal `n` killed it). `--mcp-config` is added only when the
command's name is exactly `claude`, because any other program would not understand it.
`use <id>` is `exec <id> -- claude`. `--claude-config-dir`, `--fresh-context` and
`--no-mcp` mean what they mean for `use`.

### `env` — the same session, in your shell

```sh
eval "$(agctl claude env bob@example.com)"               # zsh or bash
agctl claude env bob@example.com --shell fish | source   # fish
```

`env` prepares the session directory and prints the commands that point the current shell
at it: an `export` of the two variables (`set -gx` in fish), an `unset` of
`CLAUDE_CODE_OAUTH_TOKEN` with a comment saying why (`set -e`), and, unless `--no-mcp`, an
alias `claude` that adds `--mcp-config` (a function in fish). Every value is single-quoted.
An alias reaches only an interactive shell; a script started from that shell does not see
it. `--shell` is `zsh` (the default), `bash` or `fish`.

### `use --live` — hot-swap the account Claude Code is using

```sh
agctl claude use --live bob@example.com
agctl claude use --live bob@example.com --yes --json
agctl claude use --undo
```

`use --live <id>` writes `<id>`'s credential into the keychain item your running Claude
Code reads — `Claude Code-credentials` in the default layout — so every session using the
live store runs as that account from its next message, within 30 s, with no restart and
without running `claude`. It is opt-in: without `--live`, `use` starts an isolated session.
agctl reports what the item holds; it cannot see a session switch.

Both accounts must be ones agctl owns: `<id>`, and the account whose credential the item
holds now. That credential is not thrown away, unless it is an older copy of `<id>`'s own
credential, which the incoming one supersedes. It is **parked** in its own account's
namespace as `.credentials.adopted.json`, and `use --undo` puts it back from there. When no
account agctl owns is the live one, the swap refuses (exit 14) and says to
`agctl claude login` that account first.

Before the prompt, agctl changes no credential: it reads its registry, its environment and
the live item once, and asks `GET /api/oauth/profile` with that item's own access token —
which is how it learns whose credential the item holds. Then it asks once, naming the store,
the incoming account and both credentials' digest prefixes, and that one answer covers
every write below. `--yes` answers it; with no terminal and no `--yes` the swap is
`cancelled` (exit 20). After the answer, one swap:

1. refreshes `<id>`'s credential if it has expired, and saves the new pair to `<id>`'s own
   store;
2. parks the displaced credential, under agctl's own namespace locks;
3. writes the item — one `add-generic-password -U`, over a pipe — under Claude Code's three
   credential-store locks, starting no write that cannot finish inside their 3 s budget;
4. releases those locks and appends the write to the audit log, then rewrites
   `~/.claude.json` under Claude Code's config lock: `oauthAccount` becomes `<id>`'s, from
   its profile, and five stale caches are deleted (see [Security posture](#security-posture));
   this step gets an audit line of its own. Running Claude Code sessions watch that file
   once a second, which is what the completion sentence's "within a second" rests on.

On success it prints `swapped:` with the item and the new credential's digest prefix, says
the swap takes effect on your next message, within 30 s — and, when `~/.claude.json` was
rewritten, adds that running sessions show the new account within a second — and asks you
to run `/model` once in a running session to refresh its model access. It then names where
the displaced credential was parked and the audit id. `--json` does not imply `--yes`: it
prints a `"kind": "plan"` document before the prompt and a `"kind": "outcome"` document at
the end, so read the last document rather than the second.

**When `~/.claude.json` was not rewritten.** The config step never changes the swap's
outcome. If it does not land — Claude Code held its config lock, the file changed under
agctl's lock, the profile request failed — the swap still exits 0, `--json` reports the
step in `config` (`outcome`, `reason`, `backup`, `hold_ms`, `budget_ms`) and in `warnings`,
and stderr says the file was not updated and why, that running sessions keep showing the
previous account, and to run the same `agctl claude use --live <id>` again. That re-run is
the fix: when the item still holds the account, the swap answers `already_active` (exit 0)
and offers to rewrite the file on its own — a prompt of its own, which `--yes` also answers
and which writes nothing when declined. After `--undo`, the sentence names `use --live` with the
account the undo put back. A missing `~/.claude.json` is only a `note:`: Claude Code writes
`oauthAccount` itself at its next start.

**`--undo`.** `use --undo` reverses the most recent `--live` swap: the parked credential
goes back into the item, the credential it displaces goes back to its own account's
namespace, and `~/.claude.json` is rewritten for the account restored — the same prompt,
locks, audit lines and exit codes. After an applied undo, a second `--undo` reverses that
undo and swaps forward again. If the item changed hands after the swap — a `/login` inside
Claude Code, another switcher — `--undo` does not guess: it answers `already_active` when
the item already holds the account it would restore, and refuses (exit 27) when it holds
anyone else.

**From an isolated session's shell.** When `CLAUDE_SECURESTORAGE_CONFIG_DIR` is set and not
empty — as `use`, `exec` and `env` set it — `use --live <id>` swaps the keychain item of the
namespace it names instead of the live one, and leaves `~/.claude.json` alone. The variable
must spell a namespace agctl owns, byte for byte, or the swap refuses (exit 15). A
`use --undo` of a live swap run from such a shell refuses (exit 13) rather than lock one
store and write another; run it without the variable.

**What it will not do.** It never refreshes the live credential; Claude Code does that. It
refuses while `CLAUDE_CODE_OAUTH_TOKEN` is set in its own environment (exit 11), against a
live store whose credential has not moved into the keychain yet (exit 24: run `claude`
once), and for an incoming account whose credential lives only in its namespace's keychain
item, which cannot be swapped in yet (exit 14).

**Known limitation: one grant, two copies.** After a live swap, the incoming account's token
pair is in two places: the live item and that account's own agctl store. Anthropic rotates
a refresh token when it is used, so whichever side refreshes first leaves the other holding
a dead one. A `status` refresh of that account can cost the live session its next refresh,
and the session's own refresh can leave agctl's copy needing a new `login`.

## How accounts are discovered

Three sources, and what separates them is who is allowed to write the credential:

1. **The live keychain item** — the credentials the `claude` you run right now is using.
   agctl reads it and never refreshes it; only `use --live` and `use --undo` write it. In
   the table, identity comes from the blob's own `tokenAccount`, or from `.claude.json` for
   this row only. `use --live` trusts neither: Claude Code writes the item with no
   `tokenAccount`, and a `.claude.json` a swap could not rewrite still names the account the
   swap displaced. So it asks `GET /api/oauth/profile` with the item's own access token, and
   refuses (exit 29) when nothing can say whose credential the item holds.
2. **Per-configuration-directory keychain items** — a Claude Code credential item named
   after some *other* config directory, recorded by `import --from keychain`. Read once,
   read-only forever.
3. **agctl-owned namespaces** — `<config-dir>/claude/<account-uuid>/<organization-uuid>/.credentials.json`,
   created by `login`. These are the only credentials agctl will ever refresh, and apart
   from the live item `use --live` replaces, the only ones it writes.

A keychain item is named after a *directory spelling*, not after an account, so the same
account can appear under several names and two names can point at one directory. agctl
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

- **agctl writes two classes of keychain item, and deletes none.** The `security(1)`
  subcommands it issues are `show-keychain-info`, `find-generic-password` and
  `dump-keychain` — all reads — plus `add-generic-password -U`, on standard input, for two
  cases. The first is the item of a namespace agctl created, whose name is derived from the
  account registry: `status` refreshes it in place once a Claude Code session has migrated
  that namespace into the keychain, and `use --live` from that session's shell swaps it. The
  second is the live item — `Claude Code-credentials`, or `Claude Code-credentials-<sha8>`
  under a non-empty `CLAUDE_CONFIG_DIR`, derived from the environment the way Claude Code
  derives it — which only `use --live` and `use --undo` write, once per run and only after
  you confirm or pass `--yes`. Both are written under Claude Code's own lock protocol, and no
  other item is nameable as a target. There is no `delete-generic-password` code path at
  all, and no secret ever appears in a command line: the credential goes to `security -i`
  over a pipe. Every write is appended to `~/.config/agctl/claude/keychain-writes.jsonl`,
  which records digest prefixes and never token material; the entry is written after the
  write, and a failure to append is reported rather than rolling the write back, so a
  process killed between the two leaves a write the log does not name. The `~/.claude.json`
  step after a swap or undo is appended there too, and a catch-up's once it has read the
  file, unless you decline it. Each is a `config_write` line with its outcome and reason,
  the account ids, the backup's file name and digest prefixes of the file.
- **A live swap refuses to run without an appendable audit log.** Against the live item,
  `use --live` and `use --undo` open the audit log before they touch the live store or park
  anything, and append through that open file. If it cannot be appended to — a symbolic
  link at its name, a mode `append` refuses — the swap refuses (exit 22), and `doctor`'s
  `audit log` row says why. A namespace swap keeps the older rule: a refused log is reported
  and the swap goes on.
- **Nothing irreversible happens before you confirm.** Until the prompt, a live swap reads
  the registry, the environment and the live item once, and sends one
  `GET /api/oauth/profile`, which rotates nothing; beyond that it only takes agctl's own
  locks and opens its audit log. The refresh POST, the parking and both writes follow the
  answer. Neither Claude Code's credential-store locks nor its config lock is ever held
  across a network request or a prompt, and the two are never held together.
- **Outside its own configuration directory, agctl writes only for `use --live` and
  `use --undo`, one lock when an isolated session is seeded, and the session directory you
  name with `--claude-config-dir`.** Against the live store (`~/.claude`, or
  `CLAUDE_CONFIG_DIR`) a live swap creates and removes Claude Code's three credential-store
  lock artefacts — `.oauth_refresh.lock` and `.storage-write` inside the resolved store, and
  the legacy `<store>.lock` beside it — and writes the keychain item; it never writes or
  removes a credential file there. Its config step then writes exactly three things: the
  lock beside the configuration file (`~/.claude.json.lock`), a backup in Claude Code's
  `backups/` directory (`~/.claude/backups/` by default, created at 0700 when absent), and
  the file itself, through a temporary file beside the link's target and a rename. Seeding
  an isolated session takes that same lock for one read, only when it is free. Everything
  else agctl creates is under its own configuration directory.
- **`~/.claude.json` changes by one key and five deletions, as a peer of Claude Code's own
  config lock.** After an applied live swap or undo, or on the re-run that catches the file
  up, agctl replaces `oauthAccount` with the object Claude Code builds from
  `/api/oauth/profile`, deletes five caches every reader treats as "fetch again"
  (`modelAccessCache`, `orgModelDefaultCache`, `cachedExtraUsageDisabledReason`,
  `cachedUsageUtilization`, `passesEligibilityCache`), and changes nothing else. It takes
  Claude Code's lock beside the link, never beside its target, and waits for a busy one only
  with nothing of Claude Code's held. It writes the backup first, in Claude Code's own
  `.claude.json.backup.<epoch ms>` format at 0600, and never prunes one; Claude Code's next
  save does. It refuses unless re-serialising the unmodified file reproduces its bytes
  exactly, and re-reads the file before the rename and aborts if it changed. The new
  contents go to a temporary file beside the symlink's target, with the target's mode, and
  that file is renamed over the target; the link itself is never touched. It starts no step
  that cannot finish inside the lock's 1.2 s budget, and never breaks Claude Code's config
  lock: a stale one skips the rewrite, and one agctl leaves behind by being killed is Claude
  Code's to reclaim after 10 s. When `~/.claude/.config.json` exists, Claude Code uses that
  file instead, and so does agctl.
- **A displaced credential is parked, and never where Claude Code reads.** The one exception
  is an older copy of the incoming account's own credential, which the incoming one
  supersedes. A live swap files the credential it displaces in that account's own
  namespace as `.credentials.adopted.json`, at 0600 — a name Claude Code's credential read,
  its deletion and `/logout` never visit, so a keychain hiccup cannot make a session fall
  back to the account you swapped away from. `doctor` lists each such copy, `use --undo`
  restores it, and `accounts remove --delete-secret` clears it.
- **Refresh tokens sit at rest in 0600 files** —
  `~/.config/agctl/claude/<acct>/<org>/.credentials.json`, in a directory tree created
  at 0700. This is the same posture as Claude Code's own plaintext fallback store, which
  holds the same material in the same shape at the same mode. It is not the keychain, and
  it is not encrypted: anything running as your user can read it.
- **The namespace lock lives outside the namespace** —
  `~/.config/agctl/claude/.locks/<acct>.<org>.lock` — is created once, and is never
  unlinked, not even by the command that deletes the namespace it protects. `flock` locks
  an inode, so a lock file that can be deleted and recreated is a lock two processes can
  hold at the same time.
- **Claude Code activity in a namespace is detected and the refresh is refused.** Before a
  refresh POST, agctl checks the write target, takes the lock, re-checks for a Claude
  Code session under the lock, and re-checks once more immediately before the rename. Any
  surprise at any of those points ends in a refusal. There is no flag that overrides it: a
  row reading `claude session detected — refresh refused` is the system working. A
  namespace a session has *migrated* into the keychain is the one activity that is not a
  refusal: agctl refreshes that item instead of the file, and refuses again if the item
  changes while the refresh is in flight.
- **A row agctl does not own is never refreshed and, when expired, is not even
  fetched.** Its owner refreshes it; agctl reports.
- **agctl removes a lock artefact it did not create in exactly three circumstances.**
  `doctor --remove-stale`, fenced by the seven conditions — and the one record-attested
  exception to the first of them — listed under
  [`doctor`](#doctor--what-is-actually-on-this-machine); and, as a protocol peer taking
  Claude Code's credential-store locks itself, a stale one of those locks **inside agctl's
  own directory tree** while refreshing a migrated namespace's keychain item or swapping a
  namespace's item, and **in the live store** while `use --live` or `use --undo` writes the
  live item. Those two take twelve seconds of modification-time sampling before they remove
  anything, remove at most one lock per attempt, stand down if any `claude` process is
  stopped, and append the whole decision to the audit log whether they broke the lock or
  abandoned the attempt. The config lock beside `~/.claude.json` is never removed.

## The usage endpoint

The numbers come from `GET https://api.anthropic.com/api/oauth/usage`, the endpoint
Claude Code's own `/usage` command reads. **It is undocumented.** It is not part of
Anthropic's published API, it carries no compatibility promise, and it may change shape or
disappear in any Claude Code release — which is what
[`docs/re-verify.md`](docs/re-verify.md) is for.

agctl sends an honest `User-Agent`: `agctl/<version>`. It does not pretend to be
Claude Code. A client that lies about who it is cannot be rate-limited, deprecated or
excluded separately from the product it is impersonating, which is bad for both sides. If
Anthropic ever starts refusing the honest agent, `AGCTL_CLAUDE_USER_AGENT` replaces the
string without waiting for a release.

Reading your own subscription usage with your own credentials is the same operation
`/usage` performs, but you are responsible for your own use of Anthropic's services under
their terms. agctl reads usage figures and refreshes tokens it owns; it sends no
inference requests and consumes no quota. It also reads `GET /api/oauth/profile`, the
request Claude Code makes for the same facts: at `login`, at `accounts relocate` when the
stored credential names no organization, at a refresh of a credential whose plan or
rate-limit tier is not recorded, and at most twice per `use --live` or `use --undo`, to
learn whose credential the live item holds and to build the `oauthAccount` it writes.

**Caching and polling.** A usage response is cached for **300 s** per account, at
`<config-dir>/cache/claude/<acct>.<org>.<sha8>.json`. Inside that window a repeated
`status` answers from disk and makes no request. `--refresh` and `--no-cache` bypass it.
`watch --interval` will not go below **60 s**. When a fetch fails — a 429, a dead network,
a keychain that went away — the last good numbers are shown with the row marked `stale` or
`rate-limited`, rather than a blank cell.

## One switcher at a time

agctl coexists with Claude Code. It does **not** coexist with another tool that rewrites
the same credentials.

- A third-party menu-bar account switcher (for example `claude-account-switcher`) works by
  deleting and recreating the live keychain item on every switch. agctl lists those
  tools' `claude-switcher:*` items and never reads or writes them, but it cannot stop the
  live item from being replaced underneath it. Run one switcher, not two.
- While a live swap is outstanding, go back with `agctl claude use --undo`, not with
  `/login` inside Claude Code, and run no third-party switcher until you have. Either one
  replaces the live item behind agctl's back. `--undo` then answers `already_active` when
  the item already holds the account it would restore, and otherwise refuses (exit 27):
  `agctl claude status` names who is live now, and `use --live` can switch from there. If
  that login's token has expired by then, agctl cannot tell whose it is (exit 29) until one
  message in Claude Code refreshes it.
- `/logout` inside a Claude Code session that is pointed at an agctl namespace — an
  isolated session from `use`, `exec` or `env` is one — **deletes that namespace's
  credential store**. Claude Code's logout clears both the
  keychain item and the plaintext file. Nothing is corrupted, but that account needs a new
  `agctl claude login`.
- Two agctl stores with different `--config-dir` values have independent locks. Logging
  the same account into both makes two independent holders of one refresh chain, and each
  will eventually invalidate the other's token. Use one store per account.

## Environment variables

| variable | meaning |
|----------|---------|
| `AGCTL_CONFIG_DIR` | the environment form of `--config-dir`. Default: the XDG configuration directory plus `agctl`, i.e. `~/.config/agctl` |
| `AGCTL_CLAUDE_USER_AGENT` | replaces `agctl/<version>` as the `User-Agent` of every request |
| `AGCTL_CLAUDE_OAUTH_SCOPES` | replaces the space-separated scope set requested at login. A diagnostic: the server grants the same five scopes whatever is asked for |
| `RUST_LOG` | tracing filter for the diagnostics on stderr. Unset or unparseable means `warn`. `RUST_LOG=agctl=trace` is the useful setting; no token material is ever logged at any level |
| `TZ` | selects the zone the `5h reset` and `Weekly reset` columns are printed in. Unset — or set to something unrecognised — means the system zone (`/etc/localtime`), and UTC when even that cannot be determined |

The three `AGCTL_*` names above are the whole `AGCTL_*` surface agctl defines —
`RUST_LOG` and `TZ` it only reads. Every other `AGCTL_*`
name you may find in the source is a test seam compiled only under the `testing` feature
and absent from a release build — see [Build](#build) and `scripts/release-gate.sh`. The
gate checks eleven of them. `AGCTL_CLAUDE_PROFILE_URL` is one: it redirects the profile
request, and with it the access token that request carries.

### Read, but owned by Claude Code

agctl also reads a handful of variables it does not define, because they decide what
Claude Code itself would do:

| variable | meaning |
|----------|---------|
| `CLAUDE_CONFIG_DIR`, `CLAUDE_SECURESTORAGE_CONFIG_DIR` | read on every run by `EnvView::from_process` in `src/provider/claude/namespace.rs`; together they decide which keychain service name agctl rebuilds — see [docs/re-verify.md](docs/re-verify.md) section 1 |
| `CLAUDE_CODE_OAUTH_TOKEN` | short-circuits Claude Code's own credential lookup; agctl reports that row read-only and never refreshes it |
| `HOME` | locates the live store |
| `USER`, `LOGNAME` | the `acct` attribute every `find-generic-password` is keyed on (`src/secret/mod.rs`); an unexpected value finds nothing rather than erroring |

`CLAUDE_CONFIG_DIR` and `CLAUDE_SECURESTORAGE_CONFIG_DIR` also decide which store
`use --live` writes: a non-empty `CLAUDE_SECURESTORAGE_CONFIG_DIR` names a namespace agctl
owns, and unset or empty means the live store, whose configuration file is
`$CLAUDE_CONFIG_DIR/.claude.json` when that variable is set. `use <id>`, `exec` and `env`
set both for the session they prepare and remove `CLAUDE_CODE_OAUTH_TOKEN` from it; set in
agctl's own environment, that variable makes `use --live` refuse (exit 11).

## Exit codes

| code | meaning |
|------|---------|
| `0` | the run produced a complete, healthy result |
| `1` | the run failed outright and produced nothing useful — a bad configuration, an I/O failure, a refused command |
| `2` | the run produced output, but at least one **shown** row is degraded: expired, `needs login`, rate-limited, stale, keychain-locked, busy, or refused |

Exit 2 is about rows you can see. A row hidden by default cannot change the exit status,
because you did not ask about it. A pending credential that was replayed successfully is
not a degraded row and exits 0.

`exec` and bare `use <id>` exit with the child's own code instead — `128 + n` when signal
`n` killed it — so a script sees `claude`'s status, not agctl's.

`use --live` and `use --undo` give each outcome its own code, so a script can act on one
without parsing English. `--json` names the same outcome in its last document. Every row
below that shows a `refusal` or a `reason` has `"outcome": "refused"`, and a refusal
carries one of the two, never both.

| code | `--json` | meaning |
|------|----------|---------|
| `0` | `applied`, `already_active` | the item holds the account you asked for |
| `10` | `refusal: "A"` | a lock agctl was holding moved under it; nothing was written |
| `11` | `refusal: "C"` | `CLAUDE_CODE_OAUTH_TOKEN` is set in agctl's own environment |
| `12` | `refusal: "D"` | the credential does not fit the 4 032-byte keychain line |
| `13` | `refusal: "E"` | `--undo` of a live swap, from a shell that names a namespace |
| `14` | `refusal: "F"` | a credential cannot be parked or read; the message says which |
| `15` | `reason: "not_owned"` | `CLAUDE_SECURESTORAGE_CONFIG_DIR` names no namespace agctl owns |
| `16` | `busy` | another process holds the store's Claude Code locks |
| `17` | `discarded` | the item changed, or the hold ran out of time; nothing was written |
| `18` | `unknown` | the write timed out and could not be verified; re-run `status` |
| `19` | `failed` | `security(1)` refused the write; the item is untouched |
| `20` | `cancelled` | the prompt was declined, or there was no terminal and no `--yes` |
| `21` | `needs_refresh` | the incoming credential expired in a migrated store; run `status` |
| `22` | `reason: "audit_refused"` | the audit log cannot be appended to |
| `23` | `reason: "live_unreachable"` | the live store's path is missing or a dangling link |
| `24` | `reason: "live_item_absent"` | the live item is absent; run `claude` once |
| `27` | `reason: "live_undo_foreign_login"` | another account took the live item |
| `29` | `reason: "profile_unavailable"` | the server could not be asked whose credential it is |
| `29` | `reason: "live_token_expired"` | the live token expired; send Claude Code one message |

An applied swap or undo whose `~/.claude.json` rewrite did not land still exits `0`: the
swap applied, `config` says what did not, and `warnings` too unless the file is missing.
On `18` the rewrite is not attempted, and `config` says so with the reason `swap_unknown`.
The line about a secure-storage backend in agctl's own environment is a warning, not a
refusal, and exits `0` too.

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
`tests/e2e_*.rs`, all of it behind `#![cfg(feature = "testing")]` except `e2e_lock.rs`,
whose greps over the tree and the built binary need no test seam. Some of those tests wait
out real intervals on purpose, because the interval is what they test: `doctor`'s 12 s
stale-sampling interval, the 5 s command lock timeout, and the config lock's contention
ladder. No test may touch the real keychain, the real `$HOME`, the network, or a real
`security` or `claude`: the keychain is `fixtures/fake-security.sh`, and every endpoint is
a local mock.

Before releasing an artifact, run `scripts/release-gate.sh`: it builds a default-feature
release into a scratch directory and proves the binary contains no test seam.

After a Claude Code upgrade, work through
[**docs/re-verify.md**](docs/re-verify.md) — agctl's correctness depends on four
contracts read out of Claude Code's own binary, and an upgrade can change any of them.

## Scope

| phase | scope |
|-------|-------|
| 1 | `status`, `watch`, `login`, `accounts`, `import` (read-only), `doctor` |
| 2 (this) | switching the account Claude Code uses: `use`, `exec`, `env`, `use --live` |
| 3+ | other providers: Codex, Cursor, Copilot, and the rest |

Phases 1 and 2 have landed, both Claude only and macOS only. Phase 2 adds neither Linux nor
another provider, and it expects to be the only tool switching accounts on the machine;
see [One switcher at a time](#one-switcher-at-a-time).

## License

Apache-2.0. See [LICENSE](LICENSE).
