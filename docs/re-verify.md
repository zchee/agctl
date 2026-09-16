# Re-verify after a Claude Code upgrade

agctl reads a machine that Claude Code owns. Its behaviour is not derived from a published
interface but from facts read directly out of Claude Code's shipped binary, and any Claude
Code release can change them without notice. §1–§4 are the four contracts agctl is built on
most directly; §5 re-establishes the eighteen further facts (F42–F59) the write path and the
lock protocol lean on. Work through the whole file after every Claude Code upgrade, and
before every agctl release.

**Every command here is read-only.** Nothing writes, nothing runs `claude`, nothing touches
the keychain.

Set the version under test once:

```sh
CC=~/.local/share/claude/versions/2.1.266     # or whatever `claude --version` reports
```

Claude Code ships as a single self-contained Mach-O with the JavaScript bundle embedded, so
every pattern below is `rg -a` (treat binary as text) against that one file. The identifiers
are minified and **change on every build** — the patterns below deliberately match on the
string literals and the shape of the expression, never on a minified name. If a pattern
returns zero hits, that is the signal to read the surrounding code by hand, not to relax the
pattern until it matches.

They do not change on *every* build — 2.1.265 and 2.1.266 share every identifier in this
file — so a matching name proves nothing. Only a matching shape does.

Last verified: **Claude Code 2.1.266**, 2026-09-09. The original evidence was gathered
against 2.1.263 and re-established against 2.1.265 and 2.1.266; every pattern below was run
against all three, and all four contracts are unchanged. 2.1.263→2.1.265 moved only minified
names (`Vt`→`Xt`, `z0`→`nH`, `Kys`→`eEs`, `cr`→`pr`). 2.1.265→2.1.266 moved **none** of
them, even though the two binaries differ in 109 447 133 bytes and the JS payload shifted by
up to 292 bytes — the minifier happened to assign the same symbols twice. Do not read a
stable identifier as evidence that the bundle is unchanged; that is exactly why the patterns
below match shapes and string literals rather than names.

---

## 1. F14 — the keychain service-name rule

**What agctl depends on.** agctl finds Claude Code's credential items by rebuilding
the service name Claude Code would use: `"Claude Code"` plus a build-time suffix, plus a
per-configuration-directory suffix `-<first 8 hex of sha256(dir)>`, where the directory
string is NFC-normalized and never resolved through symlinks, and where the suffix is
omitted when the gating variable is *falsy* (not merely absent). If this rule changes,
agctl looks in the wrong place: rows silently vanish, or an item is attributed to the
wrong configuration directory.

```sh
rg -a -o 'Claude Code\$\{[^}]*OAUTH_FILE_SUFFIX\}\$\{[^}]*\}\$\{[^}]*\}' "$CC"
rg -a -o 'normalize\("NFC"\)[^;]{0,120}substring\(0,8\)' "$CC"
rg -a -c 'CLAUDE_SECURESTORAGE_CONFIG_DIR' "$CC"
```

**Expected, 2.1.266:**

```
Claude Code${Xt().OAUTH_FILE_SUFFIX}${n}${c}
normalize("NFC"):be(),c=t?"":`-${a("sha256").update(r).digest("hex").substring(0,8)
10
```

Read the second line carefully: `c = t ? "" : "-" + sha256(r).hex[0..8]` is the suffix, and
`t` is the *truthiness* test on `CLAUDE_SECURESTORAGE_CONFIG_DIR` (falling back to
`CLAUDE_CONFIG_DIR`), which is why `CLAUDE_SECURESTORAGE_CONFIG_DIR=""` yields the
*unsuffixed* live service name. `normalize("NFC")` must appear on **both** branches, and no
`realpath`/`path.resolve` may appear between them.

**Fails if:** the template gains or loses a `${…}` segment; the digest length changes from
8; `normalize("NFC")` disappears; the ternary becomes a presence test (`!== undefined`)
rather than a truthiness test; a path-resolution call appears.

**Affected agctl code:** `src/provider/claude/namespace.rs` (`service_name`, `sha8`),
`src/secret/location.rs`, `src/config/import.rs`.

---

## 2. F40 — the plaintext credential store

**What agctl depends on.** agctl writes its own credentials in exactly the shape
Claude Code's plaintext fallback store reads, so that a namespace agctl created can be
handed to a Claude Code session unchanged: `<store dir>/.credentials.json`, a temporary
file named `<path>.tmp.<8 lowercase hex>` created `wx` at 0600, then renamed. It also
depends on the reader refusing symlinks, which is why agctl's own writer walks the path
with `O_NOFOLLOW` per component.

```sh
rg -a -o 'storagePath:[A-Za-z0-9_$]+\([A-Za-z0-9_$]+,"\.credentials\.json"\)' "$CC"
rg -a -o 'storePath:[A-Za-z0-9_$]+\([A-Za-z0-9_$]+,"\.credentials\.json"\)' "$CC"
rg -a -o '\.tmp\.\$\{[A-Za-z0-9_$]+\(4\)\.toString\("hex"\)\}' "$CC"
rg -a -c '"refused-symlink"' "$CC"
```

**Expected, 2.1.266:**

```
storagePath:G(e,".credentials.json")
storePath:_(e,".credentials.json")
.tmp.${et(4).toString("hex")}
.tmp.${eEs(4).toString("hex")}
3
```

Two store implementations are present — the legacy one (`storageDir`/`storagePath`) and the
gated "storageV5" one (`storeDir`/`storePath`); which is active at runtime is not
statically determinable, so **both** must still name `.credentials.json`. The tmp name is
four random bytes hex-encoded, i.e. the eight hex characters agctl's writer and
`doctor`'s stray-file reporting both assume; Claude Code's own matcher for it is
`/^[0-9a-f]{8}$/`, which the third grep's shape must stay consistent with.

**Fails if:** either store stops using `.credentials.json`; the tmp suffix changes width or
alphabet (e.g. `(6).toString("hex")`, or a pid-prefixed name — note that a *different*
`.tmp.${process.pid}.…` shape exists elsewhere in the bundle for unrelated staging and is
not this one); `"refused-symlink"` disappears, meaning the reader no longer refuses
symlinked stores.

**Affected agctl code:** `src/secret/file_store.rs`, `src/commands/doctor.rs` (stray tmp
reporting).

---

## 3. F20 / F22 — the usage response schema and its credits consumer

**What agctl depends on.** agctl parses the same response `/usage` does: the legacy
top-level windows, the `limits[]` array of `{kind, group, percent, resets_at, scope?}`, and
`extra_usage {is_enabled, monthly_limit, used_credits, utilization, currency?,
disabled_reason?}` for the credits column. It renders credits from `extra_usage` **only** —
the `spend` object appears in captures but has no consumer in Claude Code and no documented
unit, so agctl does not render it.

```sh
rg -a -o 'extra_usage:[A-Za-z0-9_$]+\(\{is_enabled:.{0,230}' "$CC"
rg -a -o '.{0,90}/api/oauth/usage.{0,90}' "$CC"
```

**Expected, 2.1.266** — two schema declarations from the first grep, then three hits from
the second (two bare literals and the request site):

```
extra_usage:c({is_enabled:P(),monthly_limit:A().nullable(),used_credits:A().nullable(),utilization:A().nullable(),currency:s().nullable().optional()}).nullable().optional()}).nullable().describe("Plan rate-limit utilization windows from the claude.ai usage
extra_usage:nt({is_enabled:To(),monthly_limit:Zt().nullable(),used_credits:Zt().nullable(),utilization:Zt().nullable(),currency:le().nullish(),disabled_reason:le().nullish()}).passthrough().nullish(),limits:pr(nt({kind:le(),group:le(),percent:Zt(),resets_at
```

```
 /api/oauth/usage?at_wall=1&skip_spend=1
 /api/oauth/usage
n?"api_usage_fetch_at_wall":"api_usage_fetch",async()=>{if(!gt()||!Ep())return{};let r=n?"/api/oauth/usage?at_wall=1&skip_spend=1":"/api/oauth/usage",o=0,d=await Uy(async()=>{o++,t(`fetchUtilizati
```

The second schema hit is the wire schema — `.passthrough()` throughout, so unknown members
are kept rather than rejected — and it is the one that matters. Widen the context in both
directions to read the whole declaration:

```sh
rg -a -o 'extra_usage:[A-Za-z0-9_$]+\(\{is_enabled:.{0,900}' "$CC" | tail -1   # limits[] and scope
rg -a -o '.{0,300}extra_usage:[A-Za-z0-9_$]+\(\{is_enabled:' "$CC" | tail -1   # legacy window keys
```

The first prints `limits:…({kind, group, percent, resets_at, scope:{model:{display_name},
surface:{display_name}}})`, which is the shape agctl prefers whenever it is present and
non-empty. The second prints the legacy top-level keys that agctl falls back to when
`limits[]` is absent or empty — in 2.1.266: `five_hour`, `seven_day`,
`seven_day_oauth_apps`, `seven_day_opus`, `seven_day_sonnet`, `cinder_cove`.

A **new** key in `limits[]` is not a failure: `WindowKind::Unknown` in `src/usage/model.rs`
keeps an unrecognised `kind` verbatim and the table still renders. A new *legacy top-level*
key is different — `legacy_windows` in `src/provider/claude/usage.rs` only understands
`five_hour`, `seven_day` and `seven_day_<scope>`, so anything else (`cinder_cove` today) is
dropped on the fallback path. That is currently harmless because every live response
carries `limits[]`, but it is the thing to check if a fallback-path row ever renders with a
window missing.

**Fails if:** a member of `extra_usage` is renamed or changes nullability such that the
existing parse rejects it; `limits[]` loses `kind`/`percent`/`resets_at`; `.passthrough()`
becomes `.strict()`; the request path changes from `/api/oauth/usage`; a `spend`
declaration appears **with** a consumer that renders it, which would mean the credits
source has moved.

**Affected agctl code:** `src/usage/model.rs`, `src/provider/claude/usage.rs`
(`parse_usage`), `schemas/status.v1.json`.

---

## 4. F36 — the lock constants `doctor --remove-stale` reasons about

**What agctl depends on.** `doctor --remove-stale` decides a Claude Code lock artefact is
abandoned by taking two mtime samples 12 s apart and requiring them to be identical. That
number is derived: Claude Code's holders heartbeat every `update` ms and Claude Code itself
decides `holderAlive` from exactly that mtime comparison, and `stale` ms is the age past
which `proper-lockfile` will break a lock. If `update` grows past 12 s, agctl's two
samples can straddle a heartbeat gap and call a *live* lock dead.

```sh
rg -a -o '\.oauth_refresh\.lock"\),realpath:[^,]+,stale:[0-9]+,update:[0-9]+' "$CC"
rg -a -o 'lockAgeMs:[A-Za-z0-9_$]+,mtimeMs:[A-Za-z0-9_$]+\}\}var [A-Za-z0-9_$]+=[0-9]+' "$CC"
rg -a -c '1000\+Math\.random\(\)\*1000' "$CC"
```

**Expected, 2.1.266:**

```
.oauth_refresh.lock"),realpath:!1,stale:60000,update:5000
lockAgeMs:p,mtimeMs:E}}var nH=7500
6
```

- `stale:60000` is where agctl's `STALE_MIN_AGE` (60 s) comes from.
- `update:5000` is the heartbeat, and is why `STALE_SAMPLE_INTERVAL` is 12 s — comfortably
  more than two heartbeat periods.
- `7500` is the contention deadline Claude Code waits out before reporting `lock_timeout`;
  the retry backoff is five rounds of `1000 + Math.random()*1000` ms. That third grep counts
  a backoff *shape* that the bundle also uses elsewhere, so treat a changed count as a
  prompt to re-read the contention function, not as a failure on its own — the first two
  greps are the authoritative ones.
- `realpath:!1` means the primary lock is keyed on the *unresolved* store path. agctl
  must keep looking for `.oauth_refresh.lock` inside the namespace and the legacy
  `<namespace>.lock` beside it, not at a canonicalized location.

**Fails if:** `update` rises above ~6000 (raise `STALE_SAMPLE_INTERVAL` to more than twice
it); `stale` changes (adjust `STALE_MIN_AGE`); `realpath` flips to `!0`; the lock file name
changes.

**Affected agctl code:** `src/commands/doctor.rs` (`STALE_MIN_AGE`,
`STALE_SAMPLE_INTERVAL`, the artefact name list), `src/secret/foreign_activity.rs`
(`REFRESH_LOCK`, `STORAGE_WRITE_LOCK`).

---

## 5. F42–F59 — the facts the write path and the lock protocol rest on

Phase 2 gave agctl a keychain **write** path and its own implementation of Claude Code's
lock protocol, and both are derived from the peer's behaviour rather than from an interface
it promises to keep. These eighteen facts are the derivation. They are checked as rows
rather than as sections because each is a single grep whose answer is a count or one line;
where a row's consequence is not obvious from the expected value, it carries a note below.

Each id is the fact's number in the phase-2 plan (`.omc/plans/agentctl-claude-switch-phase2.md`
§0.2), which states the fact in full. The commands here are that section's commands.

**A row that fails is not automatically a release blocker** — F52 and F51 measure this
machine, not the binary, and drift there is expected. A row that fails on a *binary* fact is
a blocker until the affected agctl code is re-read against the new shape.

### 5.1 Binary facts — `rg -a` against `"$CC"`

| id | what agctl depends on | command | expected, 2.1.266 |
|----|-----------------------|---------|-------------------|
| F42 | The write transport: one `add-generic-password -U -a … -s … -X <hex>` line, on **stdin** via `security -i` while it is ≤ 4032 chars, else the same in argv with the secret on the command line. No `-T`/`-D`/`-j`/`-C`. | `rg -a -c 'add-generic-password' "$CC"`; `rg -a -o '.{0,320}add-generic-password.{0,320}' "$CC"` | `6`; the `-i` branch `im("security",["-i"],{input:i,…,timeout:p})` and the warn string `Keychain payload (${o.length}B JSON) exceeds security -i stdin limit; using argv` |
| F43 | The delete transport exists and agctl issues it **nowhere** (I1′). | `rg -a -c 'delete-generic-password' "$CC"` | `5` |
| F44 | The read transport and its four constants. | `rg -a -o 'var [A-Za-z0-9_$]+=2000,[A-Za-z0-9_$]+=4032[^;]{0,80}' "$CC"` | `var p=2000,H=4032,K=44,W=36` |
| F45 | `proper-lockfile` mechanics, and that **every lock artefact is a directory** (`mkdir`/`rmdir`). | `rg -a -c 'ELOCKED' "$CC"`; `rg -a -o '.{0,240}ELOCKED.{0,240}' "$CC"` | `11`; acquire is `r.fs.mkdir(i,…)`, heartbeat is `stat` → mtime drift → `ECOMPROMISED` → else `utimes` |
| F46 | Two locks, in order: primary `.oauth_refresh.lock`, then the legacy `<realpath(dir)>.lock`. | `rg -a -c '\.oauth_refresh\.lock' "$CC"`; `rg -a -o '.{0,400}\.oauth_refresh\.lock.{0,400}' "$CC"` | `2`; `realpath:!1,stale:60000,update:5000` (same line §4 checks) |
| F47 | `.storage-write`'s options and its `AsyncLocalStorage` re-entrancy guard. | `rg -a -o '.{0,260}\.storage-write.{0,260}' "$CC"` | 2 hits; `realpath:!1`, `retries:{retries:10,minTimeout:100,maxTimeout:1000}`, `stale:15000`, behind `if(_.getStore())return e()` |
| F48 | Change detection at the head of every refresh check, whose **stat-error** branch is the live keychain-backed case. | `rg -a -c 'Dge\(' "$CC"`; `rg -a -o '.{0,260}Dge\(.{0,260}' "$CC"` | `6` (two are an unrelated auto-memory predicate); the body ends `catch{await eH(e,n)}` |
| F49 | `probeCredentials` exists on the file store and **not** on the keychain store. | `rg -a -c 'probeCredentials' "$CC"` | `3` — file store returns `dev:ino:size:mtimeNs`; the keychain store object defines none |
| F50 | `.claude.json` has its own lock, and a documented refusal to fall back while a live holder has it. | ``rg -a -o 'Config lock[^`"]{0,60}' "$CC"`` | `Config lock still held by a live process after retries…See gh-73364`, `Config lock compromised:`, `Config lock release failed:` |
| F53 | **The peer gives up at 4 s.** Every phase-C hold budget is derived from that floor. | ``rg -a -o 'Lock acquisition failed after [^`"]{0,60}' "$CC"``; `rg -a -o 'var [A-Za-z0-9_$]+=5;.{0,200}ELOCKED.{0,200}' "$CC"` | the message, and 5 attempts with 4 sleeps of `1000+Math.random()*1000` ⇒ **4 000–8 000 ms** |
| F54 | A broken lock makes the victim **stand down before its POST** — the load-bearing half of the break-rule safety argument. | `rg -a -c 'isCompromised' "$CC"`; `rg -a -o 'lock_compromised_pre_post.{0,160}' "$CC"` | `6`; the pre-POST check returning `"lock_compromised"`, and a `…_lock_compromised_post_post` sibling |
| F55 | The victim only learns at its next heartbeat, so it is outside every lock for up to `update` = 5 s after a break. | `rg -a -o '[a-zA-Z./_]* lock compromised \(likely process suspend or slow fs\)' "$CC"` | `jobs/.order lock compromised (…)` and `pins.json lock compromised (…)`, 2 hits each |
| F56 | `--mcp-config` and `.mcp.json` both exist. | `rg -a -c -- '--mcp-config' "$CC"`; `rg -a -c '\.mcp\.json' "$CC"` | `32`; `67` |
| F58 | The peer's credential-store writes run **inside** `.storage-write` — which is why agctl's re-read/compare/write is a `mutate()`, not a bare `update()`. | `rg -a -o '\$Pn\(async\(\)=>\{.{0,320}' "$CC" \| grep update` | the closure ending `return s===o?{success:!0}:await e.update(s,a)` — `update` **inside** `$Pn` |
| F59 | `--mcp-config` is repeatable and has **no** environment-variable equivalent, which is why `claude env` must print an alias rather than an assignment. | `rg -a -o '.{0,150}"--mcp-config".{0,200}' "$CC"`; `rg -a -o 'CLAUDE_[A-Z_]*MCP[A-Z_]*' "$CC" \| sort -u \| wc -l` | `"--mcp-config":(e)=>t.mcpConfig.push(e)` and the `flatMap` re-emit; `18` variables, **none** carrying a config path |

**F42.** The argv branch is the one to watch: it puts the credential on a command line, where
any process can read it from `ps`. agctl never reaches it — its payloads are far below 4032
— but a shrinking limit would change that, so the number is checked, not assumed. The other
two `add-generic-password` call sites are Claude Code's API-key save and its own
`Claude Code-doctor-probe` item; the probe item is the one `doctor`'s guard must expect.

**F50 refinement (2.1.266).** The config path is `` `.claude${W1()}.json` ``, not the literal
`".claude.json"`; `W1()` is empty on a default install, which is why the observed name is
`.claude.json`. And `<config dir>/.config.json`, **when it exists, wins outright** and
`.claude.json` is never consulted. Neither contradicts F50; both matter to any code that
opens the live config file.

**F53/F54/F55 together are the break rule's safety argument**, and they fail as a set. If
`Fge` drops below 5, or the sleep range narrows, the 4 s floor moves and every derived hold
budget must move with it.

**F57's matcher must not be widened.** See §5.2.

### 5.2 Machine facts — this machine, not the binary

These three measure the live environment. **Counts only**: never print the values, and never
read a process's environment (a live `claude`'s environment carries third-party secrets that
are none of agctl's business — that is why the holder check reads process *state* alone).

| id | what to re-establish | command | expected |
|----|----------------------|---------|----------|
| F51 | The live config directory mixes Claude Code's state with unrelated tooling, and `~/.claude.json` is itself a symlink into it. | `ls -la ~/.claude ~/.claude.json` | `.omc*`, `hud/`, `daemon*`, `jobs/`, `teams/`, `hooks/`, `scripts/`, `telemetry/` present; `~/.claude.json` a symlink |
| F52 | `.claude.json` mixes identity, subscription state and configuration in one file. | `python3` over `~/.claude.json`, **keys and sizes only** | ~165–166 top-level keys; the nine account-scoped keys (`oauthAccount`, `userID`, `machineID`, `cachedUsageUtilization`, `overageCreditGrantCache`, `passesEligibilityCache`, `s1mAccessCache`, `s1mNonSubscriberAccessCache`, `customApiKeyResponses`); `mcpServers` 12 entries, **5** with a non-empty `env`/`headers` block, of which **3** are credential-shaped |
| F57 | Lock artefacts carry no holder identity, so the holder check is `pgrep -x claude` then `ps -o state=` per pid. | `pgrep -x claude`; `ps -o state= -p <pid>` | some live sessions are **missed** — see below |

**F52's counts drift, and that is not a failure.** They were 165 keys when the plan was
written and 166 two hours later, because a live session added one. The number sizes the
exposure; it does not create it. Read a changed count as drift unless a *named* account-scoped
key has appeared or disappeared.

**F57's two limitations are accepted, and one is now observed.** `-x claude` matches the
*invoked* name, so a session started straight from `~/.local/share/claude/versions/<v>` has
`comm` = that version and is missed — measured on this machine at 2 of 5 live sessions. The
check then degrades to no holder evidence and the mtime rule alone, which is safe rather than
wrong. Do **not** widen the matcher in response: never `-f`, which would match unrelated
command lines, and never `-i`, whose case-insensitivity sweeps in the `Claude.app` desktop
helpers. State `T` likewise covers `SIGSTOP`, tty-stop and `Ctrl-Z` alike, so a long-suspended
pane blocks live-store breaks for as long as it is suspended; that is why the `busy` message
names the pids.

---

## After the checklist

1. Record the version you checked and the date at the top of this file.
2. Run the gate: `cargo fmt --check`, then `cargo clippy --all-targets --all-features
   -- -D warnings` and `cargo nextest run --all-features`.
3. Run `scripts/release-gate.sh`.
4. If any contract moved, fix the affected code **and** the fixtures under
   `fixtures/claude/` before releasing. A contract that changed silently is exactly the
   failure mode this file exists to prevent.
