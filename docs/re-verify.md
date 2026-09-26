# Re-verify after a Claude Code or Codex CLI upgrade

agctl reads two machines it does not own. Its behaviour is not derived from a published
interface but from facts read directly out of each peer's shipped binary, and any release of
either can change them without notice. §1–§4 are the four Claude Code contracts agctl is
built on most directly; §5 re-establishes the eighteen further Claude facts (F42–F59) the
write path and the lock protocol lean on; §6 does the same for the five Codex contracts
(F61, F62, F65, F67, F90) phase 3 depends on. Work through §1–§5 after every Claude Code
upgrade, §6 after every Codex CLI upgrade, and all of it before every agctl release.

**Every command here is read-only.** Nothing writes, nothing runs `claude` or `codex`,
nothing touches the keychain.

Set the version under test once:

```sh
CC=~/.local/share/claude/versions/2.1.266     # or whatever `claude --version` reports
CODEX=$(command -v codex)                     # or whatever `codex --version` reports
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

## 6. Codex — the five contracts phase 3 depends on

Phase 3 reads a second peer, the Codex CLI, the same way phases 1 and 2 read Claude Code:
facts pulled from its shipped binary and source rather than from a published interface. The
phase-3 plan's fact register (`.omc/plans/agentctl-codex-phase3.md` §0.1–§0.2, evidence
captured in `.omc/handoffs/p3-codex-facts.md` and `p3-w0-facts.md`) establishes thirty-six
such facts, F60–F95 with no gaps (14 in "0.1 Register", F60–F73; 22 in "0.2 What W0 must
establish", F74–F95). §6.1–§6.5 below are the five — F61, F62, F65, F67, F90 — that agctl's
Codex support actually depends on at runtime, so they are the ones worth re-checking on
every Codex CLI upgrade; the other thirty-one settled a design decision once (the login
mechanism, the refresh policy's error classes' host behaviour, the daemon's pid-file shape,
among others) and are not re-derived here — read the fact register directly if one of them
is ever in doubt.

Last verified, per fact — not all five at once, and this file does not claim otherwise:

- **F61, F62, F65, F67**: read from source and the installed binary at **codex-cli
  0.155.0-alpha.4** (upstream `rust-v0.155.0-alpha.4`, commit
  `66eab8ece44141ff92707868269e1d53b40c4ac5`), 2026-09-16, recorded in
  `.omc/handoffs/p3-codex-facts.md`. **Not re-checked since.** The later recheck lane
  (`.omc/handoffs/p3-w0-facts-recheck.md`, 2026-09-19, against the locally installed
  **0.155.0-alpha.12**) covers a different slice of the register (F74–F77, F83–F86 there)
  and does not touch any of these four.
- **F90**: read the same way at alpha.4, 2026-09-16, recorded in
  `.omc/handoffs/p3-w0-facts.md`, and independently re-checked and confirmed **UNCHANGED**
  at alpha.12 (`.omc/handoffs/p3-w0-facts-recheck.md`, 2026-09-19): `login/src/auth/
  storage.rs` is byte-identical at both tags — the cited lines hold verbatim.

Re-run every grep below whenever the installed Codex CLI moves past alpha.12, and treat
F61/F62/F65/F67 as due for a first re-check regardless of version, since none has been
looked at again since alpha.4.

### 6.1 F61 — the `auth.json` shape

**What agctl depends on.** `$CODEX_HOME/auth.json` holds a serde struct `AuthDotJson` with
**8 fields**: `auth_mode` (inferred by `resolved_mode()` when absent), `OPENAI_API_KEY`
(always serialized, `null` when absent), `tokens` — a `TokenData` with **4 fields**:
`id_token`, `access_token`, `refresh_token` (opaque, not a JWT) and `account_id` — plus
`last_refresh`, `agent_identity`, `personal_access_token`, `bedrock_api_key`,
`bedrock_access_keys`. agctl's own credential type (`Credentials`/`CodexIdentity` in
`src/provider/codex/credentials.rs`) reads `tokens.account_id` — falling back to the
id-token claim `chatgpt_account_id` when absent — the three token secrets by path, and
`last_refresh`, and keeps every other member as an opaque `Value` so an unrecognised one
round-trips through an agctl-initiated write instead of being dropped (see §6.5). The live
access token's life is **10 days** — R59, and the reason the phase-3 plan's §9.6 live checks
and every manual phase-3 command need `codex` to have run recently.

```sh
rg -a -o 'struct (AuthDotJson|TokenData) with [0-9]+ elements' "$CODEX"
```

**Expected, 0.155.0-alpha.4:**

```
struct AuthDotJson with 8 elements
struct TokenData with 4 elements
```

**Fails if:** either count changes — a member was added, removed or renamed. Re-read
`login/src/auth/storage.rs:41-63` and `login/src/token_data.rs:11-41` at the new tag and
check whether `Credentials::account_id`/`last_refresh`/the three `SecretPath::Token` names in
`src/provider/codex/credentials.rs` still name real fields.

**Affected agctl code:** `src/provider/codex/credentials.rs`, `src/provider/codex/home.rs`
(`$CODEX_HOME` resolution).

---

### 6.2 F62 — the store mode and the keychain service name

**What agctl depends on.** The live store mode is **`file`** (`cli_auth_credentials_store`
defaults to `file`, and this machine's `config.toml` sets it explicitly); under `keyring`,
Codex's default ("Direct") layout writes one generic-password item, service **`"Codex
Auth"`**, account **`cli|<first 16 hex of sha256(canonicalized CODEX_HOME)>`**, value = the
whole `auth.json` document. `agctl codex doctor` and `login` both need that exact service
name and account-derivation rule to tell an item **agctl's own login child** created from a
foreign one — `KEYRING_SERVICE` and `keyring_account()` in `src/provider/codex/home.rs`.

```sh
rg -a -c '"Codex Auth"' "$CODEX"
```

**Expected, 0.155.0-alpha.4:** at least one hit — the service-name literal is embedded in the
keyring backend. (Presence is what matters here, not an exact count: the string can legally
appear more than once, e.g. in an error message that also names it.)

**Fails if:** the string disappears, meaning the service name changed and every `Codex Auth`
item agctl has ever attributed on this machine is now named after a retired convention.
Re-read `core/src/config/auth_keyring.rs:85-117` and
`login/src/auth/storage.rs:235-250,296-306` for the new name and the new
account-derivation hash width.

**Affected agctl code:** `src/provider/codex/home.rs` (`KEYRING_SERVICE`, `keyring_account`),
`src/commands/codex/doctor.rs`.

---

### 6.3 F65 — the refresh trigger and request

**What agctl depends on.** Codex refreshes proactively when `access_token.exp <= now + 5
min` (falling back to `last_refresh < now - 8 days` only when `exp` cannot be parsed), by
**`POST https://auth.openai.com/oauth/token`**, `Content-Type: application/json`, body
`{"client_id": "app_EMoamEEZ73f0CkXaXp7hrann", "grant_type": "refresh_token",
"refresh_token": "<...>"}`. A response is classified **Permanent** — no further automatic
retry — on 401, on 400 `invalid_grant`, or on a body `error` in
`{refresh_token_expired, refresh_token_reused, refresh_token_invalidated}` (Codex's own
`classify_refresh_token_failure`; an earlier plan draft paraphrased the third code as
`revoked` — the tree follows the source's literal spelling, confirmed at S32 review, ledger
`p3-s32-review-request.md:438`); anything else is transient. agctl's own D-035 refresh state
machine (`src/provider/codex/oauth.rs`, `src/provider/codex/refresh.rs`) mirrors this client
id, this URL and this permanent/transient split, but is stricter than Codex's own client: it
never re-sends automatically at all — `agctl codex accounts refresh --resend` is the one
audited, user-issued exception, gated an hour behind an unknown outcome.

```sh
rg -a -o 'https://auth\.openai\.com[A-Za-z0-9/_.-]*' "$CODEX" | sort -u
rg -a -c 'app_EMoamEEZ73f0CkXaXp7hrann' "$CODEX"
rg -a -o 'refresh_token_(expired|reused|invalidated|revoked)' "$CODEX" | sort -u
```

**Expected, 0.155.0-alpha.4:**

```
https://auth.openai.com/oauth/authorize
https://auth.openai.com/oauth/revoke
https://auth.openai.com/oauth/token
```

(client-id count: at least 1; the third grep: exactly
`refresh_token_expired`/`refresh_token_invalidated`/`refresh_token_reused`, never
`refresh_token_revoked`.)

The `/oauth/authorize` URL above is Codex's own, read from its binary — it is not a seam
agctl exposes. AC110 originally named a fourth Codex seam, `AGCTL_CODEX_AUTHORIZE_URL`, on
the assumption agctl would build this URL itself; it does not (D-037's L2' login shells to
the real `codex login` instead), so no such override exists anywhere in this tree, and AC110
is amended to the three Codex seams that actually do (S37, lead ruling).

**Fails if:** the token URL or the client id changes, or the third grep's result set changes
— gaining `refresh_token_revoked` or losing one of the three current codes means
`src/provider/codex/oauth.rs`'s `classify_refresh_token_failure` match table is stale.
Re-read `login/src/auth/manager.rs` at the new tag — the line numbers above
(`191-204,1572-1651,1710-1738`) are alpha.4 anchors, recorded 2026-09-16 and never
reconfirmed: F65 itself was not part of the one later recheck this repository has done
(alpha.12, 2026-09-19), and a *different* fact that touches the same file, F93, moved by a
few lines when that recheck did cover it (`p3-w0-facts-recheck.md`: its `manager.rs:200-202`
anchor became `208-212`). Treat these line numbers as approximate past alpha.4, and confirm
them by content (the client id, the URL, the three body-error codes above), not by line
number alone.

**Affected agctl code:** `src/provider/codex/oauth.rs` (`TOKEN_URL`, `CLIENT_ID`, the
permanent/transient classification), `src/provider/codex/refresh.rs` (the D-035 send/marker
state machine).

---

### 6.4 F67 — the usage endpoint

**What agctl depends on.** Codex's own `/status` and TUI rate-limit display read **`GET
{chatgpt_base_url}/wham/usage`**, default `https://chatgpt.com/backend-api/wham/usage`, with
`Authorization: Bearer <access_token>`, **`ChatGPT-Account-Id: <tokens.account_id>`**, and
`X-OpenAI-Fedramp: true` when the account is fedramp. `src/provider/codex/usage.rs` reads the
same endpoint and the same two identifying headers, and parses `rate_limit.{primary,secondary}`
windows (`used_percent`, `limit_window_seconds`, `reset_after_seconds`, `reset_at`) plus
`credits` the same way the TUI's mapped `RateLimitSnapshot` does.

```sh
rg -a -c '/wham/usage' "$CODEX"
rg -a -o 'chatgpt_base_url = "[^"]*"' "$CODEX"
rg -a -c 'ChatGPT-Account-Id' "$CODEX"
```

**Expected, 0.155.0-alpha.4:**

```
chatgpt_base_url = "https://chatgpt.com/backend-api/"
```

(both count greps: at least 1 each.)

**Fails if:** the base URL, the path, or either identifying header's name changes, or the
window shape (`used_percent`/`limit_window_seconds`/`reset_after_seconds`/`reset_at`) gains
or loses a member in a way the current parse would reject. Re-read
`backend-client/src/client/rate_limit_resets.rs:23-80` and the
`RateLimitWindowSnapshot` model at the new tag.

**Affected agctl code:** `src/provider/codex/usage.rs`.

---

### 6.5 F90 — the `auth.json` serializer

**What agctl depends on.** Codex writes `auth.json` with `serde_json::to_string_pretty`
(2-space indent, `": "` separators, **no trailing newline**), through
`OpenOptions::truncate(true).write(true).create(true)` with `mode(0o600)` applied only on
**create** — an existing file keeps whatever mode it already had. `AuthDotJson` has **no**
`#[serde(flatten)]` catch-all, so **Codex's own next save silently drops any member it does
not recognise**, including one agctl might have added. agctl's write path
(`Credentials::write`, `src/provider/codex/credentials.rs`) uses `serde_json::to_writer_pretty`
over the whole parsed `Value` rather than a fixed struct, specifically so an unrecognised
member survives an agctl-initiated write; it cannot make Codex preserve one on Codex's own
next save, which is why AC87 is relaxed to parse-equal plus key order plus "unknown members
verbatim *on agctl's side*" rather than a byte-identical round trip.

```sh
rg -a -o 'struct AuthDotJson with [0-9]+ elements' "$CODEX"
rg -a -c 'truncate(true)' "$CODEX"
```

**Expected, 0.155.0-alpha.4:** `struct AuthDotJson with 8 elements` (same grep and count as
§6.1 — F61 and F90 share the struct declaration); the second grep: at least 1 (Rust debug
symbols for `OpenOptions` builder calls are not guaranteed to survive optimization, so treat
a 0 here as inconclusive rather than a failure, and fall back to reading
`login/src/auth/storage.rs:206-223` directly).

**Fails if:** Codex switches to a writer that fsyncs or renames (making the torn-read window
F66 assumes narrower or gone), or `AuthDotJson` gains a flatten catch-all (which would change
what "Codex drops unknown members" means for AC87). Re-read
`login/src/auth/storage.rs:206-223` at the new tag.

**Affected agctl code:** `src/provider/codex/credentials.rs` (`Credentials::write`), and
every AC87 test fixture under `fixtures/codex/`.

**A residual this section does not cover.** Two properties are held inside agctl rather than by
any Codex-binary fact, so no Codex CLI upgrade touches them — and neither is held the way a
reader might assume. They are stated separately here because one sentence used to claim both.

*That no Codex command asks the keychain for one account's password* is held first by
`tests/common/codex.rs`'s `checked`, which fails any e2e run whose fake `security` log records a
`find-generic-password`, and second by `scripts/phase3-greps.sh`'s `codex_no_password_lookup`
rule over the source. The grep is the second line of defence, not the first.

*That every write receipt reaches the audit log* is held at run time by
`src/provider/codex/auth_store.rs`'s `UNAUDITED_RECEIPT` panic-on-drop guard, which every receipt
is born armed with — and by essentially nothing else. `phase3-greps.sh`'s `receipt_type`,
`receipt_destructure`, `receipt_check` and `reached_audit` rules pin the type, three syntactic
shapes, the guard's one spelling and its one disarmer; none of them follows a receipt from its
binding to its audit, and an unaudited receipt planted at a real production site leaves them all
green. **The guard therefore fires only on a path a test actually drives, and nothing in the tree
requires a newly added receipt site to be driven by one.** The static AC119 source-reading family
that used to state this here was **dropped from the phase-3 plan by user decision, 2026-09-22
(ledger #460)** and its files are gone. None of this proves anything about the coverage of code
added after it: do not read a green run as a substitute for a security review of new
Codex-touching code.

---

## 7. Linux — S1 matched evidence (agctl-linux-support v1.2)

This is an **evidence spike, not a Linux support declaration**. The source baseline is
`b09c92a`. Unlike the historical read-only checklist above, the commands in **this section**
execute vendor binaries and mutate explicitly isolated scratch trees. Never substitute an
operator home. No ordinary Claude/Codex store, macOS keychain, installed launcher, or host
package installation was changed. Every observation below carries the UTC output of `date`
from its recording command; the local source/dependency inspection used JST.

**Stop for scoped review, not another login:** the approved §7.4 operator checkpoint
completed successfully: real credential create/replacement, the storage mutex across those
publications, and the owner sidecar during a forced real refresh are measured in U2/U3.
Logout and scratch removal are confirmed. The exceptional in-place fallback was not forced
with live credentials; its evidence remains the matched source and controlled kernel test,
not a real fallback write. Three changed premises still go to the plan owner's planner and
scoped-critic return:
- the actual storage mutex name `.storage-write.lock`, which is platform-independent and
  pre-existing (U3);
- the vendor's in-place write fallback (U2, D-060 §4.2);
- version-named Claude processes (U4, D-058).

No S2 implementation or credential enablement is authorized by this record. Linux Codex
login selects D-064's named **`unsupported on this platform` before spawn** branch, and the
lead accepted it as the U5 outcome. That does not disable proven file-backed Codex
status/import/doctor or the remaining Claude work.

### 7.1 Host and matched artifacts

Measurements: `2026-09-25 22:14:34 UTC`, `22:14:47–22:14:49 UTC`,
`22:15:33–22:15:45 UTC`, and `22:28:32 UTC` (each from the associated host command).
The host is `debian-13-trixie.gaudiy-platform`, Debian GNU/Linux 13 (trixie),
`Linux 6.12.107+deb13-cloud-amd64 x86_64`, real UID 1000. `/tmp` is tmpfs;
`/proc` is procfs, mounted `rw,nosuid,nodev,noexec,relatime`, with no `hidepid` option.
The inherited probe umask was `0002`.

| Artifact | Measured version / size | SHA-256 |
|---|---|---|
| Installed `/home/zchee/.local/bin/claude` → `/home/zchee/.local/share/claude/versions/2.1.220` | `2.1.220 (Claude Code)`; not used for contract probes | `674f61f20ff306f3100cf9200e4c36c4b70278b5bef2884549819b942a89c863` |
| `/tmp/agctl-linux/claude/2.1.282/claude` | `2.1.282 (Claude Code)`; 238767288 bytes | `3afe8535c0cc33f0e24f7b25dab7a1727b8b592196f8496a8bc302ba2161eed3` |
| `/tmp/agctl-linux/codex/codex.tar.gz` | `codex-x86_64-unknown-linux-musl.tar.gz`, release `rust-v0.157.0-alpha.10`; 107203213 bytes | `781c7c2615b2e843b94ced7cc5557e6caaa86991b257378f377675b5e6bc39f0` |
| `/tmp/agctl-linux/codex/codex-x86_64-unknown-linux-musl` | `codex-cli 0.157.0-alpha.10`; 283398696 bytes | `3d1ccd1bb6d0864c01b01192204a00e3e8ebfc28ca7ef395c7bc3ca8cad7d898` |

Codex is **not installed on the ordinary host PATH**. The non-interactive SSH PATH also
omits `~/.local/bin`; the existing Claude launcher was therefore invoked by absolute path.
AC177's literal `claude; codex; command -v ...` witness needs these explicit paths, not a
false claim that both are installed. Both version checks ran with a scratch HOME/config.
No version fallback was needed: the release publishes musl rather than a GNU Linux Codex
asset, but its version is the exact requested one. The local source tag
`rust-v0.157.0-alpha.10^{commit}` resolves to
`2170d8b3c77883dbe743078fb8bbb017f27caa9c`.

The downloaded `https://claude.ai/install.sh` was **read, not executed**. Its lines 38,
158–168 and 196–216 derive the base URL, platform manifest and binary checksum procedure.
The exact manifest entry was:

```text
platforms["linux-x64"]:
  binary: claude
  checksum: 3afe8535c0cc33f0e24f7b25dab7a1727b8b592196f8496a8bc302ba2161eed3
  size: 238767288
```

Reproduce the artifact checks without running the installer:

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
ROOT=/tmp/agctl-linux
CC=$ROOT/claude/2.1.282/claude
CODEX=$ROOT/codex/codex-x86_64-unknown-linux-musl
RG=$ROOT/tools/usr/bin/rg
base=https://downloads.claude.ai/claude-code-releases/2.1.282
# Saved manifest: curl -fsSL "$base/manifest.json" -o "$ROOT/claude/2.1.282/manifest.json"
# Saved binary: curl -fsSL "$base/linux-x64/claude" -o "$CC"
jq '.platforms["linux-x64"]' "$ROOT/claude/2.1.282/manifest.json"
digest=$(jq -r '.platforms["linux-x64"].checksum' "$ROOT/claude/2.1.282/manifest.json")
printf '%s  %s\n' "$digest" "$CC" | sha256sum -c -
# release.json was fetched from the public GitHub releases/tags/rust-v0.157.0-alpha.10 API.
jq -r '.assets[] | select(.name == "codex-x86_64-unknown-linux-musl.tar.gz") |
  [.name, .size, .digest, .browser_download_url] | @tsv' "$ROOT/codex/release.json"
sha256sum "$CC" "$CODEX" "$ROOT/codex/codex.tar.gz"
```

**Expected, Claude 2.1.282 / Codex 0.157.0-alpha.10:** both published checksums verify
(`sha256sum -c`: `OK`); the values above match. Codex's archive digest comes from the
release asset's published `digest` field, not from a checksum invented after download.

**Matched extraction, not identical bundles.** The macOS reverse-source pin is
`ac66a5f2158ff75bfb951d25363bcf2f4e9dd3bd` (`package.json`: 2.1.282).
The Linux ELF is platform-specialized: the macOS `Gn → Ns(On, Dr)` factory becomes Linux
`zn → In` (plaintext), and literal `"darwin"` error-policy arguments become `"linux"`.
Consequently the embedded Linux JS is **not byte-identical** to `cli.unpack.js@ac66a5f`;
using the macOS factory as Linux proof would be wrong.

At `2026-09-25 22:16:51 UTC`, ELF `.bun` started at byte 88952832, length 149756066.
The Bun trailer described 2282 modules, entry index 5. Section/table bounds and module
names were validated before extraction. Three `.js`-named compressed web assets (Chart,
highlighting, Mermaid) contain Zstandard bytes and were not treated as JS source; the
credential modules below were NUL-free UTF-8. Formatting copies was for inspection only.
These byte ranges reproduce the original modules directly from the verified ELF:

| Linux Bun module | Absolute byte offset | Byte length | Contract inspected |
|---|---:|---:|---|
| `chunk-37swe2q7.js` | 194118952 | 5048 | `ve`, config directory/NFC |
| `chunk-nbcqw6vp.js` | 194136113 | 52793 | `ce().mkdir`, recursive/default mode |
| `chunk-1s5hx5dz.js` | 194933514 | 12311 | `Rn`, `lte`, exclusive temp and in-place fallback |
| `chunk-bzev8hcq.js` | 196358720 | 23201 | `ci`, proper-lockfile path/options |
| `chunk-qpevst33.js` | 196381922 | 2964 | `pw`, secure-store precedence |
| `chunk-63sndd1w.js` | 196384887 | 169643 | `zn`, `In`, `Bi`, `GLr`, plaintext/mutex |
| `chunk-wbbthbh9.js` | 196616192 | 612080 | `ean`, `$ko`, owner, refresh/change detection |
| `chunk-5gy2g37a.js` | 206044450 | 5340 | V5 `iC`, `y`, file reader/writer |

For example, `dd if="$CC" bs=1 skip=196384887 count=169643 status=none` obtains the
legacy module; save under `/tmp/agctl-linux/` before inspecting it. Source citations below
name these modules/functions plus the macOS homologues; byte ranges and ELF digest make
those citations reproducible after minifier names move in another release.

**Fails if:** a version/digest differs, a claimed source tag does not resolve to the pin,
or a Linux conclusion is supported only by the macOS extraction.
**Affected agctl code:** all platform decisions in S2–S5; no source changed in S1.

### 7.2 U1–U8

#### U1 — Linux plaintext selection (consumer: S4)

**Citations:** C2/C3 at `cli.unpack.js:118113–118119,117769–117848,118469–118475@ac66a5f`;
Linux `chunk-63sndd1w.js` functions `zn`, `In`, `Bi`; V5
`chunk-5gy2g37a.js` functions `iC`, `W` and object `y`.
Linux `zn()` returns `In`, whose name is `plaintext` and whose reads/writes use
`be().storagePath`. V5's default `iC(e,r=y)` wraps the file object, not a keychain object;
both constructors select `<pw()>/.credentials.json`. The V5 feature/context gate controls
whether that handle is used; an ordinary auth-status trace is not proof that both gates ran.

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
"$RG" -a -o 'function zn\(\)\{if\(Os\)return Os;return In\}' "$CC"
"$RG" -a -o 'function iC\(e,r=y\).{0,100}' "$CC"
"$RG" -a -o 'storagePath:[A-Za-z0-9_$]+\([A-Za-z0-9_$]+,"\.credentials\.json"\)' "$CC"
"$RG" -a -o 'storePath:[A-Za-z0-9_$]+\([A-Za-z0-9_$]+,"\.credentials\.json"\)' "$CC"
```

**Expected, 2.1.282:** the first two functions and both file paths above. The dynamic
`auth status` observations at `2026-09-25 22:19:35–22:19:37 UTC` opened the selected
scratch file, then statted/read it again, returned 0, and left its inode/mode/size unchanged.
The initial opens were `O_RDONLY|O_NOCTTY|O_LARGEFILE|O_CLOEXEC`, without `O_NOFOLLOW`:
this observed legacy read must not be mistaken for V5's explicit no-follow reader.

The synthetic probes above used `env -i`, scratch cwd/HOME, scratch `CLAUDE_CONFIG_DIR` (except
intentional unset/empty cases), and scratch `XDG_CONFIG_HOME`, `XDG_CACHE_HOME`,
`XDG_DATA_HOME`, `XDG_STATE_HOME`, `XDG_RUNTIME_DIR`, `TMPDIR`. `DBUS_SESSION_BUS_ADDRESS`
was absent. `unshare -Urn` succeeded and removed network access; additionally
`ANTHROPIC_BASE_URL=http://127.0.0.1:9`,
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_AUTOUPDATER=1` were set.
Fixtures came from `fixtures/claude/credentials-old-blob.json`, were mode 0600, and were
synthetic throughout. No fixture contents or token values are reproduced here.

Representative command (set `P` to the already seeded scratch case):

```sh
cd "$P/work"
date -u '+%Y-%m-%d %H:%M:%S UTC'
env -i PATH=/usr/bin:/bin HOME="$P/home" CLAUDE_CONFIG_DIR="$P/config" \
  XDG_CONFIG_HOME="$P/config-xdg" XDG_CACHE_HOME="$P/cache" XDG_DATA_HOME="$P/data" \
  XDG_STATE_HOME="$P/state" XDG_RUNTIME_DIR="$P/runtime" TMPDIR="$P/tmp" \
  ANTHROPIC_BASE_URL=http://127.0.0.1:9 CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  DISABLE_AUTOUPDATER=1 unshare -Urn /tmp/agctl-linux/tools/usr/bin/strace \
  -f -s 300 -e trace=openat,open,stat,newfstatat,statx,rename,unlink,mkdir,rmdir,fsync,fdatasync,flock,fcntl,chmod,fchmod,connect,execve \
  -o "$P/trace" "$CC" auth status
```

Bounded negative search at `2026-09-25 22:26:37 UTC`: whole-ELF `rg -a -c -F` counts
were `libsecret=2`, `secret-tool=2`, `keytar=1`, `org.freedesktop.secrets=0`,
`Secret Service=0`. **Those nonzero strings were not erased or called absence.** The
source `secret-tool` occurrence is a shell-grant helper enumeration
(`chunk-8aspyxzh.js`), not the credential-store factory. The other two terms had no hits
in the extracted UTF-8 JS source. Legacy/V5 storage modules have no Secret Service
backend; representative auth-status/expired-refresh traces contain no D-Bus/keyring/helper
path. Other subsystems and unexecuted branches are not ruled out by a negative trace.

**Verdict:** plaintext backend selection established by actual Linux source plus isolated
file reads; V5 selection is source-established, not dynamically forced. U2 records the
separately approved successful-write checkpoint; this evidence does not enable agctl writes.
**Fails if:** either factory selects another backend or a matched credential read reaches
another store. **Affected agctl code:** `secret/location.rs`, `secret/file_store.rs`,
`provider/claude/namespace.rs`, discovery and S4's file adapter.

#### U2 — Directory precedence and writer (consumer: S4)

**Citations:** C1/C7 at `cli.unpack.js:12364–12382,116768–116774,118173–118194,
843545–843564@ac66a5f`; Linux `chunk-qpevst33.js::pw`,
`chunk-37swe2q7.js::ve`, `chunk-63sndd1w.js::Bi.write`,
`chunk-5gy2g37a.js::y.writeCredentials`, `chunk-1s5hx5dz.js::{Rn,lte,dx,YD,De}`.

The auth-status matrix used distinct preseeded candidate files per case. At
`2026-09-25 22:19:35–22:19:37 UTC`, every row returned 0 and opened only the selected
credential path below (relative paths are relative to that case's scratch `work/`):

| Secure-storage variable | Config variable | Observed `.credentials.json` parent |
|---|---|---|
| unset | unset | scratch `HOME/.claude` |
| unset | empty string | cwd, not `HOME/.claude` |
| unset | `relative` | cwd/relative |
| unset | absolute scratch config | that config |
| absolute scratch secure | absolute scratch config | secure, not config |
| empty string | absolute scratch config | `HOME/.claude`, not config |
| `relative` | absolute scratch config | cwd/relative |
| unset | decomposed Unicode `cafe` + combining acute | NFC-composed `café` directory |

Thus the rule is presence-sensitive: a defined secure-storage variable wins; its empty
value means home. Otherwise config uses `??`, so empty config means cwd. Both source
branches normalize NFC and do not canonicalize symlinks. agctl's empty-config-to-home
rule is not the peer's rule; keep the plan's refusal for ambiguous live mutation.

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
"$RG" -a -o 'function pw\(\).{0,210}' "$CC"
"$RG" -a -o '\.tmp\.\$\{[A-Za-z0-9_$]+\(4\)\.toString\("hex"\)\}' "$CC"
"$RG" -a -o '.{0,45}new Set\(\["EXDEV","EPERM","EEXIST","EBUSY"\]\).{0,50}' "$CC"
# For each matrix case: run the U1 command with the stated variable presence/value,
# then inspect credential-path syscalls, not stdout credential material.
stat -c 'inode=%i mode=%a size=%s %n' "$P/config/.credentials.json"
```

**Expected, 2.1.282:** normal writes use same-directory `.tmp.<8 lowercase hex>`,
exclusive creation and rename. Legacy passes mode 0600 then path chmod 0600; V5 passes
both mode and exactMode 0600, so its temp descriptor is chmodded before publication.
`ce().mkdir` is recursive with no supplied mode: request 0777, masked by umask, not an
unconditional 0700 directory contract. The observed lock mkdir requested 0777 and yielded
0775 under umask 0002; that lock observation is not a credential-directory creation test.

**Changed premise for D-060 §4.2: the vendor writer falls back to an in-place write.**
This is static matched-Linux evidence. Linux `lte` catches the staging rename's error. When
the error code is in `bS = new Set(["EXDEV","EPERM","EEXIST","EBUSY"])`, `lte` calls its
in-place arm instead of failing. That arm:
1. opens the target `O_WRONLY|O_CREAT|O_NOFOLLOW`;
2. calls `truncate(0)`;
3. calls `writeFile`;
4. chmods the file.

It calls `sync()` only when the caller passed `flush:true`. The same construct is in the
macOS extraction, so it is platform-independent rather than Linux-only. The table uses the
formatted Linux inspection copy of `chunk-1s5hx5dz.js` and the macOS reverse source
`cli.unpack.js@ac66a5f`:

| Construct | Linux `chunk-1s5hx5dz.js` | macOS `cli.unpack.js@ac66a5f` |
|---|---|---|
| Fallback set | 153 (`bS`) | 53343 (`bb`) |
| `Rn` wrapper → writer | 429–431 → `lte` from 432 | 53706–53711 → `yte` 53712–53896 |
| Writer options (`mode`, `exactMode`, `flush`, `stagingDir`, `renameFn`) | 432–443 | 53713–53723 |
| Temp directory `Me(target, stagingDir)`; `undefined` returns the target path, so the temp sits beside it | `Me` 328–329, call 448 | `Me` 53562–53564, call 53730 |
| In-place arm `K` | 453–517 | 53735–53804 |
| `open(O_WRONLY\|O_CREAT\|O_NOFOLLOW)` on the target | 457 | 53739 |
| `truncate(0)` | 489 | 53770 |
| `sync()` only if `flush === true` | 493–497 | 53780–53788 |
| Staging branch (`exactMode` or `flush`) | 520 | 53807 |
| Rename catch → set lookup → `K(p)` | 568–574 (`bS.has` 572, `K(p)` 573) | 53877–53889 (`bb.has` 53885, `K(p)` 53888) |

Neither credential writer passes `flush:true`. File sync is conditional on that option, and
no directory fsync is present. So the vendor guarantees neither unconditional atomic
replacement nor crash durability.

**Reachability of the four errors on this writer's same-directory rename.** Sources: the
host `rename(2)` man page, read at `2026-09-25 22:37:37 UTC`, and a controlled kernel test
at `2026-09-25 22:50:53 UTC`. The test was a same-directory Python `os.rename` inside
`unshare -Urm` on scratch files under `/tmp/agctl-linux/scratch/`; it did not run the vendor.

| Error | When a same-directory rename returns it | Exposure |
|---|---|---|
| `EXDEV` | Only when old and new paths are on different mounts. The temp is created in the target's directory, so the parent mount is shared. A mount-point target returns `EBUSY` instead (measured). | Not reachable. |
| `EBUSY` | The target is a mount point. **Measured:** renaming onto a file bind-mounted onto itself returned `EBUSY`. A following in-place `O_WRONLY` open, truncate and write on that target succeeded, and the inode was unchanged. | Reachable where `.credentials.json` is a single-file bind mount, for example a container volume or secret mount. The vendor then writes in place, which opens a torn-read window. |
| `EEXIST` / `ENOTEMPTY` | The man page lists these for a non-empty **directory** newpath, and for `RENAME_NOREPLACE`, which this writer never passes. **Measured:** a regular file renamed onto a directory returned `EISDIR`, which is outside the set, so the vendor rethrows and removes its temp. An open-for-write on that directory also returned `EISDIR`. | Not reachable in a normal home. Only a non-conforming network or FUSE filesystem could return `EEXIST` for a file target; not measured. |
| `EPERM` | A sticky parent directory whose file and directory both belong to another user, without `CAP_FOWNER`; a seccomp or LSM denial; some FUSE or network filesystems. An immutable or append-only target also refuses the in-place `O_WRONLY` open, so that case fails closed. This is by kernel semantics and was not measured. | Not reachable in an owner-owned local `~/.claude`. |

**Determination for D-060 §4.2:** agctl's peer torn-read protections apply on those four
rename errors. In a normal owner-owned local home none of the four is reachable. The
measured reachable case is `EBUSY` on a mount-point target.

agctl's own write contract is stricter and remains distinct. `src/secret/file_store.rs:21–29`
already cites the vendor's fallback as fact F40. agctl writes an `O_EXCL` 0600 temp, fsyncs
it and renames it. It has no in-place fallback: on a failed rename, including `EXDEV`, it
leaves the old file and hands the new credentials to the next run. This vendor evidence
neither relaxes nor replaces that contract.

The expired-fixture `-p x --output-format json` attempt at
`2026-09-25 22:19:37–22:19:55 UTC` timed out (124) under the no-network sandbox.
It read credentials and took refresh locks but did not write them: before/after inode
417331, mode 0600, size 354. Other fsync calls in the process belong to other files;
their presence cannot be attributed to this unchanged credential file.

**Successful operator checkpoint, `2026-09-26 UTC`.** The §7.4 retry used the matched
binary, `env -i`, `umask 077` and `/tmp/agctl-linux/scratch/oauth-checkpoint-2`.
`checkpoint-result.txt` recorded login start `01:25:52`, exit `01:26:10`, status 0.
A `date -u`/stat check at `01:27:22` independently confirmed the resulting file:

| Stage | Device / inode | Mode / UID / GID | Size / nlink |
|---|---|---|---|
| After login | 34 / 454895 | 0600 / 1000 / 1003 | 524 / 1 |
| Before approved expiry edit (`01:27:29`) | 34 / 454895 | 0600 / 1000 / 1003 | 524 / 1 |
| After same-inode expiry edit (`01:27:29`) | 34 / 454895 | 0600 / 1000 / 1003 | 513 / 1 |
| After real refresh (`01:27:31`) | 34 / 454924 | 0600 / 1000 / 1003 | 524 / 1 |

The expiry edit used jq in shell memory and builtin printf to the same path; no credential
copy or payload was printed. The non-interactive refresh command ran `01:27:29–01:27:31`,
returned 0 and left a future expiry (boolean check only). Changed inode plus the trace's
successful rename establishes normal replacement; the preparatory expiry edit retained
its inode and must not be mistaken for a vendor in-place write.

**Observed publication sequence**, from `login.strace` and `refresh.strace`, inspected at
host `date -u` `01:27:22` and `01:28:04`. All times below are trace UTC; `C` means the
scratch `config/.credentials.json`. All listed syscalls completed with 0 or a valid fd,
including the split `unfinished/resumed` records:

| Publication | Storage lock mkdir | Temp open / length | Rename onto C | chmod C / storage lock rmdir |
|---|---|---|---|---|
| Login first publish | `01:26:10.056539` | `C.tmp.27ea7beb`, `01:26:10.057485`; ftruncate 2 | `01:26:10.057742` | 0600 at `01:26:10.057923` / `01:26:10.058080` |
| Login second publish | `01:26:10.069046` (returned `01:26:10.069080`) | `C.tmp.1e7aa9d0`, `01:26:10.069992`; ftruncate 524 | `01:26:10.070354` (returned `01:26:10.070392`) | 0600 at `01:26:10.070533` / `01:26:10.070639` |
| Real refresh publish | `01:27:30.267531` | `C.tmp.622b1809`, `01:27:30.269133`; ftruncate 524 | `01:27:30.269782` | 0600 at `01:27:30.270716` (returned `01:27:30.270769`) / `01:27:30.270950` |

Every temp open was `O_WRONLY|O_CREAT|O_EXCL|O_LARGEFILE|O_CLOEXEC`, requested mode
0600, and every temp name has eight lowercase hex digits. Each ftruncate sized the **temp
fd**, not the destination. No credential-target write-open/truncate or rename failure was
observed. Storage-lock mkdir requested 0777 and statx measured 0700 under umask 077.
Credential-directory mkdir likewise requested 0777 but returned EEXIST: this directory
was precreated 0700 by the harness, so this is not evidence of an unconditional vendor
0700 directory policy.

No fsync/fdatasync occurred within any of the three storage-lock-held publication intervals,
on either the credential or its directory. Whole-process fsync counts were 12 for login,
3 for refresh and 2 for logout; these counts cannot be attributed to credential durability.
They do not contradict the source-established absence of a credential `flush:true` call.
The login's intermediate 2-byte publication is a newly measured detail, **not a claim about
its contents**. The writer performs separate atomic renames, not one atomic login transaction.

**Verdict:**
- **Path semantics: settled.**
- **In-place fallback: settled statically.** It is platform-independent and bounded by the
  reachability table above. It is a changed premise for D-060 §4.2. A live fallback was
  not exercised by the approved single-login/normal-refresh checkpoint.
- **Real create and normal replacement: settled by the operator checkpoint.** Temp mode,
  inode change, lock/publish/release sequence and sync absence during publication are
  measured. No additional browser step remains for this approved procedure. Consumer
  S4/Phase 2 still requires the scoped ruling; Phase 1 is unaffected by these write facts.
**Fails if:** the reviewed implementation assumes all vendor writes are atomic or silently
maps empty config to home. **Affected agctl code:** S4 file transport/read validation,
`namespace.rs`, `secret_file.rs`, and swap/undo containment.

#### U3 — Locks, timing and owner sidecar (consumer: S4)

**Citations:** C4/C6 at `cli.unpack.js:117707–117766,132070–132115,162500–162573@ac66a5f`;
Linux `chunk-wbbthbh9.js::{ean,yv,$ko,VIr,cc,yc}`, `chunk-63sndd1w.js::GLr`,
`chunk-bzev8hcq.js::{ci,ne,Nt}`.

| Resource | Matched Linux source / observation |
|---|---|
| Primary refresh | `<store>/.oauth_refresh.lock`; explicit lockfilePath, realpath=false, stale 60000 ms, update 5000 ms |
| Legacy refresh | `<realpath(store)>.lock`; acquired second, explicitly overrides lockfilePath |
| Storage mutex | **`<store>/.storage-write.lock`**, not `.storage-write`; caller passes `.storage-write` with no lockfilePath, and proper-lockfile appends `.lock` |
| Storage timing | stale 15000 ms; retries 10, minTimeout 100, maxTimeout 1000; no explicit update, so proper-lockfile derives 7500 ms; AsyncLocalStorage re-entrant |
| Refresh contention | 5 attempts, four sleeps of `1000 + Math.random()*1000` ms; 7500 ms contention deadline unchanged |
| Owner metadata | `<store>/.oauth_refresh.lock.owner`; metadata file, not a fourth lock; written after the two refresh acquisitions and removed before release |

At `2026-09-25 22:19:37–22:19:55 UTC`, the real expired-token attempt repeatedly made
primary then `config.lock`, created/renamed the owner temp, and removed owner then legacy
then primary. The owner temp requested 0666, resulting owner mode 0664, size 239; primary
mkdir requested 0777, resulting mode 0775. Its source schema has numeric pid/birthtimes
and string process-start/domain/namespace fields (optional process start and legacy
birthtime). An attempted type-only sidecar read raced with removal; the schema description
is from matched source, not a fabricated successful read. The owner **write** is not gated
at `$ko`'s call site; `tengu_quiet_marten` gates consuming it for reclaim evidence.

At `2026-09-25 22:25:58 UTC`, a separate no-network `auth logout` of a synthetic scratch
credential without a refresh field returned 0 and traced exactly:

```text
mkdir("<scratch>/config/.storage-write.lock", 0777) = 0
unlink("<scratch>/config/.credentials.json") = 0
rmdir("<scratch>/config/.storage-write.lock") = 0
```

**Measured, not static:** this trace shows the matched Linux binary taking its storage mutex
as `.storage-write.lock`. It is the deletion path, not a successful write or refresh.

What logout does before that deletion (Linux 2.1.282 source): for a first-party session,
the logout command in `chunk-77w00cam.js` reads the store. It then calls
`hE(refreshToken, clientId)` for `claudeAiOauth` and again for `designOauth`. `hE`, at
formatted `chunk-wbbthbh9.js:29406–29425`, POSTs `${TOKEN_URL}/revoke` with
`token_type_hint:"refresh_token"` and a 5000 ms timeout. On failure it logs and continues
with the local logout. Logout therefore revokes only the refresh token currently in the
store. The synthetic fixture had no refresh field, so no revoke was attempted.

Two real expired-fixture peers
at `2026-09-25 22:27:24–22:27:36 UTC` produced primary-lock `EEXIST` contention and a
lock `utimensat`; both hit timeout 124 and left no acquired lock/owner entries. The observed
utimensat was acquisition-time precision probing, not a measured periodic heartbeat.

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
"$RG" -a -o '\.oauth_refresh\.lock"\),realpath:[^,]+,stale:[0-9]+,update:[0-9]+' "$CC"
"$RG" -a -o 'function ne\(e,r\)\{return r.lockfilePath.{0,30}' "$CC"
"$RG" -a -o '.{0,260}\.storage-write.{0,260}' "$CC"
# Repeat U1's isolated wrapper with `auth logout` only on its expendable synthetic fixture;
# repeat with `-p x --output-format json` and an expired fixture for refresh locks.
```

**Binary anchor replay**, `2026-09-25 22:23:34–22:23:35 UTC`: every §1/§2/§4/§5.1
pattern was executed against this ELF with `rg -a`. Counts below preserve the distinction
between `-c` matching lines and `-o` occurrences; historical expected counts are not reused.

| Anchor | Linux result / consequence |
|---|---|
| F14 | service template 1, NFC/hash shape 1, secure-storage variable matching lines 10 |
| F40 | legacy path 1, V5 path 1, temp shapes 2, refused-symlink matching lines 3 |
| F36 | primary options 1; 7500 ms deadline shape 1; backoff matching lines 6 |
| F42/F43/F44 | add-password lines 5, delete-password 0, old four-constant tuple 0; residual non-store/dormant transports are not Linux factory selection |
| F45 | ELOCKED lines 11; bounded contexts 14; mkdir/rmdir/mtime mechanics retained |
| F46 | refresh-lock lines/contexts 4, including owner metadata; two-lock order source and trace confirmed |
| F47 | contexts 2, including binary string data; options retained, **actual directory gets `.lock` suffix** |
| F48 | old `Dge(` lines 5 / contexts 10 are unrelated hook parsing; current `uv` at formatted `chunk-wbbthbh9.js:27461–27475` probes V5 or stats the file, then handles failures via `PS` |
| F49/F50 | probeCredentials lines 3; Config-lock messages 7 occurrences; no keychain selection inference |
| F53 | failure message 2 (one string-pool hit); retry expression 1, `_F=5` |
| F54/F55 | isCompromised lines 5; pre-POST contexts 3 including string-pool fragments; suspend/slow-fs messages 4; source still checks compromise before POST |
| F56 | --mcp-config lines 38; .mcp.json lines 75 |
| F57 | host process-name observation belongs to U4; historical “no holder identity” is superseded by the owner sidecar |
| F58 | old `$Pn` expression 0; current `Et → GLr → e.update` re-establishes mutation inside the storage mutex |
| F59 | repeatable flag contexts 12; unique CLAUDE_*MCP* strings 26; source still pushes/flatMaps repeated flags, no equivalent config-path env identified |

F51/F52 are the historical operator-machine inventory and were deliberately **not** run:
they are not Linux vendor-binary facts and would enter live homes. F35's backend-selection
question is resolved by U1, not by retaining an old macOS factory symbol. A nonzero binary
count is never a control-flow proof: source modules and the relevant runtime path decide it.

**The storage mutex name is platform-independent and pre-existing.** The vendor passes the
bare base name `.storage-write` to proper-lockfile with `realpath:false` and **no
`lockfilePath`**. proper-lockfile's `ne(e,r)` then returns `` `${e}.lock` ``, and `Ne`
mkdirs that name. The same shape appears in every bundle checked:

| Bundle | Storage-write call (no `lockfilePath`) | Lockfile-name rule |
|---|---|---|
| Linux 2.1.282 | measured `mkdir(".storage-write.lock")` above; `rg -a` context (F47 row below) | same proper-lockfile |
| macOS `ac66a5f:cli.unpack.js` | `117718–117728` (`ci(Hi(s, ".storage-write"), {realpath:false, …, stale:15000, …})`) | `ne` `116358–116360` (return at `116359`); `Ne` `116367–116369` (mkdir of `ne(...)` at `116369`) |
| 2.1.263 `9cf6ecf:cli.unpack.js` | `95878` (`Cs(U(a, ".storage-write"), {realpath:false, …`) | same library |
| 2.1.266 `3abb410:cli.unpack.js` | `97779` (`vs(U(n, ".storage-write"), {realpath:false, …`) | same library |

The macOS and older-bundle lines were re-read with `git show <rev>:cli.unpack.js` at
`2026-09-26 08:08:19 JST`. The primary and legacy refresh-lock names are exact **because**
those two calls pass `lockfilePath`. The storage-write call does not, so its directory name
gains the `.lock` suffix.

**Verdict (a): changed premise for D-061's "same three locks" on Linux.** The third lock
the Linux peer takes is `<store>/.storage-write.lock`, not `<store>/.storage-write`.

**Verdict (b): an existing, platform-independent agctl mismatch since the facts were first
recorded.**
- `src/secret/foreign_activity.rs:33` defines
  `pub const STORAGE_WRITE_LOCK: &str = ".storage-write";`.
- `src/secret/claude_lock.rs:1205–1206` mkdirs `anchor.store_dir.join(STORAGE_WRITE_LOCK)`
  through that constant.
- The constant is also read by `foreign_activity.rs:105` and by `commands/doctor.rs:24`,
  `745`, `983` and `1197`.
- Every bundle above, macOS included, mkdirs `.storage-write.lock`. agctl's storage mutex
  therefore does not exclude the peer's storage mutex on either platform.

The earlier comparison was **static-only** for the write path; the successful Linux login
and refresh below now measure `.storage-write.lock` held across real credential publications.
The macOS comparison remains matched-source evidence. No agctl/peer concurrent exclusion
test was run, but the differing lock paths are directly established. No code or test was
changed in S1. Do not advertise safe three-lock Linux writes or fix this silently: the
ruling still belongs to the plan owner and scoped critic.

**Fixture check**, `rg -n 'storage-write\.lock'` over `src/`, `tests/` and `fixtures/` at
`2026-09-26 08:03:11 JST`: **0 hits**. No fixture spells a `.lock`-suffixed storage-write
name. The unsuffixed name appears as literals in these places:
- Integration tests:
  - `tests/common/mod.rs:236,291` (`hold_artefacts`)
  - `tests/e2e_refresh.rs:212`
  - `tests/e2e_doctor_stale.rs:148`
  - `tests/e2e_accounts.rs:402`
  - `tests/e2e_swap.rs:1029,1646,4082` (1646 is a comment). `e2e_swap.rs:1659–1660` and
    `1842–1844` reach it through `hold_artefacts`.
- Unit tests:
  - `held_locks_tests.rs:202`
  - `claude_lock_tests.rs:594,652,1203,1214,1992,2109`
  - `file_store_tests.rs:790`
  - `doctor_tests.rs:436,439,735,794,882`
  - `status_tests.rs:788,2547`
  - `foreign_activity_tests.rs:30`

**Real-write and real-refresh checkpoint: settled**, consumer S4/Phase 2; Phase 1 unaffected.
The approved scratch-only expiry edit and successful real refresh are recorded in U2.
The trace was inspected with host `date -u` at `2026-09-26 01:28:04 UTC`; split syscall
returns were checked before cleanup. The order was:

| Trace UTC (`2026-09-26`) | Successful operation |
|---|---|
| `01:27:29.733550` | mkdir `config/.oauth_refresh.lock`, requested 0777 |
| `01:27:29.735452` | mkdir legacy `config.lock`, requested 0777 |
| `01:27:29.736517` | exclusive write-create `config/.oauth_refresh.lock.owner.tmp.aea73e4d`, requested 0666 |
| `01:27:29.736589` | ftruncate owner temp fd to 235 bytes |
| `01:27:29.736978` | rename owner temp to `.oauth_refresh.lock.owner` |
| `01:27:30.267531` | mkdir `config/.storage-write.lock`, requested 0777 |
| `01:27:30.269133–01:27:30.270769` | credential temp create/size, rename onto `.credentials.json`, chmod 0600 (U2) |
| `01:27:30.270950` | rmdir `.storage-write.lock` |
| `01:27:30.274465` | unlink `.oauth_refresh.lock.owner` |
| `01:27:30.275437` | rmdir legacy `config.lock` |
| `01:27:30.275654` | rmdir primary `.oauth_refresh.lock` |

statx measured both refresh directories and the storage directory at 0700; the owner file
was 0600 and 235 bytes under umask 077. Its contents were not read. The storage mutex
covered the credential rename and final chmod; the owner persisted until after publication
and was removed before either refresh lock. Both login publications in U2 were likewise
inside `.storage-write.lock`. This resolves the former storage-write/owner checkpoint
blocks without claiming a periodic heartbeat or forcing a live fallback.

**Traced logout and cleanup.** `oauth-observe.sh logout` recorded host `date -u` start
`2026-09-26 01:28:27 UTC`, end `01:28:28 UTC`, exit 0 and credential absent. The trace
shows storage mkdir at `01:28:28.451328`, credential unlink at `01:28:28.451973`, then
storage rmdir at `01:28:28.452136`, all successful. At `01:29:05 UTC`, explicit tests
confirmed no credential, storage/primary/legacy lock or owner sidecar remained. The
requested tmux kill found the dedicated socket's server already absent. At `01:29:15 UTC`,
absence was rechecked, the scratch tree was removed and removal verified. The local
logout does not prove successful server-side revocation, whose errors the vendor swallows.
No ordinary operator store was touched.

**Fails if:** a consumer ignores the suffix, treats owner metadata as an extra lock, or
uses unreadable-holder evidence as permission to remove a lock.
**Affected agctl code:** `secret/claude_lock.rs`, `foreign_activity.rs`, doctor stale removal.

#### U4 — Process identity and visibility (consumer: S2)

**Citations:** host `proc_pid_stat(5)`, `proc_pid_comm(5)`, `proc_pid_status(5)`, `proc(5)`
and `kill(2)` were present under `/usr/share/man/`; `runtime/proc.rs:105–111,151–199`
and `secret/held_locks.rs:76–121` establish the agctl consumers.

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
getconf CLK_TCK
readlink /proc/self/ns/pid
stat -f -c %T /proc
grep '^btime ' /proc/stat
grep ' /proc ' /proc/mounts
# Parse stat after its LAST ')': the tail's zero-based slot 19 is field 22.
# Read comm separately, and Uid:'s FIRST column from status; do not read cmdline/environ.
unshare -Urpf --mount-proc sh -c '
  mount -o remount,hidepid=2 /proc
  readlink /proc/self/ns/pid
  readlink /proc/1/ns/pid
  grep " /proc " /proc/mounts
  grep NSpid /proc/self/status'
```

**Expected, this host:** at `2026-09-25 22:20:14 UTC`, CLK_TCK=100 (tick resolution
1/100 second), btime=1790224503, boot ID `11937b4b-bf10-453f-839b-64ba2178a6fa`,
outer PID namespace `pid:[4026531836]`. The observing child PID 337927 reported state R,
start ticks 15031104, comm `python3`, real UID 1000. A controlled child PID 337929
retained start ticks 15031107 across two reads/SIGSTOP, state T, then vanished on reap;
zombie PID 337930 reported Z, and ptrace-stopped PID 337931 reported t. All were reaped.
Actual same-PID recycling was not forced; same-tick reuse remains indistinguishable by
boot/namespace/ticks and must not be described as microsecond precision.

At `22:20:15 UTC`, a matched Claude peer launched via a scratch symlink **named `claude`**
reported comm `claude`, UID 1000, ticks 15031107; at `22:20:17 UTC`, a hardlink to the
same binary inode named **`2.1.282`** reported comm `2.1.282`, UID 1000, ticks 15031309.
Each name/start identity was observed twice while the process waited for stdin. Both were
terminated and reaped.

**Changed premise for D-058: Linux `comm` follows the launch path's basename, not the
product name.** Both launches were re-measured with `proc_probe.py`. It reads
`/proc/<pid>/{stat,status,comm}`, `readlink`/`stat` of `/proc/<pid>/exe`, and only the first
NUL-terminated field of `/proc/<pid>/cmdline` (at most 4096 bytes). It never reads
`environ` or the remaining argv. Two peers were launched from the same file under
`unshare -Urn` with scratch homes:
- a symlink `claude/bin/claude` pointing to a hardlink `claude/versions/2.1.282` of the
  staged binary (inode 413746);
- that hardlink directly.

| Launch (`2026-09-25 22:38:22–22:38:24 UTC`) | PID | state / start ticks | `comm` | real UID | `/proc/<pid>/exe` target | exe device / inode | `cmdline[0]` |
|---|---:|---|---|---:|---|---|---|
| Symlink `…/claude/bin/claude` | 342228 | S / 15139840 | `claude` | 1000 | `/tmp/agctl-linux/claude/versions/2.1.282` | 34 / 413746 | `/tmp/agctl-linux/claude/bin/claude` |
| Version path `…/claude/versions/2.1.282` | 342283 | S / 15140042 | `2.1.282` | 1000 | `/tmp/agctl-linux/claude/versions/2.1.282` | 34 / 413746 | `/tmp/agctl-linux/claude/versions/2.1.282` |

A second read about one second later returned the same state, ticks, `comm` and UID for
each PID. The executable identity (`exe` target, device, inode) is the same in both rows,
and only the launch name differs. The kernel's `comm` is the basename of the path given to
`execve`. For the symlink launch that is the symlink name, `claude`. For the direct launch
it is the version file's name, `2.1.282`.

The installer's standard launch path is the symlink: on this host `~/.local/bin/claude`
points to `~/.local/share/claude/versions/2.1.220`. Its name was read at `22:14:34 UTC` and
the version directory was not modified. A peer started from a shell by `claude` therefore
reports `comm` `claude`. Any caller that execs the resolved version path, such as a wrapper,
an IDE extension or a Claude process spawning another Claude, reports the version string.
Which of those callers exec the resolved path was **not measured**.

D-058's exact-name limitation therefore misses direct version-path launches on Linux, as
§5.2 F57 records for macOS (2 of 5 live sessions missed there). The ruling belongs to the
plan owner and scoped critic. This record proposes no matcher change, and in particular no
argv or substring widening.

Unprivileged user/network/mount/PID namespaces worked. A private proc remount with
`hidepid=2` succeeded and rendered as `hidepid=invisible`. At `22:26:58 UTC`, the outer
view listed 496 numeric PID directories while a nested view listed 3. Within the nested
view, self and PID 1 **both** had namespace `pid:[4026532552]`, and NSpid had one column.
Thus “self namespace equals PID 1” or a one-column NSpid is **not proof of a complete host
view**. No cross-UID hidepid classification was certified by this same-user fixture.

**Compatibility verdict:** persisted macOS identities are unversioned RFC3339 timestamps
with microseconds (older records may be ctime strings or lack the field); they are not
comparable with a Linux boot/namespace/tick identity. `writer_is_gone` currently treats
any unequal readable strings as recycled and asks `holder` before comparing identity.
Linux must validate record format/domain/namespace **before either a mismatch or a
namespace-local ESRCH can authorize recovery**. Unversioned/unknown/incomparable records
must refuse recovery, not appear stale simply because the spelling changed. A versioned
Linux identity and a consumer compatibility guard are required; merely changing the proc
string is insufficient. Verified boot mismatch can establish staleness only for a valid,
comparable Linux record. Wall timestamps use checked `btime + ticks / CLK_TCK` conversion;
they are presentation, not the persisted identity comparison.

**Verdict:** proc facts and old-record incompatibility established. Two changed premises go
to the scoped ruling: `comm` depends on the launch path, and nested views give partial
visibility. The final visibility policy and the exact-name residual also require that
ruling. Enforce D-058/D-061's conservative
`Unreadable → HolderUnreadable` before removal on incomplete/unproved sweeps. A mounted
procfs and successful enumeration alone do not prove absence. Preserve rustix's independent
kill-zero probe (EPERM means existing; unexpected errors must not license mutation).
**Fails if:** partial namespaces, denied reads, old-record strings or malformed stat data
become “dead/no peer”. **Affected agctl code:** `runtime/proc`, `held_locks`, namespace
records, `ProcHolders`, and doctor.

#### U5 — Codex effective mode and login proof (consumer: S5)

**Citations, all at `2170d8b3c77883dbe743078fb8bbb017f27caa9c`:**
`codex-rs/login/src/auth/storage.rs:195–222,295–309,431–448,460–499,502–527`;
`keyring-store/Cargo.toml:11–24` and `keyring-store/src/lib.rs:46–105`;
`core/src/config/auth_keyring.rs:39–78`;
`config/src/loader/mod.rs:103–132,719–722` and `config/src/loader/README.md:24–46`;
`utils/home-dir/src/lib.rs:6–61`; `cli/src/login.rs:204–234`.

File is a distinct backend; it truncates/creates `auth.json`, mode 0600 on create, with no
rename/fsync. Auto tries keyring first for load/save, then falls back to file on the specified
failure/absence paths; successful keyring save removes a fallback file. Ephemeral is an
in-process map. Linux enables `linux-native-async-persistent`; absent inherited D-Bus env
is not proof that the keyring backend cannot act. CODEX_HOME is canonicalized and must be
an existing directory; otherwise HOME supplies `.codex`. Every probe explicitly set both.

Session `-c` overrides beat ordinary user config, but not every managed source. Legacy
managed config is above session flags; separate requirements can force the effective store
(`auth_keyring.rs:71–73`). Linux reads `/etc/codex/requirements.toml`; macOS MDM is target-
specific, not a Linux policy mechanism. Preflight-reading these mutable paths cannot prove
what a subsequently spawned child will load; this spike established no race-free policy
pinning mechanism within the planned child contract.

At `2026-09-25 22:22:36 UTC`, the exact binary's help confirmed `login --with-api-key`
reads stdin and `login status` exists. At `22:22:59 UTC`, real binary probes used a clearly
synthetic stdin value, scratch HOME/CODEX_HOME/cwd/XDG directories, empty inherited env,
no D-Bus address and no network. A **private** `unshare -Urnm` mount bound each case's
scratch `etc/` over `/etc`; no persistent `/etc` file was written and no operator managed
contents were read. For the managed case only, scratch `etc/codex/requirements.toml`
forced `cli_auth_credentials_store="keyring"`.

| Requested mode / policy | Login exit | Status exit | File / observed backend |
|---|---:|---:|---|
| file | 0 | 0 | auth.json created 0600, inode 417539, size 83; no D-Bus attempt |
| auto | 0 | 0 | attempted scratch `runtime/bus` (ENOENT), then auth.json 0600, inode 417575, size 83 |
| keyring | 1 | 1 | attempted scratch `runtime/bus` (ENOENT); no auth.json |
| ephemeral | 0 | 1 | no auth.json; state did not survive the process |
| `-c file` over user config keyring | 0 | 0 | auth.json 0600, inode 417682, size 83 |
| `-c file` with managed requirement keyring | 1 | 1 | requirement file opened, scratch `runtime/bus` attempted (ENOENT); no auth.json |

The real error for the keyring/managed cases was `failed to write OAuth tokens to keyring:
Platform secure storage failure: no secret service provider or dbus session found`.
No credential values or auth-status output values are needed to establish these outcomes.
The API-key login accepted the synthetic input locally; that is not an authenticated OAuth
login, token validation, browser/CA/proxy proof, or authorization to adopt that fixture.

The essential managed-override invocation inside the scrubbed environment was:

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
# P is a scratch case with pre-created home/codex/work/XDG/etc directories.
# Feed only an explicitly synthetic stdin fixture; never an operator key.
# Preserve the complete env -i isolation from U1, replacing CLAUDE_CONFIG_DIR with CODEX_HOME.
unshare -Urnm sh -c 'mount --bind "$1/etc" /etc; shift; exec "$@"' sh "$P" \
  /tmp/agctl-linux/tools/usr/bin/strace -f -s 300 \
  -e trace=open,openat,connect,execve,keyctl,add_key,request_key,rename,fsync,fchmod \
  -o "$P/trace-login" "$CODEX" -c 'cli_auth_credentials_store="file"' login --with-api-key
```

**Verdict:** choose D-064 **Linux Codex login unsupported**, returning
`unsupported on this platform` **before spawn**, with no installation. The lead accepted
this as the U5 outcome. File argv, scratch
HOME and absent D-Bus env are insufficient proof, and post-spawn discovery is too late.
This is the plan's accepted refusal branch, not a new blocker for Claude or proven file-
backed Codex status/import/doctor. For those external file reads, unresolved managed policy
still means not-read/uncertain, never a fallback to a potentially stale auth.json.
**Fails if:** a file override or a created file is treated as no-keyring-side-effect proof.
**Affected agctl code:** `provider/codex/login_child.rs`, planned login backend,
`home.rs::file_in_effect`, `commands/codex/{login,doctor}`.

#### U6 — Managed settings root (consumer: S5)

**Citations:** C5 `cli.unpack.js:47987–48003@ac66a5f`; actual Linux binary's switch has
macOS `/Library/Application Support/ClaudeCode`, Windows's root, and default
`/etc/claude-code`; `rMr`/Linux `HDr` is a no-override stub in this build.

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
"$RG" -a -o '.{0,100}/etc/claude-code.{0,100}' "$CC"
"$RG" '/etc/claude-code.*managed-settings' \
  /tmp/agctl-linux/scratch/claude-absolute_config/trace
```

**Expected, 2.1.282:** the isolated auth-status trace captured at
`2026-09-25 22:19:36 UTC` opens `/etc/claude-code/managed-settings.json` with O_PATH
and stats it (ENOENT here); it also enumerates `managed-settings.d` (ENOENT).
The filtered record was inspected at `22:26:58 UTC`. No existing managed-file contents
were opened by the investigator.
**Verdict:** Linux `/etc/claude-code/managed-settings.json` established. Keep D-062's
textual n/a keychain rows and unchanged schemas; U8's old schema question is not this task.
**Fails if:** the compiled default root or actual open path moves.
**Affected agctl code:** `commands/doctor.rs:1209–1212`, planned platform managed-root helper.

#### U7 — Parser choice and host setup (consumers: S2/S3)

**Citations:** crates MCP `get_crate_info`, `get_crate_dependencies`,
`get_crate_documentation`, `get_crate_versions` for procfs/procfs-core **0.18.0**;
published source archives from `https://static.crates.io/crates/` inspected locally at
`2026-09-26 07:22:11 JST` and `07:23:59 JST`. Both declare `MIT OR Apache-2.0`, MSRV
1.70; procfs 0.18.0 was published `2025-08-30T01:07:56Z` (registry timestamp).
The crate README says it is tested against current stable. It is not an abandoned or
license-incompatible reason to hand-roll; no new dependency was added in S1.

`procfs-core-0.18.0/src/process/stat.rs:231–269` reads to end, uses first `(` / **last `)`**,
and parses field 22 as starttime. It does **not** impose a read bound, uses lossy UTF-8,
and its unchecked delimiter slices can panic on malformed envelopes; blindly passing
arbitrary bytes to it fails D-058. `process/status.rs:204–207` takes real UID from the
first Uid column. `src/lib.rs:479–501,580–608` distinguishes PermissionDenied, NotFound,
Incomplete, Io and parse/internal errors. Full procfs `Process::stat/status` delegates to
these parsers and does not add the required per-file bound.

| Option | Assessment |
|---|---|
| **Recommend `procfs-core = { version = "0.18", default-features = false }`** | Reuse last-parenthesis/stat/status parsing, with agctl-owned bounded reads and validated UTF-8/delimiter/state envelope before calling it; retain original filesystem errors. Required dependencies are bitflags and hex. Numeric parsing, truncation and panic-proof envelope fixtures are mandatory. |
| Full `procfs`, defaults disabled | Adds procfs-core, bitflags and rustix; convenient process APIs but still needs bounded-read/visibility adapters. Defaults also enable chrono/flate2. It does not settle complete-sweep or namespace trust. |
| Hand-written stat parser | Avoids a dependency but duplicates an available parser; not justified by this review when a narrow bounded/prevalidated core adapter can satisfy the contract. Return to review if that adapter cannot meet D-058. |

This is a dependency recommendation for scoped approval, not a completed implementation
or a claim that procfs-core alone meets the contract. `Cargo.toml:28` already uses
`rustix = "1"` with process/fs features; `runtime/proc.rs:108` already calls
`rustix::process::test_kill_process`. Do not add another syscall crate for kill-zero.

Host prerequisites were remeasured at `2026-09-25 22:14:34 UTC` and `22:28:32 UTC`:

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
cd /tmp/agctl-linux/src
RUSTUP_HOME=/tmp/agctl-linux/rustup CARGO_HOME=/tmp/agctl-linux/cargo \
  /tmp/agctl-linux/cargo/bin/rustc -Vv
RUSTUP_HOME=/tmp/agctl-linux/rustup CARGO_HOME=/tmp/agctl-linux/cargo \
  /tmp/agctl-linux/cargo/bin/cargo -V
for x in gcc bash perl shasum git cargo-nextest rg direnv strace; do command -v "$x" || true; done
```

**Expected:** in-tree rustc `1.98.1 (48a229cea 2026-09-01)`, host
`x86_64-unknown-linux-gnu`, LLVM 22.1.8; cargo `1.98.1 (797e8a9bc 2026-08-05)`.
The commit dates here are compiler output, not an investigator clock estimate.
Gcc/bash/perl/shasum/git/unshare/man/curl/jq exist. Cargo-nextest, direnv, global rg,
strace, and the operator's dev-profile cargo config (the one AGENTS.md describes) were absent.

S1 ran only `apt-get download strace ripgrep` from `/tmp/agctl-linux/tools` followed by
`dpkg-deb -x` there: **no apt install, sudo, or persistent package mutation**. The usable
executables are `/tmp/agctl-linux/tools/usr/bin/{strace,rg}`, versions 6.13 and 14.1.1.
Package SHA-256 values measured at `22:29:51 UTC`:

- `strace_6.13+ds-1_amd64.deb`: `cae290b67cf835350a2cde58ca332256fba475784b3e02a9a8677d73eaf47511`.
- `ripgrep_14.1.1-1+b4_amd64.deb`: `7e0c32510c264c31335fe3b9ae37ab76dcd22f7d1627a0a08518a5bf28b17ac2`.

For the §7.4 checkpoint session, S1 fetched tmux and its one missing library the same way,
with `apt-get download` and `dpkg-deb -x`. The result is `tmux 3.5a` at
`/tmp/agctl-linux/tools/usr/bin/tmux`. It runs only with
`LD_LIBRARY_PATH=/tmp/agctl-linux/tools/usr/lib/x86_64-linux-gnu`, because `ldd` reported
`libevent_core-2.1.so.7 => not found` at `22:37:37 UTC`. Package SHA-256 values measured at
`22:38:25 UTC`:

- `tmux_3.5a-3_amd64.deb`: `e6b6aa51780044e2c4a0e618c33f832b70ec80caa30303e6c254a0c851b5af78`.
- `libevent-core-2.1-7t64_2.1.13-stable-1~deb13u1_amd64.deb`: `faa7d20cc8fa05ac3b0497065fa60bc920eacd3711ff039649d43a7aa34421ce`.

**Setup verdict:** Phase 1 must provision cargo-nextest into the tmpfs CARGO_HOME
(`cargo install cargo-nextest --locked`), expose the temporary rg for gates, and settle
Linux-valid direnv/dev-config setup without copying macOS target/link flags. A scratch
HOME can hold a dev-profile cargo config targeting `/tmp/agctl-linux/target` with
incremental disabled, while RUSTUP_HOME/CARGO_HOME remain explicit. No nextest/direnv
installation or dev-config creation is claimed here. The source copy still lacks `.git`;
grep/structural gates require a fresh credential-free Git snapshot, not that tar tree alone.
`check.log` still records 15 platform compiler errors (10 production + 5 test); this is
preserved baseline evidence, **not** a fresh S1 build or a passing Linux gate.
**Fails if:** unbounded parser reads, unchecked slicing, optional default dependencies or
missing tools are silently accepted. **Affected agctl code:** S2 process backend and S3 gates.

#### U8 — Real-child environment (consumer: S5)

**Question, v1.2:** if proof-backed login is selected, does real Linux Codex file login work
under scratch HOME/CODEX_HOME and the scrubbed environment, including browser/CA/proxy
behavior? This replaces the old, already settled doctor-schema question.

**Citations/method/result:** U5's matched source and actual child probes at
`2026-09-25 22:22:59 UTC`; `provider/codex/login_child.rs:120–135,220–237` currently
inherits HOME on macOS, which is not an existing Linux scratch-HOME guarantee.
Inspect with `rg -n -e U5 -e U8 docs/re-verify.md`.

**Verdict:** resolved by D-064's **pre-spawn unsupported branch**, which the lead accepted
as the U5 outcome. No supported Linux
OAuth child is being enabled, so no real Codex browser login is needed or claimed. The
synthetic API-key probe only proves that command's local file path, not the real-login
checkpoint. If a future reviewed plan enables login, U8 reopens and requires operator
OAuth plus real environment/lifecycle evidence; do not use this record as that approval.
**Fails if:** the disabled branch spawns a child or installs its output.
**Affected agctl code:** planned Linux Codex login backend; macOS HOME behavior unchanged.

### 7.3 AC177–AC181 witness table

Statuses distinguish collected evidence from approval: a grep finding the word U2 cannot
turn an unobserved write into a pass. The plan owner and scoped critic own the remaining
ruling; this executor does not self-approve it.

| AC | Plan witness and what this record establishes | Result |
|---|---|---|
| AC177 | Host `claude --version; codex --version; sha256sum "$(readlink -f "$(command -v claude)")" "$(readlink -f "$(command -v codex)")"`; explicit isolated paths are necessary because Codex is not installed and SSH PATH omits the launcher. §7.1 records both measured spike versions/digests and pins, plus the old launcher. `rg -n -e U1 -e U5 docs/re-verify.md` locates the matched consumers. | **PASS — evidence**, with path adaptation documented |
| AC178 | Host vendor probes plus `rg -n -e U1 -e U2 -e U3 docs/re-verify.md`. Both factories, path matrix, source-bounded fallback and binary-anchor drift are documented. The approved real checkpoint now measures create/replacement, storage mutex across publication, owner sidecar, ordered refresh-lock release, logout and cleanup. Exceptional in-place fallback remains source/kernel evidence, not a dynamically forced live write. No operator step remains in the approved procedure; D-061 and D-060 §4.2 changed premises still require the scoped ruling. | **BLOCKED — review**, approved checkpoint complete |
| AC179 | `rg -n -e U5 -e U8 docs/re-verify.md`: a real managed override defeats file argv, which selects `unsupported on this platform` before spawn. The other proven file commands remain in scope. | **PASS — D-064 refusal outcome, accepted by the lead** |
| AC180 | Host `getconf CLK_TCK; readlink /proc/self/ns/pid; stat -f -c %T /proc`; `rg -n -e U4 -e U7 docs/re-verify.md`. Recorded: measured tick, state, name and namespace facts; `comm` by launch path with the exe target and `cmdline[0]`; old-record incompatibility; the crate review. The final visibility and record guard, and the D-058 name premise, need the scoped ruling. | **BLOCKED — review**, observations complete |
| AC181 | `rg -n 'U[1-8]' docs/re-verify.md`: all eight consumers have explicit results. The approved §7.4 login/refresh/logout checkpoint and cleanup are complete; U2 normal-write and U3 storage/owner sub-items are settled. Exceptional fallback was not exercised live. The remaining gate is the scoped U2/U3/U4 changed-premise ruling, not another step of the approved operator procedure. No S2 GO is inferred. | **BLOCKED — review**, approved checkpoint complete |

No Codex checkpoint is required for the accepted refusal branch. Stop before S2 until the
plan owner resolves these gates.

### 7.4 Operator checkpoint procedure (Claude)

The operator approved **one login → scratch-only expiry edit → one traced refresh →
traced logout → scratch removal**. This procedure gathers the real-create, normal-replace,
storage-mutex and owner-sidecar evidence for U2/U3. It does not force a rename error; the
in-place fallback retains the source/kernel evidence and limits stated in U2. The worker
waited for the lead's login-complete notice before editing expiry or running the refresh.
No agent opened the login URL, handled the code or received credential contents.

**Completed outcome, host `date -u`, `2026-09-26 UTC`:** retry login ran
`01:25:52–01:26:10` (exit 0, credential present); the successful result was independently
checked at `01:27:22`. The approved same-inode expiry edit ran at `01:27:29`; the single
real refresh ran `01:27:29–01:27:31` (exit 0, new inode and future expiry). Traced logout
ran `01:28:27–01:28:28` (exit 0, credential absent). At `01:29:05` all credential lock
artefacts were also absent and the dedicated tmux server was already gone. Scratch removal
was verified at `01:29:15`. U2/U3 contain the metadata and syscall ordering. Nothing remains
to attach to; the commands below document the procedure, not an active waiting session.
The exceptional in-place fallback was not forced. The scoped review gate remains open.

**Failed first attempt — not credential-write evidence.** The script's host `date -u`
recorded login start `2026-09-26 01:15:53 UTC`, exit `01:20:50 UTC`, exit status **1** and
`credential_file=absent`. At `01:23:02 UTC`, a fresh stat also returned ENOENT for
`/tmp/agctl-linux/scratch/oauth-checkpoint/config/.credentials.json`. Inspection at
`01:23:38 UTC` found only five initial credential read/stat ENOENT records, no credential
temp, no storage-write or refresh locks, and no owner sidecar. At `01:24:15 UTC`, the
separate temp/lock search did find `.claude.json.tmp.<pid>.<12hex>` open/rename operations
and `.claude.json.lock` mkdir/rmdir; those are configuration writes, **not** credential
writes. Their fsyncs do not establish credential durability. No expiry edit, refresh or
logout was attempted against an absent credential. The tmux socket had no server by
`01:23:38 UTC`. A login timeout is a hypothesis, not a measured diagnosis; no pane or
credential contents were read. This attempt settles none of the blocked sub-items.
The absent credential was rechecked and the failed scratch tree removed at host
`date -u` `2026-09-26 01:25:58 UTC`; the raw trace was not copied elsewhere.

**Gated retry**, prepared at host `date -u` `2026-09-26 01:24:55 UTC`:
- Fresh root `P=/tmp/agctl-linux/scratch/oauth-checkpoint-2`, with subdirectories
  `home config config-xdg cache data state runtime tmp work`, all mode 0700.
- The sole tmux session was `agctl-login-2` on socket `/tmp/agctl-linux/tmux.sock`, running
  `/tmp/agctl-linux/oauth-checkpoint.sh`. Its SHA-256 is
  `13f9b982f444fe67c12f20da1d1f9973df69935993d98bf3a31de54f8fa04a41`.
- The pane waited at `Press Enter to start the login...` **before starting Claude**. Neither
  `login.strace` nor `checkpoint-result.txt` existed at the readiness check. The login's
  own timeout could start only after the operator attached and pressed Enter.
- `/tmp/agctl-linux/oauth-observe.sh` SHA-256 is
  `860ddb993b0b0851d4af20f178747a93ec41947e6b39ec42650895a1c7f11b48`.
  Both scripts passed `bash -n`; refresh/logout waited for the completion notice.
- `auth login --help` was checked at `01:15:52 UTC` and listed `--claudeai`. There are no
  optional second-login stages. The still older `agctl-s1-claude-login` and its unused
  `/tmp/agctl-linux/scratch/operator-claude-2.1.282` tree were removed at `01:18:56 UTC`.

**Isolation.** Every stage uses `umask 077`, cwd `$P/work`, and `env -i` with only:

```sh
PATH=/usr/bin:/bin HOME=$P/home CLAUDE_CONFIG_DIR=$P/config
XDG_CONFIG_HOME=$P/config-xdg XDG_CACHE_HOME=$P/cache XDG_DATA_HOME=$P/data
XDG_STATE_HOME=$P/state XDG_RUNTIME_DIR=$P/runtime TMPDIR=$P/tmp
TERM=xterm-256color LANG=C.UTF-8 BROWSER=/bin/false
CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 DISABLE_AUTOUPDATER=1
```

`DBUS_SESSION_BUS_ADDRESS` is absent. Network access is allowed for login, refresh and
logout. `BROWSER=/bin/false` prevents an automatic browser launch on the host; the operator
opens the printed URL in their macOS browser and pastes the code into the tmux pane.

**Trace whitelist**, shared by the three stages:

```sh
TRACE=openat,open,creat,stat,lstat,fstat,newfstatat,statx,access,faccessat,faccessat2
TRACE=$TRACE,readlink,readlinkat,mkdir,mkdirat,rmdir,rename,renameat,renameat2
TRACE=$TRACE,link,linkat,unlink,unlinkat,chmod,fchmod,fchmodat,chown,fchown,fchownat,lchown
TRACE=$TRACE,truncate,ftruncate,fsync,fdatasync,utimensat,utimes,flock,fcntl
/tmp/agctl-linux/tools/usr/bin/strace -f -tt -s 300 -e trace="$TRACE" \
  -o "$P/login.strace" /tmp/agctl-linux/claude/2.1.282/claude auth login --claudeai
```

The explicit list is used instead of `%file`, which also includes `execve` and could expose
URL-bearing child arguments. No `read`, `write`, `pwrite`, `execve`, `connect` or `sendto`
payload is traced. The worker never captures the tmux pane. Login records its UTC start/end,
exit status and final credential stat in `$P/checkpoint-result.txt`.

**Attach line**, run by the operator:

```sh
ssh -t debian-13-trixie.gaudiy-platform 'LD_LIBRARY_PATH=/tmp/agctl-linux/tools/usr/lib/x86_64-linux-gnu /tmp/agctl-linux/tools/usr/bin/tmux -S /tmp/agctl-linux/tmux.sock attach -t agctl-login-2'
```

Press Enter to start login, open the URL locally, paste the returned code, check the CLI's
exit outcome, notify the lead that login finished, and
detach with `Ctrl-b d`. The pane waits on `sleep infinity` after login exits.

**Worker steps after the completion notice:**
1. Read only `checkpoint-result.txt` and path/metadata trace records. Record the create
   sequence, temporary filename shape, open flags/mode, rename, chmod, fsync/fdatasync,
   directory mkdir mode and `.storage-write.lock` acquisition/release. Use `stat` for
   credential device/inode/mode/UID/GID/size/nlink; never print its contents.
2. Run `oauth-observe.sh refresh`. It checks that the scratch credential is a regular,
   non-symlink file; `jq -ce` validates the expected object/numeric expiry/refresh-token
   shape and changes only `.claudeAiOauth.expiresAt` to `1`. The transformed JSON stays in
   an unexported shell variable, is written by builtin `printf` back to the **same path and
   inode**, then the variable is unset. No credential copy is written elsewhere; neither
   the JSON nor jq diagnostics are printed. Record pre/post-edit stat and `date -u`.
3. Under the same scrubbed environment and trace whitelist, run the matched binary with
   `-p 'Reply exactly OK.' --max-turns 1 --tools '' --no-session-persistence --output-format text`.
   A `timeout` bounds the command to 120 seconds, followed by a 10-second kill grace. Stdin
   is `/dev/null`; stdout/stderr are discarded. Trace goes to `$P/refresh.strace`; only
   UTC start/end, exit status, stat and a boolean future-expiry check are reported.
4. Record primary `.oauth_refresh.lock` then legacy `<realpath(store)>.lock` order,
   `.oauth_refresh.lock.owner` creation/removal, `.storage-write.lock` around credential
   publication, release order, and whether replacement used temp+rename or an in-place
   open/truncate. Record any credential or directory fsync/fdatasync; do not attribute a
   sync on an unrelated descriptor to the credential.
5. Run `oauth-observe.sh logout`. This executes `claude auth logout` under the same
   environment, whitelist and timeout, recording `$P/logout.strace` with command output
   discarded. Record UTC start/end, exit status, storage-lock/unlink/release order and
   confirm `.credentials.json` is absent with `test`/`stat`, without reading it.
6. Record the derived facts in U2/U3. Kill the tmux server on this dedicated socket, remove
   this scratch home, and verify it is absent. No raw trace or credential blob is copied
   out of the home.

Cleanup after the traced logout and evidence collection:

```sh
date -u '+%Y-%m-%d %H:%M:%S UTC'
P=/tmp/agctl-linux/scratch/oauth-checkpoint-2
test ! -e "$P/config/.credentials.json" || exit 1
if LD_LIBRARY_PATH=/tmp/agctl-linux/tools/usr/lib/x86_64-linux-gnu \
  /tmp/agctl-linux/tools/usr/bin/tmux -S /tmp/agctl-linux/tmux.sock list-sessions \
  >/dev/null 2>/dev/null; then
  LD_LIBRARY_PATH=/tmp/agctl-linux/tools/usr/lib/x86_64-linux-gnu \
    /tmp/agctl-linux/tools/usr/bin/tmux -S /tmp/agctl-linux/tmux.sock kill-server
fi
rm -rf -- "$P"
test ! -e "$P"
```

Logout attempts to revoke the currently stored refresh token, but its source swallows a
revoke failure (U3). A successful local deletion therefore is not proof of server-side
revocation. The operator can revoke the session from account settings independently.
If any step would expose credential material, stop that sub-step and report the limitation.

---

## After the checklist

1. Record the version you checked and the date at the top of this file.
2. Run the gate: `cargo fmt --check`, then `cargo clippy --all-targets --all-features
   -- -D warnings` and `cargo nextest run --all-features`.
3. Run `scripts/release-gate.sh` — it also proves the three Codex seams (its own `seams`
   array, mirrored in `.claude/skills/check/SKILL.md`'s table) absent from the release
   artifact and `AGCTL_CODEX_USER_AGENT` present.
4. If any contract moved, fix the affected code **and** the fixtures under
   `fixtures/claude/` or `fixtures/codex/` before releasing. A contract that changed silently
   is exactly the failure mode this file exists to prevent.
