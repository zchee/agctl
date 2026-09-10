# Re-verify after a Claude Code upgrade

agctl reads a machine that Claude Code owns. Four of its behaviours are not derived from
a published interface but from facts read directly out of Claude Code's shipped binary, and
any Claude Code release can change them without notice. This checklist re-establishes those
four facts against a newly installed version. Work through it after every Claude Code
upgrade, and before every agctl release.

**Every command here is read-only.** Nothing writes, nothing runs `claude`, nothing touches
the keychain.

Set the version under test once:

```sh
CC=~/.local/share/claude/versions/2.1.265     # or whatever `claude --version` reports
```

Claude Code ships as a single self-contained Mach-O with the JavaScript bundle embedded, so
every pattern below is `rg -a` (treat binary as text) against that one file. The identifiers
are minified and **change on every build** — the patterns below deliberately match on the
string literals and the shape of the expression, never on a minified name. If a pattern
returns zero hits, that is the signal to read the surrounding code by hand, not to relax the
pattern until it matches.

Last verified: **Claude Code 2.1.265**, 2026-09-09. The original evidence was gathered
against 2.1.263; every pattern below was run against both, and all four contracts are
unchanged. Only the minified names moved (`Vt`→`Xt`, `z0`→`nH`, `Kys`→`eEs`, `cr`→`pr`),
which is exactly why the patterns match shapes and string literals rather than identifiers.

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

**Expected, 2.1.265:**

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

**Expected, 2.1.265:**

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

**Expected, 2.1.265** — two schema declarations from the first grep, then three hits from
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
`limits[]` is absent or empty — in 2.1.265: `five_hour`, `seven_day`,
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

**Expected, 2.1.265:**

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

## After the checklist

1. Record the version you checked and the date at the top of this file.
2. Run the gate: `cargo fmt --check`, then `cargo clippy --all-targets --all-features
   -- -D warnings` and `cargo nextest run --all-features`.
3. Run `scripts/release-gate.sh`.
4. If any contract moved, fix the affected code **and** the fixtures under
   `fixtures/claude/` before releasing. A contract that changed silently is exactly the
   failure mode this file exists to prevent.
