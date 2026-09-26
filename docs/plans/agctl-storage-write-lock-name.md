# agctl — Claude storage mutex name correction

- **Version:** v1.2.
- **Status:** landed — user GO given on the §10 decisions (D1 doctor-only, D2 synthetic-only, D3 Linux omitted, D4 signed local commit on `main` without push, D5 L1–L5 only); L1–L4 executed, six macOS gates passed, independent verifier ACCEPT (0 blockers); landing revision is the signed commit that carries this status line, on `main` after `809f3bf`. See §12.
- **Mode:** RALPLAN-DR **DELIBERATE**.
- **Baseline:** `main = b0328fc`; final plan path: `docs/plans/agctl-storage-write-lock-name.md`.
- **Work item:** `agctl-storage-write-lock-name-4slm` (Claude storage mutex name mismatch).
- **Numbering:** L1–L5, AC218–AC239, D-069–D-075; no renumbering of Linux or Remote Control plans.
- **Review boundary:** lead-authored analyst gap check incorporated; this author does not approve this plan.
- **Authoring:** plan-only; no implementation, build, live credential operation, or remote probe performed.

## 0. Steps and stop point

| Phase | Description | Status | Closing evidence / artifact |
|---|---|---|---|
| Planning | Draft, scoped critic, numbered user decisions | ✅ done | v1.2; critic APPROVE; user GO with D1–D5 recorded in `docs/plans/open-questions.md` |
| Correction | L1–L4, one executor working sequentially | ✅ done | Bounded diff SHA-256 `3072118ab75f30099cfa0170a6f83a89c960a0ea869f303aadd8170fa673bc90`; witnesses AC225–AC227 |
| Certification | L5, independent verifier and approved delivery | ✅ done | Six macOS gates exit 0; verifier ACCEPT; landing = the commit carrying this table |

| Step | Lane / composition | Description | Status | Landing |
|---|---|---|---|---|
| L1 | Executor | Freeze baseline, inventories, and selected witness eligibility | ✅ done | Baseline `337633e` (1937 identities); synthetic-only per D2 |
| L2 | Same executor | Shared name, legacy reporting/refusal, exact-path tests | ✅ done | `STORAGE_WRITE_LOCK` / `LEGACY_STORAGE_WRITE_ARTEFACT`; doctor-only legacy notice |
| L3 | Same executor | Bidirectional storage-only witnesses and regression inventory | ✅ done | A/B witnesses PASS, wrong-name control `excluded == false`; 1954 identities (+17, −0) |
| L4 | Same executor | Documentation and planted source pin | ✅ done | README D-073 hunks; F47/F58; `check_storage_mutex` with three plants |
| L5 | Executor → independent verifier → lead | Closing gates, evidence acceptance, selected delivery | ✅ done | Gates 1–6 exit 0 (executor and verifier reruns); verifier ACCEPT; signed local commit on `main`, not pushed |

**Stop point:** after L5 delivery. Next: the user publishes `main`; Linux Phase 2 (`agctl-1y9.3`) may then take this landing as its baseline. The `namespace.rs:223` wording stays a docs-only follow-up.
No new beads, per-step charters, or handoff ledgers. Use the existing work item only.
Executor: `omc-configured-executor-4e63ea1e64dd`; independent verifier:
`omc-configured-verifier-4e63ea1e64dd`; native named teammates, no model override.
Linux Phase 2 and AC217's Linux operator login/forced-refresh/logout/cleanup remain unapproved.
At each transition or ordered pause, update both tables with artifacts and the next action.
Every execution timestamp is obtained with `date` in the command writing its evidence.

## 1. Context and evidence

### 1.1 Repository baseline

| Fact | Evidence at `b0328fc` unless noted |
|---|---|
| agctl uses the unsuffixed name, shared by both platforms | `src/secret/foreign_activity.rs:30–33`; `claude_lock.rs:1205–1212` |
| Detection names primary, storage, canonical legacy, in that order | `src/secret/foreign_activity.rs:99–125` |
| Production acquisition always plans three locks; storage is innermost | `src/secret/claude_lock.rs:1150–1215,1281–1290` |
| Storage take has zero retries; 15 s stale profile; hold budget is 3000 ms | `src/secret/claude_lock.rs:179,221–228` |
| EEXIST releases the acquired prefix and record before restarting; maximum three restarts | `src/secret/claude_lock.rs:192,1397–1444` |
| Held records attest exact path equality, not basename or prefix | `src/secret/held_locks.rs:70–142`; `claude_lock.rs:1888–1912` |
| Doctor scans the same constant; its removal name check and text also use it | `src/commands/doctor.rs:755–760,970–1010,1208–1216` |
| Doctor uses 60 s age and two samples 12 s apart; removal needs namespace authority or a dead writer's exact record | `src/commands/doctor.rs:107`; `README.md:283–312`; `doctor.rs:1160–1206` |
| Linux rejects all peer-lock removal before the path permit | `src/commands/doctor.rs:970–979`; Linux plan D-067 |
| Current doctor JSON represents isolation reporting, not this text scan | `schemas/doctor.v1.json:4–5`; `src/render/json.rs:354–405` |
| Scope is a separate platform-independent prerequisite, not Linux S4 implementation | `docs/plans/agctl-linux-support.md`, D-061/D-066 and AC217 |

The working tree was read as `main...origin/main [ahead 2]`, HEAD `b0328fc`, with unrelated
`README.md` badge hunks, modified `.claude/fmt-hooks.json`, and untracked `.github/`.
These are another session's work; L1 rechecks rather than assuming this observation persists.
The planner's frozen-path diff against `b0328fc` was empty. No tests were run by the planner.

### 1.2 Matched source, measured evidence, and limits

`$V` below denotes `/Users/zchee/src/github.com/zchee/claude-code-reverse-new`.
The source artifact is **`8f8d028:cli.unpack.js`**, associated with macOS Claude Code 2.1.283.
`/Users/zchee/bin/claude` is the proposed peer, not a binary run or digest verified by this draft.
All following current macOS anchors refer to that source artifact, not Linux disassembly.

| Fact | Source or measurement |
|---|---|
| `ne(e,r)` uses explicit `lockfilePath` or appends `.lock` to the base; `Ne` mkdirs that result | `cli.unpack.js:117195–117207` |
| `Wjr` passes `<store>/.storage-write`, `realpath:false`, no `lockfilePath` | `cli.unpack.js:118543–118578`; actual directory is `.storage-write.lock` |
| Storage options are retries 10, minimum 100 ms, maximum 1000 ms, stale 15000 ms | `cli.unpack.js:118555–118566`; `docs/re-verify.md`, F47/U3 |
| Credential mutation runs through the mutex wrapper | `cli.unpack.js:118582–118605`; historical F58's mutate-versus-update contract survives |
| macOS factory is composed Keychain plus plaintext, not plaintext-only because HOME is scratch | `Un`, `cli.unpack.js:119307–119312`; `Ns.delete:118677–118681` |
| Normal logout deletion is wrapped by `Wjr`; acquisition failure has a separate fallback | `dQ`, `cli.unpack.js:1011975–1011994`; `authLogout:1289146–1289172` |
| The Keychain leg invokes `security delete-generic-password`; reads can invoke `find-generic-password` | `cli.unpack.js:118872–118913` |
| Nonempty secure-storage/config spelling contributes eight SHA-256 hex digits to the service; account comes from USER or OS user info | `JL/wk`, `cli.unpack.js:117604–117626` |
| Direct first-party OAuth revokes test each refreshToken first, but logout also flushes telemetry and invokes other hooks | `cli.unpack.js:1011900–1011956`; absence of refreshToken is not a no-network proof |
| Linux synthetic logout showed mkdir of suffixed name → credential unlink → rmdir | `docs/re-verify.md §7.2 U3`; measured Linux 2.1.282, not a macOS runtime witness |
| Older macOS bundles also append the suffix; this is pre-existing, not a new Linux divergence | `docs/re-verify.md §7.2`, bundle table for `ac66a5f`, `9cf6ecf`, `3abb410` |

F53's 4000–8000 ms bound concerns **primary refresh retries**, not storage. Storage inherits
factor=2 and randomize=false (`cli.unpack.js:116919–116950`): ten delays are 100, 200, 400,
800 and six × 1000 ms, totaling **7500 ms** before final refusal after eleven failed attempts.
This is scheduled backoff, not a strict wall-time ceiling: startup, filesystem and scheduling add
latency. HOLD_BUDGET=3000 ms is below that retry-wait total; never wait out that total while held.
Vendor storage heartbeat=7500 ms is a separate derivation, not a measured heartbeat (U3).
Telemetry suppression flags are read at `cli.unpack.js:17405–17436`; flush at `1231523–1231553`
is conditional on exporter state, not proof that every logout makes an outbound request.

## 2. Objectives and guardrails

**Must have:** one corrected shared mutex constant; unchanged ordering/budgets/stale protocol;
legacy-only reporting with unconditional removal/migration refusal; exact-path records;
macOS storage-only exclusion evidence, wrong-name fail-to-exclude control, retained baseline
identities, six closing gates, and an explicit proof-level statement for the Phase 2 handoff.

**Must not have:** dual-lock compatibility; old-name aliasing; per-platform spelling;
legacy deletion/rename/migration, even with `--yes`; new credential backend or OAuth flow;
Linux peer reclamation; changed registry/schema/snapshot bytes; Codex or Remote Control work;
unapproved live credential access; waiting toward 15000 ms storage staleness; unrelated staging.
No new production dependency or runtime test seam is planned. Prefer existing std/rustix primitives.
A necessary new dependency, seam, schema change, or changed vendor premise returns to review.

## 3. RALPLAN-DR summary

**Principles:** (1) match the observed directory, not the vendor's base argument;
(2) preserve authority and lock ordering; (3) preserve evidence, not misleading old labels;
(4) distinguish a deterministic model witness from real-vendor behavior.

**Top three drivers:** restore shared-store exclusion; keep existing recovery/write boundaries;
produce a small, auditable dependency baseline before Linux Phase 2.

| Viable option | Benefit | Bounded cost / limitation |
|---|---|---|
| A — shared-name fix, doctor-only legacy notice, synthetic peer witness | Small production diff; deterministic, credential-free default gates | Proves agctl and modeled fresh-lock semantics, not the real vendor; explicit user acceptance needed |
| B — same correction plus opt-in real macOS direction A | Adds matched vendor evidence for deletion exclusion | §9 containment/overlap eligibility and traffic choice required; no blanket no-network requirement |
| C — B plus status/watch legacy notice | Operators notice leftovers without running doctor | Wider presentation surface; no schema/snapshot edits permitted; adds no mutual-exclusion assurance |

Recommend **A**, doctor-only reporting, with B available only after its prerequisites are met.
If the user requires a real-vendor macOS claim, choose B and keep L1 blocked until eligible;
never relabel A as B. Dual-lock acquisition and legacy cleanup are rejected by the user's
no-deletion/no-migration ruling and D-061's unchanged three-lock order, not merely cost.
Confidence in the recommended bounded change: performance 0.96, scalability 0.95,
reliability 0.86, cost effectiveness 0.94; estimates, not measured benchmark results.

## 4. Decisions

### D-069 — One shared name; correct the base-name versus mutex distinction

Set `STORAGE_WRITE_LOCK` to `.storage-write.lock` in `foreign_activity.rs:33`.
The existing `plan()` and `detect()` consumers use that value; do not duplicate spelling by OS.
Correct `claude_lock.rs` module/LockFs/Which/plan/take comments and its F47/F58 references.
F47 replacement fact: “The storage mutex directory is `.storage-write.lock`: the caller
passes base `.storage-write` without `lockfilePath`; proper-lockfile appends `.lock`.
Its options are `realpath:false`, retries 10 / 100–1000 ms, stale 15000 ms, with re-entrancy.”
F58 replacement fact: “Credential-store mutations run inside `.storage-write.lock`;
agctl's re-read/compare/write remains a mutate operation, but the old unsuffixed lock did
not provide this exclusion.” Preserve historical evidence commands and every measured number.

### D-070 — Legacy is informational, never a peer lock or cleanup target

The user's ruling is settled: `.storage-write` is ONLY a legacy agctl artefact; no deletion
or migration. Add one `LEGACY_STORAGE_WRITE_ARTEFACT` constant in `foreign_activity.rs`,
used only by legacy recognition/reporting/refusal, not `detect()` or acquisition planning.
Keep `claude_artefacts()` as the peer-only set; separately sample legacy metadata without
reading its contents or following links. Both names present means one peer plus one legacy
report, not two peer locks. Absence of the old name adds no output. Old name alone creates
no `ForeignActivity::ClaudeLock`, no peer age, and no busy state attributable to that name.
Recommend doctor-only text; status/watch remain silent about legacy leftovers.
Doctor and held-record reporting must never print a removal command for a legacy path.
Explicit macOS removal refusal precedes any stale sampling/removal attempt; Linux retains
its blanket unsupported-removal response. Dead exact-path records and `--yes` cannot override.
Cleanup under the old macOS age/attestation rules, and automatic rename, are rejected options.

### D-071 — Exact records and ownership evidence stay exact

New records obtain corrected paths from `plan()`; old records retain their old bytes and paths.
`HeldLockRecord::attests` remains equality-based. An old record cannot authorize corrected-name
removal, nor vice versa; include both directions, same basename/different parent, and symlink cases.
No held-record version, filename, schema, PID/start identity, or owner-sidecar interpretation changes.
The vendor `.oauth_refresh.lock.owner` is metadata, not a fourth mutex (`docs/re-verify.md U3`).
A vendor-store path outside agctl's namespace needs a dead agctl record attesting that exact path;
name recognition alone grants no removal permit. A vendor lock inside an owned namespace still
uses the existing conservative macOS stale checks; do not claim all vendor locks are unremovable.

### D-072 — Witness contract, production primitive, and proof limits

Add sibling tests under `src/secret/claude_lock_tests.rs` with prefix `storage_mutex_`.
`take_all` accepts `[LockPlan; 3]`, so it is not a storage-only API (`claude_lock.rs:1500–1505`).
Use a test-local RAII holder built from the production `LockAnchor::in_store` and `RealFs`
`mkdir`/`rmdir` operations; derive its name from the storage element of `plan()`, not a test copy.
This is the production descriptor-relative mutex primitive, not full `HeldLocks` acquisition;
full ordering/records/cancellation are exercised separately through production `acquire_with`.
No new production constructor, command, environment override, or pause fault. Test-only holder
and synthetic peer remain inside the sibling test module; a release artifact cannot call them.

**A, agctl holds:** open a fresh anchored scratch store, acquire only the storage slot, assert
primary and canonical-legacy paths absent, and start a peer on a synthetic credential file.
A source-derived synthetic peer independently appends `.lock`, uses atomic mkdir/rmdir and
fresh-lock EEXIST contention/retry behavior; it never uses agctl's corrected-name constant.
Synchronize readiness and each attempt using channels/barriers; observe attempts and credential
file existence from before peer start through release. Polling silence alone proves nothing.
Require at least one peer attempt while the correct mutex exists; no unlink/replace in that
interval. Release by a conservative 1000 ms target; measured acquisition-to-release must be
≤3000 ms. Peer succeeds after release or gives a bounded refusal; enforce a separate 12 s
peer-process deadline and join/reap it. This deadline never extends agctl's 3000 ms hold.
A run missing overlap, exceeding a bound, or failing cleanup fails; none is a skipped pass.

**B, peer holds:** a synthetic peer independently creates fresh `.storage-write.lock` and
signals ready. Run production `acquire_with` using real filesystem operations. Assert Busy
within 3000 ms, one storage mkdir per round, at most four rounds, acquired primary/legacy
released between rounds, no sleep while held, no write and no surviving held record. Remove
only the fixture-owned peer directory, then demonstrate a fresh production acquisition succeeds.
This direction is agctl-only evidence; a real logout's short hold is not reliably controllable.

**Wrong-name control:** use the same storage-only primitive with `.storage-write`, keep primary
and legacy absent, and run the identical peer. Assert the credential is deleted/replaced and
peer completion occurs **before** old-name release. The resulting exclusion assertion is FALSE
and the control test passes precisely because it exposes that failure. Log that result explicitly.
Do not skip the control, count process startup as an attempt, or call mere presence exclusion.
Do not stretch any agctl hold to vendor staleness or require an `onCompromised` warning.

**Optional real A/control:** after §9 containment/overlap checks, explicitly run
`AGCTL_STORAGE_MUTEX_REAL_PEER=/Users/zchee/bin/claude cargo nextest run --all-features --run-ignored all -E 'test(storage_mutex_real_peer_exclusion)'`.
Use empty HOME, config and secure-storage directories with distinct absolute NFC-normalized
scratch paths; clear auth/provider/OTEL overrides, omit refresh fields, unset
`CLAUDE_CODE_ENABLE_TELEMETRY`; set `DISABLE_TELEMETRY=1` and
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`. No login, token, live home, or TTY; record
version/digest and scratch service. Metadata-only `security find-generic-password -a "$USER" -s "$service"`
must return 44 before/after. Never request credential output; a present item or prompt aborts.
These flags are source-backed suppression, not an all-egress proof. The user may accept ancillary
traffic uncertainty; exclusion assertions do not depend on network success. No network-denial
harness is required. Unexpected out-of-scratch access remains a stop, not permission to continue.
Use a proven attempt/ready observation, not a fixed launch sleep; if a real attempt cannot be
observed inside the budget, report inconclusive and retain the synthetic result separately.
Only the executor owns any separately authorized credential path; lead sees redacted timing,
paths/service name, exit codes, and outcome. Linux AC217 authorization is not inherited.

### D-073 — Doctor and public wording, with no recovery expansion

Doctor notice: “Legacy agctl artefact: `<path>` (`.storage-write`); not a Claude Code mutex;
left unchanged. agctl does not remove or migrate this artefact.” Include observed type, no contents.
MacOS refusal: “`<path>` is a legacy agctl artefact, not a Claude Code mutex; removal and
migration are unsupported.” Keep path-authority checks; do not follow an untrusted link to label it.
README removal-list item becomes: “be named `.oauth_refresh.lock`, `.storage-write.lock`, or a
legacy `<namespace>.lock`;”. Add the legacy notice near that list, not a new cleanup recipe.
README live boundary says “`.oauth_refresh.lock` and `.storage-write.lock` inside the resolved
store, and the legacy `<store>.lock` beside it”. `src/provider/claude/namespace.rs` is outside
D-066's enumerated scope: its doc comment keeps the current `.storage-write` wording, and that
stale spelling is recorded in §11 follow-ups, not corrected under this GO.
Correct doctor module docs/refusal list accordingly. Keep 60 s doctor staleness and 12 s sampling
unchanged; they are more conservative than vendor storage stale=15 s. No threshold redesign.
Schema and snapshot files stay byte-identical; dynamic status payload names necessarily change
for the corrected mutex. Do not confuse frozen schemas with identical old/new busy-state payloads.

### D-074 — The Linux Phase 2 dependency is an evidence baseline, not permission

Handoff records the landing revision and `b0328fc..landing` bounded diff; before/after full
macOS inventories retaining every baseline identity; corrected existing cases versus new
witnesses; six macOS gate logs; witness direction, peer kind, control, bounds and limitations;
independent verifier verdict; frozen-path diff. Include optional Debian evidence if selected.
Recommend Debian gates 1–3 as optional: no platform implementation changes, but they strengthen
the next Linux baseline. If waived, write “Linux not rerun for this correction,” never “portable
behavior verified.” Prior Phase 1 results are context, not a rerun of this revision.
The lead must explicitly record whether synthetic evidence is accepted for D-066's macOS
prerequisite; absent that user ruling, Linux Phase 2 remains blocked even if this fix lands.

### D-075 — Delivery is separately selected

Recommend a dedicated branch from `b0328fc`, one signed correction commit including its docs,
then a PR with no merge. Alternatives: separate code/docs commits on that branch; or explicitly
authorized main delivery. No push, main edit, PR merge, or historical commit rewrite is implied
by GO alone. **Parent publication is user-owned and is a prerequisite, not a choice:** the user
alone publishes `43f3770` and `b0328fc`; no lead or worker push may make either ancestor reachable
on any remote. A branch based on `b0328fc` carries both ancestors, so pushing that branch or opening
its PR waits until the user has published them, or until the user separately approves another
delivery base. Until then the lead's delivery ends at a local signed commit.
Select only this work's README hunks: inspect `git diff -U0 -- README.md`, author a reviewed
lock-only patch, `git apply --cached --unidiff-zero "$patch"`, inspect
`git diff --cached -- README.md`, and confirm badge hunks remain unstaged. Never stage README whole.
Use signed commits from a message file, approved attribution, and the repository merge protocol.

## 5. Task flow and file-level TODOs

### L1 — Freeze input and prove the selected witness is eligible

Recheck cwd, branch/HEAD, worktree, relevant handoff/state, frozen paths and the §9 source anchors.
Capture the full baseline `cargo nextest list --all-features --message-format json` into
`$E/inventory-before.json` and run §7.1's `ac235_extract` and its controls on it, so the parser
is proven before any edit; retain both outside git with the closing gate logs, not in a new ledger. Inventory all `storage-write` references.
Recheck installed peer only if real mode selected; do not enter a live backend to resolve facts.
**Acceptance:** AC218, AC230, AC231; no unexplained baseline drift; §10 choices recorded.

### L2 — Correct the shared protocol and separate legacy reporting

Edit `src/secret/foreign_activity.rs`, `src/secret/claude_lock.rs`, `src/commands/doctor.rs`,
and no other production file; `src/provider/claude/namespace.rs` is not touched. Add focused
sibling tests in `foreign_activity_tests.rs`, `claude_lock_tests.rs`, `doctor_tests.rs`,
`held_locks_tests.rs`. The `held_locks.rs` implementation is frozen under this GO, unconditionally.
If a test establishes a need outside the approved files or the D-071 record contract, stop and
obtain a separately reviewed scope amendment before continuing; never enlarge this GO in place.
**Acceptance:** AC219–AC224; same order/timings, legacy untouched, Linux refusal preserved.
Local check: `cargo nextest run --all-features -E 'test(storage_mutex_)'` (nonempty selected set).

### L3 — Add witnesses; classify every existing site without deleting identities

Apply the following inventory classes: **A** correct a peer-name expectation; **B** retain or
add explicit legacy-only coverage; **C** add a new witness. Re-run inventory after edits.

| Current site | Class and required treatment |
|---|---|
| `src/secret/foreign_activity_tests.rs:30` | A via constant; C directory, legacy-only, both-names cases; retain regular-file anomaly coverage |
| `src/secret/claude_lock_tests.rs:659,741,770,835,1202,2607,2625` | A comments/assertions and implicit constant consumers; C A/B/control, cleanup and bounds |
| `src/secret/held_locks_tests.rs:202` | B retain old-path negative; C corrected-path positive/negative and bidirectional non-aliasing |
| `src/secret/file_store_tests.rs:790` | A corrected nonempty directory; B add legacy nonempty no-delete case, do not weaken refusal |
| `src/commands/doctor_tests.rs:445,906` | A corrected removal/name assertion; B old name becomes explicit false/refusal, all ages/types/records |
| `src/commands/status_tests.rs:795,2554` | A corrected peer set and lock-free observer; C legacy alone is not busy, both names preserve peer refusal |
| `tests/common/mod.rs:237,292` | A namespace/live helper third path; retain canonical-store ordering and symlink semantics |
| `tests/e2e_refresh.rs:215` | A corrected peer artefact; C legacy-only path does not falsely block |
| `tests/e2e_doctor_stale.rs:148` | B retain old sibling-record non-attestation; C corrected counterpart and legacy cleanup refusal |
| `tests/e2e_accounts.rs:405` | A corrected anomalous regular file; B legacy reporting without removal |
| `tests/e2e_swap.rs:1029,1646,4082` | A corrected no-live-write/third-lock cases; B additionally retain old-name noncreation checks |
| `tests/e2e_swap.rs:1660,1844` | A descriptions only; preserve contention/SIGTERM identities and assertions |

Source line numbers are discovery anchors, not patch offsets. Retain every baseline test function
identity; changed expectations express the corrected contract, not deleted baseline coverage.
**Acceptance:** AC225–AC229 and AC235; named witnesses pass, control visibly fails to exclude.

### L4 — Correct evidence/docs and add a nonvacuous regression pin

Edit `README.md` only in D-073's region/boundary hunks; edit `docs/re-verify.md` F47/F58 and
append a bounded current-artifact clarification, preserving historical observations. Update
`scripts/phase3-greps.sh` with the D-069/D-070 source pin described in §7.2. No other scripts
need modification for the chosen sibling-only witness. Keep source/module docs consistent.
**Acceptance:** AC232–AC234; new pin fails planted controls then passes real tree; AC83 clean.
Local checks are targeted; reserve the six complete gates for the closing run, release last.

### L5 — Certify once per pass, verify independently, deliver only as selected

Executor runs the six macOS gates in §7.1 after L1–L4; captures the final inventory
(`$E/inventory-after.json`, AC235) and the bounded diff.
If selected, run Debian gates 1–3 on the same reviewed revision/source snapshot, no host flags.
Verifier independently checks AC218–AC239, runs the closing sequence, and rejects skipped
witnesses, unexplained deletions, timing overrun, or synthetic evidence labeled real-peer proof.
Fixes return to the same executor; verifier rechecks changed evidence and affected gates.
**Acceptance:** AC236–AC239 and explicit verifier ACCEPT. The lead then prepares the selected
local delivery (branch, lock-only staging, signed commit); any push or PR waits for the user's
parent publication per D-075.
Stop before Linux S4; even a merged fix does not authorize its operator checkpoint.

## 6. Acceptance criteria

Commands use portable spelling; execute through local development conventions in `AGENTS.md`.
`$E` is the existing run's untracked evidence directory; `$V` is defined in §1.2. Test prefixes
below are required additions, not claims those tests already exist. A zero-test selection fails.

| ID | Exact command / observation | Required result |
|---|---|---|
| AC218 | `git status --short --branch`; `git rev-parse HEAD`; `git diff --exit-code b0328fc -- src/render/snapshots src/tui/snapshots schemas` | Baseline/approved drift recorded; frozen diff empty; unrelated work preserved |
| AC219 | `cargo nextest run --all-features -E 'test(storage_mutex_shared_name_and_order)'` | Third plan is corrected name; primary→legacy→storage; reverse release |
| AC220 | `cargo nextest run --all-features -E 'test(storage_mutex_foreign_detection)'` | Corrected directory detected; old-only not a peer; both names count one peer |
| AC221 | `cargo nextest run --all-features -E 'test(storage_mutex_legacy_report_and_refusal)'` | Doctor-only chosen text; no delete/migrate/rename at any age, type, dead record, or --yes |
| AC222 | `cargo nextest run --all-features -E 'test(storage_mutex_record_exact_paths)'` | New path recorded; old/new records never alias; outside-store authority unchanged |
| AC223 | `cargo nextest run --all-features -E 'test(storage_write_is_one_non_blocking_attempt_per_round)'` | Baseline identity passes, at most four rounds, prefix/record released, no sleep while held |
| AC224 | `cargo nextest run --all-features -E 'test(storage_mutex_doctor_authority)'` | Host authority/60 s/12 s tests pass; Linux refusal unchanged by source review, runtime-tested only if Debian selected |
| AC225 | Under `set -o pipefail`: `cargo nextest run --all-features --no-tests fail --success-output final --failure-output final -E 'test(storage_mutex_peer_exclusion)' 2>&1 \| tee "$E/ac225-witness.log"`; then `rc=$?; printf 'exit=%s %s\n' "$rc" "$(date)" >> "$E/ac225-witness.log"; test "$rc" -eq 0` | Nonempty A/B set; correct-name exclusion in both specified directions; overlap and timing lines retained in the log; recorded pipeline exit 0 |
| AC226 | Same form, filter `test(storage_mutex_wrong_name_control)`, log `$E/ac226-control.log` | Peer completes/mutates while old name is held; the log retains the explicit excluded=false line; not a skipped test |
| AC227 | Same form, filter `test(storage_mutex_bound_and_cleanup)`, log `$E/ac227-bounds.log` | Observed holds ≤3000 ms with measured values in the log; primary/legacy absent for A/control; bounded cleanup on all exits |
| AC228 | `cargo nextest run --all-features -E 'test(storage_mutex_status_compatibility)'` | Same JSON schema/shape; corrected peer name; legacy alone not busy; no new wire field |
| AC229 | `cargo nextest run --all-features -E 'test(storage_mutex_symlink_and_anomaly)'` | Symlink/regular-file/nonempty cases retained; no followed-link deletion or legacy mutation |
| AC230 | `rg -n 'storage-write' src/provider/codex src/commands/codex` | No matches (exit 1), before and after; Codex untouched |
| AC231 | `git -C "$V" show 8f8d028:cli.unpack.js \| sed -n '117195,117207p;118543,118578p;119307,119312p;1011900,1011994p'` | §1/§9 anchors verified; selected witness eligibility and limitations recorded |
| AC232 | `scripts/phase3-greps.sh` | Added name/legacy-use pin rejects its planted violations and accepts real tree |
| AC233 | `rg -n -e 'direnv[ ]exec' -e 'config\.dev\.toml' docs/plans/agctl-storage-write-lock-name.md`; `scripts/docs-gate.sh` | First command no matches; docs gate succeeds without unrelated edits |
| AC234 | `git diff -- README.md docs/re-verify.md`; `git diff --exit-code b0328fc -- src/provider/claude/namespace.rs src/secret/held_locks.rs`; `rg -n 'storage-write' src tests docs/re-verify.md README.md` | D-069/D-073 wording; namespace/held-record freeze diff empty; every old literal classified, `namespace.rs:223` as out-of-scope retained; historical base searches preserved |
| AC235 | §7.1 recipe: `cargo nextest list --all-features --message-format json >\| "$E/inventory-before.json"` at L1 and `…/inventory-after.json` at L5; `ac235_extract` on each; `ac235_compare "$E/identities-before.txt" "$E/identities-after.txt"`; the five §7.1 controls | Both inventories retained; extraction rejects missing/malformed/empty input and count mismatch; comparator exits nonzero on any removal (renames included), zero when only additions exist; controls behave exactly as §7.1 requires |
| AC236 | §7.1's six exact commands, sequentially | Six exit 0 logs, release last; executor and independent verifier passes identified |
| AC237 | `git diff --exit-code b0328fc -- src/render/snapshots src/tui/snapshots schemas`; `rg -n 'storage-write' src/render/snapshots src/tui/snapshots schemas` | Empty diff; no matches; no regeneration accepted |
| AC238 | `git diff --cached --stat`; `git diff --cached -- README.md`; `git diff -- README.md` | Staging matches selected delivery; unrelated badge/config/CI changes excluded |
| AC239 | `git show --stat "$landing"`; `git diff b0328fc.."$landing" -- src tests scripts README.md docs/re-verify.md` | Bounded landing/evidence and verifier ACCEPT linked; Phase 2 remains separately gated |

## 7. Verification and planted controls

### 7.1 Six closing macOS gates, exactly this order

1. `cargo fmt --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo nextest run --all-features`
4. `scripts/phase3-greps.sh`
5. `scripts/phase3-structural.sh`
6. `scripts/release-gate.sh`

Do not repeat this complete sequence per L-step. The independent verifier is a separate pass.
Run focused tests first; optional real-peer tests must be explicitly selected and not counted
as passed when the environment gate is absent. A selected real mode missing its witness blocks.
Optional Debian gates 1–3 use the reviewed snapshot, plain cargo and cleared host-specific
RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS, per Linux plan §7.1; no credential checkpoint or live home.
Witness evidence capture (AC225–AC227): run each focused command under `set -o pipefail` with
`--no-tests fail --success-output final --failure-output final`, `2>&1 | tee "$E/<ac>.log"`, then
`rc=$?; printf 'exit=%s %s\n' "$rc" "$(date)" >> "$E/<ac>.log"; test "$rc" -eq 0`, so the log
records the pipeline status and the enclosing command still fails on it (wrap it in `if` when the
caller runs `set -e`); the pipeline status is the test status. Nothing depends on nextest output
defaults or environment variables; `--no-capture` is not used.

AC235 identity retention runs this inline recipe, not prose. Inventory shape, verified against the
working tree at `b0328fc` while planning (1937 test cases including one ignored): top-level
`rust-suites` keyed by binary id, each holding `testcases` keyed by test name, plus `test-count`.
An identity is `<binary-id> <test-name>`. Renames count as removals and are not permitted.

```sh
set -o pipefail
# Extraction: LC_ALL=C-sorted "binary-id test-name" lines; a missing, truncated,
# empty or zero-count inventory fails here (jq -e exits nonzero).
ac235_identities() {
  jq -e '(.["rust-suites"] | type) == "object" and (.["test-count"] | type) == "number" and .["test-count"] > 0' "$1" >/dev/null || return 1
  LC_ALL=C jq -r '.["rust-suites"] | to_entries[] | .key as $b | (.value.testcases | to_entries[] | "\($b) \(.key)")' "$1" | LC_ALL=C sort -u
}
# Parser check: the identity count must be positive and equal test-count.
ac235_extract() {
  ac235_identities "$1" >| "$2" || { echo "AC235 FAIL: $1 is missing, malformed or empty"; return 1; }
  n=$(wc -l <"$2" | tr -d ' '); c=$(jq '.["test-count"]' "$1")
  [ "$n" -gt 0 ] && [ "$n" -eq "$c" ] || { echo "AC235 FAIL: $n identities vs test-count $c in $1"; return 1; }
  echo "AC235 extracted $n identities from $1"
}
# Comparator: an identity in BEFORE but not in AFTER is a removal; a nonempty
# removal set returns failure, and so does a comm error. Additions alone pass.
ac235_compare() {
  [ -s "$1" ] && [ -s "$2" ] || { echo "AC235 FAIL: empty identity set"; return 1; }
  removed=$(LC_ALL=C comm -23 "$1" "$2") || { echo "AC235 FAIL: identity comparison failed"; return 1; }
  [ -z "$removed" ] || { printf 'AC235 FAIL: removed identities:\n%s\n' "$removed"; return 1; }
  echo "AC235 PASS: $(wc -l <"$1" | tr -d ' ') baseline identities retained"
}
# Driver: every step's status is propagated; a helper failure ends the recipe.
ac235_extract "$E/inventory-before.json" "$E/identities-before.txt" || exit 1
ac235_extract "$E/inventory-after.json" "$E/identities-after.txt" || exit 1
ac235_compare "$E/identities-before.txt" "$E/identities-after.txt" || exit 1
```

Five controls, each logged and each required: (1) removed identity — with
`LC_ALL=C sed '1d' "$E/identities-before.txt"` as the after set, `ac235_compare` must return
nonzero and print the removed line; (2) empty, `{"rust-suites":{},"test-count":0}`, truncated
(`{"rust-suites":`) and missing inventories must each make `ac235_extract` return nonzero with
no PASS line; (3) the before set plus one added line must pass; (4) complete-driver count
mismatch — the whole recipe run with `jq '.["test-count"] += 1'` applied to an otherwise
unchanged after inventory must exit nonzero and print no PASS line; (5) comparator input error —
`ac235_compare / /` must return nonzero and print no PASS line. The recipe and all five controls
were executed during planning under bash, zsh and sh against the inventory above, with the driver
run as a whole and not only its helpers; L1 repeats them on the frozen baseline and L5 on the
final tree. A control that does not behave as stated blocks.

### 7.2 Nonvacuous pins and controls

The new production-code pin excludes `_tests.rs` and comment-only lines as existing pins do.
Require exactly one unsuffixed string literal, the named legacy constant in `foreign_activity.rs`;
require the corrected shared constant exactly once; reject use of the legacy constant in
`detect()`'s peer candidates or `claude_lock.rs` acquisition planning. File-wide allowlisting
of `foreign_activity.rs` alone is insufficient: it would permit regression of the main constant.
Plant separately (1) main constant reverted, (2) another unsuffixed literal, (3) legacy constant
inserted into the peer candidate set. Each must fail the new named check; the real tree passes.
Plant the wrong-name witness mutation in a disposable gate snapshot, not the working tree;
the corrected A assertion must fail while the explicit wrong-name control remains diagnostic.
Existing structural probes keep exact expected compiler errors; unrelated build failure is not proof.
Chosen test helpers are unit-test-only, so no vacuous binary-string seam check is added. Any
runtime seam proposal instead requires review plus positive testing-build and negative release
structural checks; the existing release gate's absence check is not permission to add a seam.

## 8. Deliberate pre-mortem and expanded tests

| Failure scenario | Prevention / detection | Stop rule |
|---|---|---|
| Name fix appears green because another lock blocks the peer | Storage-only A/control, primary/legacy absent, actual attempt overlap, wrong-name mutation proceeds | No overlap or control fails to expose bug → witness inconclusive, no acceptance |
| Rename makes doctor delete the vendor's mutex or old agctl leftover | Exact-path permit, unchanged stale checks, Linux refusal, legacy never removable, old/new record anti-aliasing | Any broader authority or offered legacy removal command → blocker |
| Real logout reaches a live backend or has unexamined ancillary traffic | Exact scratch service, absence checks, cleared environment, cited telemetry flags, explicit traffic choice | Unexpected item/prompt/out-of-scratch access stops; traffic uncertainty needs user choice, not a no-network claim |

**Unit:** shared name/order/profile; independent peer suffix; legacy/both-name detection; type
anomalies; exact records; old-age legacy refusal; symlinked live store; all cleanup/error branches.
**Integration:** existing refresh/status/doctor/account/swap cases plus corrected storage EEXIST;
no token request or credential write on refusal; released prefix and record on restart/cancel.
**E2E:** existing swap/SIGTERM tests retain identities; storage-only A/B/control uses real filesystem
operations. Real vendor A/control is separately selected, matched, and eligibility-gated.
**Observability:** monotonic acquisition, attempt, mutation and release events; exit/refusal; path
and peer kind; budget and cleanup result. No tokens, credential contents, login URL or code.
Synthetic logs must say “agctl-only; vendor not executed.” No aggregate pass hides missing modes.

## 9. Unknowns and settling commands

| Unknown / disposition | Settling command or bounded procedure | Gate |
|---|---|---|
| Installed peer still matches 2.1.283/source artifact | With selected real-mode authorization: `/Users/zchee/bin/claude --version`; `shasum -a 256 /Users/zchee/bin/claude`; `git -C "$V" rev-parse 8f8d028` | Before any real peer run |
| Ancillary traffic/TTY and out-of-scratch hook reads remain unmeasured | `git -C "$V" show 8f8d028:cli.unpack.js \| sed -n '17405,17436p;1011900,1012025p;1231523,1231553p'`; trace hooks/startup; apply D-072 flags and record the user's remaining traffic choice | Not a blanket network blocker; no live backend access authorized |
| Scratch service is absent; no prompt or other Keychain access | Verify `JL/wk` at `117604–117626`; derive the exact configured suffix; metadata-only `security find-generic-password -a "$USER" -s "$service"`, expected 44 before/after; prove reachable calls remain scoped | B eligibility, not presumed from unique path |
| Real peer attempt can be observed within a ≤3000 ms hold | Design an observation that proves mkdir attempt, not just process launch; run only after the preceding gates close | If not observable, no real exclusion claim; synthetic alternative needs user choice |
| Debian tooling/snapshot remains available | `ssh -o BatchMode=yes -o ConnectTimeout=15 debian-13-trixie.gaudiy-platform 'uname -m; command -v cargo; command -v cargo-nextest'` after Debian choice | Optional gate availability; no credentials read |
| Concurrent tree/baseline drift | `git status --short --branch`; `git log -3 --oneline`; `git diff -- README.md` | L1 and before staging |

No unknown permits silent fallback from selected real mode to synthetic, schema regeneration,
legacy removal, or Linux operator work. §10 selects scope; the lead records unresolved items in
the existing open-question register without creating a new ledger.

## 10. Numbered user decisions required for GO

The lead relays this list verbatim and records the answer before execution:

1. **Correction/report scope:** approve D-069–D-071 and doctor-only legacy notice/refusal (recommended), or additionally request status/watch notices within the frozen schema/snapshot boundary? Legacy deletion and migration remain forbidden in either choice.
2. **Witness proof level:** accept mandatory synthetic macOS A/B/control as agctl-only evidence and explicitly accept that limitation for D-066's prerequisite (recommended), or add opt-in real-vendor A/control after §9 containment/overlap checks? For real mode, accept D-072's source-backed telemetry suppression with residual ancillary-traffic uncertainty, or defer that optional witness pending further source checking. Assertions do not depend on network success; no network-denial harness, live credential, or Linux AC217 checkpoint is authorized.
3. **Debian recheck:** omit Debian gates for this platform-independent correction and record the limitation (recommended), or require Debian gates 1–3 on the reviewed correction before acceptance?
4. **Delivery:** choose a dedicated branch from `b0328fc`, one signed correction+docs commit and a PR without merge (recommended), separate code/docs commits, or explicitly authorized main delivery. Prerequisite, not a choice: the user alone publishes the unpushed parents `43f3770` and `b0328fc`; no lead or worker push may publish them, and branch/PR publication waits for that publication or a separately approved delivery base. No merge is implicit.
5. **GO boundary:** after scoped critic approval and the choices above, authorize L1–L5 only. Linux Phase 2, Linux AC217's operator checkpoint, unrelated README/CI edits, and Remote Control Phase 4 remain stopped.

## 11. ADR and success criteria

**Decision:** pending user selection; recommend one shared corrected name, doctor-only immutable
legacy reporting, sibling-only synthetic witnesses, and an independently verified bounded landing.
**Drivers:** actual vendor mutex identity; unchanged authority/order; reproducible prerequisite evidence.
**Alternatives considered:** eligibility-gated real peer; additional status/watch notice; dual locking;
legacy cleanup. The last two protocol/cleanup alternatives are invalidated by fixed scope/rulings.
**Why chosen:** production correction stays small; diagnostic distinction is explicit; no live backend
is needed to demonstrate the old collision and corrected primitive. It makes no unearned vendor claim.
**Consequences:** formerly unexcluded writes can contend and restart; old artefacts remain on disk;
existing status payload name changes are intentional while wire schemas/snapshot bytes remain frozen.
Synthetic-only acceptance is a user decision, not an inference by the executor or verifier.
**Follow-ups:** selected real-peer eligibility work only if requested; Linux S4 entry approval and
separate AC217 operator consent; vendor version bumps revalidate source and witness assumptions;
`src/provider/claude/namespace.rs:223` still names `.storage-write` and awaits a separately
approved docs-only amendment, outside D-066.
**Success:** AC218–AC239 satisfied for selected scope; baseline identities retained; no frozen-path
changes; unrelated work unstaged; six macOS gates pass; independent verifier ACCEPT; chosen delivery
recorded. No completion claim from this plan alone, and no self-approval by its author.

## 12. Changelog
- **v1.0 — 2026-09-26 17:51:25 JST (from `date` in this authoring command):** planner draft;
  lead analyst gap check incorporated; pending scoped critic and user GO. No runtime
  validation or real-peer checkpoint claimed.
- **v1.0 amendment — 2026-09-26 17:56:26 JST (from date):** verified storage backoff and made ancillary traffic an explicit opt-in decision.
- **v1.1 — 2026-09-26 18:12:17 JST (from `date` in the applying command):** scoped critic REVISE on v1.0 resolved.
  B1: AC235 replaced by the executable fail-closed recipe and controls in §7.1, run at L1 and L5.
  B2: `namespace.rs` edit removed from D-073/L2/AC234; `held_locks.rs` frozen unconditionally with
  a stop-and-amend rule. B3: parent publication made a user-owned prerequisite in D-075, L5 and
  §10 item 4. SF1: `take_all` anchor corrected. SF2: AC225–AC227 capture successful-test output
  under `set -o pipefail`. Lead-applied from the critic's minimal-change text; D-072 unchanged.
- **v1.2 — 2026-09-26 18:21:26 JST (from `date` in the applying command):** the critic's v1.1 re-check
  CONFIRMED B2, B3, SF1 and SF2 and left B1 open on status propagation. The AC235 comparator now
  fails on a `comm` error and the driver exits on any helper failure; controls (4) complete-driver
  count mismatch and (5) comparator input error were added and proven with the driver run as a
  whole under bash, zsh and sh. SF3 applied: AC225–AC227 keep the witness status through the
  logging command. Lead-applied; D-072 unchanged.
- **v1.2 approval record — 2026-09-26 18:27:28 JST (from `date` in the applying command):** the scoped critic's
  B1-only re-check returned APPROVE on the v1.2 bytes above (B1 CONFIRMED RESOLVED, SF3 APPLIED,
  no blockers, no should-fixes; `.omc/drafts/swl-critic-verdict-v1.2.md`, reviewed 18:26:41 JST).
  This status line and changelog entry are the only edits since that hash; content unchanged. The
  plan stays `pending approval` until the user records the §10 decisions and gives GO.
- **L5 landing record — 2026-09-26 23:13:43 JST (from `date` in the applying command):** user GO on §10 (D1 doctor-only notice/refusal; D2 synthetic macOS A/B/control accepted as agctl-only evidence, vendor not executed, no keychain read, no live HOME; D3 Debian gates omitted, Linux not rerun for this correction; D4 one signed correction+docs commit on `main`, no push, a recorded deviation from the branch+PR recommendation; D5 L1–L5 only). L1 baseline `337633e` (the plan's `b0328fc` literal was stale; the lead's unrelated `809f3bf` sits between baseline and landing and touches only `src/main.rs` and CI). Executor `omc-configured-executor-4e63ea1e64dd` ran L1–L4 and gates 1–6 (exit 0; nextest 1953 passed, 1 pre-existing ignored). Independent verifier `omc-configured-verifier-4e63ea1e64dd` reran the focused set (19/19), AC235 identity retention (1937 retained, +17, −0, five controls under bash/zsh/sh), the AC232 pin, a constant-revert mutation (witness A fails, wrong-name control passes with `excluded == false`) and gates 1–6 in order (exit 0); VERDICT ACCEPT, 0 blockers. Its first full nextest run failed one pre-existing `e2e_doctor` test because the verifier's TMPDIR carried a UUID-shaped segment; the rerun under the default temp environment passed and the failed evidence is retained. AC218–AC237 met; AC238/AC239 closed by this lead-staged commit. Bounded diff SHA-256 `3072118ab75f30099cfa0170a6f83a89c960a0ea869f303aadd8170fa673bc90`; frozen paths unchanged against `b0328fc`, `337633e` and `809f3bf`. Evidence in the session scratchpad (`swl-evidence/`, `swl-verify/`), not committed.
