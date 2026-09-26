# agctl — Linux process and file-only credential support

- **Version:** v1.3 (v1.3.1 editorial relocation, see §12).
- **Status:** v1.2 approved by the user on 2026-09-26 07:11:40 JST (from `date`); v1.3 scoped critic APPROVE recorded by the lead 2026-09-26 11:10:32 JST (from `date`); v1.3 confirmed and Phase 1 ordered GO by the user 2026-09-26 11:42:30 JST (from `date`); D-066 decided as a separate bug bead `agctl-storage-write-lock-name-4slm`. Phase 0 (S1) evidence is complete under `agctl-1y9.1` (Linux vendor/procfs evidence spike); S2 started under `agctl-1y9.2`. Phase 1 entry and Phase 2's separate dependency remain gated as §0 specifies.
- **Mode:** RALPLAN-DR **DELIBERATE**.
- **Date:** 2026-09-26 11:05:02 JST (from `date` in this final v1.3 authoring command).
- **Baseline:** `main` = `b09c92a`; re-derive anchors after integrating concurrent work.
- **Sources:** lead's Linux findings table; `agctl-1y9` (Linux file-only credential backend);
  `docs/re-verify.md`; Claude Code bundle `ac66a5f`; repository sources indexed in §1.
- **Numbering:** this plan owns S1–S6, AC177–AC217, and D-056–D-068; v1.3 adds AC217 and D-066–D-068 only.
  The Remote Control plan reserves AC129–AC176 and D-040–D-055; do not renumber either plan.
- **Authoring boundary:** this lane edits only this plan and preserves v1.2 at `snapshots/linux-v1.2.md`;
  it creates/updates no beads, source, tests, docs, open-question file or Remote Control plan.
- **Review boundary:** the lead's analyst pass is incorporated (v1.1); the scoped critic
  (2026-09-26 00:50:54 JST) returned REVISE; v1.2 applied its blocker and should-fixes; the critic's
  scoped re-check of v1.2 returned **APPROVE** (2026-09-26 01:01:33 JST); the user then approved v1.2.
  This v1.3 return incorporates the lead-authored seven-premise analyst gap check and cites
  `docs/re-verify.md §7`; the single scoped critic verdict is pending.

## 0. Phases and stop point

| Phase | Scope | Status | Closing gate | Artifact / landing |
|---|---|---|---|---|
| 0 | S1: matched Linux vendor evidence and platform contracts | ✅ complete | AC177–AC181 evidence and v1.3 ruling accepted (critic APPROVE, SF1 applied) | `agctl-1y9.1` (Linux vendor/procfs evidence spike); `docs/re-verify.md §7.1–§7.4`; v1.3 accepted |
| 1 | S2–S3: process backend, build restoration, test routing, CI | 🔶 in progress (user GO 2026-09-26 11:42:30 JST) | AC182–AC189 and six gates on both OSes | `agctl-1y9.2` (Linux process backend and CI); one commit at phase end |
| 2 | S4–S6: file-only credentials, commands, delivery certification | 🔜 not started | D-066 prerequisite (`agctl-storage-write-lock-name-4slm`, separate bug, blocks `.3`); AC190–AC217 and six gates on both OSes | `agctl-1y9.3` (Linux file credentials and delivery); no code or commit |

**Current stop point:** Phase 1 in progress since 2026-09-26 11:42:30 JST (from `date`): user confirmed v1.3, chose D-066's separate-bug option (`agctl-storage-write-lock-name-4slm`) and ordered Phase 1 GO; S1's evidence is committed with this record.
**Next action:** S2 then S3 by one executor lane, one verifier pass over AC182–AC189, six gates once on macOS and Debian, one Phase 1 commit; stop before S4.
Do not interpret a successful Linux compile, this amendment, or the existing bead as implementation approval.

**Phase 1 recommendation: GO for S2–S3 once the scoped critic accepts the U4 ruling.** U4 (D-058/D-067)
and settled U7 are its enabled consumers; no Phase 2 credential dependency gates Phase 1. The lead records
that acceptance and explicit GO before S2; until then execution remains stopped. The ruling selects exact
names, versioned boot/namespace/tick/real-UID identity, same-domain ESRCH-only own-writer evidence, and
no Linux peer-lock removal. S2/S3 operational work (not another structural unknown): gate runner rechecks
tmpfs rustc/cargo, installs cargo-nextest and dev config under tmpfs CARGO_HOME, exposes extracted rg,
and prepares the credential-free reviewed Git snapshot. Debian gates use plain cargo, no `.envrc`, no
custom RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS (§7.1). None is claimed gate-ready or passing by S1.

**Phase 2 entry remains NO-GO.** U1/U2/U3/U6 are settled as facts and conservative contracts here;
U5/U8 select D-064's pre-spawn `unsupported on this platform` branch, not proof-backed Codex login.
Entry additionally requires Phase 1 acceptance and user authorization, landing and verification of
D-066's separate platform-independent storage-lock-name correction. The Linux half of AC217 is a
Phase 2 S4 closing gate, not an S1 result; the macOS half is evidence required from that dependency.
Phase 2 delivery additionally requires separate authorization/completion of AC217's Linux forced-refresh operator checkpoint
and AC192 implementation of the fixed `ambiguous config dir: use an absolute path` read/status/write
refusal (D-068); the text decision is settled here, not another unanswered user question.
No further operator OAuth step remains in S1's approved procedure (`docs/re-verify.md §7.4`); the new
Phase 2 checkpoint is distinct and not authorized by that completed procedure.

**D-056 — Sequencing.** Each code phase has one executor lane working its S-steps in order, followed by
one independent verifier pass. No per-step lanes, charters, or handoff ledgers. Fixes return to that executor;
the verifier rechecks the changed evidence. The six end gates run once per completed phase, release gate last.
Phase 0 is a bounded evidence spike, not a port concealed inside a research task.

The evidence spike must settle every structural question for an enabled consumer before Phase 1 begins.
A changed credential, lock, or Codex-login premise returns this plan to the planner and scoped critic; it is
not executor discretion. D-064's preselected Linux Codex-login refusal branch is a settled scope outcome,
not a changed premise or a blocker for Claude support and Codex file-backed status/import/doctor.
Phase 1 restores build/test coverage but does not advertise supported Linux credential operations.
Phase 2 is the delivery boundary: no Linux support claim until all required behavior and release gates pass.

At phase completion, pause/resume, or transition, report this phase table and the active phase's S-step table,
including landed artifacts/commits where they exist. State the exact stop point and next action.
All execution timestamps must come from `date` in the same command that writes the timestamped record.

## 1. Context and evidence boundaries

### 1.1 Verified repository gaps

The lead's Linux `cargo check --all-targets --all-features` on rustc 1.98.1 reported 15 errors:
ten in `src/runtime/proc.rs` and five in its sibling tests. This is the supplied baseline evidence,
not a build rerun by the planner. Other files passing name resolution does not establish a complete type-check.

| Ref | Source anchor | Evidence and implication |
|---|---|---|
| R1 | `src/runtime/proc.rs:105-210,247-358,367-534` | Public process API plus Apple-only libproc implementation; preserve conservative classification. |
| R2 | `src/runtime/proc_tests.rs:187-189` | Apple status constants prevent Linux all-target builds. |
| R3 | `src/secret/held_locks.rs:76-121`; `namespace_lock.rs:361` | Persisted start identities affect stale-lock recovery; unknown identity is not removal permission. |
| R4 | `src/secret/mod.rs:74-85,94-131,295-341` | Read-only keychain trait, absolute macOS executable, testing-only disabled backend. |
| R5 | `src/secret/location.rs:23-28,74-125` | Live/config-dir currently read keychain only; owned and adopted copies use files. |
| R6 | `src/secret/keychain_write.rs:115-205,322-394,438-450,491-613` | Private WriteTarget authority; stdin transport, line limit and managed child lifecycle. |
| R7 | `src/secret/file_store.rs:485-541`; `secret_file.rs:170-281` | Namespace-bounded writes; exclusive 0600 temp, fsync, rename, cancellation and pending outcomes. |
| R8 | `src/secret/claude_lock.rs:540-609`; `foreign_activity.rs:99-155` | Anchored locking and migration/lock evidence; Linux needs explicit capability routing. |
| R9 | `src/provider/claude/discovery.rs:102-148,175-234,276-320` | Preflight and listing determine keychain rows; an empty listing alone is not a file backend. |
| R10 | `src/provider/claude/namespace.rs:90-115,225-259` | Captured environment, store/config separation, and deliberate empty-config divergence. |
| R11 | `src/config/mod.rs:174-206`; `config/import.rs:320-367` | ConfigDirReadOnly carries a path and service; unknown identity may remain service-keyed. |
| R12 | `src/commands/use.rs:2331-2404,2477-2603,3387-3434,4001-4332` | Under-lock validation, verification, D-024 parking, shadow-file removal, undo. |
| R13 | `src/provider/codex/login_child.rs:875-913`; `commands/codex/login.rs:136-151,393-402` | Before/after listings and file-mode override; override explicitly is not a guarantee. |
| R14 | `src/commands/codex/doctor.rs:200-222`; `provider/codex/home.rs:399-439` | macOS listing probe; auto+Unknown currently permits file fallback. |
| R15 | `src/commands/doctor.rs:207-210,1209-1212`; `schemas/doctor.v1.json:4-19` | Named keychain text rows; macOS managed path; JSON schema covers isolation only. |
| R16 | `src/secret/security_cli_tests.rs:396-433` | Four security argv shapes asserted across the whole current transport. |
| R17 | `scripts/phase3-structural.sh:7-24,56-100,137-165` | Working-tree snapshot, positive control, exact planted diagnostic location. |
| R18 | `scripts/release-gate.sh:148-196`; `.claude/skills/check/SKILL.md:62-103` | Testing seams absent, four production names present; synchronize seam inventories. |
| R19 | `.github/workflows/ci.yaml:15-90`; `README.md:29,38` | Concurrent CI has both OSes and an unconditional brew prerequisite; README says macOS only. |

R19 describes another session's uncommitted work. Coordinate with its owner; do not overwrite that work or
assume its final layout. Pre-existing changes in README, beads, fmt hooks, and `.github/` are not this task's edits.
R1–R18 are planning anchors, not permission to change unrelated callers or existing behavioral contracts.
S1's matched evidence is `docs/re-verify.md §7.1–§7.4`: Linux Claude 2.1.282 and scratch Codex
0.157.0-alpha.10, not the host's ordinary Claude 2.1.220 launcher. §7.1 supplies the exact binary
paths/digests and Linux extraction ranges. §7.2 U3 supersedes R8's unsuffixed storage-lock assumption;
§7.2 U2 supersedes any unconditional vendor atomicity/durability claim. No concurrent agctl/peer
storage exclusion or live exceptional fallback was measured; the approved OAuth checkpoint is complete.

### 1.2 Vendor evidence: cite the exact artifact, not a platform inference

`C` anchors below mean `cli.unpack.js` from Claude Code reverse-source commit `ac66a5f` (2.1.282),
a **macOS bundle**. Read it with `git show ac66a5f:cli.unpack.js`; it is not a verified Linux binary.
`X` anchors mean Codex source commit `2170d8b3c77883dbe743078fb8bbb017f27caa9c` in the local upstream checkout.
That source pin is not evidence of the version installed on the Linux host.

| Ref | Pinned anchor | What it establishes, and its limit |
|---|---|---|
| C1 | `:12364-12382,116768-116774` | MacOS source precedence/NFC; independent Linux result is §7.2 U2, not this artifact. |
| C2 | `:118113-118119,843344-843349` | Legacy and V5 path constructors name `.credentials.json`. |
| C3 | `:117769-117848,118469-118475` | Composed reader/update and `Ns(On, Dr)` factory; not proof Linux selects plaintext. |
| C4 | `:117707-117766,162500-162573` | Storage lock, primary then canonical legacy refresh locks; §7.2 U3 independently confirms Linux invocation and the suffixed storage name. |
| C5 | `:47994,47998` | Source has macOS managed root and default `/etc/claude-code`; corrected pinned anchors. |
| C6 | `:132070-132115,162551` | Optional refresh-lock owner sidecar exists; do not equate metadata with a fourth lock. |
| C7 | `:118173-118194,843545-843564` | Legacy/V5 request 0600; §7.2 U2/§7.4 distinguish Linux normal rename observations from exceptional in-place/no-fsync behavior. |
| X1 | `codex-rs/login/src/auth/storage.rs:206-222,431-448,511-527` | File writer; auto tries keyring first; file factory is a distinct backend. |
| X2 | `codex-rs/keyring-store/Cargo.toml:14-15` | This Codex source enables `linux-native-async-persistent` on Linux. |
| X3 | `codex-rs/core/src/config/auth_keyring.rs:58-78` | Requirements can override the configured credential-store mode. |

Historical D-020 in `.omc/handoffs/p2-deviations.md:8` concerns a stubbed V5 factory in **2.1.266**.
It proves neither the current Linux factory nor that Linux has no keyring. Recheck F35/F40/F45–F58,
not only the old factory symbol. `docs/re-verify.md:81-121,254-277,384-404,504-532` supplies checklists,
not a substitute for matched Linux evidence. Do not transfer old version measurements into new fact rows.

## 2. Objectives and guardrails

### Must have

- Native Linux/amd64 build, tests and release certification on the named Debian host and Ubuntu CI.
- Preserve macOS behavior, process signatures, CLI contract, schemas, snapshots, test inventory and results.
  D-066 recommends a separately approved storage-name bug fix before Phase 2; this Linux plan grants no
  macOS behavior/text/fixture carve-out. Phase 2 compares against that dependency's approved baseline.
- Linux process classification and stable start identity without reading command lines or other processes' env.
- Linux file-only Claude live/owned behavior after evidence approval; the same lock and audit discipline.
- D-024 displaced-credential parking and undo without deleting the Linux active file.
- Deliberate discovery/import limits; no fabricated path from a service hash or absent keyring evidence.
- Linux Codex login returns named unsupported before spawn (D-064); Claude support and proven file-backed
  Codex status/import/doctor proceed. No proof-backed Linux login branch is enabled by this plan.
- Correct platform managed-settings path, explicit unsupported cases, and documentation at delivery only.
- Fail closed on unknown backend, unsafe path, incomplete process evidence, or unsupported effective store mode.

### Must not have

- Windows support, other-Unix support claims, or Linux Secret Service/keyring integration.
- Changing macOS behavior to make Linux easier, or keychain fallback on macOS after a failed read.
- Runtime platform selection via PATH or an operator-visible backend environment variable.
- Credential reads from the operator's live homes in tests or the planning lane; raw secrets in reports/logs.
- Arbitrary-path write constructors, weakened lock reclamation, new credential exposure sites, or schema drift.
- Linux Remote Control foreground-TTY/restart support: the RC flag remains macOS-only. The proc facade leaves
  a future Linux `tty_foreground` implementation site, but does not read stat tty_nr/tpgid fields 7/8 here.
- New Cargo platform features, broad unrelated refactors, fake completion by skipped tests, or benchmark claims.

The existing epic mentions other Unix targets, but this plan deliberately delivers Linux and macOS only.
Unimplemented targets must receive an explicit unsupported-target boundary, not Linux procfs assumptions.

## 3. RALPLAN-DR decision summary

### 3.1 Principles

1. **P6 — Evidence before behavior:** no Claude Code/Codex claim without a citation; unknowns block their consumer.
2. **Platform isolation:** compile only the selected production transport; preserve shared command contracts.
3. **Authority before mutation:** retain WriteTarget, anchored descriptors, three locks, audit and refusal semantics.
4. **Compatibility before convenience:** macOS output and existing tests remain the regression baseline.
5. **Observable proof:** negative evidence must be genuinely measured; failure or invisibility is not absence.

### 3.2 Decision drivers

1. Correct live-store mutation and recovery under concurrent peer activity.
2. Deterministic Linux behavior without weakening the existing macOS guarantees.
3. Small reviewable change surface and repeatable two-platform gate execution.

### 3.3 Options and bounded tradeoffs

| Option | Advantage | Cost / defect | Disposition |
|---|---|---|---|
| A: split target-selected modules behind current boundaries | Deterministic, all-features-safe artifact; isolated OS implementations simplify containment review | More source movement and two backend test matrices | Choose |
| B: probe for `security` on PATH at runtime | Little initial wiring; easy prototype | PATH changes semantics; an installed shim is not a platform contract; Apple FFI remains | Invalidate |
| C: Cargo platform features | Convenient opt-in experiments | Wrong combinations compile; `--all-features` conflicts; operators can select an invalid transport | Invalidate |
| D: target cfg inside the existing boundary files | Deterministic and all-features-safe with less source movement | Mixed-platform code makes containment review and grep allowlists harder | Viable; not chosen |

A and D are both viable: target cfg makes selection deterministic and compatible with the existing
all-features gate in either layout. Prefer A for isolation and reviewability, not because D is impossible.
C's mutually exclusive platform features conflict with that gate. B cannot prove the peer store model and
cannot cure the proc compile failures. B/C do not become fallbacks if S1 disproves file-only Claude.

**D-057 — Choose A over viable D.** Split target-selected implementations at existing boundaries for
isolation and reviewability, not a generic backend framework or platform feature.
The existing KeychainReader remains read-only. Call sites select a verified store capability rather than
interpreting a missing keychain executable as file-store authorization.

## 4. Architecture and compatibility contract

### 4.1 Process facade and platform modules

Keep `runtime::proc::{exists, holder, start_time, start_timestamp, self_start_time, claude_processes}`
and `Holder` / `ProcError` signatures unchanged (R1). Move Apple implementation details behind a macOS
module and put procfs access behind a Linux module; shared classification rules stay testable without an OS.
Do not introduce a process-wide cache of peer liveness, process names, or sweep results.

**D-058 — Linux process contract.** Use procfs-core 0.18 with defaults disabled behind an agctl-owned
bounded, validated input adapter; the contract is agctl's, not a guarantee supplied by the crate:

- Enumerate numeric PID directories from procfs; bound every file read and reject malformed/truncated content.
- Validate UTF-8, delimiter ordering and the state envelope before calling procfs-core; its unbounded reads,
  lossy UTF-8 and unchecked malformed-envelope slices cannot be exposed to arbitrary input (U7).
- Parse `/proc/<pid>/stat` after the **last `)`**, not whitespace-splitting the parenthesized comm field.
- Classify `T` and `t` as Stopped, `Z` and `X` as Dead, and other recognized Linux states as Alive;
  malformed/unsupported state bytes are parse errors, never Dead or recovery evidence.
- Keep exact `claude` in `/proc/<pid>/comm` (15-byte name capacity) and the **real UID**, the first `Uid:`
  column in `/proc/<pid>/status`. `docs/re-verify.md §7.2 U4` measured the same inode launched as `claude`
  versus `2.1.282`: comm follows the launch path's basename. The installer's `~/.local/bin/claude`
  symlink matches; a direct version-path launch, including a stopped one, is invisible to this matcher.
  This retains F57's macOS exact-name limitation, not full peer discovery. Any launcher exposing a non-`claude`
  basename (version path, node/npm wrapper or another launcher) is outside this matcher; the wrapper examples
  are contract residuals, not additional measured vendor runs. Linux comm is self-settable (`PR_SET_NAME`);
  U4's repeated matched-binary observations showed no name change, not a proof it is immutable. No inference
  from argv, exe, symlinks, substrings, casing or process environment is authorized. Linux doctor/refusal
  text says `no stopped peer visible by exact name`, never `no peer` or a complete-view claim.
- Retain `kill(pid, 0)` via rustix for `exists`: success/EPERM mean existing, ESRCH means absent **in the
  caller's PID namespace** (R1:103-111). hidepid does not affect kill-zero. Proc-directory absence is not a
  substitute; unexpected probe errors must not license mutation. Preserve the bool facade and use D-067's
  internal error-preserving probe for own-record recovery evidence.
- Derive start ticks from stat field 22; use positive `_SC_CLK_TCK` and `/proc/stat` btime for timestamps.
  Use checked conversion/addition/multiplication, not debug assertions or wrapping arithmetic.
- `start_time` is the versioned Linux boot/namespace/tick identity specified in D-067, not a wall timestamp.
  Boot differences distinguish generations only after domain validation; they never by themselves license
  recovery. `start_timestamp` remains wall time for presentation, not the identity used to prove PID reuse.
  Residual: the same PID reused within one tick of the same boot is indistinguishable using these fields.
  Tick duration is `1/CLK_TCK`; U4 measured CLK_TCK=100 on the host, not microsecond precision.
- If boot/namespace identity or required stat data cannot be read, return unknown rather than a weak fake value.
  Validate D-067's record format/domain before comparing strings or using namespace-local ESRCH.
- Detect PID reuse across multi-file reads, using consistent start identity before/after classification;
  a raced observation cannot certify absence. Disappeared processes and refused reads are distinct outcomes.
- Preserve R1's positive stopped evidence, `exists` EPERM behavior, and incomplete-sweep errors.
  An unreadable but signalable process is unclassified; failed classification of an existing PID is Alive.
- Keep namespace scope distinct from hidepid: hidepid=1/2 restricts other users' processes; a same-real-UID
  sweep on ordinary procfs can cover that UID in the same PID namespace. It cannot prove that every peer
  sharing a bind-mounted store belongs to that namespace. U4's **nested namespace plus hidepid** view
  listed 3/496 PIDs despite self/PID1 equality and one-column NSpid; it did not certify cross-UID hidepid
  behavior or prove that hidepid alone hid same-UID peers. No measured evidence certifies complete visibility
  of store-sharing peers. D-067 selects no Linux peer-lock breaking: positive stopped evidence refuses;
  a negative sweep is `Unreadable`, not `NoStoppedClaude` or mtime-only `None`, even on a no-hidepid mount.

**Linux consumer guard (AC184/AC186).** In `ProcHolders::stopped_claude_present`, the Linux arm maps any
sweep `Err`, incomplete sweep or negative sweep without proved visibility to `HolderEvidence3::Unreadable`,
including a successful enumeration finding no exact-name stopped peer. It never emits the legacy
`HolderEvidence3::None` continuation or a recovery-authorizing `NoStoppedClaude`. Define `Unreadable` in the shared
`src/secret/audit.rs::HolderEvidence` enum (re-exported by `claude_lock.rs` as `HolderEvidence3`) on both
platforms; only the Linux backend produces it. Select the error mapping through `secret/backend.rs` so
§7.2's cfg allowlist remains unchanged. The macOS arm continues mapping sweep `Err` to `None`.
D-061 must consume `Unreadable` as `Reason::HolderUnreadable` and refuse mutation and stale-lock removal
before any `rmdir` or credential write; backend reporting alone does not satisfy this guard. Positive stopped
evidence also remains a refusal. Do not alter macOS sweep, break-rule behavior or existing test bodies.

The lead's v1.1 analyst pass supplied the edge-case checklist; S1's host observations and dependency
review are recorded in §7.2 U4/U7. No precision or visibility guarantee is inferred beyond those results.

**D-067 — Separate own-writer identity from peer-lock reclamation.** Keep the record's optional string
fields and process facade signatures. New identity spelling is
`linux-v1:<boot-uuid>:<pidns-dev>:<pidns-ino>:<start-ticks>:<real-uid>`, with canonical lowercase boot UUID,
checked unsigned decimal fields and no extras; PID stays in `agctl_pid` / `pid`. Namespace identity comes
from the proc namespace handle. Missing data yields `None`; this is agctl's format, not the owner sidecar.

For **agctl-own records**, validate version/domain/syntax and equality with the current boot, PID namespace
and real UID **before** probing holder or interpreting ESRCH/mismatch. Old RFC3339/ctime, missing fields,
unknown versions/domains, malformed data, changed boots/UIDs and incomparable namespaces remain unknown;
no read migration. Only a valid same-domain record plus `kill(pid, 0)` yielding ESRCH may make Linux
`writer_is_gone` true. Success, EPERM, other errors, zombie classification, or a readable start-tick mismatch
are not that proof. Use an internal error-preserving probe behind the existing facade/backend, not `Holder::Dead`
(which merges zombies) or an unchecked bool result. This licenses own-writer-gone diagnosis/record recovery
evidence, not deletion of a peer directory. Both doctors must label incompatible identity unknown, never
`dead (pid recycled)` solely on string inequality; macOS spelling, parsing and diagnostics stay unchanged.
SF1 (critic, applied by the lead): the Codex doctor represents an unknown/incompatible holder with the existing
`namespace.lock = null` plus an explicit `namespace.notes` unknown-holder message (`schemas/codex-doctor.v1.json:284-295,306`,
`src/render/codex_doctor.rs:425-437`); no new enum value, no schema or macOS change.

For **peer-lock breaking**, select **never on Linux**. The sweep cannot prove that every peer sharing the
store is in the recording PID namespace. Even valid own-record ESRCH does not authorize removal of a
currently present Claude lock: `HeldLockRecord::attests` at `held_locks.rs:129-131` attests path strings,
not the directory's current inode or a later peer's ownership. Old/foreign records map to
`Unreadable` / `HolderUnreadable`; valid own-writer-dead records may be reported as such, but this does not
bypass the independent peer-lock removal capability. Do not delete/rewrite a record on read or add an
automatic record-cleanup operation. Fresh uncontended acquisition, this invocation's owned lock release,
and normal kernel-flock namespace acquisition remain allowed.

`doctor --remove-stale` on Linux always returns exit 1 with
`stale lock removal unsupported on this platform: peer visibility is unproved`, including `--yes`,
namespace-root and held-record-attested paths. Its independent path at `commands/doctor.rs:959-1080` must
refuse before sampling, prompting, `Permit::Attested` authorization or removal. Held-record reporting
must separate writer-gone evidence from removability and never offer usable Linux removal commands.
No manual deletion workaround or force flag. S2/AC185–AC186 prove both mechanisms and all consumers.
Reopening peer removal requires a later reviewed visibility/ownership authority, not self/PID1 namespace
heuristics or an assumption that a remembered path is still the old lock.

`docs/re-verify.md §7.2 U7` settles the dependency: `procfs-core = { version = "0.18", default-features = false }`
(MIT OR Apache-2.0; source/MSRV/maintenance checked there). S2 may add that Linux-target dependency;
reuse existing rustix for kill-zero. Keep filesystem error fidelity in the adapter; add truncation,
UTF-8, delimiter, numeric overflow and panic-proof envelope cases. Full procfs adds APIs/dependencies
without solving bounds/visibility; a handwritten stat parser is unjustified while this adapter fits.
If the adapter cannot meet D-058, stop for review rather than silently broaden dependencies or hand-roll.

### 4.2 Credential selection and authority

**D-059 — File-only capability, not disabled-keychain emulation.** Keep macOS's current store table (R5).
For Linux, use an explicit target-selected file path for each authorized kind:

| Kind | Linux read rule | Linux mutation rule |
|---|---|---|
| Live | Verified effective store directory plus `.credentials.json` | Only an approved live WriteTarget under the three-lock protocol |
| Owned | Registry-derived namespace `.credentials.json` | Existing namespace ownership/locks; swap path follows S4 |
| ConfigDirReadOnly | Explicit, valid recorded directory only | Never mutate, refresh, adopt in place, or derive a write namespace |
| Foreign / unknown path | Report unsupported/absent evidence honestly | No credential reads or writes |

An empty ConfigDirReadOnly path is not cwd, live home, or a decoded service hash. Keychain-only imported
records remain non-readable on Linux until an explicit supported import supplies a real path (R11).
Reading a record never grants write authority. Existing registry fields and schemas remain compatible.

**I10 on the actual Linux file route (AC190/AC192/AC193/AC201).** For the authorized Live, Owned and
ConfigDirReadOnly paths through `location::resolve` / its Linux file adapter, ENOENT alone maps to
`Resolved::Absent`. EACCES/EPERM, I/O errors, malformed or torn content, and unsafe paths (symlink,
wrong owner/mode, or EXDEV) map to `Resolved::Transient` or a pre-mutation refusal, never `Absent`.
None of these failures triggers another store, adopted-copy or keychain fallback, and none proves that a
target is writable. Keep macOS's existing kind/source table and outcome mapping unchanged (R5).
Add `linux_file_read_outcomes` unit fixtures and `linux_file_read_outcomes_e2e` covering every case
against the actual Linux file route, not a disabled/fake KeychainReader; assert no fallback, no mutation
and the expected Absent-versus-Transient/refusal classification. An EXDEV at the write boundary refuses
without copy-delete; it must not be converted into a missing-file or writable-target result.

**D-068 — Refuse ambiguous Linux live paths for reads as well as writes.** U2 establishes vendor
precedence: defined `CLAUDE_SECURESTORAGE_CONFIG_DIR` wins (empty means `HOME/.claude`); otherwise
`CLAUDE_CONFIG_DIR` is used (empty means cwd); selected strings are NFC-normalized, without realpath.
The existing `namespace::live_store_dir` empty-config-to-home mapping stays macOS-compatible. Linux's
capability adapter must check captured variable presence/value **before** calling that legacy helper:

- If secure-storage is absent and config is explicitly empty, or the selected nonempty path is relative,
  refuse live reads and mutation as ambiguous (Transient/refusal, not Absent); open neither cwd nor home.
  Do not silently choose the peer's cwd or agctl's old home interpretation.
- With secure-storage defined empty, the selected store is `HOME/.claude` even if config is empty/relative;
  a valid absolute HOME and the ordinary no-follow/owner/mode checks are still required. With both variables
  absent, the same home rule applies. An absolute selected config path is eligible for bounded reads and
  the existing live-authority checks; NFC normalization does not authorize symlink traversal.
- A nonempty secure-storage override is eligible only for an authorized, absolute read location under
  D-059; **all** nonempty overrides still refuse live mutation, including on another filesystem.
  ConfigDirReadOnly import likewise requires an explicit nonempty absolute path; no cwd/home/hash inference.

This deliberately narrows Linux reads instead of reproducing vendor cwd reads; users can supply an
explicit absolute config path. Read/status and mutation refusal reason is exactly
`ambiguous config dir: use an absolute path` (one line), never `Absent`, `empty store` or a home fallback. Vendor empty-config→cwd
is platform-independent; macOS's deliberate R10 home mapping remains divergent and unchanged.
This does not broaden WriteTarget::live. AC190/AC192 cover the precedence matrix, exact redacted reason
and no-open/no-fallback assertions, including ignored lower-precedence config values. Evidence:
`docs/re-verify.md §7.2 U2`.

**D-060 — One write authority, different transports.** Preserve private WriteTarget construction from
EnvView or OwnedSha8 (R6). Factor its authority away from macOS stdin encoding; retain the current module
as a facade if that minimizes callers. macOS uses its unchanged transport; Linux uses a file transport.
`SecurityCli`, `/usr/bin/security`, argv construction and keychain stdin command generation are compiled
only in the macOS production module(s). Linux must not create a KeychainStdinLine or apply its 4032-byte limit.
Keep the existing credential JSON/read bounds and use the existing credential serialization boundary.

The Linux file transport consumes WriteTarget and an anchored store-directory capability tied to the hold.
It must not accept an arbitrary root/dir pair from commands. `file_store::write_credentials` currently only
accepts owned namespace writes (R7); do not widen that public function to allow arbitrary live directories.
Reuse SecretFile's atomic primitive through a bounded live adapter and the existing no-follow anchor (R8).
The capability must bind target, opened directory, tree and acquired locks; a mismatched target is refused.

File update contract: exclusive 0600 same-directory temporary, bounded serialization, file fsync, rename,
directory fsync/outcome handling; preserve the current inode/path checks and report post-rename uncertainty.
Every active/adopted installation or undo rename is within its destination directory and filesystem.
An EXDEV outcome refuses; never fall back to copy-then-delete. Nonempty secure-storage overrides, including
ones on another filesystem, remain refused before mutation. **Vendor writes are not unconditionally atomic
or durable:** `docs/re-verify.md §7.2 U2` establishes the platform-independent in-place fallback on rename
EXDEV/EPERM/EEXIST/EBUSY (open `O_WRONLY|O_CREAT|O_NOFOLLOW`, truncate(0), write, chmod), and no
credential `flush:true` or directory fsync. Same-directory EXDEV is not reachable; EBUSY on a mount-point
target was measured in a controlled kernel test; directory-target errors and sticky/LSM/FUSE cases retain
U2's stated limits, not a live-vendor measurement. Normal real login/refresh used exclusive 0600 temps,
rename and final chmod inside `.storage-write.lock`, with no fsync/fdatasync in the publication intervals.
Login published 2 bytes then 524 bytes in separate lock intervals; neither the first file's contents nor
an all-or-nothing login transaction is established by that observation.

**Torn-read protections apply whenever a read can overlap the vendor's in-place fallback; a normal
rename trace does not remove that obligation.** AC190 models same-inode truncate-to-zero/partial JSON,
then completion: **zero bytes is Transient, never Absent or “empty store.”** A syntactically valid object
without the credential key is also **Transient** on this Linux route, even while the reader holds the
correct storage mutex: a multi-publication login may expose a valid intermediate state between its two
lock intervals. ENOENT alone remains Absent. The keyless-object fixture (for example `{}`) is a conservative
contract case, **not** an assertion about the measured 2-byte publication, whose contents §7 did not inspect.

These actual-route synthetic fixtures do not claim S1 forced a live fallback. With agctl's existing wrong
lock name, even an “under-lock” reread could overlap the vendor's torn in-place write. With the corrected
shared name and AC217-proven mutual exclusion, a reader holding it cannot overlap one protected peer
publication, but it can run **between** two publications. Refuse a keyless intermediate before any swap;
if a peer publication races a transaction and the post-write reread/digest differs, report **undetermined**,
never success. Add a deterministic two-publication interleaving fixture to AC195; a digest check is only
an observation at that boundary, not a guarantee against a future write after return. No claim of one
atomic login transaction. Preserve under-lock reread/drift checks and no fallback/mutation on Transient.
AC193 keeps agctl's stricter
O_EXCL 0600 temp + file fsync + rename + directory-fsync/outcome contract and EXDEV refusal unchanged;
agctl never adopts the vendor's in-place/no-fsync behavior. A live exceptional fallback remains unmeasured
and is not a release prerequisite: S4's synthetic same-inode/failure cases settle agctl behavior. Any future
real-vendor fallback claim needs a separately approved isolated checkpoint, not reuse of §7.4's normal trace.
No pending/adopted credential file is added beside a live home without separately reviewed write authority.
A pre-rename cancellation leaves the original unchanged; post-rename verification and audit determine outcome.
If rotated material requires preservation, retain existing owned pending semantics rather than discard it.

### 4.3 Locks, parking, audit and undo

**D-061 — Preserve the transaction, correct the actual peer mutex.** Linux swap/undo acquires primary
`<store>/.oauth_refresh.lock` → canonical legacy `<realpath(store)>.lock` →
`<store>/.storage-write.lock`, never the unsuffixed base name. `docs/re-verify.md §7.2 U3` measures that
sequence on real refresh and `.storage-write.lock` across both login publications and logout. The
source establishes storage stale=15000 ms, derived update=7500 ms and unchanged refresh timing; the
checkpoint did not measure a periodic heartbeat. Retain the existing hold budget and nonblocking
storage acquisition rather than importing the vendor's retry ladder.
Use the same stopped-peer checks, heartbeat/drift checks, under-lock reread, digest checks,
post-write verification and audit outcomes. Release every acquired lock on success, refusal, cancellation
and failure, but never remove a pre-existing peer lock on unreadable Linux evidence.
If evidence requires different timing, return the measured change to review; do not tune constants to pass tests.

The owner sidecar is metadata, not a fourth lock or a recovery authorization: U3 measured the 235-byte,
0600 `.oauth_refresh.lock.owner` created after primary/legacy acquisition, retained through publication,
then removed before legacy/primary release. The three lock directories were 0700 under umask 077.
These modes are umask-conditioned observations, not a vendor unconditional-0700 rule; the credential
directory was precreated 0700. Its owner-file contents were not read; schema facts remain matched-source
facts. agctl neither impersonates that sidecar nor uses it to bypass D-067's refusal.

**D-066 — Separate storage-name correction before Phase 2 (recommendation; user decision required).**
This is not Linux-only: U3 cites the same proper-lockfile `.lock` suffix in macOS ac66a5f, 2.1.263 and
2.1.266. R8's `STORAGE_WRITE_LOCK = ".storage-write"` at `foreign_activity.rs:33` feeds acquisition at
`claude_lock.rs:1205-1206`, activity checks and doctor. The existing third lock never excluded the
vendor's storage mutex on macOS either; successful old fixtures cannot prove that exclusion.

| Scope option | Benefit | Cost / disposition |
|---|---|---|
| Separate platform-independent bug fix, landed and verified before S4 | Keeps the approved Linux/macOS compatibility boundary reviewable; fixes existing users independently | Requires user authorization and an explicit dependency baseline; **recommend** |
| Include the correction in S4 with a macOS guardrail carve-out | One delivery and shared constant change | Widens approved macOS behavior, doctor text and fixture scope; not authorized by this amendment |

No correction, extra bead or carve-out is authorized here. If the user declines the separate dependency,
Phase 1 may complete but Phase 2 stays NO-GO; inclusion instead requires an explicit reviewed scope
amendment. The correction's scope covers the shared name and `claude_lock.rs` module docs/acquisition, foreign-activity
peer evidence at `foreign_activity.rs:105`, doctor's name recognition/text at `doctor.rs:24,745,983,1197`,
`README.md:290,754`, F47/F58 in `docs/re-verify.md §5.1`, and U3's inventoried unit/integration spellings.
F58's “mutate, not update” rationale assumed storage exclusion that the unsuffixed agctl mutex did not
provide on macOS; correcting a comment alone cannot restore that guarantee. Doctor must retain recognition
of a leftover `.storage-write` as a **legacy agctl artefact, never a peer mutex**, and recognize the suffixed
name as the real peer mutex. Do not silently delete/migrate old directories or count them as peer-activity
exclusion; Linux removal still obeys D-067. No per-platform re-spelling of the shared constant is allowed
in S4. The separate fix defines any additional legacy cleanup policy rather than adding one here.
It may correct these names/expectations, not weaken the protocol or erase macOS cases. Existing snapshot/
schema bytes stay frozen; any required change there needs separate approval.

Before S4, the lead records the separately approved fix's exact landing revision, bounded diff and
macOS gate/exclusion evidence. Phase 1 retains b09c92a's macOS behavior; Phase 2's compatibility comparison
uses the approved dependency baseline for only those named corrections (AC188/AC211), not an unrestricted
new baseline. All other behavior and snapshot/schema hashes still compare to b09c92a. No Linux support
claim may precede this dependency and AC217.

**AC217 concurrent witness:** none was run in S1. The separate fix supplies macOS
`storage_mutex_peer_exclusion` with a matched real peer/isolated synthetic store; S4 supplies Debian
fixture coverage **and a separately user-approved Linux operator checkpoint**: a fresh throwaway login,
approved expiry edit/forced real refresh while agctl holds the corrected storage mutex, then logout and
scratch cleanup. The previous S1 operator procedure is complete and grants no authorization for this new
checkpoint. The worker handles credential-path operations; the lead receives only redacted timing/path/
outcome facts. No ordinary live home or credential is used. A fake peer implementing proper-lockfile
semantics proves agctl behavior only, not the vendor's exclusion.

Exercise both holder directions and isolate the third mutex: an agctl storage-only **test hold** must use
the same production mutex primitive with primary/legacy locks absent, so a forced refresh actually reaches
storage contention. The production transaction still takes all three. For the reverse direction, observe
agctl reaching the peer-held storage mutex, not merely contending on refresh locks. Trace actual contention,
exact `.storage-write.lock`, no overlapping protected publication/mutation, and clean release; instrumented
synchronization must respect the production hold budget and not create an unbounded pause.

U3's source profile is 10 retries with min/max 100/1000 ms and stale=15000 ms; agctl HOLD_BUDGET is
3000 ms (`claude_lock.rs:179`). A within-budget hold is below the peer's stale threshold: do not extend it
to provoke a break or require `onCompromised`/failure as the only passing outcome. Retry then success after
release is valid; exhaustion/refusal also passes if no protected overlap occurs. Report the observed branch,
not an inferred one. Corrected fixtures must pass and the wrong unsuffixed-name control must expose missing
exclusion. Debian/Ubuntu gate-3 fixtures do not replace either real-host witness or the Linux forced-refresh
checkpoint. If deterministic contention cannot be observed or the user declines the checkpoint, Phase 2
remains NO-GO for delivery; do not substitute the S1 normal refresh trace.

**Unreadable-holder stop (AC184/AC186).** Add `HolderUnreadable` to the shared
`src/secret/audit.rs::BreakReason` enum (the `claude_lock.rs::Reason` alias), alongside the shared
`HolderEvidence3::Unreadable` from D-058; both variants compile on macOS and Linux, but only Linux produces
this evidence. In `resolve_stale_with`, abandon with `Reason::HolderUnreadable` as soon as the holder check
returns `Unreadable`, before the sampling/removal continuation and any `rmdir` or credential write.
Propagate that abandoned result as a held-lock refusal through acquisition and doctor using their existing
redacted refusal layout; do not retry it into an mtime-only break or treat it as a writable target.
A Linux sweep error, incomplete proc evidence or unproved visibility cannot enter the legacy
`HolderEvidence3::None` continuation. MacOS keeps `None` and its existing mtime-only behavior unchanged.

Add Linux fixture `unknown_evidence_keeps_stale_lock`: inject a sweep `Err` through the Linux
`ProcHolders` mapping with old, unchanged A/B/C mtimes available, then assert `Unreadable`,
`Decision::Abandoned(Reason::HolderUnreadable)`, intact lock directory, zero `rmdir` calls and zero writes
in the fixture's mutation recorder. B/C need not be sampled after the early refusal. Include incomplete-sweep and
unproved-visibility cases with the same assertions; the refusal reason contains no secret. Under D-067,
even a successful negative exact-name sweep is unproved visibility. Propagate `HolderUnreadable` as a
terminal refusal from `resolve_stale` through acquisition; its existing `Abandoned(_)` continuation must
not drop into a retry or mtime-only break that removes the directory. Add `linux_doctor_stale_refuses`
for the separate doctor remove path, with `--yes`, in-root and held-record-attested inputs, zero sampling/
`rmdir`/mutation and no usable stale-removal hint. Also prove fresh acquisition and own-lock release still
work; kernel-flock namespace lock acquisition remains distinct from Claude stale-directory reclamation.
Keep `unavailable_evidence_continues_on_modification_times_alone` at
`src/secret/claude_lock_tests.rs:1318-1331` byte-identical and passing on macOS (`None` → `Broken`);
its unchanged source and result are the macOS regression witness, not a test rewritten for Linux.

D-024 remains: namespace displacement parks in its owned adopted sibling; live displacement parks in the
old identity's owned namespace, not beside the live file (R12:3387-3434). Confirmed application commits
staged adoption; failed/undetermined application must not be reported as safely adopted.
This is per-file atomic installation, not one atomic rename from live home into an owned namespace:
R12 places those files in different directories. Preserve the staged multi-file recovery protocol rather
than claiming the entire swap/parking transaction is atomic across both directories.
Undo validates identity, digests and current ownership; forward then undo restores the appropriate active
and adopted copies without losing a peer-refreshed credential. Keep identical-copy/refusal-F semantics.

The `shadowing_store` removal at `commands/use.rs:2534-2590` is macOS migration behavior.
It must be unreachable for Linux file targets: otherwise a successful Linux swap deletes its active file.
Likewise, Linux adopted credentials must not be selected on a false MigratedToKeychain state (R5/R8).
Audit uses the existing redacted store/operation/outcome vocabulary; no token, blob or secret is logged.
If the schema cannot truthfully express file-target outcomes without alteration, stop for review (AC211).

### 4.4 Discovery, foreign activity, import and doctors

On Linux, synthesize live rows from the verified file and registered owned rows from their namespaces (R9).
Support explicit valid ConfigDirReadOnly imports, but no keychain-service hash enumeration or home scanning.
Do not fabricate Unlocked/NoItem from the absence of a Linux KeychainReader. Normal Linux status must not
say its keychain is locked/unavailable or recommend macOS `security` repair commands.
Retain macOS row source, ordering, notes, folds and errors byte-for-byte; use existing file source on Linux.

Retain primary/legacy/`.storage-write.lock` evidence in Linux foreign-activity checks (D-061/D-066).
Omit migration listings only for the verified Linux file capability. Permission/metadata errors remain
uncertainty, not no activity; R8's metadata-error collapse must be handled for the new path without silently
changing macOS behavior. D-068 validates selected paths before discovery/import reads; refused selection
must not create an absent row or invoke a fallback. D-067 also applies to both doctors' identity diagnostics
and Claude doctor's independent remove path, not just the process facade.
Never mutate external config-dir stores or an account whose effective backend cannot be established.

**D-062 — Platform managed settings.** Use `/Library/Application Support/ClaudeCode/managed-settings.json`
on macOS and `/etc/claude-code/managed-settings.json` on Linux (C5/R15). U6's matched source and isolated
open/stat trace confirm the Linux path (`docs/re-verify.md §7.2 U6`); this is no longer a pending premise.
Do not change ordinary per-account config precedence or enable Windows paths as a side effect.
Retain Claude doctor's `keychain` section and its named `preflight`, `live service`, `services listed` rows;
on Linux each says `n/a — not applicable on this platform`, never zero services or a failed preflight (R15).
Choose fixed textual n/a rows, **not a new JSON platform field**. `doctor.v1.json:4-19` describes only the
isolation half, not these keychain rows or a current doctor JSON CLI. Keep that schema byte-identical;
do not invent a JSON n/a enum in a schema which has no such row. Test these rows directly in Linux e2e.

**D-063 — Codex Linux store policy.** No Linux keyring integration, no keyring password reads, and no claim
that Codex has no Linux keyring: X1–X3 contradict that shortcut. Owned agctl file namespaces remain supported.
For live/external homes, file mode is eligible only when effective file selection is established from matched
vendor evidence. `keyring`, `auto`, `ephemeral`, malformed/unknown mode and unresolved policy overrides
are reported as unsupported/uncertain for effective file use; they must not silently use stale `auth.json`.
In the named `credential store` section, report `platform support: unsupported on this platform (file mode only)`
for an unsupported effective mode, rather than missing credentials. Unknown policy gets an explicit uncertain
verdict. JSON retains `store.read = "not read"` and `live.state = "not read"`, which are already permitted
by `schemas/codex-doctor.v1.json:98-100,149-150`; no new enum or platform field. Keep mode values fixed.
Do not repurpose the parse-error-only `config_note` as a platform verdict. Carry any extra text-only reason
outside the serialized schema. MacOS's KeyringProbe behavior and all its render output remain unchanged (R14).

### 4.5 Codex login evidence and testing seam

**D-064 — Select Linux login refusal; preserve macOS evidence.** Keep the macOS before/after listing
proof intact (R13). Linux cannot replace those listings with `Ok(Vec::new())` and call that proof of
“nothing gained.” `docs/re-verify.md §7.2 U5` shows matched Codex 0.157.0-alpha.10 managed `keyring`
requirements defeating the argv file override: exit 1, D-Bus attempted, no `auth.json`. Neither version
matching, an argv override nor a scratch artifact proves file-only execution with no keyring side effects.

Select the named **Linux Codex login unsupported** branch: `codex login` returns
`unsupported on this platform` before spawning any child, with no credential installation or success.
This is the accepted U5/U8 result, not a full-plan stop: Claude-side support and Codex `status` / `import` /
`doctor` over a proven file `auth.json` proceed under their own evidence gates. AC179/AC204/AC205 require
this branch only. Refusal applies even when an environment or argv requests file mode, the fake child
would succeed, or a valid scratch artifact already exists; no fallback or post-spawn refusal is enabled.

Proof-backed Linux login is future reviewed work, not an alternate implementation choice in S5. Therefore
no Linux child/HOME isolation change or file-proof constructor is required in this delivery, and U8's real
browser/CA/proxy checkpoint is inapplicable, not pending or skipped evidence. Reopening would require a
sound effective-store/no-side-effect mechanism despite managed/config changes, scratch HOME as well as
CODEX_HOME/cwd, scrubbed environment, bounded survey and complete child lifecycle proof. R13's inherited
HOME behavior remains unchanged on macOS. Absence of a D-Bus address alone would not prove file-only use.

Keep `AGCTL_KEYCHAIN_BACKEND=none` for **macOS testing builds only**; neither Linux production nor Linux
fixture routing consults it (R4). Its name stays in the release-gate absence list for both artifacts.
The epic's historical spelling `AGENTCTL_KEYCHAIN_BACKEND` is not a new compatibility alias.
Preserve the macOS disabled/fake-reader behavior. Linux uses its real file backend with isolated fixture
roots; do not promote the old seam to a Linux test double or add a production backend selector.
`AGCTL_SECURITY_BIN` must not cause Linux production or Linux platform-path tests to launch security.

## 5. Task flow and detailed steps

Dependencies: S1 → scoped v1.3 ruling/lead GO → S2 → S3 → D-066 approved dependency → S4 → S5 → S6.
S1 evidence is complete; this is its changed-premise return, not authorization to restart probes.
Each step has a local acceptance gate; the full six-command matrix closes each code phase, not every step.

### S1 — Establish matched Linux evidence and settle blocking contracts (Phase 0)

**Evidence complete, scoped ruling pending:** `docs/re-verify.md §7.1–§7.4` is S1's result. The actual
Claude probe was 2.1.282, not the host's 2.1.220 launcher; Codex was the explicit scratch 0.157.0-alpha.10
binary, not an installed PATH command. Retain their exact paths/digests/source pins as evidence. The
approved real Claude login/expiry-edit/refresh/logout checkpoint and scratch cleanup are complete; no
further operator step remains in that procedure. No ordinary live credential paths were probed.

U1–U8 have evidence-backed outcomes in §9. D-064 selects pre-spawn Linux Codex-login refusal; D-067
resolves unproved visibility by no Linux peer-lock reclamation; D-068 refuses ambiguous paths. D-066 proposes
an explicit separate correction prerequisite for Phase 2 rather than changing frozen macOS behavior.
Actual concurrent agctl/peer exclusion remains unmeasured and belongs to AC217, not S1 completion;
live exceptional in-place fallback is also unmeasured and is not substituted by the normal publication trace.
The single scoped critic checks these changed premises; the lead must then record Phase 1 GO under §0.
No additional code or vendor probes belong to this planner return.

- **Source anchors:** C1–C7, X1–X3, R1/R3/R10/R13; `docs/re-verify.md:81-121,254-310,384-404,504-557`.
- **Local gate:** AC177–AC181; each structural unknown is resolved for its enabled consumer or explicitly
  disables that consumer. A failed U5 chooses the accepted login refusal branch; no code edits in this step.
- **Output:** evidence verdict incorporated into this plan/reverification record by the authorized owner.

### S2 — Isolate process backends and implement the Linux contract (Phase 1)

Introduce target-specific proc modules without changing callers' API or macOS behavior. Implement D-058
with `procfs-core = { version = "0.18", default-features = false }` behind the bounded, strictly validated
adapter. Add sibling parser/classifier and real-process tests for malformed UTF-8/stat/state/numeric data,
missing/partial proc views, T/t and Z/X, UID, exact launch-basename matching, checked arithmetic and clocks.
Implement D-067's version/domain/real-UID guard before holder/ESRCH or mismatch-based recovery; never
migrate old records on read. Same boot/namespace/UID plus kill ESRCH alone proves an own writer gone;
it never proves ownership of a currently present lock directory. Linux negative sweeps and peer-lock
removal remain refused, including doctor's
independent `remove_stale` path and out-of-root held-record attestation. Both doctors must diagnose
incomparable identities as unknown, not recycled/dead. Fresh locks, owned release and namespace flock stay
usable. Route these capabilities through the approved backend boundary without new target-cfg sites.
Keep macOS identity/test bodies and R3's legacy behavior unchanged; no storage-name correction in S2.

- **Source anchors:** R1–R3; `secret/claude_lock.rs:787-798`; `commands/doctor.rs` process consumers.
- **Local gate:** AC182–AC186; default/all-features checks pass on both platforms, focused tests green.
- **Output:** unchanged process facade, target-isolated implementation, Linux contract coverage.

### S3 — Restore truthful two-platform tests and CI prerequisites (Phase 1)

Inventory cases with `cargo nextest list --all-features` on macOS before changing test routing.
For a genuinely macOS-only e2e file, prefer a leading `#![cfg(target_os = "macos")]` over wrapper targets;
record the exact changed-file list. Candidate whole-file gates: `tests/e2e_keychain.rs` and `tests/e2e_swap.rs`
(their module contracts require fake security). Mixed files such as `tests/e2e_codex_login.rs` need per-case
routing, not a whole-file skip. Preserve all macOS case identities and results, not literal source-file bytes.
Do not hide shared portable cases: run them on Linux or add equally strong Linux contract cases.
Classify each snapshot test as platform-neutral (run unchanged on both), macOS-only (cfg-gated), or requiring
Linux assertions in a new sibling test file. Use explicit Linux assertions instead of rewriting shared snapshots.
The four-security-argv assertion remains in its current test file and belongs only to macOS transport (R16).

Coordinate the in-progress CI owner, integrate their resulting workflow, and scope package prerequisites
by OS: Ubuntu installs ripgrep with `apt-get`, macOS with brew. Use only `ubuntu-26.04` and `xcode-27`;
verify current action majors before editing. Keep the final required check dependent on both platforms,
with no `continue-on-error` Linux jobs.
Run all six gates on macOS and Debian; run the relevant full matrix on Ubuntu CI before closing Phase 1.
U7 found rustc/cargo 1.98.1 and extracted tools, not a gate-ready checkout. The gate runner installs
cargo-nextest/dev config under tmpfs CARGO_HOME, exposes extracted `rg` on PATH, uses plain cargo with
no `.envrc` or custom flags (§7.1), and prepares the reviewed source as a Git snapshot for planted gates.
Missing tooling/config is an operational setup blocker, not a reason to skip a gate.

- **Source anchors:** R2/R16–R19; `AGENTS.md:28-40,84-117`; `tests/common/mod.rs:783-801`.
- **Local gate:** AC187–AC189 plus Phase 1 six-gate certification; verifier signs off inventory and exclusions.
- **Output:** Linux build/test baseline, justified target-only exclusions, working two-OS CI.

### S4 — Add bounded file-target reads, swap transport and undo (Phase 2)

Enter only after D-066's separately authorized correction is landed with macOS exclusion/gate evidence.
Implement D-059–D-061/D-068 at the credential boundary; preserve all other macOS behavior and tests.
Add bounded Linux live-file authority using the existing anchored primitives, not arbitrary path writes.
Reject ambiguous selected paths before reads or mutation; no cwd/home fallback. Model same-inode vendor
truncate/partial-write and unusable intermediate publications in actual-route synthetic tests, while
retaining agctl's stronger atomic writer. Route Phase A/C reads and verification consistently; do not leave
a keychain reread inside a file transaction. Use the shared corrected mutex (no platform-specific
re-spelling) and prove Linux AC217, including its separately approved forced-refresh operator checkpoint.
Retain three locks, audits, refresh-preservation semantics and D-024 parking. Make shadow-file deletion
macOS-only. Exercise forward/undo, identical copies, drift, concurrent peer refresh and all failure boundaries.

- **Source anchors:** R4–R8/R10–R12; `file_store.rs:544-708`; `secret_file.rs:170-281`; `docs/re-verify.md §7.2 U2/U3`.
- **Local gate:** AC190–AC199 and AC217; Linux integration/real-peer evidence plus macOS swap/undo suites
  against D-066's explicitly bounded dependency baseline.
- **Output:** complete Linux file transaction with no macOS side effects and no live-file cleanup regression.

### S5 — Route discovery, login, import and doctors through platform facts (Phase 2)

Implement explicit file discovery/import limits, source labels, foreign activity and managed settings path.
Apply D-063 to Codex doctor/effective live-store selection without changing owned refresh state machines.
Implement D-064's selected Linux login refusal before spawn, with no Linux file-proof branch.
Preserve macOS listing receipts and private proof construction. Add Linux fixture cases and narrowly
scoped cfg lines without changing macOS case identities/results.
Validate all command success/refusal paths with a fake security sentinel on PATH and a fake codex that
would succeed if invoked; Linux login must invoke neither.

- **Source anchors:** R8–R15; X1–X3; `provider/codex/proof.rs`; `commands/codex/login.rs:370-402`.
- **Local gate:** AC200–AC207; Linux login always refuses before spawn with zero installations;
  proven file-backed Codex status/import/doctor work, and every Linux command records zero security calls.
- **Output:** usable Linux commands with explicit unsupported modes, preserved macOS output and receipts.

### S6 — Harden platform gates, document support and certify release (Phase 2)

Add planted source checks and compile-fail capability checks described in §7. Keep test seams absent from
both default-feature releases, updating release-gate and check-skill inventories together if seams change.
Run the expanded test matrix, unchanged-surface diff checks, and six closing gates on both OSes; Ubuntu CI
must independently pass. Update README and re-verification docs only after this evidence exists.
Have the independent verifier inspect results and source/test inventories; unresolved blockers prevent
release claims. List remaining deliberate limitations and return approval/landing decisions to the lead.

- **Source anchors:** R16–R19; `AGENTS.md:28-40`; `docs/re-verify.md:1-12,285-310,541-557`.
- **Local gate:** AC208–AC217; all Phase 2 ACs and six gates green, release gate last on each OS.
- **Output:** verified support documentation and release evidence, not an automatic merge or push.

## 6. Acceptance criteria

Each criterion requires saved command/test evidence in the implementation review; this table is not evidence.
Named tests/fixtures below are required witnesses to implement, not claims that they already exist or pass.
“Debian host” means `debian-13-trixie.gaudiy-platform`; “ubuntu CI” means `ubuntu-26.04`.
Test witnesses run within the existing phase-end §7.1 gate 3; gate witnesses reuse that phase's six-gate run,
not additional gates. S1 inspection commands check the authorized owner's U1–U8 evidence in
`docs/re-verify.md`, including matched source citations and measured results, not labels without evidence.

| ID | Verifiable acceptance condition | Witness |
|---|---|---|
| AC177 | S1 identifies actual Linux probe versions, explicit scratch binary paths/digests and matched sources, distinct from the host launcher. | Inspect `docs/re-verify.md §7.1`: expect Claude probe 2.1.282 (not installed 2.1.220), Codex 0.157.0-alpha.10 and matched source pins. To repeat on Debian, use the recorded absolute artifact paths for `--version` and `sha256sum`; do not substitute `command -v` or assume Codex/`~/.local/bin` is on SSH PATH. |
| AC178 | Plaintext selection, path precedence, normal publication, exceptional fallback and three locks/owner sidecar have cited verdicts with measured/source-only distinctions. | Inspect `docs/re-verify.md §7.2 U1/U2/U3` and §7.4; expect completed login/refresh/logout/cleanup, umask-conditioned modes, `.storage-write.lock`, no unconditional atomicity/durability claim, and v1.3 D-060/D-061/D-066/D-068 scoped ruling. Concurrent exclusion and live exceptional fallback remain explicitly unmeasured. |
| AC179 | U5/U8 select Linux Codex login's pre-spawn unsupported branch; this does not disable proven file-backed status/import/doctor. | Inspect `docs/re-verify.md §7.2 U5/U8` and D-064; expect managed keyring override evidence and the explicit `unsupported on this platform` decision, no pending Linux login proof or browser checkpoint. |
| AC180 | Procfs/dependency evidence yields D-058/D-067: validated procfs-core adapter, versioned Linux identity and no Linux peer-lock reclamation. | Inspect `docs/re-verify.md §7.2 U4/U7`: expect CLK_TCK 100, hidden 3-of-496 PID view despite namespace heuristics, launch-basename evidence and procfs-core 0.18 selection. Scoped ruling must reject old/unversioned identity recovery and negative-sweep completeness inference. |
| AC181 | Every structural unknown has an explicit scoped ruling for its consumer, while unmet operational/Phase 2 proofs remain gated. | Inspect §0, §9 and U1–U8 evidence: expect critic acceptance of U4 and lead recording of Phase 1 GO before S2; D-064 refusal selected; D-066 user authorization/dependency and AC217 remain Phase 2 prerequisites, not fabricated S1 results. |
| AC182 | Existing process signatures/types and macOS classification behavior are unchanged. | macOS: `proc_tests` baseline cases plus `git diff b09c92a -- src/runtime/proc.rs src/runtime/proc_tests.rs`; expect unchanged facade signatures and macOS case identities/results, only approved backend separation. |
| AC183 | Linux stat parsing validates UTF-8, delimiters/state, spaces/parentheses, truncation, numeric bounds and bounded reads before procfs-core. | Debian host + ubuntu CI: `linux_stat_parser_contract`; expect last-`)` parsing, explicit errors for invalid UTF-8/unsupported state/missing fields/overflow and bounded reads; dependency parser's permissiveness never converts malformed input into evidence. |
| AC184 | T/t, Z/X, UID and exact-name matching remain conservative; every Linux negative sweep is unproved visibility and maps to Unreadable, never legacy None. | Debian host + ubuntu CI: `linux_proc_classification_contract`, `linux_process_lifecycle`, `unknown_evidence_keeps_stale_lock`; include same-inode launches via `claude` symlink versus version basename and a stopped version-path peer. Expect only exact `claude` matched, no argv/exe inference, negative/error/partial sweep Unreadable and terminal HolderUnreadable with zero removals/writes. Assert Linux wording `no stopped peer visible by exact name`, never `no peer`. MacOS proc tests unchanged. |
| AC185 | Linux identity includes version, boot, PID namespace, start ticks and real UID; own-writer liveness is separate from permission to break a peer lock. | Debian host + ubuntu CI: `linux_start_identity_contract`, `linux_record_identity_guard`; missing/RFC3339/ctime/unknown-domain/malformed/different-boot/ns/UID records stay unknown before recovery probes. Only valid same-boot/ns/UID plus kill ESRCH makes writer_is_gone true; success/EPERM/other errors/zombies/tick mismatch remain false. Assert no record rewrite, no peer-removal permit, and truthful unknown diagnostics in both doctors. Repeated identity stable; PID reuse is fixture evidence only. SF1: the Linux Codex-doctor JSON fixture validates against the unchanged `codex-doctor.v1.json` using `namespace.lock = null` + `namespace.notes`. |
| AC186 | Linux peer-lock removal always refuses independently of own-record liveness; fresh own acquisition/release and namespace flock remain usable. | Debian host + ubuntu CI: `unknown_evidence_keeps_stale_lock`, `linux_doctor_stale_refuses`, `linux_record_identity_guard`, `linux_process_lifecycle`; successful negative/error/partial sweeps, old A/B/C mtimes, valid own-writer ESRCH, zombies/reused PIDs and in-root/attested paths with/without --yes. Expect terminal HolderUnreadable; doctor exit 1 and exact D-067 text before sampling/permit/rmdir/write, no usable removal hint, intact directories; valid own-writer-dead report does not authorize deletion. MacOS unchanged None → Broken witness and fresh-lock controls pass. |
| AC187 | Linux default/all-features builds and nextest all-features pass on `debian-13-trixie.gaudiy-platform`. | Debian host: reuse Phase 1 §7.1 gates 2/3/6; expect all-features compilation/tests and default-feature release build to exit 0. |
| AC188 | MacOS inventory/results stay unchanged through Phase 1; Phase 2 permits only separately approved D-066 name corrections, with snapshots/schemas always frozen. | Before/after macOS nextest list/run and Phase 1 gate 3 compare to b09c92a. Before S4, record D-066's approved landing revision/diff/macOS evidence; Phase 2 compares named corrected expectations to that revision and every unrelated surface to b09c92a. Record added correction witnesses separately, never delete baseline cases. Debian/ubuntu gate 3 retains portable coverage. Snapshot/schema diff to b09c92a stays empty. |
| AC189 | Ubuntu/macOS CI jobs pass with OS-correct prerequisites; Phase 1 six gates pass on both measured hosts. | macOS + Debian host: reuse Phase 1 §7.1 gates 1–6, all exit 0; ubuntu CI + `xcode-27` CI: required matrix green, apt-get/brew confined to the proper jobs. |
| AC190 | Linux ENOENT alone is Absent; zero-byte and syntactically valid keyless stores are Transient, including between two separately locked peer publications. | Debian host + ubuntu CI: `linux_file_read_outcomes`, `linux_file_read_outcomes_e2e`; actual-route same-inode zero/partial/completed JSON, explicit keyless-object fixture and two-publication interleaving. Expect zero/keyless/malformed states Transient with no fallback/mutation, valid completed credential readable, and AC195 undetermined on post-write drift. The keyless fixture does not assert contents of S1's uninspected 2-byte publication. Path/error cases and no-open refusals remain covered. |
| AC191 | Live file writes require unforgeable target/hold authority; arbitrary, mismatched or non-owned write paths refuse. | Debian host + ubuntu CI: `linux_file_target_authority`; expect runtime mismatch refusal and unchanged files; reuse Phase 2 §7.1 gate 5 target/hold construction plant, expecting its precise compiler rejection. |
| AC192 | D-068 refuses empty selected config/relative selected path for reads and writes before opening a fallback; secure-storage defined-empty preserves precedence. | Debian host + ubuntu CI: `linux_path_authority_refusals` plus AC190 actual-route tests; matrix secure-storage unset/empty/absolute/relative × config unset/empty/absolute/relative, absolute/invalid HOME and explicit import paths. Expect empty selected config/relative selections refused with zero cwd/home opens and zero fallback; secure-storage empty selects HOME/.claude irrespective of lower config; nonempty secure-storage live writes always refuse. Symlink/nonregular/owner/mode violations remain non-Absent; unchanged files. Assert exact `ambiguous config dir: use an absolute path` reason on reads/status/writes. MacOS env tests unchanged. |
| AC193 | agctl keeps exclusive 0600 same-directory temp + file fsync + rename + directory-fsync outcome handling, never vendor in-place fallback. | Debian host + ubuntu CI: `linux_atomic_file_transport` plus EXDEV cases in AC190 tests; expect atomic installation on success, correct uncertainty for post-rename durability failure, unchanged source/destination and no copy-delete or truncate-in-place on EXDEV. Vendor no-fsync behavior does not weaken agctl's contract. |
| AC194 | Linux swap/undo use the measured three names/order with owned release, not the obsolete unsuffixed storage base. | Debian host + ubuntu CI: `linux_swap_undo_three_locks`; assert primary `<store>/.oauth_refresh.lock` → canonical `<realpath(store)>.lock` → `<store>/.storage-write.lock`, intended active/adopted restoration and no acquired lock left behind. Owner sidecar is not a fourth lock or reclaim authority; AC217 separately proves peer contention. |
| AC195 | Digest drift, two-publication peer races, stopped peers, hold expiry and cancellation never produce false success. | Debian host + ubuntu CI: `linux_transaction_refusal_matrix`; keyless first publication refuses before swap; a peer replacement visible at post-write verification yields undetermined, not success. Correct storage mutex excludes overlap within each publication but not between separately locked login publications; no promise against writes after return. All acquired locks released and injected failures classified accurately. |
| AC196 | D-024 parks live displacement only in the correct owned namespace; failed apply does not commit adoption. | Debian host + ubuntu CI: `linux_displacement_parking`; expect the old identity's owned adopted sibling only, no live-home parked copy and no committed adoption after failed apply. |
| AC197 | Linux never removes its active `.credentials.json` through the macOS shadowing cleanup branch. | Debian host + ubuntu CI: `linux_active_file_survives_swap_and_undo`; expect the active file present with the verified intended credential after both operations. |
| AC198 | Undo/identical-copy/refusal-F cases preserve concurrent refreshes and adopted lineage; no credential silently disappears. | Debian host + ubuntu CI: `linux_undo_lineage_matrix`; macOS: existing swap/undo cases in Phase 2 gate 3; expect preserved peer-refreshed bytes/lineage and unchanged macOS results. |
| AC199 | File-target audit reflects applied/refused/undetermined outcomes and contains no credential material. | Debian host + ubuntu CI: `linux_file_audit_outcomes`; expect the actual result category and redacted fields only; synthetic secret sentinel absent from captured logs. |
| AC200 | Discovery/import enumerate only verified file locations; no service-hash reversal, home scan, file-error fallback or macOS repair suggestion. | Debian host + ubuntu CI: `linux_discovery_import_boundaries` and `linux_file_read_outcomes_e2e`; expect only authorized rows, honest transient/refusal diagnostics and zero fallback/repair-command output. |
| AC201 | Suffixed storage-lock evidence is detected; lock/metadata unreadability remains uncertain activity, never write eligibility. | Debian host + ubuntu CI: `linux_foreign_activity_uncertainty`, `linux_file_read_outcomes_e2e`; populate each real lock name, inject metadata errors and confirm uncertainty/refusal, no absent/writable inference and zero store writes. Obsolete `.storage-write` alone never proves vendor exclusion; D-066 owns its legacy treatment. |
| AC202 | Linux managed path matches evidence and named keychain rows say n/a; macOS output/config precedence and schemas are unchanged. | Debian host + ubuntu CI: `linux_doctor_platform_rows`; expect verified `/etc/claude-code` and all three fixed n/a rows. macOS: existing doctor cases plus AC211 inspection; expect unchanged output/precedence/schema bytes. |
| AC203 | Linux Codex names unsupported modes; JSON says not read, never absent; only established file mode can read auth.json. | Debian host + ubuntu CI: `linux_codex_effective_store_matrix`; expect named unsupported/uncertain verdicts and both JSON not-read values, while proven file mode reads only its auth.json. |
| AC204 | Linux Codex login always returns named unsupported before spawn; proven file-backed status/import/doctor remain supported. | Debian host + ubuntu CI: `linux_codex_login_unsupported_before_spawn`, `linux_codex_file_commands_with_login_unsupported`; expect `unsupported on this platform`, zero child/security spawns, zero credential installations, and working authorized file commands. No alternative Linux file-proof success case is enabled. |
| AC205 | No environment, argv, managed mode, existing artifact or successful fake child can bypass Linux's pre-spawn refusal. | Debian host + ubuntu CI: `linux_codex_login_unsupported_before_spawn` table covers file/auto/keyring/ephemeral/unknown policies, HOME/CODEX_HOME/DBUS variations, scratch artifact presence, and a would-succeed fake child. Expect identical named refusal with zero child invocations/installations and no success. Linux post-spawn proof/failure tests are deliberately inapplicable, not ignored placeholders; existing macOS child/proof failure tests still run. |
| AC206 | Fake `security` on PATH records zero Linux calls across the full command matrix, including login, swap and undo. | Debian host + ubuntu CI: `linux_commands_never_spawn_security`; expect an empty sentinel invocation log across all success/refusal command cases. |
| AC207 | Old backend seam is macOS-testing-only and absent from both releases; Linux works without it and ignores attempts to select it. | macOS: existing disabled/fake-reader cases; Debian host + ubuntu CI: `linux_backend_selector_ignored`; expect unchanged real-file routing. Reuse Phase 2 §7.1 gate 6 on both hosts and CI; seam scans report absent. |
| AC208 | New grep plants each fail and real trees pass on both OSes; structural plants fail at the intended file/line/code. | macOS + Debian host + ubuntu CI: reuse Phase 2 §7.1 gates 4/5; expect every planted violation rejected at its intended witness and clean real-tree controls passing. |
| AC209 | Both release artifacts contain no testing seams; required production names remain present. | macOS + Debian host + ubuntu CI: reuse Phase 2 §7.1 gate 6; expect every seam absent and all required production identifiers present in default-feature artifacts. |
| AC210 | Security/procfs literals and production target_os cfg sites obey §7.2's exact allowlists; fixture/test exclusions are explicit. | macOS + Debian host + ubuntu CI: reuse Phase 2 §7.1 gate 4 allowlist plants; expect outside-list mutations rejected and actual production tokens only at the named files. |
| AC211 | MacOS baseline snapshot/schema bytes remain identical; only D-066's separately reviewed name expectations may differ elsewhere in Phase 2. | MacOS: `git diff --stat b09c92a -- src/render/snapshots src/tui/snapshots schemas` and `git diff --exit-code b09c92a -- src/render/snapshots src/tui/snapshots schemas`; expect empty output/exit 0 and matching hashes. AC188 records the bounded dependency diff and inventories; no silent new-baseline reset or unrelated exception. |
| AC212 | Shared unit/integration/e2e, process lifecycle and Linux filesystem failure tests pass; no skips/stubs hide required cases. | macOS + Debian host + ubuntu CI: reuse Phase 2 §7.1 gate 3, including `linux_process_lifecycle`, `linux_file_read_outcomes_e2e` and `linux_transaction_refusal_matrix`; expect all required cases pass, none ignored/stubbed. |
| AC213 | Same source snapshot passes all six gates on macOS and Debian, and the required Ubuntu/macOS CI matrix. | macOS + Debian host: reuse Phase 2 §7.1 gates 1–6 with matching source manifest; ubuntu CI + `xcode-27` CI: same source revision and required checks green; all gates exit 0, release gate last. |
| AC214 | Docs state actual artifact scope and deliberate limitations, not inferred vendor atomicity or complete Linux process visibility. | Inspect authorized README/re-verify diff with concurrent edits separated: expect exact probe versions/paths, file-only scope, Codex pre-spawn refusal, no Linux peer-lock recovery, exact-name/version-launch residual, D-068 refusals, D-066 correction baseline and both-platform AC217 evidence. Distinguish synthetic torn-read tests from unmeasured live exceptional fallback and source-only timing from measured lifecycle. |
| AC215 | Independent verifier accepts phase evidence; all blocker findings are resolved before phase completion is claimed. | macOS + Debian host / ubuntu CI results: independent verifier's Phase 1 and Phase 2 review of the same §7.1 gate runs and named fixture witnesses; expect accepted verdicts and zero unresolved blockers. |
| AC216 | No live credentials, unrelated dirty changes, platform feature knobs or new exposure sites enter the delivery diff. | macOS: `git diff --name-status b09c92a` and `git diff b09c92a -- Cargo.toml src tests`; expect only authorized changes after excluding pre-existing work, no platform features/live material/new exposure sites; reuse gate 4 exposure checks and gate 6 seam scans. |
| AC217 | Real storage contention, isolated from refresh-lock contention, proves peer exclusion on both hosts; Linux also requires an approved forced-refresh checkpoint. | D-066 correction supplies macOS `storage_mutex_peer_exclusion` before S4. S4 supplies Debian matched real-peer both-direction traces and a separately authorized throwaway-login/forced-refresh/logout/cleanup checkpoint with agctl's bounded storage-only test hold. Gate-3 Debian/Ubuntu proper-lockfile fixtures and wrong-name control prove agctl, not vendor behavior. Expect actual retry/contention, no protected overlap, clean release; success after release or refusal are valid, onCompromised is not required. No extension beyond 3000 ms hold to reach 15000 ms peer staleness. |

## 7. Verification and operational matrix

### 7.1 Six closing gates, in this order

Run on both macOS and Linux at each code-phase end. Commands below are the portable form; on macOS
each runs through the machine's direnv layout and dev-profile cargo config exactly as AGENTS.md
describes (those wrappers are lane-facing and deliberately absent from this file: AC83,
`scripts/docs-gate.sh`). The dev config applies to dev/test invocations, not the default-feature
release artifact.

1. `cargo fmt --check`
2. `cargo clippy --all-targets --all-features -- -D warnings`
3. `cargo nextest run --all-features`
4. `scripts/phase3-greps.sh`
5. `scripts/phase3-structural.sh`
6. `scripts/release-gate.sh` — always last, default features only.

The scripts spawn cargo themselves (R17); arrange the approved dev/test configuration for their checks,
without leaking it into release builds or changing gate assertions. This may require a narrowly scoped
script configuration hook with a documented default. Never send macOS direnv target/link flags to Linux.
On Debian, the S2/S3 **gate runner**, not the lead, installs nextest and a Linux-valid
dev-profile cargo config file under the tmpfs CARGO_HOME (its path is recorded in the gate report), with target-dir
`/tmp/agctl-linux/target` and incremental disabled. Run **plain cargo with no `.envrc` and no custom
RUSTFLAGS/CARGO_ENCODED_RUSTFLAGS**; explicitly unset inherited flag variables and reject host-specific
flags in cargo configuration. The untracked macOS layout includes `-C target-feature=+neon` and Apple
link flags and must never be copied to x86_64 Debian. No Linux direnv installation is required.
Gates 2/3 pass that file with `cargo --config <path> ...`; gates 4–6 run scripts directly
with the approved internal dev-config hook (release artifact still uses its production profile, not the
scratch dev config); gate 1 is `cargo fmt --check`. Recheck rustc/cargo 1.98.1 and expose U7's extracted
rg path. The current source is a tar copy without `.git`; the gate runner supplies the reviewed Git
snapshot below. Record tool paths/config and source equality before gates; no omission or permanent install.

Use `ssh -o BatchMode=yes -o ConnectTimeout=15 debian-13-trixie.gaudiy-platform '<cmd>'`.
Check `/tmp/agctl-linux/{rustup,cargo}` and `/tmp/agctl-linux/src` before reusing them; tmpfs is not durable.
Copy a reviewed credential-free source snapshot with a tar pipe, not the developer's live config or home.
The structural/grep scripts need a valid Git working-tree snapshot (R17): a source-only tar without `.git`
is insufficient. Create an isolated repository snapshot or transport the required repository metadata;
record source equality and avoid copying unrelated dirty files into that snapshot. No detached stale source.
Check required gcc, cargo tools, bash, rg, perl, shasum and Git rather than assuming host parity.
Ubuntu CI uses its own toolchain/dependency installation and is additional evidence, not a Debian substitute.

The historical `phase3-version-gate.sh` remains required where it already runs. Its phase-2 baseline may be
macOS-only; do not call its inability to compile on Linux a new-product failure or quietly delete the macOS gate.
There are six requested phase-end gates above; this plan does not replace or weaken other existing checks.

### 7.2 Planted checks and release seam audit

Extend existing planted-check harnesses, not a second ad-hoc checker. Each new grep rule needs a failing
mutation and a passing real tree. Scan production Rust code, excluding comments, test siblings and fixtures.
Use these exact production-code allowlists; a different layout requires a reviewed list update, not a wildcard:

| Check | Allowed files / exclusions |
|---|---|
| Executable string `security` or `/usr/bin/security`, and security transport argv/command literals | `src/secret/security_cli.rs`, `src/secret/keychain_write.rs` |
| Literal path `/proc` or `/proc/...` | `src/runtime/proc/linux.rs` |
| `target_os` in cfg/cfg_attr/cfg! | `src/runtime/proc.rs`, `src/secret/mod.rs`, `src/secret/backend.rs`, `src/secret/keychain_write.rs`, `src/provider/codex/login_backend.rs` |
| Test/fixture exclusion | `src/**/*_tests.rs`, `src/secret/fake_security.rs`, `tests/`, `fixtures/`; never exclude ordinary source via cfg text |

`runtime/proc.rs` selects `proc/macos.rs` / `proc/linux.rs`. `secret/backend.rs` owns platform capability
and managed-root selection; commands consume those values without scattered target cfgs.
Keep SecurityCli transport at its current path and keychain transport in a macOS-gated block at its current
`keychain_write.rs` path. Move the executable constant from `secret/mod.rs` into `security_cli.rs`; re-export
only on macOS. Shared WriteTarget remains available without compiling the macOS transport on Linux.
`provider/codex/login_backend.rs` owns target-specific login evidence selection; keep proof constructors
provider-private. Its declaration does not require another target cfg in `provider/codex/mod.rs`.
The literal scan targets executable/command string tokens, not prose containing the word security.

- Existing keychain argv/exposure counts still scan source regardless of cfg; keep the macOS paths pinned.
- Add a planted target-cfg violation outside the list, plus procfs/executable-literal violations.
- No peer cmdline/environ reads; KeychainStdinLine/argv-size rules apply only to macOS transport.
- Linux live-file mutation requires private target/hold authority; Linux login must refuse before spawn.

Structural plants attempt out-of-module target/hold construction; macOS login-proof privacy checks remain.
The proposed Linux file-proof constructor/plant is deliberately inapplicable under D-064: no such enabled
capability is added. AC204/AC205 prove the Linux no-spawn guarantee instead; do not add a skipped/stub plant.
Require a clean unplanted compile first, then the expected Rust error at the exact planted source span (R17).
Run platform-applicable plants on their target; report each deliberately non-applicable clause explicitly.
A runtime seam cannot weaken a structural production guarantee. Synchronize R18's two seam inventories.

### 7.3 Expanded tests and observability

| Layer | Required cases | Platform / evidence | Witness |
|---|---|---|---|
| Unit | proc parsing/state/UID/name/start identity; policy/path selection; malformed and bounded inputs; I10 file-read outcomes | Linux sibling tests plus unchanged macOS unit tests | Debian host + ubuntu CI: `linux_stat_parser_contract`, `linux_proc_classification_contract`, `linux_start_identity_contract`, `linux_file_read_outcomes`; expected classifications/refusals in AC183–AC193. MacOS baseline cases stay green. |
| Integration | real proc children stopped/resumed/exited; no-follow paths, inode drift, 0600 replacement, cancellation | macOS and Debian; Linux proc cases also Ubuntu | Debian host + ubuntu CI: `linux_process_lifecycle`, `linux_atomic_file_transport`, `linux_transaction_refusal_matrix`; expected states, safe replacement or unchanged bytes on refusal. MacOS existing counterparts stay green. |
| E2E | status/watch/accounts/import/doctor; Claude login, swap, undo; Codex pre-spawn refusal; I10/empty-path errors through actual Linux route | Isolated fixtures; actual Linux backend, fake vendor binary only where declared | Debian host + ubuntu CI: `linux_file_read_outcomes_e2e`, `linux_swap_undo_three_locks`, `linux_codex_login_unsupported_before_spawn`, `linux_doctor_stale_refuses`; expect truthful outcomes, no fallback, zero Linux Codex child spawns/installs, and zero stale-removal mutations. |
| Peer contract | actual Claude storage mutex exclusion distinct from refresh locks; matched Codex override behavior | S1 named-host facts; D-066 macOS dependency and S4 Debian real-peer witness | AC177–AC181 retain cited evidence; AC217 `storage_mutex_peer_exclusion` on macOS and Debian must establish both contention directions, corrected-name non-overlap and wrong-name control. MacOS synthetic real-peer case and Linux separately approved forced-refresh checkpoint; no S1 concurrent-exclusion claim. |
| Failure / recovery | old/versioned identities, namespace/hidepid incompleteness, same-inode partial writer, rename/fsync failure, interrupted adoption | Deterministic fixture/fault evidence, no live-store experiments | Debian host + ubuntu CI: `unknown_evidence_keeps_stale_lock`, `linux_record_identity_guard`, `linux_doctor_stale_refuses`, `linux_file_read_outcomes_e2e`, `linux_displacement_parking`; expect no Linux peer-lock reclamation, guard before recovery evidence, zero stale removals/writes, transient torn reads/no fallback and no lost credential. MacOS unchanged unknown-evidence test still yields Broken. |
| Observability | redacted backend/outcome/refusal categories, lock-release/audit records, zero security calls | Assert bounded logs and unchanged macOS outputs | Debian host + ubuntu CI: `linux_file_audit_outcomes`, `linux_commands_never_spawn_security`, `linux_doctor_platform_rows`; expect redacted outcomes, zero security calls and fixed n/a rows. MacOS existing output witnesses unchanged. |
| Artifact | default-feature release seam absence and required production identifiers | macOS + Debian artifacts, Ubuntu release gate | Reuse each phase's §7.1 gate 6 on macOS, Debian host and ubuntu CI; expect seams absent and production identifiers present, no additional gate. |

Use dedicated sibling test files, real local temp files/processes and approved fake CLI fixtures.
Network-independent credential fixtures are synthetic; an authenticated peer test is separate, opt-in and worker-owned.
Count/read proc files linearly in observed PIDs; no per-process spawned `ps`, no repeated full sweep per account.
No performance claim is a gate here. If a regression is suspected, measure serially with comparable flags,
not with host-native benchmark RUSTFLAGS or simultaneous benchmark runs.

On macOS run `git diff --stat b09c92a -- src/render/snapshots src/tui/snapshots schemas`: it must be empty;
compare hashes of existing snapshots/schemas too. This is not a claim of cross-platform output equality.
Separately report `git diff --stat b09c92a -- tests/` and the exact cfg-edited e2e file list; that diff need
not be empty, but Phase 1 macOS nextest inventory and results must be unchanged. In Phase 2, D-066's
separately approved name corrections/additional witnesses are listed against their landing revision;
every unrelated baseline case/result stays fixed and no correction is attributed silently to Linux routing.
Linux path/error differences get Linux assertions, not rewritten macOS snapshots. Account separately for
pre-existing concurrent changes.
No `test.skip`, ignored placeholder, only-filter, stub, or unimplemented branch can satisfy an AC.

## 8. Deliberate pre-mortem and risks

| Scenario | Early warning | Prevention / proving test | Stop condition |
|---|---|---|---|
| PM1: normal rename trace is mistaken for unconditional vendor atomicity/durability | U2's exceptional same-inode writer/no-fsync contract ignored; transient empty file appears absent | D-060 actual-route truncate/partial/intermediate fixtures; retain stronger agctl fsync+rename and under-lock checks | No fallback, no inferred write authority, no live-fallback measurement claim |
| PM2: exact-name or proc namespace heuristics are mistaken for complete peer visibility | Version-path peer has comm `2.1.282`; hidden-PID view passes namespace heuristics; old record appears recycled | D-067 pre-holder identity guard, negative-sweep Unreadable and independent doctor refusal witnesses | No Linux peer-lock reclamation in either phase; future reviewed visibility authority required |
| PM3: vendor upgrade selects a different backend or mutex | New matched artifact contradicts plaintext/name facts, or contention witness fails | Repeat U1/U3 for upgrade; D-066 separate correction plus both-platform AC217 actual contention | Block live-file scope; no Secret Service expansion or safe-three-lock claim |
| PM4: Codex argv file override is superseded by managed policy | U5 measured attempted D-Bus despite file argv | D-064 unconditional Linux pre-spawn refusal, policy/environment matrix | No enabled Linux Codex login until a separate reviewed proof mechanism exists |
| PM5: port reports green by removing tests | Case count or shared coverage falls; macOS snapshots rewritten | Test inventory/results, narrow cfg edits, Linux contract counterparts and independent verifier | Reject gate evidence and restore coverage |

S1's bounded vendor facts are settled; the Phase 1 bottleneck is scoped approval plus gate-host setup.
Phase 2's entry bottleneck is the separately authorized D-066 correction/macOS proof, followed by Linux
AC217 exclusion and preservation of write authority outside owned namespaces. Neither compiler success
nor synthetic lock fixtures alone settle actual peer exclusion.
Risk of concurrent CI/RC changes is controlled by owner coordination, refreshed anchors and narrow diffs.
Do not merge a later tty implementation into the Linux backend merely because the facade now has room.

## 9. Unknowns and settling commands

The S1 questions below have bounded evidence in `docs/re-verify.md §7.1–§7.4`; this amendment rules on
changed premises, pending scoped critic acceptance. New measurements must still record `date` in the same
command and distinguish actual observations from matched-source/fixture evidence.

| ID | S1 outcome and evidence | Ruling / consumer / remaining gate |
|---|---|---|
| U1 | Matched Linux 2.1.282 legacy/V5 factories select plaintext; legacy isolated read measured, V5 source-established (§7.2 U1) | D-059 file-only capability; S4 still proves agctl routes/authority, not an inferred keyring absence |
| U2 | Defined secure-storage wins; empty secure-storage → HOME/.claude, otherwise empty config → cwd; NFC/no realpath. Source exceptional in-place/no-fsync writer differs from normal measured rename publications (§7.2 U2, §7.4) | D-060 retains stronger agctl writer, AC190 models same-inode torn/intermediate states; D-068 refuses ambiguous read/write selections. Approved operator checkpoint complete; live exceptional fallback remains unmeasured and not required. S4 proves AC190/AC192/AC193 |
| U3 | Primary/legacy/storage order confirmed, actual third name `.storage-write.lock`; mismatch pre-exists on macOS. Owner sidecar lifecycle measured under umask 077; periodic heartbeat not measured (§7.2 U3, §7.4) | D-061 measured name/order, sidecar not authority; D-066 recommends separately approved correction before Phase 2. Separate-fix authorization/additional cleanup policy remain dependency work; legacy-only classification is fixed. MacOS then Linux AC217 actual exclusion still unmeasured; Linux requires a separate approved forced-refresh operator checkpoint |
| U4 | Exact comm follows launch basename; stopped direct-version peer is not exact `claude`. A nested PID-namespace plus hidepid view exposes 3/496 PIDs despite namespace heuristics; old macOS identities are incomparable (§7.2 U4) | D-058 preserves exact-name contract and documents residual; D-067 guards format/domain/real UID before recovery; only same-boot/ns/UID kill ESRCH proves an own writer gone, never authority to break a peer directory. S2 proves AC183–AC186, including direct doctor path; no completeness authority inferred |
| U5 | Matched Codex 0.157.0-alpha.10 managed keyring policy defeats argv file override, attempts D-Bus, produces no auth.json (§7.2 U5) | D-064 selects pre-spawn unsupported unconditionally; S5 AC204/AC205. Proven file-backed status/import/doctor remain in scope |
| U6 | Linux `/etc/claude-code/managed-settings.json` confirmed by source plus isolated open/stat (§7.2 U6) | D-062 settled; S5 tests selected path and unchanged macOS precedence |
| U7 | procfs-core 0.18 MIT OR Apache-2.0 selected with defaults disabled and bounded validated adapter; rustc/cargo 1.98.1 observed (§7.2 U7) | D-058 settled. S2/S3 gate runner still provisions nextest/dev config under tmpfs CARGO_HOME, rg PATH and real Git snapshot; plain cargo, no `.envrc`/custom flags (§7.1); no setup state inferred durable from tmpfs |
| U8 | No Linux proof-backed login enabled, so scratch-HOME real login/browser experiment inapplicable (§7.2 U8) | Resolved by D-064 refusal; no pending operator Codex OAuth step. Reopens only under a later reviewed enabling plan |

The old claim that peer locks carry no owner identity is superseded by U3; owner metadata still grants
agctl no recovery authority. A fake child cannot prove vendor policy, and normal real rename publication
cannot prove exceptional writer behavior or concurrent agctl exclusion. Those proof boundaries survive
U2/U3 closure.

D-066 is the remaining user scope decision: approve a separate correction/dependency (recommended), or
request a reviewed in-plan carve-out. No additional bead is authorized before that decision. The lead owns
cross-plan open-question tracking; this lane returns replacement U2/U3/U4 lines without editing that file.

## 10. Beads to file after approval

The existing epic `agctl-1y9` (Linux file-only credential backend) has exactly three permitted phase children
for this plan: one per phase, filed by the lead only after user approval. These three children are this plan's
work items. No other beads, charters or ledgers are authorized by this plan. D-066's recommended external
bug fix requires a separate user decision before the lead files any additional bead; this amendment neither
files it nor expands the three-child Linux scope. No bead was created or updated by this lane.

| Proposed child | Scope | Dependency | Close evidence |
|---|---|---|---|
| Linux vendor and procfs evidence spike | Phase 0 / S1 | Existing parent prerequisites rechecked by lead | AC177–AC181 verdict and cited source pins |
| Linux process backend and CI restoration | Phase 1 / S2–S3 | Evidence spike GO | AC182–AC189 and both-platform six gates |
| Linux file credentials and command delivery | Phase 2 / S4–S6 | Process/CI phase accepted + D-066 separately approved dependency/macOS witness | AC190–AC217, verifier and release evidence |

Do not add per-step or microstep beads, charters or ledgers, or close the parent on compile success.
Batch permitted tracker-only updates rather than adding noise commits. Commit/push/merge require the
lead's separate authorized execution flow.

## 11. ADR and success criteria

**Decision:** D-057 selects build-time macOS/Linux backends, preserving shared APIs; D-059–D-064 constrain
Linux to evidence-backed file operations with Codex login refused before spawn. D-066 recommends a
separately approved storage-name correction before Phase 2; D-067 separates own-writer evidence from forbidden peer-lock reclamation and
versions identities; D-068 refuses ambiguous reads/writes instead of guessing cwd/home.
**Drivers:** correct concurrent store mutation, conservative evidence interpretation, bounded macOS compatibility.
**Alternatives considered:** viable D uses target cfg inside existing boundary files for less source movement;
runtime `security` probing and Cargo platform features remain invalidated in §3.3. For the storage defect,
an in-plan macOS carve-out is viable but requires broader user approval; the separate dependency is preferred.
For process recovery, namespace/self checks are invalidated by U4's hidden-PID measurement; argv/exe matching
would widen the frozen contract without solving completeness. For empty config, reproducing cwd or silently
using home conflicts with current authority, so refusal is selected. Linux proof-backed login lacks the
required guarantee under U5, not merely implementation effort.
**Why chosen:** A and D remain deterministic and all-features-safe; split modules aid review. The separate
correction isolates a pre-existing bug from a port, and explicit refusals avoid converting absence of proof
into authority. agctl's stronger atomic writer is retained rather than copying the vendor fallback.
**Consequences:** two platform test matrices; no Linux stale-removal command; exact-name sweeps miss direct
version-path peers; ambiguous Linux live paths refuse; Linux Codex login is unavailable, while proven file
commands remain. Phase 2 waits for D-066 approval/landing/macOS proof and closes only after Linux AC217.
**Follow-ups:** lead obtains D-066 user decision and scoped critic/Phase 1 GO. S2/S3 prepare operational gates;
S4 supplies Linux contention/torn-read evidence. Vendor upgrades repeat matched checks. Complete proc
visibility, proof-backed Linux Codex login, other Unix/Windows, Secret Service and Linux RC require later
reviewed scope; none automatically enlarges this plan's authority.

**D-065 — Acceptance and handoff.** Success means every AC has evidence, both code-phase verifier passes
are accepted, immutable macOS surfaces remain identical, and Linux delivery documentation matches the
verified scope, including D-064's selected Linux Codex-login refusal and D-067/D-068 limitations. v1.2
approval does not approve D-066's separate scope or v1.3 before its scoped re-check. Phase 1 follows §0's
critic/lead GO; Phase 2 adds the dependency gate. No approval overrides an evidence refusal. The lead owns
user confirmation and any `/oh-my-claudecode:start-work` handoff; this planner performs neither execution
nor self-approval.

Planning confidence, not benchmark measurements: performance 0.80; scalability 0.85; reliability 0.72;
cost effectiveness 0.86. S1 settled bounded vendor facts, but reliability remains limited by unimplemented
consumer refusals and missing actual concurrent exclusion/Phase 2 dependency evidence, not pending S1 OAuth.
The implementation is expected to remain O(observed PIDs + configured accounts) per pass, without a daemon
or whole-home discovery; verify actual behavior rather than reporting that expectation as a measurement.

## 12. Changelog

- **v1 — 2026-09-26 00:43:24 JST (from `date` in this write):** initial pending-approval deliberate plan;
  three phases, six steps, source-indexed boundaries, AC177–AC216 and D-056–D-065. No execution performed.
  Corrected pinned managed-root anchors; retained Linux factory, owner-sidecar and Codex policy uncertainties.
  At v1, analyst consultation and Architect/Critic review were outstanding; no execution was approved.
- **v1.1 — 2026-09-26 00:50:14 JST (from `date` in this write):** incorporated the lead's analyst pass;
  explicit boot/tick/UID/kill/hidepid contract, EXDEV refusal, operator browser checkpoint, exact cfg/literal
  allowlists, fixed n/a doctor rows, Codex not-read JSON mapping, Linux scratch HOME evidence and macOS-only
  backend testing seam. E2e cfg edits are allowed with unchanged macOS inventory/results; snapshots/schemas
  remain byte-identical. Analyst consultation is complete; Architect/Critic review and user approval remain.
- **v1.2 — 2026-09-26 00:59:50 JST (from `date`):** one permitted blocker return; pending scoped re-check and user approval.
  - B1 (§4.1 D-058, §4.3 D-061, §6 AC184/AC186, §7.3, §9 U4): shared Unreadable/HolderUnreadable variants, Linux-only production, early stale-lock refusal, zero-write fixture and byte-identical macOS regression test.
  - SF1 (§0, §2, §4.5 D-064, §5 S1/S5, §6 AC179/AC181/AC204/AC205, §7.3, §8, §9 U5/U8, §11): failed Linux Codex-login proof selects named unsupported refusal before spawn; other proven scope proceeds.
  - SF2 (§3.3, §11 ADR): viable in-file target-cfg option D added; A remains chosen for isolation/reviewability, with B/C still invalidated.
  - SF3 (§6, §7.3): all 40 ACs have a Witness cell naming tests/inspection or reused phase gates, host and expected state; no extra gates or ledger.
  - SF4 (§4.2 D-059, §6 AC190/AC192/AC193/AC200/AC201, §7.3): explicit Linux I10 ENOENT-only Absent mapping; actual-route unit/e2e failure cases refuse without fallback or write eligibility.
  - SF5 (§10): exactly three phase children under the existing epic after approval; no other beads, charters or ledgers.

- **v1.2 re-check — 2026-09-26 01:02:16 JST (lead; from `date` in this write):** the scoped critic lane re-checked the v1.2 hunks (B1, SF1–SF5) against the v1.1 snapshot and returned APPROVE at 2026-09-26 01:01:33 JST; no plan text changed beyond this record, the header's review-boundary line and §0's next action. Status: pending approval.
- **v1.2 approved — 2026-09-26 07:11:40 JST (from `date`):** user approval recorded by the lead. §10's proposals were filed as
  `agctl-1y9.1` (Phase 0 / S1 evidence spike), `agctl-1y9.2` (Phase 1 / S2–S3) and `agctl-1y9.3`
  (Phase 2 / S4–S6) under `agctl-1y9`; `.2` is blocked by `.1`, `.3` by `.2`. S1 started as one executor
  lane (`linux-s1`, `omc-configured-executor-4e63ea1e64dd`, no model override), no code edits.
- **v1.3 — 2026-09-26 11:05:02 JST (from `date` in this write):** single S1 changed-premise amendment, including the lead-authored seven-premise analyst gap check; scoped critic pending, no S2/code execution.
  - Storage name / scope (§0/§2, §4.3 D-061/D-066, S4, AC178/188/194/201/211/217, §7–§11): measured `.storage-write.lock`; separate user-approved correction recommended before Phase 2, including legacy agctl artefact recognition, F58's false exclusion premise and no per-platform constant spelling. Both-host real-peer proof plus separately approved Phase 2 Linux forced-refresh checkpoint; no additional bead authorized.
  - Writer (§4.2 D-060, S4, AC178/190/193/195/214, §7–§9): normal rename/no-fsync does not negate source fallback; zero-byte and valid-keyless stores are Transient; two-publication interleaving and post-write drift must not claim success. Uninspected 2-byte contents remain unknown; no claim against writes after return. agctl's stronger writer retained; live fallback unmeasured.
  - Name matching (§4.1 D-058, S2, AC180/184/214, §8–§9/ADR): exact `claude` retained; non-claude launchers/self-settable comm are residual limits; text says no stopped peer visible by exact name; no argv/exe inference.
  - Identity / visibility (§4.1 D-067, §4.3–§4.4, S2, AC185/186, §7–§9/ADR): distinguish hidepid-independent kill from proc enumeration and cross-namespace store sharing. Version/boot/ns/ticks/real UID guard precedes recovery; only same-domain kill ESRCH proves an own writer gone. Peer-lock breaking never enabled; doctor/attested paths and acquisition continuation refuse independently; fresh owned locks/flock usable.
  - Empty paths (§4.2 D-068, §4.4, S4, AC190/192, §9/ADR): refuse ambiguous Linux reads/status/writes before cwd/home opens; fixed `ambiguous config dir: use an absolute path` text, secure-storage defined-empty precedence and divergent macOS home behavior preserved.
  - Settled branches / setup (§4.1 D-058, §4.4 D-062, §4.5 D-064, §5, AC177/179/180/183/204/205, §7–§9): procfs-core 0.18 validated adapter, confirmed managed root, unconditional Codex pre-spawn refusal. Gate runner owns tmpfs nextest/dev config/rg PATH/Git snapshot setup; Debian uses plain cargo with no .envrc or custom flags. Exact scratch artifacts replace PATH assumptions.
  - GO / NO-GO (§0/S1/AC181/§8/§10/§11 D-065): recommend Phase 1 GO upon scoped critic acceptance of U4; U7 settled, setup is execution work. Lead records GO before S2. Phase 2 entry adds approved correction/macOS proof; delivery adds Linux checkpoint and implemented ambiguity text. S1 operator procedure complete; the separate Phase 2 checkpoint is not yet authorized.
- **v1.3 accepted — 2026-09-26 11:10:32 JST (lead; from `date`):** scoped critic `critic-linux3` returned APPROVE on frozen SHA `7b79699147f3eb9edf3d4f4e6f4be8c341916b5f01eac86627239de822a9cf93` (snapshot `08e592f5…`, numstat 448/194); no B-findings; SF1 (Codex doctor unknown-holder representation via `namespace.lock = null` + `namespace.notes`, schema unchanged) applied by the lead to D-067 and AC185's witness. Phase 0 closed (`agctl-1y9.1`). Phase 1 structural GO recorded; execution only on the user's explicit order. Pending user decisions: v1.3 confirmation; D-066 scope; AC217's Linux forced-refresh operator checkpoint authorization (Phase 2).
- **v1.3.1 — 2026-09-26 12:44:35 JST (lead; from `date`):** editorial only. Relocated from `.omc/plans/` to `docs/plans/` on the user's order (`.omc/` is never committed; the operational copy is a symlink to this file). §7.1's six gate commands are respelled in portable form because AC83 (`scripts/docs-gate.sh`, run first by the release gate) forbids this machine's direnv/dev-config wrappers anywhere under `docs/`; `docs/re-verify.md` §7.2 U7 received the same two-line respelling. No decision, AC, witness or gate order changed.
