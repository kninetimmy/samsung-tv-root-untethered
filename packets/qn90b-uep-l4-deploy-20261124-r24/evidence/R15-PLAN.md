# Historical r15 plan — NOT r16 instructions; r15 is permanently STOPPED

This packet inherits r14's **completed stage 1** and offers only stage 2
`LIVE_ARM_ACTIVE` and stage 3 `LIVE_ARM_DISABLE`. It never replays install.
No TV contact, driver execution, marker creation, secret staging, shipped-code
change, Git write, or live readiness probe is part of authoring this packet.
Manager/host/module/native pins and the gate-op bytes remain exactly r14's at
source `8f92e54346a6d89ecda4ce540c341d855b8646a6`.

## What changed from r14

| File | Reason |
|---|---|
| `recovery.py` | Validate/remove only the exact dead relay in prerequisites; fresh-session absence check; independently aborting relay file/link/absence tests |
| `active.py` | Digest-verify inherited install status; async relay prerequisites before attempt consumption |
| `disable.py` | Run the same relay reconciliation before the stage-3 attempt, including after stage 2's reboot |
| `install.py` | Explicitly refuse replay of inherited stage 1 before an attempt or SDK session |
| `deploy.py` | After relay stop/removal, close that SDK and verify absence in a new ordinary SDK session; retain ownership evidence on failure |
| `packet.py` | r15 identity, inherited install digest, exact r15 seal entry list; shipped artifacts/constants and decision-35 residual unchanged |
| `session_checks.py` | Retain all 37 inherited cases; execute additional real-shell relay and prerequisite/cleanup cases |
| `mutation_checks.py` | Retain all 20 inherited mutants; falsify relay refusals, fresh-session checks, inherited-anchor integrity and both stages' attempt ordering |
| `offline_checks.py` | Require new suites plus authoring suite, inherited anchor, pinned 0-warning build and exhaustive r14 provenance before sealing |
| `authoring_checks.py` | Compare inherited production scripts to a real temporary bake and retain them byte-identically; do not run `prepare.py` |
| `PLAN.md` | This continuation plan, forensic corrections, refusals and review risks |
| **Added:** `relay_checks.py` | Execute generated reconciliation/cleanup shell bytes with filesystem/process fixtures, real hashing/links/unlink/rmdir and modeled POSIX ownership |
| **Added:** `port_from_r14.py`, `port-from-r14.json` | Pinned-seal allowlist carry; complete old/new digests and one reason per delta; generated-output reasons; verifier checks the actual tree, not just claimed ledger rows |
| **Added:** `stage-status-install.json` | Byte-identical, separately digest-pinned inherited r14 success evidence, included in r15's seal |
| **Added:** `evidence/FORENSIC.md`, `evidence/r14-evidence-digests.json` | Receipt-cited incident analysis and a non-secret predecessor-immutability snapshot |
| **Replaced/omitted:** `port_from_r13.py`, `port-from-r13.json` | Previous authoring provenance is superseded by the r14-to-r15 ledger; r14 remains intact |
| **Regenerated:** `rehearsal-results.json`, `session-results.json`, `mutation-results.json`, `offline-results.json` | Fresh r15 execution evidence, never inherited green claims |
| **Regenerated:** `build/SamsungTvRootAgent.dll`, `build/SamsungTvRootAgent.runtimeconfig.json` | Build the unchanged packet agent embedding byte-identical gate scripts with SDK 3.1.426; not a new shipped manager/host |

Everything else in the sealed r14 set is carried byte-identically. No STOP,
SPENT, marker, active failure status, attempt, receipt log or credential is
copied. The port tool copies only the pinned sealed allowlist plus the pinned
install status; it never traverses r14/execution. Auxiliary .NET deps/dev files
are unsealed compiler byproducts under build, not stage inputs.

## Incident and causal limits

`evidence/FORENSIC.md` gives exact receipt record numbers and qualifications.
Stage 2 failed at 2026-11-10T15:06:32Z on an already-present fixed recovery
directory, before cp, dotnet, materials generation, staging or any gate op.
The attempt was consumed **before preflight**, not after it. Stage 1's removal
command returned success, but its `test ! -e PATH && test ! -L PATH` can print
success even when the first test fails. r15 splits the relay guards and never
treats same-command absence as cross-session proof. Successful standalone
unlink/rmdir calls support removal in that view, not persistence across views
or reboot. Same later directory inode and old file timestamps suggest retained
state; namespace/overlay asymmetry is plausible but unproven. The fix does not
require choosing that hypothesis over selective restore or other persistence
behavior.

## Relay reconciliation — before either remaining attempt

The owner must first authorize the relevant stage and its SDK-staging cleanup;
this is **not** a read-only readiness probe. `main()` checks marker, source
HEAD and seal, then awaits `prerequisites()`, then constructs/takes OneAttempt.
Prerequisites checks host OpenSSL and the prior-stage anchor, then calls
`recovery.reconcile`. No failed relay precondition consumes an attempt or
creates STOP/status. There is no automatic retry or removal fallback.

Both the first ordinary SDK session and a newly constructed, separately
connected second session require uid 901, the stage boot/proof, the canonical
SDK root, pinned installed relay/runtimeconfig source hashes and no listening
26105 socket in IPv4 or the IPv6 table if that kernel exposes it. IPv4 is
mandatory; an existing but unreadable/failed table read refuses.

### Absent

The first session accepts only absent-and-not-symlink. It does not create
anything. It disconnects. A fresh ordinary SDK session independently checks
absence, boot/proof, sources and listeners again. Only then can prerequisites
return. After the attempt, unchanged `recovery.start()` exclusively creates the
relay directory and copies the pinned files as before; its child guards now
abort independently.

### Present: strict remove, then recreate through existing machinery

Before **any unlink**, require:

1. Directory, not symlink, canonical path/cwd, owner 901 and mode 0700; group
   unconstrained (`901:*:700`). Capture/recheck its device/inode/owner/mode.
2. Exact three-entry inventory: `pid`, `recovery.dll`,
   `recovery.runtimeconfig.json`. No additional entry, missing entry, nested
   directory or special file.
3. Each child regular, not symlink, owner 901, mode 0600, exactly one hard link.
4. DLL SHA-256 `ef42c7590ecb5e67b794295939e2be9658520b1b3b1222095063f93a5049f541`;
   runtimeconfig SHA-256 `2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b`.
5. PID file at most 64 bytes, positive decimal PID and decimal birth; its exact
   bytes must be `PID BIRTH\n` (digest comparison, rejecting NULs/extra LFs).
6. `/proc/PID` absent and not redirected. This intentionally refuses even PID
   reuse with a different birth: safer false refusal, never kill an unknown PID.
   No listener on 26105 (checked before the shape audit).

Unlink only those three validated names, rmdir only that fixed name, assert
absence with separate fatal tests, emit **provisional** removal. Disconnect.
The new ordinary SDK session must confirm absence and the anchor independently.
It never removes again. Reappearance, including the exact old inode, is a
clear refusal **before the attempt**. A removal/transport/disconnect error also
refuses; partial unlink requires separate review, not relaxed shape acceptance.

Remove/recreate keeps the already-reviewed start/validate path and does not
adopt an old running process, stale pid receipt or potentially namespace-bound
DLL. Its deliberate failure mode is safety over liveness: if removals cannot
be observed absent from the next SDK session, r15 will not proceed. It does not
promise that this TV's unresolved persistence mechanism will allow execution.

### Closeout and the next reboot

Existing guarded process stop and exact-file removal remain. Their receipt is
provisional: `Deployment.finish` disconnects the remover SDK and requires a new
ordinary session's anchored absence verification before clearing the recovery
ownership receipt or reporting verified closeout. Failure retains the receipt,
records cleanup pending, and the existing stage handler STOPs after an attempt.
Stage 3 independently reconciles again on its own anchor, so a reboot that
resurrects a known dead relay cannot hit the old unchecked mkdir wall.

### Every refusal category

Missing/changed marker, seal, source HEAD, OpenSSL, inherited-stage success or
anchor; malformed anchor; SDK connection/capture/disconnect failure or ambiguous
receipt; wrong uid/boot/proof/canonical root; changed or unreadable relay source;
listener-table failure/listener; redirected/non-directory relay; wrong directory
owner/mode/identity; wrong inventory; linked/nonregular/wrong-owner/wrong-mode
child; wrong DLL/runtimeconfig bytes; oversized/malformed/non-byte-exact pid;
existing/reused pid; unlink/rmdir failure; local or fresh-session remaining path
or link: refuse. All reconciliation refusals run **before OneAttempt.take**.
After an attempt the unchanged stage failure discipline is STOP/no replay.

## Stage anchors and remaining operation

Inherited install evidence SHA-256:
`be77d4940030944e8939ca223f66d253864c980de919e0ad6d5a2b8d35794042`.
Both the port and `active.anchor_from_prior()` verify it, and the file is sealed.
Its boot is `dc1477b5-295d-452b-90c4-ce10aec2f3c8`, proof
`38bcea864cd701b5826bd5a744a43f01b95922234cb2ac9cda6a45567b526f91`.
This is historical evidence, not a claim of new observation. Reconciliation
checks the live boot/proof before any cleanup and before the attempt; the
unchanged active preflight/session also require that anchor, manager v5.19,
read-only config, module, absent budget/temp and all 24 protected files.

The old inspection boot `0404f29a-1277-44bb-bee7-5b77a0b3b6bc` remains only the
historical inspection/settings/register baseline. Never use it as stage 2's
boot. Install cannot be replayed even if someone supplies its old marker.

Stage 2 root op stays `gate-config-active:<boot>`: replace exact read-only bytes
with `active\n`, never run the gate manually. Owner power-cycle; await this
boot's cleared receipts and `uep gate module exit=0` in boot-scoped
`module-uep-gate.log` before requiring `boot=<fresh> clear=1 restore=0`; verify
cleared fingerprint immediately, +10 and +30 minutes. Any enforcing read STOPs.
The driver reads module-uep-gate.log, not the runner's old modules.log; display
and picture sanity remain an **owner visual** check, not a driver claim.

Stage 3 anchors to r15's successful active status and fresh proof. Root op
`gate-remove:<boot>` still requires exact active config and current-boot,
byte-exact budget receipt (writer-shaped metadata, including legitimate 0666),
unlinks config, verifies absence. Owner power-cycle; verify enforcing state,
absent-or-stale budget, intact manager/module/24 files and unchanged denial
control: pinned ELF, uid 901, `native_exit=126`, `Permission denied`, no native
success marker, staging removed. Then SPENT. Denial code/script bytes unchanged.

## Budget-writer residual — unchanged, not newly accepted here

`UepGate.SaveBudget` uses following/truncating `File.WriteAllText` for
`uep-state.conf.tmp` before rename. Packet temp-path refusal cannot cover its
check-to-write window. Exclusive-create hardening remains task 40 / **v5.20**.
Decision 35's **owner-accepted residual** is carried unchanged as design context,
not authority to arm r15. Explicit stage-2 residual acceptance is required again
at the owner arming gate; this packet authoring creates no standing approval.

## Host verification and sealing

Use repo `.venv/Scripts/python.exe` (Python 3.14), `-B`, SDK 3.1.426,
`DOTNET_MULTILEVEL_LOOKUP=0`, `DOTNET_ROOT` pinned by each build helper. New r15
and evidence directories were created/verified using packet.make_private_directory
and packet.private_acl (Windows PowerShell **5.1**, owner+SYSTEM only).

`authoring_checks.py` verifies the carried scripts against a pure temporary bake,
real C# receipts, embedded resources, Bash syntax, ruff F821 and a 0-warning
temporary agent build. No `prepare.py` or `inspect_tv.py` entrypoint is run.
`session_checks.py` executes all inherited and relay cases; the relay shim maps
paths, proc and POSIX metadata only, and uses fixture content pins for the TV DLL
that is unavailable host-side. Real generated shell, native symlinks/hard links,
SHA-256, process-table fixtures, inventory and unlink/rmdir execute on the host.
Mutation cases run the real broken source and must fail on the intended terminal
assertion; every mutated file is restored and digest-checked. A false removal
receipt and independent-session reappearance must both be caught.

`offline_checks.py` reruns authoring, driver, session and mutation suites,
verifies all artifact pins and inherited fixes, rebuilds the unchanged packet
agent at 0 warnings, verifies the exhaustive port ledger and only then writes
offline-results + the exact entry-manifest seal. Results/build/authoring command
outcomes are in sealed JSON outputs. No green result is copied from r14.

Sequence: digest-verified carry -> author -> host suites -> port ledger ->
offline seal -> final manifest/ledger/immutability/ACL validation -> independent
read-only review -> separately approved read-only readiness probe (decision 36)
-> explicit stage-2 arming/residual acceptance. Prerequisites is not a readiness
probe because a known dead relay can be removed there. No live approval is
implied by a host seal.

## Non-fixes and reviewer attack surface

- No proof or repair of the underlying namespace/filesystem/restore mechanism.
  A persistent old view fails safely; no deletion retry or filesystem sync trick.
- A fresh-session absence sample cannot prove every future session/view or close
  the check-to-start race. Reviewer should attack different session views,
  concurrent same-uid/parent-directory replacement, and boot changes first.
  Existing identity/hashes and the final exclusive mkdir still fail closed;
  a change after prerequisites can still burn an attempt. No claim of atomic
  global namespace exclusion is made.
- Prerequisite cleanup is uid-901 SDK staging mutation before attempt accounting;
  owner arming must authorize it. It never launches a relay or gate/root op.
- General preflight attempt consumption and the misleading pre-material
  FileNotFoundError cleanup path remain findings, not silent unrelated fixes.
- The broad inherited terminal-message matcher (task 42), SaveBudget race,
  mid-boot rearm, kernel/security-layer changes, daemon/supervisor and live
  hardware behavior remain outside this packet. No shipped-code change required
  for this narrowly scoped fail-closed relay fix.

---

## Historical r14 plan (retained below for design provenance, not current state)

r14 is the successor to r13, which was sealed and then rejected by its own

r14 is the successor to r13, which was sealed and then rejected by its own
independent read-only review **before arming** (0 blockers, 1 major, 2 minors).
No r13 stage ever ran, nothing was armed, and no TV write occurred. r14 keeps
every earlier fix and closes the fifth review.

## What changed from r13 (fifth review)

| # | r13 defect | r14 fix |
|---|---|---|
| M1 | a log ending in the incomplete suffix `uep gate module exit=` was classified as a nonzero exit and STOPped immediately; the active stage would make that permanent with the active config installed | `module_gate` reads the raw log, keeps the trailing-newline signal, and treats a partial exit suffix as pending; a complete duplicate or nonzero exit still stops immediately |
| m1 | the mutation harness matched the expected message anywhere in the traceback, including displayed source lines, so an unrelated crash could be counted as a kill | the harness matches only the terminal exception line, records it, and the seal re-checks every record's terminal line |
| m2 | the exception fast-path looked for `uep gate EXCEPTION`, but the host emits `uep gate (boot) EXCEPTION …` | the fast-path matches the phase in parentheses and stops on the real host format |

Everything from r13 is carried: the byte-exact SHA-256 removal receipt (NUL and
LF+NUL refused), the empty/partial-line poll, the proper missing-summary/detail
cases, the synthetic order case, the writer's real `0666` metadata, the
budget-temp residual, and the module log/display PLAN corrections.

No repository code changes are part of r14. The shipped v5.19 bytes are the
same; only the packet, its embedded removal script, and the test layer change.

## Budget-writer residual (owner decision)

`UepGate.SaveBudget` builds `uep-state.conf.tmp` with `File.WriteAllText` and
then renames it. `WriteAllText` follows a symlink and truncates an existing file,
so a temp path planted between the packet's pre-write check and the host's write
could redirect that root write. The pre-write refusal detects a path planted
before the stage starts; it cannot close the race inside the host.

The complete fix is an **exclusive create** in `SaveBudget`, which changes the
shipped manager/host bytes and requires a new v5.20 build, new PREV/NEW pins, a
PR and CI (tracked as task 40). r14 does not carry those bytes.

Arming stage 2 (`LIVE_ARM_ACTIVE`) therefore proceeds only with the
**owner-accepted residual** above: the reviewer and owner accept that the
check-to-write window in the current v5.19 writer is not closed by this packet.
Stage 1 and stage 3 do not arm a store through `SaveBudget`. This acceptance is
required again at the explicit stage-2 arming gate; a future v5.20 build retires
the residual.

## Session/mutation coverage (r14)

`session_checks.py` has 37 cases. The ones that close this review:

- `module-gate-waits-for-partial-exit` feeds a log ending in `exit=` and then
  `exit=1` (no newline), followed by a completed `exit=0`; both partial suffixes
  must stay pending.
- `module-gate-rejects-exception` feeds the real `uep gate (boot) EXCEPTION …`
  format followed by a valid log; the exception must stop on the first read.
- the empty-log, partial-line, persistent-missing-exit, missing-detail/summary,
  duplicate/nonzero and complete-unexpected cases from r13 remain.

`mutation_checks.py` applies 20 exact defects, including the partial-exit
terminal mutant, the real-format-exception mutant, the immediate-unexpected
mutant, the required-shape mutant, the NUL-accepting receipt guards and the r11
grep guard. Every mutant must exit non-zero **and** contain the intended
assertion on its terminal exception line; source lines displayed in the
traceback do not count. The harness restores every file and verifies its
SHA-256. The seal refuses if any mutant survives or dies for the wrong reason.

## Stages

The deployment goal and device baseline are unchanged: deploy manager v5.19,
prove the UEP gate runs in the root boot module with a read-only config,
activate the config and verify the guarded clear on a fresh boot, then disable
it and re-verify the enforcing-only baseline plus the hash-locked unsigned
execution denial control. Three owner-armed stages, one owner power-cycle each,
one attempt per stage, never replayed.

Source is `8f92e54` (merge of PR #24). The inspection is carried from r12: the
device is unchanged at boot `0404f29a-1277-44bb-bee7-5b77a0b3b6bc`, enforcing
fingerprint `c07bd300 00000001 00000000 000004e2`, manager v5.18, no gate
config, no module and no budget state. No TV write occurred between that
inspection and this packet.

### Stage 1 `LIVE_ARM_INSTALL` (one owner reboot)

Root op `gate-install:<boot>`. Refusals, all **before any write**: config,
state, state temp, module directory and backup absent; manager and runtimeconfig
at the v5.18 baseline; every staged asset present and hash-pinned; app directory
present and not linked; and no `*.r9-tmp` collision at any install destination.

Then: back up the v5.18 manager pair and verify the backup hashes; install
v5.19 (dll + runtimeconfig, temp + rename, owner `201:0`, mode `755`, package
SMACK label preserved); create the module directory with `0:0`, `755`, label
`_`, and install `boot.sh` 0755 plus `module.json`, `UepGateHost.dll` and its
runtimeconfig at 0644; create `uep-off.conf` = `read-only\n` at `0:0:644`,
label `_`; run the host manually as root and require exactly
`uep gate (manual) uid=0: read-only: enforcing` and
`uep gate: read-only manual: enforcing … (zero stores)`, with budget state
absent before and after.

Owner power-cycles. Bounded polling verifies a distinct boot, a fresh
zero-identity automatic proof, manager v5.19 `449cf034…`, the module's own
receipts and `uep gate module exit=0` in the boot-scoped
`module-uep-gate.log`, the enforcing fingerprint, the 24-file protected register
byte-identical, and the bridge active. HDMI/GameMode/picture sanity is an
**owner visual** check performed at the TV; the driver does not inspect video.
(PLAN correction: the driver reads module-uep-gate.log, the boot-scoped log, not
the runner's append-only, boot-id-less `modules.log`.)

### Stage 2 `LIVE_ARM_ACTIVE` (one owner reboot)

Root op `gate-config-active:<boot>`: require the read-only bytes, hash and
metadata; atomically replace with `active\n`; receipt before/after. No probe
runs in this op.

Owner power-cycles. Verification: this boot's cleared receipts
(`uep gate: cleared boot: c07bd300 00000000 00000000 000004e2 (one word,
neighbourhood pinned)` and `uep gate (boot) uid=0: cleared (boot)`) are awaited
with bounded polling **before** the budget state is required; budget state
`boot=<fresh boot id> clear=1 restore=0`; fdet reads immediately after boot,
at +10 min and at +30 min all `c07bd300 00000000 00000000 000004e2`. **Any
enforcing read is a STOP** — v5.19 has one invocation per boot, so a mid-boot
rearm means the design is insufficient and needs its own packet. No retry. This
is the stage that carries the owner-accepted budget-writer residual.

### Stage 3 `LIVE_ARM_DISABLE` (one owner reboot)

Root op `gate-remove:<boot>`: requires the active bytes, hash and metadata and
the **present, current-boot, byte-exact** budget receipt; unlinks; receipts
`GATE_CONFIG_REMOVED_COMPLETE` / `GATE_ABSENT`. The receipt check is a SHA-256
of `boot=<current> clear=1 restore=0\n`, so a NUL, an extra line or a different
boot cannot pass; the writer's real `0666` metadata is accepted.

Owner power-cycles. Verification: bounded absent-config gate line, budget
absent or stale-but-never-fresh, enforcing fingerprint, 24-file register
byte-identical, manager v5.19 and bridge intact, and the denial control
(driver-side, uid 901): stage the pinned 5 196-byte ELF once under the bounded
watchdog, require `native_exit=126`, `Permission denied`, no
`QN90B_UEP_NATIVE_PROBE_OK` marker, then remove staging. SPENT at the
enforcing-only baseline.

## Failure and recovery

- No host action before `require_openssl()`; no attempt is taken when host
  tools are incomplete; the resolved openssl path is receipted.
- Any failure after the attempt is taken: STOP + failed status, never replay.
- Before any store: STOP leaves the TV enforcing.
- After a clear: the packaged default restores enforcing at the next boot once
  the config is gone. Recovery is the reviewed `gate-remove:<boot>` op; no
  automated retry and no config re-creation outside this packet.
- Manager rollback: restore the backed-up v5.18 pair from evidence, reboot.
- STOP blocks the stage drivers, so recovery after a failed stage is a
  separately reviewed execution path, not a driver rerun.
- Keep the independent recovery relay/reachability path available throughout.

## Authoring state (2026-11-14)

Host-side and complete through the pre-seal state:

- ported from the sealed r13 by digest (`port_from_r13.py` / `port-from-r13.json`);
  every difference from r13 is recorded with a reason and re-checked at seal;
- the inspection and protected register are carried from r12 because the
  device is unchanged and no TV write occurred; the boot and 25-file register
  still match;
- the three fifth-review findings are fixed and guarded in `offline_checks.py`;
- `session_checks.py` has 37 cases and `mutation_checks.py` kills all 20 listed
  defects with their intended terminal-line assertions before the seal;
- `authoring_checks.py` bakes, builds at 0 warnings, and pins the receipt
  constants to the C# that emits them.

Remaining, in order: `prepare.py` live bake -> `offline_checks.py` seal ->
**independent read-only review** -> owner arming (including the explicit
stage-2 residual acceptance above).

## Out of scope

Kernel patch or image change; automatic re-clear after a mid-boot rearm;
persistent supervisor/daemon; config creation or activation outside the three
reviewed ops; any second execution of `uep-probe.elf`; other Samsung security
layers (SMACK/SELP, app signing, Secure Boot/TEE/DRM); the v5.20 exclusive-create
build and any TV contact during authoring.
