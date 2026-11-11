# r14 — QN90B UEP L4 v5.19 root-context gate (successor to the stopped r13)

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
