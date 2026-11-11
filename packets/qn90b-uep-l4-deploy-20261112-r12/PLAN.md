# r12 — QN90B UEP L4 v5.19 root-context gate (successor to the stopped r11)

r12 is the successor to r11, which was sealed and then rejected by its own
independent read-only review **before arming** (1 blocker, 3 majors, 2 minors).
No r11 stage ever ran, nothing was armed, and no TV write occurred. r9 and r10
were rejected the same way. r12 keeps every earlier fix and closes the third
review.

## What changed from r11 (third review)

| # | r11 defect | r12 fix |
|---|---|---|
| B1 | the removal guard required `0644`, but the root context runs Umask 0000 and `UepGate.SaveBudget` lands the state file `0666`; a legitimate disable would STOP with the active config installed | the guard checks the writer's real shape — regular, single-linked, root-owned — and no longer pins a mode |
| M1 | a stale receipt from another boot and a receipt with extra lines were accepted | the guard reads `/proc/sys/kernel/random/boot_id`, requires exactly one line (`wc -l = 1`), and requires the exact `boot=<current> clear=1 restore=0` text |
| M2 | the pre-write `$state.tmp` refusal was represented as closing the host's write, but it cannot cover the check-to-write window inside `SaveBudget` | the claim is corrected and the residual is recorded in `packet.BUDGET_WRITER_RESIDUAL` and below; the pre-write refusal stays as a boundary check only |
| M3 | four session-suite mutants survived: canned capture fixtures, a fallback EXPECTED set, an absent-file case that could drop its row, and untested `prepare_upload` / missing `state_tmp` paths | the suite now executes generated captures against real files, requires the real 24-entry EXPECTED set, keeps the absent-file row, calls `sdk.prepare_upload` on the real assets, requires a missing `state_tmp` key to STOP, covers clean EOF, and is checked by a 14-mutant harness |
| m1 | a log with no `uep gate module exit=` line satisfied the module-gate wait | `module_gate` requires exactly one exit line and it must be `exit=0` |
| m2 | PLAN promised a `modules.log` check and a driver-side HDMI/GameMode/picture check that the driver does not perform | PLAN correction: the driver reads the boot-scoped `module-uep-gate.log` (not the runner's `modules.log`), and the HDMI/GameMode/picture check is **owner visual**, not driver-automated |

No repository code changes are part of r12. The shipped v5.19 bytes are the
same; only the packet, its embedded removal script, and the test layer change.

## Budget-writer residual (owner decision)

`UepGate.SaveBudget` builds `uep-state.conf.tmp` with `File.WriteAllText` and
then renames it. `WriteAllText` follows a symlink and truncates an existing file,
so a temp path planted between the packet's pre-write check and the host's write
could redirect that root write. The pre-write refusal detects a path planted
before the stage starts; it cannot close the race inside the host.

The complete fix is an **exclusive create** in `SaveBudget`, which changes the
shipped manager/host bytes and requires a new v5.20 build, new PREV/NEW pins, a
PR and CI (tracked as task 40). r12 does not carry those bytes.

Arming stage 2 (`LIVE_ARM_ACTIVE`) therefore proceeds only with the
**owner-accepted residual** above: the reviewer and owner accept that the
check-to-write window in the current v5.19 writer is not closed by this packet.
Stage 1 and stage 3 do not arm a store through `SaveBudget`. This acceptance is
required again at the explicit stage-2 arming gate; a future v5.20 build retires
the residual.

## Session/mutation coverage (r12)

`session_checks.py` has 30 cases. The ones that close the review:

- `upload-contract` runs `sdk.prepare_upload` on every real staged file and
  proves an unreviewed name and a target outside the owned stage are refused.
- `module-files-*` runs the exact generated capture against real files through a
  path-mapping shim; a changed byte, a changed mode, a missing directory or an
  unkeyed line STOPs.
- `protected-set` requires the real EXPECTED set, its 24 paths, and every hash
  sourced from the fresh register; the fallback is gone.
- `protected-closeout-*` rejects drift, an extra line, a swapped order, a short
  response and a duplicate line.
- `stage-sh-*` covers publish, clean EOF (a valid final row without a newline),
  an unlisted file, an absent file whose manifest row stays, and an unterminated
  wrong final row.
- `state-*` proves the capture emits every key, and a missing `state_tmp` key, a
  present temp path or a malformed value STOPs.
- `module-gate-*` accepts the three valid boot logs and rejects a missing,
  duplicate or nonzero exit, an unexpected line, a stale log and a missing
  required shape.

`mutation_checks.py` applies 14 exact defects (the r11 guard shape, the dropped
temp check, the widened upload whitelist, the removed stage containment, the
restored runtimeconfig, the removed module-content/exit/order checks, the
absence and EOF mutants, and the three state-capture mutants), requires the
mapped case to fail, restores every file and verifies its SHA-256. The seal
refuses if any mutant survives.

## Stages (unchanged from r11 except the removal guard)

The deployment goal and device baseline are unchanged: deploy manager v5.19,
prove the UEP gate runs in the root boot module with a read-only config,
activate the config and verify the guarded clear on a fresh boot, then disable
it and re-verify the enforcing-only baseline plus the hash-locked unsigned
execution denial control. Three owner-armed stages, one owner power-cycle each,
one attempt per stage, never replayed.

Source is `8f92e54` (merge of PR #24). The device is at boot
`0404f29a-1277-44bb-bee7-5b77a0b3b6bc`, enforcing fingerprint
`c07bd300 00000001 00000000 000004e2`, manager v5.18, no gate config, no module
and no budget state.

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
the **present, single-line, current-boot** budget receipt; unlinks; receipts
`GATE_CONFIG_REMOVED_COMPLETE` / `GATE_ABSENT`. The guard accepts the writer's
real `0666` metadata and does not pin a mode.

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

## Authoring state (2026-11-12)

Host-side and complete through the pre-inspection state:

- ported from the sealed r11 by digest (`port_from_r11.py` / `port-from-r11.json`);
  every difference from r11 is recorded with a reason and re-checked at seal;
- the six third-review findings are fixed and guarded in `offline_checks.py`;
- `session_checks.py` has 30 cases and `mutation_checks.py` kills all 14 listed
  defects before the seal;
- `authoring_checks.py` bakes, builds at 0 warnings, and pins the receipt
  constants to the C# that emits them.

Remaining, in order: fresh read-only inspection (own approval) -> `prepare.py`
live bake -> `offline_checks.py` seal -> **independent read-only review** ->
owner arming (including the explicit stage-2 residual acceptance above).

## Out of scope

Kernel patch or image change; automatic re-clear after a mid-boot rearm;
persistent supervisor/daemon; config creation or activation outside the three
reviewed ops; any second execution of `uep-probe.elf`; other Samsung security
layers (SMACK/SELP, app signing, Secure Boot/TEE/DRM); the v5.20 exclusive-create
build and any TV contact during authoring.
