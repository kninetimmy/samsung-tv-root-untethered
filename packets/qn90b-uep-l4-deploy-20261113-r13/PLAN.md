# r13 — QN90B UEP L4 v5.19 root-context gate (successor to the stopped r12)

r13 is the successor to r12, which was sealed and then rejected by its own
independent read-only review **before arming** (0 blockers, 2 majors, 1 minor).
No r12 stage ever ran, nothing was armed, and no TV write occurred. r13 keeps
every earlier fix and closes the fourth review.

## What changed from r12 (fourth review)

| # | r12 defect | r13 fix |
|---|---|---|
| M1 | the new exit-presence requirement STOPped on the first read when a fresh module log was still partial, so a normal startup race could permanently stop the active stage with the active config installed | `module_gate` keeps polling a partial log; a duplicate or nonzero exit still stops immediately, and a persistent missing exit or missing required shape fails only when the bounded poll is exhausted |
| M2 | the suite still missed the required-shape guard (its "missing shape" case supplied an unexpected line), and the exit-presence mutant died from an `IndexError` that the harness counted as a kill | session suite has proper missing-summary and missing-detail cases plus a startup-race case; the mutation harness requires each mutant to fail with its intended assertion message and records diagnostics, so an unrelated crash does not count |
| m1 | the removal receipt check was not byte-exact: Bash command substitution drops NUL bytes, so an embedded NUL or an appended LF+NUL could pass and reach the unlink | the guard now compares the state file by SHA-256 against the exact current-boot one-line bytes; NUL-padded and embedded-NUL receipts are refused |

Everything from r12 is carried: the writer's real `0666` metadata is accepted,
the receipt is bound to the current boot, the removal guard still checks the
active config bytes/metadata/label, the budget-temp pre-check is documented as a
residual, and the module log/display PLAN corrections stand.

No repository code changes are part of r13. The shipped v5.19 bytes are the
same; only the packet, its embedded removal script, and the test layer change.

## Budget-writer residual (owner decision)

`UepGate.SaveBudget` builds `uep-state.conf.tmp` with `File.WriteAllText` and
then renames it. `WriteAllText` follows a symlink and truncates an existing file,
so a temp path planted between the packet's pre-write check and the host's write
could redirect that root write. The pre-write refusal detects a path planted
before the stage starts; it cannot close the race inside the host.

The complete fix is an **exclusive create** in `SaveBudget`, which changes the
shipped manager/host bytes and requires a new v5.20 build, new PREV/NEW pins, a
PR and CI (tracked as task 40). r13 does not carry those bytes.

Arming stage 2 (`LIVE_ARM_ACTIVE`) therefore proceeds only with the
**owner-accepted residual** above: the reviewer and owner accept that the
check-to-write window in the current v5.19 writer is not closed by this packet.
Stage 1 and stage 3 do not arm a store through `SaveBudget`. This acceptance is
required again at the explicit stage-2 arming gate; a future v5.20 build retires
the residual.

## Session/mutation coverage (r13)

`session_checks.py` has 35 cases. The ones that close this review:

- `module-gate-waits-for-exit` feeds an empty first log and a completed second
  log: the first partial read must not STOP.
- `module-gate-rejects-persistent-missing-exit` exhausts the poll with no exit
  line and requires a STOP.
- `module-gate-rejects-missing-detail` and `module-gate-rejects-missing-summary`
  supply only one required shape plus the exit line; the final shape guard must
  STOP.
- `protected-closeout-rejects-order-synthetic` uses two paths with the same
  digest, so only the order guard can catch the swapped response.
- the removal boundary is pinned by the r12 cases plus LF+NUL and embedded-NUL
  receipts, all refused by the byte-exact hash.

`mutation_checks.py` applies 18 exact defects, including the immediate-STOP
race, the removed shape guard, the removed exit wait, the two NUL-accepting
receipt guards, and the r11 grep guard. Every mutant must exit non-zero **and**
contain the intended assertion message; the harness restores every file and
verifies its SHA-256. The seal refuses if any mutant survives or dies for the
wrong reason.

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

## Authoring state (2026-11-13)

Host-side and complete through the pre-seal state:

- ported from the sealed r12 by digest (`port_from_r12.py` / `port-from-r12.json`);
  every difference from r12 is recorded with a reason and re-checked at seal;
- the inspection and protected register are carried from r12 because the
  device is unchanged and no TV write occurred; the boot and 25-file register
  still match;
- the three fourth-review findings are fixed and guarded in `offline_checks.py`;
- `session_checks.py` has 35 cases and `mutation_checks.py` kills all 18 listed
  defects with their intended assertions before the seal;
- the first host seal was withdrawn before any review or arming when a
  self-check found the same startup-race class in a partially written log line;
  the final seal supersedes it after adding the partial-line poll and its
  mutant. No TV contact occurred between the two seals;
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
