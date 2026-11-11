# r10 — QN90B UEP L4 v5.19 root-context gate (successor to the stopped r9)

r10 is the successor to r9, which was **sealed and then rejected by an
independent read-only review before arming** (5 blockers, 5 majors). No r9
stage ever ran, nothing was armed, and no TV write occurred. r10 exists to fix
that review, not to change the deployment goal.

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

## What changed from r9 (each maps to a review finding)

| # | r9 defect | r10 fix |
|---|---|---|
| B1 | the upload whitelist rejected 5 of 8 install assets, and `stage.sh` demanded FdetProbe files no gate session stages | `sdk.UPLOAD_NAMES` names the v5.19 assets; `stage.sh` derives its allowed/required set from `files.sha256` instead of a hardcoded list |
| B2 | every all-small session deleted a gzip staging directory that was never created | `stage_transport.ensure_host_dir()` runs before the route decision; the same directory is removed at the end |
| B3 | the protected set still pinned the manager runtimeconfig the install replaces, so a successful install failed closeout | both manager files leave the pre-install set; the runtimeconfig is pinned per baseline by `stage_common.state()` |
| B4 | module capture emitted one keyed line plus three bare lines, which `fields()` rejects | one keyed line per path (`boot_mode=`, `json_mode=`, `host_mode=`, `rc_mode=`, `dir_meta=`) |
| B5 | `mkdir` under `umask 077` left the module directory root-owned 0700, unreadable by uid 901 | the install sets and verifies owner/mode/label on the directory itself |
| M1 | activation required the budget file immediately after the boot poll, before the gate had run | the active stage waits for this boot's module receipt (bounded, 24 probes) before requiring the store |
| M2 | a `.r9-tmp` collision was refused only after the manager was replaced | every temp collision is refused before the backup and the first write |
| M3 | the rehearsal re-baked templates and never exercised staging/closeout/parsing | new `session_checks.py` suite; the rehearsal now runs the sealed scripts when the live bake exists and must match the template render |
| M4 | `protect_seal()` accepted any manifest, and the inherited controller was unpinned | the manifest must equal `packet.SEAL_ENTRIES`; the controller and its baseline are digest-pinned before import |
| M5 | removal accepted an absent budget receipt | removal requires the active-boot budget receipt |

## Stage 1 `LIVE_ARM_INSTALL` (one owner reboot)

Root op `gate-install:<boot>`. Refusals, all **before any write**: config,
state, module directory and backup absent; manager and runtimeconfig at the
v5.18 baseline; every staged asset present and hash-pinned; app directory
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
zero-identity automatic proof, manager v5.19 `449cf034…`, the module run and
exit in `modules.log`, `uep gate (boot) uid=0: read-only: enforcing` plus its
detail line, budget state absent, the enforcing fingerprint, the 24-file
protected register byte-identical, the bridge active, and HDMI/GameMode/picture
sanity. This proves the two unknowns before any store is possible: root-context
execution at boot, and the module log being readable from the manager.

## Stage 2 `LIVE_ARM_ACTIVE` (one owner reboot)

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
rearm means the design is insufficient and needs its own packet. No retry.

## Stage 3 `LIVE_ARM_DISABLE` (one owner reboot)

Root op `gate-remove:<boot>`: requires the active bytes, hash and metadata and
the **present** active-boot budget receipt; unlinks; receipts
`GATE_CONFIG_REMOVED_COMPLETE` / `GATE_ABSENT`.

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

## Authoring state (2026-11-10)

Host-side and complete through the pre-inspection state:

- ported from the sealed r9 by digest (`port_from_r9.py` / `port-from-r9.json`);
  every difference from r9 is recorded with a reason and re-checked at seal;
- the ten review findings are fixed and guarded in `offline_checks.py`;
- `session_checks.py` covers the staging/session/closeout layer that r9 never
  exercised; `driver_checks.py` rehearses the transition scripts and runs the
  sealed bytes when the live bake exists;
- `authoring_checks.py` bakes, builds at 0 warnings, and pins the receipt
  constants to the C# that emits them.

Remaining, in order: fresh read-only inspection (own approval) -> `prepare.py`
live bake -> `offline_checks.py` seal -> **second independent read-only
review** -> owner arming.

## Out of scope

Kernel patch or image change; automatic re-clear after a mid-boot rearm;
persistent supervisor/daemon; config creation or activation outside the three
reviewed ops; any second execution of `uep-probe.elf`; other Samsung security
layers (SMACK/SELP, app signing, Secure Boot/TEE/DRM); any TV contact during
authoring.
