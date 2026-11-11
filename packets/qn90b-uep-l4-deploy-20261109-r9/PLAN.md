# qn90b-uep-l4-deploy-20261109-r9 - v5.19 root-context UEP gate (DRAFT)

Status: **DRAFT / UNAUTHORED / UNARMED.** No code from this plan has run against
a television. Nothing here authorizes TV contact. Successor to the SPENT
`qn90b-uep-l4-deploy-20261109-r8`.

## Why r9 exists

r8 restored the enforcing-only baseline: gate config absent, budget state
absent, manager v5.18, fresh boot `0404f29a-...`, fingerprint
`c07bd300 00000001 00000000 000004e2`, 25 protected files intact.

The only recorded route to completing L4 is now the probe redesign (task 38):
v5.18's `UepGate` runs inside the manager app (uid 901,
`User::Pkg::ghservice::RO`) where `/usr/bin/dotnet` is not visible, so every
boot with a config present failed closed (`payload check failed: dotnet
missing`, live 2026-11-09 03:47:22Z). v5.19 relocates the same gate logic to a
root boot module and changes nothing about the clear itself.

## What v5.19 changes (host-side, in the tree)

| Path | Change |
|---|---|
| `boot-agent/uep-gate-host/{UepGateHost.csproj,UepGateHost.cs,Program.cs}` | new netcoreapp3.1 host; links `../UepGate.cs` **unchanged**; production paths; one receipt line; exit 0 for every fail-closed outcome |
| `modules/uep-gate/{module.json,boot.sh}` | boot module: runs `/usr/bin/dotnet "$MODULE_DIR/UepGateHost.dll" boot` as uid 0; no store path of its own; `uep-gate` sorts after `bridge-service`, so the bridge is never delayed |
| `boot-agent/Program.cs` | v5.19; `RunUepGate` and both call sites removed; the app no longer attempts the probe |
| `boot-agent/boot-agent.csproj` | `UepGate.cs` removed from the app assembly; still compiled by the host and tests |
| `boot-agent/selftest/UepGateHostSelfTest.*` | host contract: absent / invalid / read-only / active / probe failure; exit 0; budget discipline |
| `boot-agent/README.md` | gate section rewritten for the root host |

Gate behaviour is deliberately byte-identical: same config modes, same
`ClearBudget=2` / `RestoreBudget=1`, same fingerprint words, same
`0x208c26c0` page and word offset, same refusal-consumes-attempt rule, same
never-`0x808c26c0` rule. The existing 20+ case `UepGateSelfTest` still covers
that logic unchanged. This packet reviews a relocation, not new clear logic.

## Candidate artifact pins (recomputed and sealed at authoring time)

| Artifact | sha256 |
|---|---|
| manager v5.19 `com.samsung.tv.ghservice.dll` | `449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c` |
| `UepGateHost.dll` | `3b1e3a80dcb4b6aab8ad4c97bea6bf24ae536fe3a90b633e9e6a3755cf217d1f` |
| `UepGateHost.runtimeconfig.json` | `ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38` |
| `modules/uep-gate/boot.sh` | `1afd5b7c8c4158714726e627f70ef72adcb394e0e3db3eb563609fd41d2456b0` |
| `modules/uep-gate/module.json` | `63b13c8439e4bcf94cd186406641a2a81368896cf43c8355b67352e6294177f5` |
| installed v5.18 manager (rollback source, r8 artifact) | `e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a` |
| FdetProbe pair (already on TV, L2-validated) | `2cfec6d1...` / `2c6dd613...` |
| unsigned denial probe `uep-probe.elf` | `d1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d` |
| `uep-off.conf` read-only bytes (`read-only\n`) | `ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de` |
| `uep-off.conf` active bytes (`active\n`) | `45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659` |

The packet pins source commit `8f92e54346a6d89ecda4ce540c341d855b8646a6`
(merge of PR #24, which carries the v5.19 change). The seal rebuilds from a
clean checkout of that commit and must reproduce the artifact hashes below.

## One packet, three separately armed stages

Each stage: its own content-addressed arm marker, its own one-attempt file, its
own root session (one authenticated op per session), its own owner power-cycle.
A failure **after** an attempt is taken writes STOP and the stage is never
replayed. A failure before it leaves the attempt intact.

### Stage 1 `LIVE_ARM_INSTALL` (one owner reboot)

Root op `gate-install:<inspection boot id>` (one script, one session, one
attempt). All refusals run before the first write: config/state/module/backup
absent, manager dll + runtimeconfig exactly the v5.18 baseline bytes, staged
bytes exactly the packet artifacts.

1. Back up the installed manager dll + runtimeconfig to
   `<evidence>/r9-manager-backup/`; verify the backup hashes.
2. Install manager v5.19 (dll + runtimeconfig, temp + rename), verify shas.
3. Install `/opt/usr/share/selfroot/modules/uep-gate/`:
   `boot.sh` 0755 LF-only, `module.json`, `UepGateHost.dll`,
   `UepGateHost.runtimeconfig.json` (no `.dev.json`); verify shas, reject
   symlinks, create the directory only if absent.
4. Create `uep-off.conf` = `read-only\n`, `0:0:644`, label `_`, hash
   `ef589842…`, from a temp file; verify metadata and label.
5. Run the host manually as root: `/usr/bin/dotnet /opt/.../UepGateHost.dll manual`.
   Require exactly `uep gate (manual) uid=0: read-only: enforcing` and
   `uep gate: read-only manual: enforcing … (zero stores)`, and require the
   budget state file absent before and after.

Owner power-cycles. Bounded polling (never single-shot, decision 28) verifies:

- distinct boot id and a fresh zero-identity automatic proof;
- `agent.log` manager v5.19 boot line; installed manager sha `99f9b1b4...`;
- `modules.log` contains `run uep-gate` and its exit; `module-uep-gate.log`
  contains `uep gate (boot) uid=0: read-only: enforcing` plus the detail line
  `uep gate: read-only boot: enforcing c07bd300 00000001 00000000 000004e2
  (zero stores)`;
- budget state absent; fingerprint via fdet read `c07bd300 00000001 00000000 000004e2`;
- 25-file protected register byte-identical (manager hash pinned separately);
- `tvroot-bridge.service` active; manager quiet-exit; HDMI/GameMode/picture sanity.

This stage proves the two unknowns before any store is possible: root-context
host execution at boot, and the module log being readable in the manager. No
flag value is ever written here.

### Stage 2 `LIVE_ARM_ACTIVE` (one owner reboot)

Root op `gate-config-active:<boot>`: require current bytes hash `ef589842...`,
same metadata/label; atomically replace with `active\n` (`45df5ad5...`);
receipt the before/after hashes and metadata. No probe runs in this op.

Owner power-cycles. Verification:

- `module-uep-gate.log` contains the clear lines
  `uep gate: cleared boot: c07bd300 00000000 00000000 000004e2 (one word, neighbourhood pinned)`
  and `uep gate (boot) uid=0: cleared (boot)`;
- budget state `boot=<fresh boot id> clear=1 restore=0`;
- fdet read immediately after boot, at +10 min and at +30 min, each
  `c07bd300 00000000 00000000 000004e2` (cleared). **Any enforcing read is a
  STOP**: v5.19 has one invocation per boot, so a mid-boot rearm would mean the
  design is insufficient and a supervised pass needs its own packet. No retry.
- 25-file register byte-identical; bridge active; owner-visible behavior
  intact. The TV stays in ACTIVE with the standing unsigned-exec exposure that
  decision 16 already owner-accepted.

### Stage 3 `LIVE_ARM_DISABLE` (one owner reboot)

Root op `gate-remove:<boot>`: r8's removal body re-pinned to the active bytes
(`45df5ad5...`); requires the exact metadata/label; unlinks; receipts
`GATE_CONFIG_REMOVED_COMPLETE` / `GATE_ABSENT`.

Owner power-cycles. Verification:

- bounded absent-config gate line (`uep gate (boot) uid=0: config absent
  (enforcing; no action)`), budget state absent or stale-but-never-fresh;
- enforcing fingerprint read;
- 25-file register byte-identical; manager v5.19 and bridge intact;
- denial control, driver-side over the SDK shell (uid 901, the exact context
  the L1 packet proved): stage the pinned 5196-byte ELF under a freshly created
  owned staging directory, execute it exactly once under the bounded watchdog,
  require `native_exit=126` and **no** `QN90B_UEP_NATIVE_PROBE_OK` marker, remove
  staging, receipt hashes;
- SPENT. Packet closed at the enforcing-only baseline.

## Failure and recovery rules

- No host action before `require_openssl()` (r8 guard); no attempt taken when
  host tools are incomplete; the resolved openssl path is receipted.
- Any failure after the attempt is taken: STOP + failed status, never replay.
- Before any store: STOP leaves the TV enforcing; recovery is
  `gate-remove:<boot>` (or leaving the read-only config, which is inert).
- After a clear: the packaged default restores enforcing at the next boot once
  the config is gone. Recovery is remove-config then reboot via the reviewed
  op; no automated retry, no config re-creation outside this packet.
- Manager rollback: restore the backed-up v5.18 dll/runtimeconfig
  (`e2b14b49...`) from evidence, reboot. The module can be removed
  independently; an absent module means no gate at boot.
- Keep the independent recovery relay/reachability path available throughout
  (r7/r8 machinery).

## Authoring progress (2026-11-09)

Authoring is COMPLETE through the pre-seal state; the seal itself waits for the
fresh inspection because its boot/proof pins do not exist before TV contact.

Done in the packet directory, host-side only:

- packet.py: r9 constants, baseline/installed-state assertions, three markers,
  exact v5.19 receipt strings, canonical LF artifact pins.
- inspect_tv.py: pins the v5.18 manager dll + runtimeconfig, absent
  config/state/module/backup; emits target_rc_hash, module_dir, backup_dir.
- prepare.py: bakes the three single-edge scripts (gate-install.sh,
  gate-config-active.sh, gate-remove.sh); no boot pin is baked, every
  transition pins bytes + metadata + label, and every refusal precedes writes.
- UepGateAgent.cs/.csproj: three ops, one gate change per session, 12-180 s
  timeout bound; builds at 0 warnings with the pinned SDK 3.1.426.
- Drivers: install.py (stage 1), active.py (stage 2), disable.py (stage 3),
  over the shared stage_session.py + stage_common.py; stages 2 and 3 anchor to
  the previous stage verified fresh boot/proof, never the inspection boot.
- denial.py: driver-side uid 901 staging + one bounded execution, ported from
  the L1 packet.
- flow_cases.py + driver_shim.py: 13 host script-transition cases under the
  real Git-Bash shim (real hashes/cp/mv/rm/symlinks, modelled
  uid/mode/link/smack): install happy + 4 refusals, activation happy + 3
  refusals, removal happy + 2 refusals, and the bake-shape case.
- authoring_checks.py, offline_checks.py, driver_checks.py, port_from_r8.py +
  port-from-r8.json (11 verbatim carries verified, 27 deltas documented).

Rehearsal finding fixed before any seal: 	est A && test B does not abort
under set -e when A fails. The scripts now use one test per line (the
function-level || return 1 form remains); authoring_checks and
offline_checks reject the pattern.

Remaining, in order: fresh read-only inspection (own approval) -> prepare.py
live bake -> offline_checks.py seal -> independent read-only review -> owner
arming.

## Authoring checklist (open items)

1. Scoped agent (`UepGateAgent`, one op per authenticated session):
   `phase1-snapshot`, `gate-install:<boot>`, `gate-config-active:<boot>`,
   `gate-remove:<boot>`; every op asserts the expected boot and refuses the
   bare op name; the command timeout is bounded to 12–180 s (install runs the
   host once).
2. Port r8's 48-entry seal by digest; add the five v5.19 artifacts; rebuild the
   agent under pinned SDK 3.1.426 with `DOTNET_MULTILEVEL_LOOKUP=0`,
   0 warnings enforced by parsing MSBuild's summary.
3. Rerun: `UepGateSelfTest`, `UepGateHostSelfTest`, `LaunchContextSelfTest`,
   `BridgePortSelfTest`, pytest (openssl on PATH), ruff, shell LF + `bash -n`,
   release audit.
4. Rehearsal cases: refusals for wrong boot, wrong current config hash,
   pre-existing budget state, symlinked staging, missing host file, missing
   probe hash, and the exact receipt strings the driver polls.
5. Fresh read-only inspection at TV-contact time; it re-pins boot, proof,
   protected register, manager hash and config absence. Never reuse r8's pins.
6. Seal, then a second, independent read-only review of the sealed bytes
   before any owner arming.

## Explicitly out of scope

Kernel patch or image change; automatic re-clear after a mid-boot rearm;
persistent supervisor/daemon; config creation or activation outside the three
reviewed ops; any second execution of `uep-probe.elf`; other Samsung security
layers (SMACK/SELP, app signing, Secure Boot/TEE/DRM); any TV contact in this
session.
