# QN90B UEP L4 combined deploy + validation packet (r1)

Target: QN55QN90BAFXZA / build T-PTMAKUC-REL-202602250225 (Tizen 6.5,
Linux 5.4.77, .NET 3.1.3, manager currently v5.17).

Status: **PREPARED, nothing authorized.** No TV contact and no TV-state
change has happened for this packet. Every stage below requires an explicit,
fresh user approval that writes its one-time marker into this packet
directory; without the marker the packet scripts refuse to proceed.

## Artifacts (staged here, SHA256-verified)

| Artifact | SHA256 | Source |
|---|---|---|
| manager.dll (v5.18) | e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a | boot-agent c51fbcc (PR23, master at 847443c), built netcoreapp3.1 with SDK 3.1.426 + cached TV framework refs |
| manager.runtimeconfig.json | 2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b | same build |
| FdetProbe.dll | 2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb | the exact bytes validated live in the spent L2/L3 packet (L1 payload dir) |
| FdetProbe.runtimeconfig.json | 2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b | same |
| uep-probe.elf | d1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d | the hash-locked probe admitted live in L3 |

The manager SHA pins are recorded as constants in `packet.py`; `OLD_SHA`
there is the installed v5.17 manager
(`eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1`).

## TV-state targets

- Manager: `/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll`
  (guarded replace; existing v5.17 backup verified; original v5.13 backup
  retained).
- Payload home (new): `/opt/usr/share/selfroot/fdetprobe/` — FdetProbe.dll +
  FdetProbe.runtimeconfig.json, copied once per boot from staging semantics
  with owner/mode/SMACK labels preserved (deployed once, hash verified).
- Gate config (new): `/opt/usr/share/selfroot/uep-off.conf` — created only in
  stages that have their own approval; content `read-only`, then `active`;
  removed for the disable-path validation. Never exists unless a stage
  created it.

## Stages (combined packet, one TV session; markers gate each stage)

0. **Offline (no TV contact)** — packet.py self-checks, artifact hash
   checks, `UepGateSelfTest` re-run, SDK staging skeleton compiled. Done at
   packet creation; receipts recorded here.
1. **Deploy (approval marker `LIVE_ARM_DEPLOY`)** — the guarded v5.16/v5.17
   flow: SDK baseline (identity/boot/devIP+mode/proof/pairing/24 protected
   hashes/startup/port-config with manager sha = OLD), temporary recovery
   relay validated, temporary archive-root, root-context snapshot checks,
   `manager-apply` v5.18 (one attempt, `MANAGER_UPDATE_COMPLETE` receipt, no
   retry; failure → bounded rollback to v5.17), remove root, SDK verified.
   Then fdetprobe payload deployment (same root-guarded session semantics as
   L2 staging; hash+metadata preserved; staging cleaned). No gate config is
   created in this stage. Also disallowed in this stage: reboots, settings
   changes, protected-hash changes.
2. **Watch (approval marker `LIVE_ARM_WATCH`)** — verify v5.18 relaunches
   naturally (hourly same-boot relaunch or intentional SDK opening), shows
   `v5.18` banner, and agent.log contains
   `uep gate (reopen): config absent (enforcing; no action)` with **zero**
   CAS stores and unchanged bridge/root proof. This is the pure negative
   control: absent config must do nothing.
3. **Read-only fingerprint (approval marker `LIVE_ARM_DIRREAD`)** — install
   `/opt/usr/share/selfroot/uep-off.conf`
   content `read-only` (guarded create, preserves dir), observe one
   manager launch: agent.log must contain the `read-only (boot|reopen):`
   line with the enforcing fingerprint and zero stores. This validates that
   the manager's root context can open the FDET device (the one unknown of
   the design). No store can occur in this stage by construction.
4. **Active + reboot (approval marker `LIVE_ARM_ACTIVE`)** — switch the
   config to `active`, then an explicitly approved reboot (established
   Linux reboot helper route, or user power-cycle at the TV). After the new
   BOOT_ID: fresh all-zero identity proof as SDK; agent.log shows
   `uep gate (boot): cleared (boot)` with the pinned one-word change; the
   staging-free SDK run recomputes the fingerprint and re-runs the staged
   hash-locked uep-probe once, expecting `QN90B_UEP_NATIVE_PROBE_OK` +
   `native_exit=42`; all 24 protected hashes unchanged; bridge alive.
   End state: cleared while the config exists.
5. **Disable path (approval marker `LIVE_ARM_DISABLE`, may be deferred to a
   later session)** — remove the config, approved reboot; verify enforcing
   restored (fresh boot id, `read-only`-style final read or next watch shows
   enforcing), all 24 protected hashes unchanged.

Any stage may stop the packet permanently; later stages keep their own
gates. A watchdog/timeout failure never retries — SPENT means spent.

## Invariants and failure behavior

- The TV must never be driven outside SDK-staging + root-agent guarded
  writes; every remote command is bounded and receipted.
- The CAS surface stays exactly: physical `0x208c26c0`, word 1,
  compare-before-write, full 24-word neighbourhood pinned in-payload
  (enforced by FdetProbe's neighbour-check and the manager's receipt
  parse). Never `0x808c26c0`, never a scan, never a fallback.
- Boot reapplication is the manager's CAS at boot — never a kernel patch.
- The packaged default re-applies enforcement at every boot; deleting
  `uep-off.conf` + reboot is always sufficient recovery, regardless of
  anything this packet did.
- Reboots: only stage 4/5, only after their own fresh approval; each
  reboot later than 2 in one packet session requires a new packet.
- Protected hashes, developer settings, startup fields, bridge token and
  pairing config are re-verified around every irreversible step.

## Offline status at preparation time

- Manager v5.18 built and hash-logged (see artifacts table).
- UepGateSelfTest: PASS (23 fail-closed scenarios).
- BridgePort/AutoClose/LaunchContext self-tests: PASS after the gate commit.
- PR23 merged to master at 847443c; post-merge CI all 10 jobs green.
- SDK 3.1.426 installed locally, SHA512 verified vs the official
  checksums/3.1.32-sha.txt (dotnet-sdk-3.1.426-win-x64.zip = ca5c6089...1261).
- Deploy machinery authored (ported from the proven
  qn90b-manager-quiet-deploy-20261102-r1 flow, extended for L4):
  - `deploy.py` — guarded Deployment: SDK baseline → recovery relay →
    temporary archive-root → root snapshot checks → `manager-apply` v5.18
    → **`fdet-install`** (payload hash+metadata receipts; EXPECTED merges
    the FDET hashes only after its receipt) → bounded rollback on any
    failure (v5.17 restored) → closeout; one-use; refuses without
    `LIVE_ARM_DEPLOY` (content = COMMIT + NEW_SHA).
  - `prepare.py` — generates `repair.sh`/`rollback.sh`/`status.sh` +
    **`fdet.sh`** (creates `/opt/usr/share/selfroot/fdetprobe/` with
    hash-verified payload files, labels and modes copied from the
    inspection-recorded reference metadata of `/opt/usr/share/selfroot`)
    and the three `gate-*.sh` ops (write `read-only`/`active`, remove:
    hash-pinned value checks, 0:0:0644, label preserved; each prints its
    own completion marker and refuses any pre-existing foreign content).
  - `BridgeRepairAgent.cs` — op map extended: `fdet-install`
    (one attempt/session), plus `gate-readonly`/`gate-active`/`gate-remove`
    (one gate change per session); embedded-resources csproj updated.
  - `stage.sh` — packet stage token `archive-root-a553e5ee83632f83`, files
    list carries the FdetProbe payload pair alongside the manager.
  - `offline_checks.py` — full post-prepare rehearsal (structural script
    checks incl. the fdet/gate receipts, agent binary upload bound, unsafe
    upload targets, mocked publisher guards, manager_absent guard matrix,
    guarded baseline overlays, sealed packet writes `seal.json`).
  - `precheck_offline.py` + `precheck.json` — the pre-inspection rehearsal,
    RUN AND PASSED (57 checks): parses, normalization, artifact hashes,
    script-channel oversize refusals, unsafe upload targets, marker gate
    semantics for all five markers, git-head pinning, wiring greps.
- `manager.before.dll` staged (installed v5.17 bytes, digest verified).

## Not yet done (prep TODO)

- Read-only inspection at TV-contact time (its own light approval), which
  produces `inspection.json` (identity, hashes, target/selfroot metadata,
  labels, gate-config absence, fdet-home absence).
- `prepare.py` run (offline; expansion of the baked constants), agent
  build, and the full `offline_checks.py` (+ `seal.json`).
- The identical watch/config/reboot stage driver scripts (stages 2–5)
  reuse this machinery; they are authored after the inspection template is
  materialized, with their own markers, before any TV write happens.
- Owner marker authorizations one stage at a time at TV-contact time.
