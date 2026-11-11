# qn90b-uep-l4-deploy-20261109-r2 — L4 continuation packet (stages 2-5)

Successor to the spent `qn90b-uep-l4-deploy-20261108-r1`. Stage 1 (guarded
v5.18 manager apply + FdetProbe install) completed live in r1 and is NEVER
replayed; r1's seal, receipts, backups, SPENT/STOP state and the
reconstructed-result provenance (post-mortem-20261108.md) remain untouched.
This packet carries only stages 2-5 on top of the already-installed verified
state, and bakes the repairs demanded by the 2026-11-08 review
(`.memhub/prep/qn90b-uep-l4-deploy-20261108-r1/glm-flash-review-20261108.md`).
Codex's second review found nine remaining defects; the host-only follow-up
below supersedes the original 67-case claim. The packet is still uninspected,
unsealed, unarmed, and has performed zero TV operations.

## Review findings -> r2 repairs

| # | Review finding | r2 repair | Where |
|---|---|---|---|
| 1 | Stage 4 refused the stage-3 config (script required absence) | transition-aware generator: create (absent->read-only, exclusive), replace (verified `read-only` content -> `active`, atomic mv -T, identical metadata/label/ownership/link), remove (verified `read-only`\|`active` content -> absent); foreign files, symlinks (incl. dangling), directories, wrong metadata/link counts and leftover temp files are REFUSE paths, never deletions | `prepare.py` (Prelude/CREATE/REPLACE/REMOVE bodies) |
| 2 | Disable pinned the original boot; missing imports; `fresh_boot: None` accepted | disable binds to the ACTIVE stage's receipted `fresh_boot` + `fresh_proof_sha256` (both mandatory); the expected boot travels through the authenticated root-agent op command `gate-remove:<boot id>` and is asserted inside the root shell; the baked remove script carries no boot pin; missing imports added | `disable.py`, `BridgeRepairAgent.cs` (GateOperation), `prepare.py` |
| 3 | Watch needed a manager alive at a poll instant; missing `re` | stage 2 redesigned as durable-evidence receipting (memhub decision 22): assesses the whole legacy gate-line set + interval growth of agent.log regardless of process sampling, bound by boot-start epoch and byte offsets; any EXCEPTION/foreign/malformed line stops the stage | `watch.py`, `stage_lib.gate_event_assessment` |
| 4a | Wrapped base64 broke proof capture | proof is captured as ONE terminated line (`base64 | tr -d '\n'; echo`), length-checked and digest-receipted | `activate.read_proof` |
| 4b | Pipeline status belonged to `head` | the probe's own exit status is captured BEFORE any pipe (`>uep-probe.out 2>&1` then `head -c 4096` reads the bounded file; no pipe controls $? anymore) | `activate.PROBE_RUN_BODY` |
| 4c | Cleanup `rmdir`ed a relative name from `/` | cleanup runs `cd -P <CANON>` then `rmdir -- <absolute stage path>` and asserts absence by the absolute path | `activate.PROBE_RUN_BODY`, `probe_stage_guard` |
| 4d | Disable never ran its denial test | implemented (owner decision 2026-11-09): the same staged, hash-locked probe runs once under the restored enforcer and must NOT print the marker and MUST exit 126 | `disable.main` (`staged_probe_run` prefix `l5-`) |
| 5 | Relay teardown omitted in active/disable | all three write stages call the shared `Deployment.finish` in `finally`; it closes root first, verifies ordinary SDK access, then applies identity-checked `recovery.stop`. Failed root operations also use this path. Missing ownership proof or incomplete root shutdown retains the relay and receipts its exact pending path | `deploy.Deployment.finish`, all write drivers |
| 6 | STOP/one-attempt not enforced | `refuse_if_stopped()` in every entrypoint; exclusive `OneAttempt` receipts; every failure or cancellation after taking the attempt writes/fsyncs STOP and failed status before re-raising. Success alone consumes the marker | `stage_lib.record_failure`, all four drivers |
| 7 | Post-fdett baseline compared an enlarged request against the 23-file snapshot (burned r1) | baseline compares the current 25-file path/hash map; boot/proof are immutable session constructor arguments, including for inherited zero-argument cleanup callbacks | `deploy.py` `Deployment.baseline`, `parse_hash_output` |

## Codex follow-up repairs (second review)

1. The authenticated removal boot check enables shell failure handling before
   the check and explicitly exits on mismatch. The agent also retains its
   one-gate-operation-per-session guard. Shell tests use the actual C# prefix.
2. Config probing explicitly returns on every metadata/label/link failure;
   invalid existing files cannot be mistaken for an absent config. Cases use
   correct labels alongside wrong modes/ownership and a real hard link.
3. Session boot/proof anchors are established once at construction. The original
   Trial cleanup callbacks remain compatible and keep their checks.
4. Recovery teardown is shared by success and failure paths; unknown ownership
   or unverified root shutdown produces pending cleanup and STOP.
5. Manager UTC timestamps accept the real seven-digit fractional format.
6. Active proof capture is awaited and exercised through the full driver flow.
7. Sealing validates all inputs, writes the report, hashes it, then creates the
   seal. Missing inputs write neither file; existing results/seals refuse.
8. Current-boot gate evidence requires the actual stage summary/detail pair.
   Config writes need no immediate manager-log growth. Read-only observation
   uses the pre-operation offset, so a valid early confirming launch is retained.
9. Negative tests no longer catch their own assertions. Deliberately disabling
   baseline, STOP, or log validators makes their tests fail.

`flow_cases.py` runs the actual four driver entrypoints with simulated SDK/root
transport and real validation/closeout. It covers three boot anchors, both probe
outcomes, operation/SDK failures, cancellation, missing cleanup ownership,
unverified root shutdown, stale evidence, timeouts, and first-use sealing.
`rehearsal-results.json` records the current complete suite outcome.
`host-build-results.json` records an offline netcoreapp3.1 build under SDK
3.1.426 with zero configured package sources and synthetic boot/label resources.
That temporary compile artifact is not a deployment build or live validation.
The repaired suite currently passes 87 case groups, including negative tests
that fail when validators are deliberately replaced by no-ops.

Historical correction: the first review described r1's existing-config path as
a guaranteed refusal. With its earlier ownership/canonical-path checks modelled
correctly, r1 actually continues past the failing AND-list absence guard and can
overwrite foreign config bytes. The revised differential reproduces this unsafe
overwrite; r2 refuses the same input without changing it. The spent r1 packet
and original review document remain historical records and were not edited.

## Packet layout

- `packet.py` — pins (artifact SHA-256s from r1's sealed set, re-verified by
  `port_from_r1.py`), marker names, lazy `BOOT`/`PROOF_SHA`/`EXPECTED` that
  light up ONLY on the r2 inspection + fresh register.
- `inspect_tv.py` — r2 read-only inspection: asserts the POST-stage-1 state
  (v5.18 at target, fdet pair present with pinned hashes, r1 backups intact,
  temp paths absent) and CAPTURES (not pre-checks) boot/proof/register; runs
  at TV-contact as its own light approval.
- `prepare.py` — bakes the three gate scripts from the inspection.
- `BridgeRepairAgent.cs/.csproj` — trimmed agent: phase1-snapshot + the three
  gate ops; the remove op validates the `gate-remove:<boot id>` parameter.
- `stage.sh`, `snapshot.sh`, `sdk.py`, `bootstrap_sdk.py`,
  `stage_transport.py`, `trial.py`, `recovery.py` — verbatim ports of r1's
  qualified transport (differences: none).
- `deploy.py` — session baseline and closeout library only; it MUST NOT grow a live
  deploy entrypoint again (offline check asserts that).
- `dirread.py`, `activate.py`, `disable.py`, `watch.py` — the four stage
  drivers.
- `driver_checks.py` — host-only rehearsal (runs already, no TV).
- `offline_checks.py` — seal flow; requires inspection.json +
  protected-register.json and writes the seal + results; runs only at
  TV-contact prep time after the inspection.
- `artifacts/` — the exact r1 artifact bytes (hash-verified copies).
- Provenance receipts copied from r1: `deployment-result.json`,
  `post-deploy-verification.json`, `post-mortem-20261108.md`, and r1's
  PRE-deploy inspection as `inspection-r1-predeploy.json` plus the
  protected register as `protected-register-20261108.json` (inherited
  register; the fresh capture must agree path by path for inherited paths).

## Stage flow and approvals

1. `LIVE_ARM_WATCH` (SDK reads only): receipts the durable absent-config gate
   lines of the current boot, verifies the 25-file register, no config/no
   state file on both ends, boot unchanged.
2. `LIVE_ARM_DIRREAD` (root op on the inspection boot): creates the read-only
   gate config; observes the next intentional opening's read-only summary and
   enforcing fingerprint within the 100-minute bound. The pre-operation byte
   offset plus exclusive config creation binds those lines to this stage.
3. `LIVE_ARM_ACTIVE` (root op on the inspection boot, then REBOOT by owner):
   read-only -> active; owner power-cycles; the driver awaits the new boot
   and verifies cleared state + probe admission + full register.
4. `LIVE_ARM_DISABLE` (root op on the ACTIVE boot, then REBOOT by owner):
   removes the gate via the boot-parameterized op; owner power-cycles once
   more; the driver verifies a THIRD distinct boot, enforcing restored
   (fingerprint read), probe DENIED (native exit 126), then writes the
   packet's SPENT marker. May be deferred.

## Build/seal order at TV-contact time

1. Review state: git clean on the pinned commit, TV reachable, r1 receipts
   present.
2. Run the r2 read-only inspection (light approval) — produces
   `inspection.json` + `protected-register.json`.
3. `prepare.py` (bakes gate scripts) .
4. Build the agent: pinned SDK 3.1.426 (checksum-verified install at
   `C:/Users/Kninetimmy/.dotnet-sdks/3.1.426`), with
   `DOTNET_MULTILEVEL_LOOKUP=0`. This helper uses BCL APIs and the freshly baked
   gate resources; verify `build/SamsungTvRootAgent.dll`.
5. `offline_checks.py` — full host suite + writes `seal.json` (43+ entries
   listed explicitly), one-shot, refuses reruns.
6. All filled host artifacts then re-scan: ruff (F821), `bash -n` for all
   shell scripts, AST for all python, artifact digests vs pins.
7. Stage approvals: each stage runs with its marker file armed by the owner;
   no TV contact before that, ever.

The owner must intentionally open Gaming Hub for the absent-config watch
evidence and again after the read-only config is created. Healthy automatic
ghdaemon/default launches remain quiet and do not execute the gate. No driver
opens the UI or reboots the TV. All live approvals remain separate.
