# qn90b-uep-l4-deploy-20261109-r8 — config-removal-only packet (r7 continuation)

Successor to `qn90b-uep-l4-deploy-20261109-r7`. r7 was fully authored, twice
reviewed, sealed (45 entries) and owner-armed, and failed HOST-SIDE before any
root session or TV write:

1. `remove.py` preflight over the bridge PASSED read-only on boot
   `4b2c70c7-2d64-46df-b84e-02541ed33659` (25 protected files, manager v5.18,
   gate config present read-only `0:0:644:1` label `_`, budget state absent,
   proof matched, recovery closeout verified).
2. `RemoveSession.run` then died locally in
   `samsung_tv_root.archive_root._prepare_artifacts`:
   `OpenSSL was not found; install it on the host and put openssl on PATH`.
3. The attempt had already been taken, so the failure handler wrote STOP.
   r7 is permanently consumed; the r6 read-only gate config is still on the TV
   (absent-config is the fail-closed state, so the TV is safe as left).

Receipts prove zero TV writes: no `gate-remove:`/`phase1-snapshot`/root-session
events, only read-only SDK captures. The cause is the harness shell's PATH
missing openssl; this host has a working Git OpenSSL 3.5.5 at
`C:/Program Files/Git/usr/bin/openssl.exe`.

r8 exists to run the SAME removal with the SAME code, plus one guard so this
class of burn cannot recur. Owner decision 26 (option a) is unchanged: delete
`/opt/usr/share/selfroot/uep-off.conf` via the authenticated `gate-remove:<boot>`
op, owner reboots, driver verifies the enforcing-only baseline.

## r8 delta vs the reviewed r7 bytes

Everything else is a digest-verified verbatim carry from r7's seal (38 files,
recorded in `port-from-r7.json`). Four files carry a documented delta:

| File | Delta |
|---|---|
| `packet.py` | Adds `OPENSSL_CANDIDATES` + `require_openssl()`: resolve a working openssl via PATH first, else the known Git locations; verify it runs; prepend a fallback directory to PATH so `archive_root`'s bare `openssl` calls resolve to the verified binary. |
| `remove.py` | `prerequisites()` calls `p.require_openssl()` **before** `OneAttempt.take()`, and logs the resolved path. A missing host tool now refuses with no attempt consumed, no STOP, no TV contact. |
| `offline_checks.py` | Seal list re-pins r8 lineage (`port_from_r7.py`, `port-from-r7.json`, `r7-STOP.txt`, `r7-seal.json`, `r7-port-from-r6.json`), the host-tool step runs first and its resolved openssl is recorded in `offline-results.json`, and messages name this packet. |
| `flow_cases.py` | Adds the load-bearing case: with no PATH openssl and no fallback, `remove.main()` raises before the attempt file exists and writes no STOP. |

The removal body, its refusals, the boot pin through the authenticated op
command, the relay teardown, the bounded post-reboot gate wait and the SPENT
semantics are byte-identical to the twice-reviewed r7 code.

## Scope of r8 (exactly one stage)

| Stage | Act | Verification |
|---|---|---|
| LIVE_ARM_REMOVE | root op `gate-remove:<inspection boot id>` removes /opt/usr/share/selfroot/uep-off.conf; owner reboots | same-boot: config absent, budget state file absent; fresh boot: distinct boot id, fresh zero-identity proof, absent-config gate line (bounded poll), budget state absent-or-stale (never the fresh boot), fdet fingerprint read-back `c07bd300 00000001 00000000 000004e2` (enforcing; never cleared), 25-file register byte-identical |

Out of scope, unchanged from r7/decision 26: no config creation or activation,
no payload execution of any kind (the uep-probe denial test belongs to the
v5.19 redesign), no manager/fdet changes. The five artifact bytes ship only
because the qualified staging path is carried verbatim.

## Carried unchanged (digest-verified from r7's 45-entry seal)

deploy.py, stage_lib.py, trial.py, recovery.py, sdk.py, bootstrap_sdk.py,
stage_transport.py, inspect_tv.py, prepare.py, driver_checks.py,
driver_shim.py, authoring_checks.py, stage.sh, snapshot.sh,
BridgeRepairAgent.cs/.csproj, the five artifact bytes, and the r1/r6
provenance receipts. Not carried: r7's inspection.json / protected-register.json
(a fresh inspection pins this TV contact), gate-remove.sh (re-baked), build/
(rebuilt under the pinned SDK), rehearsal/offline results (rerun), PLAN.md.

## Seal list (48 entries)

The r7 names, with the port pair replaced by `port_from_r7.py` /
`port-from-r7.json` and r7's `STOP`, `seal.json`, `port-from-r6.json` carried as
`r7-STOP.txt`, `r7-seal.json`, `r7-port-from-r6.json`.

## Stage flow, approvals, and the owner's part

1. Host checks: git clean on pinned commit 847443c, TV reachable, openssl
   resolves and runs (`require_openssl`).
2. `inspect_tv.py` (own light approval) → fresh `inspection.json` +
   `protected-register.json`; boot/proof pins become this packet's identity.
3. `prepare.py` bakes `gate-remove.sh` for that boot.
4. `offline_checks.py`: host-tool gate, rehearsal rerun, pinned SDK 3.1.426
   agent build (0 warnings enforced by parsing MSBuild's summary), syntax and
   guard sweeps, integrity gates, one-shot seal.
5. Owner arms `LIVE_ARM_REMOVE` (content = 847443cfa62a6d160a712216c3835706b350752e).
   No TV write happens before that.
6. `remove.py` removes the config through the authenticated root op, verifies
   same-boot absence, tears the relay down, then waits up to 8 h for the
   OWNER's power-cycle (the driver never reboots and never opens the UI).
7. After the new boot: enforcing-only verification, `succeed()`, SPENT written.

Failure semantics are the r2-r7 family: any failure after the attempt is taken
writes STOP + failed status. The r8 guard exists precisely so the attempt is not
taken when the host toolchain is incomplete.

## What r8 restores, and what remains

After r8 the TV is back to the enforcing-only baseline: config absent, budget
state file absent, gate silent on the absent path, fingerprint enforcing, the
25-file register intact, manager v5.18 installed. The v5.19-class UepGate probe
redesign (root-context execution, new manager version + reinstall) remains the
only recorded route to completing L4 on this TV and needs its own reviewed
packet before any TV touch. Nobody should re-create the gate config outside a
reviewed successor packet.
