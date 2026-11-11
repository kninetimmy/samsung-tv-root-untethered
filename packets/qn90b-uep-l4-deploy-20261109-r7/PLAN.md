# qn90b-uep-l4-deploy-20261109-r7 — config-removal-only packet

Successor to the consumed `qn90b-uep-l4-deploy-20261109-r6`. There the DIRREAD
stage wrote the read-only gate config live (gate-readonly op, exit 0, config
verified) and the owner's intentional reopen ran v5.18's first-ever live
non-absent gate path, which failed closed at 2026-11-09T03:47:22.9591640Z
(boot 4b2c70c7-2d64-46df-b84e-02541ed33659):
`uep gate: payload check failed: dotnet missing (/usr/bin/dotnet) - fail
closed (no action)`. v5.18's UepGate.ValidatePayload/RunProductionProbe
execute /usr/bin/dotnet inside the MANAGER app context (uid 901,
Pkg::ghservice::RO) where the binary cannot be seen or run; the same binary
works in the root/service context (tvroot-bridge.service active). All
r1-r6 sessions before today only saw the absent-config path, which skips
payload validation. r6's DIRREAD status consumed the packet (STOP written;
receipts + 52-entry seal intact).

Owner decision 2026-11-09 (memhub decision 26): leave the read-only config
in place overnight (fail-closed, safe), then remove it via a standalone
gate-remove driver — this packet — restoring the enforcing-only baseline.
The v5.19-class probe redesign (run the gate probe from the root/service
context, new manager version + reinstall) is the LATER work item and needs
its own review before any TV touch. L4 as designed cannot complete on
v5.18.

## Scope of r7 (exactly one stage)

| Stage | Act | Verification |
|---|---|---|
| LIVE_ARM_REMOVE | root op `gate-remove:<inspection boot id>` removes /opt/usr/share/selfroot/uep-off.conf; owner reboots | same-boot: config absent, budget state file absent; fresh boot: distinct boot id, fresh zero-identity proof, absent-config gate line, budget state still absent-or-stale, fdet fingerprint read-back = ENFORCING (`c07bd300 00000001 00000000 000004e2`), 25-file protected register byte-identical |

Deliberately OUT of scope (owner-scoped, decision 26):
- No config creation or activation (the r6-created config is the input and
  its only mutation).
- No payload execution: no uep-probe run of any kind. The r2 disable
  stage's LIVE denial test (native_exit=126) belonged to the ACTIVE-boot
  acceptance criterion and never happened live; its machinery (and the
  admission round, and the watch/dirread drivers) does not travel into
  r7. Probe validation belongs to the v5.19 redesign work.
- No manager or fdet changes; the artifacts ship only because the r6
  qualified staging path is carried verbatim (the root session stages the
  proven launcher/agent set; nothing redeploys anything).

## The removal body (baked, single op)

`prepare.py` bakes ONLY `gate-remove.sh`:

- prelude: root-only, C locale, umask 077, stage-dir identity guard
  (`/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83` mapped
  to canon, 901:700), temp-guards, content probe (regular file, 0:0:644,
  link count 1, smack `_`);
- body: `current = sha256("read-only\n")` ONLY — the `active` content
  (r6's replace target) and any foreign content are REFUSE paths (exit 74
  or aborted before any write); then `rm -- "$cfg"`;
- tail: `GATE_CONFIG_REMOVED_COMPLETE`, absence asserted both ways,
  `GATE_ABSENT` printed. A surviving file CANNOT satisfy the tail: the
  r6-style "assert the survived hash" fallback is dropped, so a silent
  non-removal stops the stage (set -e) instead of receipting success.

The boot expectation travels through the AUTHENTICATED agent op command
(`gate-remove:<boot id>`): the r7 root agent prepends
`test "$(cat /proc/sys/kernel/random/boot_id)" = '<boot>' || exit 74` inside
the root shell before the baked body (r6 lineage, review finding 2). The
baked script carries no boot pin of its own.

## Agent (r7 derivative of the pinned SamsungTvRootAgent)

- ops served: `phase1-snapshot` and `gate-remove:<boot id>` ONLY. The
  create/activate ops of the r2-r6 lineage are REMOVED (with their
  embedded resources) because no r7 stage may create or activate a
  config. The plain `gate-remove` command is still rejected so the
  parameter can never be skipped; one gate change per session
  (`GateAttempted`), one attempt per op.
- `BridgeRepairAgent.cs`: byte-exact r6 transform of the header comment +
  the two dropped op branches; everything else identical.
- `BridgeRepairAgent.csproj`: embeds snapshot.sh + gate-remove.sh (the two
  resources the r7 agent serves).

_fetch the boot id from the r7 inspection; the driver passes whatever the
inspection receipted, never a baked constant._

## Carried unchanged (port_from_r6.py, digest-verified from r6's 52-entry seal)

deploy.py (baseline/closeout library), stage_lib.py, trial.py, recovery.py,
sdk.py, bootstrap_sdk.py, stage_transport.py, stage.sh, snapshot.sh, the
five artifact bytes (manager v5.18, fdet pair, uep-probe.elf staged-only),
r1's provenance receipts (deployment-result.json, post-deploy-verification,
protected-register-20261108.json, inspection-r1-predeploy.json,
post-mortem-20261108.md), r6's live receipts (stage-status pair generaled as
r6-stage-status-*.json plus r6's seal and port lineage).

Stage_lib carries exactly ONE r7 delta: GATE_EVENT_SHAPES gains the
'remove' key mapped to (ABSENT_SUMMARY,) for the post-reboot boot
assessment.

## Rebuilt for r7

| File | Change vs r6 |
|---|---|
| packet.py | MARKERS = ('LIVE_ARM_REMOVE',); inspection gate flipped: the read-only gate config must be PRESENT (exact read-only content hash, 0:0:644:1, label `_`) and the budget state file ABSENT; gate algebra constants (UEP_READONLY_SHA/UEP_ACTIVE_SHA/UEP_META/UEP_LABEL) |
| inspect_tv.py | PROBE captures gate content hash + metadata + smack label + budget-state presence; asserts the r6-deposited read-only state and absent state file before writing inspection.json + protected-register.json |
| prepare.py | single-op baking (gate-remove.sh only), single-hash body, absent-asserting tail; main() verifies the same config invariants and bakes nothing else |
| remove.py | NEW standalone driver: the r6 disable-stage semantics minus the impossible ACTIVE receipt, anchored to the fresh r7 inspection (boot + proof + register) — see the scope table |
| offline_checks.py | r7 seal list (no r2-r6 modules/scripts), pre-seal refusal of ANY LIVE_ARM_* marker, refusal of r2-r6 debris, integrity gate: the baked script contains the read-only pin and NOT the active hash |
| driver_checks.py / driver_shim.py / flow_cases.py | host-only rehearsal for the removal (12 real-shell transition cases incl. symlink/dangling/hardlink/temp/foreign/active/absent/boot-mismatch refusals + 29 driver-flow cases driving remove.main() against the fixture's simulated SDK session; the staging/root-session path inside RemoveSession.run is inherited-verified r6 code and is NOT re-executed by the rehearsal) |
| BridgeRepairAgent.cs/.csproj | trimmed to the removal surface, see above |

## Rehearsal evidence (host-only, zero TV operations)

`driver_checks.py` runs from the repo root and writes rehearsal-results.json
(42 case groups recorded on 2026-11-09 after the second review round: static
F821 sweep + 12 shell cases + 29 driver-flow cases, including the paired
load-bearing validator cases that must refuse with the real code and would
reach SPENT with a no-op validator, the stale-budget/final-refusal case, the
bounded boot-gate wait (lagging line succeeds, missing line expires) and the
post-SPENT teardown case) and `offline_checks.py` re-runs the
rehearsal fresh before sealing. `authoring_checks.py` additionally pins the
synthetic bake through offline_checks' integrity gates, compiles the trimmed
agent with the pinned SDK into a temp tree (0 warnings / 0 errors), bash -n
sweeps every shell artifact, and deletes the synthetic bake afterwards, so at
rest the packet holds no stale agent bytes; the real bake + build happen once
per TV contact in the order below.

## Review round: sol 6.1 (xhigh) bug pass -> r7 repairs (2026-11-09)

A read-only review of the authored packet (host-only re-runs included)
reported 3 blockers, 2 majors, 2 minors; every finding was verified against
the code and repaired the same day:

| # | Finding | r7 repair | Where |
|---|---|---|---|
| 1 | packet.py's lazy gate read the r2-r6 era `uep_config`/`uep_state` inspection keys, but the r7 probe emits `gate_config`/`gate_state`: every real inspection would stall packet imports | key names aligned to the producer; the gate now also pins the captured `gate_meta`/`gate_label`; the UPSTREAM shape is enforced by an offline producer->consumer text gate (the probe must emit the gate_* captures and not the retired uep_* names) | `packet.py` lazy inspection gate; `offline_checks.py` pack integrity gates |
| 2 | prepare.py compared the base64-WRAPPED `gate_hash` text against the hex digest: always refused | decode-before-compare (`partition('  ')[0]` after decode, matching inspect_tv) | `prepare.py` main |
| 3 | the baked tail kept r6's surviving-file fallback (`hash == H_END` then `GATE_METADATA`), which (a) put the active content hash into the sealed bytes and made the offline integrity gate refuse, and (b) contradicted the PLAN's absence assertion | tail replaced with unconditional `test ! -e` + `test ! -L` then `GATE_ABSENT`; no `H_END`/`H_ACTIVE` algebra survives substitution; verified by authoring_checks integrity gates before any build | `prepare.py` RECEIPT_TAIL/bake, `authoring_checks.py`, `offline_checks.py` |
| 4 | `cat ... || echo budget-absent` conflated a READ FAILURE with absence: an unreadable budget file could pass preflight (removal proceeds) or claim the fresh boot post-reboot | preflight: `sdk_state.gate_state == 'absent'` required BEFORE any further capture, then the strict `test ! -e && test ! -L -> plain-absent` receipt; post-boot: the state file is read ONLY when actually present, with no fallback echo (a read failure stops the stage), and the content must match the exact `boot=<id> clear=[12] restore=[01]` shape | `remove.py` preflight + post-boot phase |
| 5 | the final `sdk_state` capture checked only the boot identity: a config/state re-introduction right before the final read could still reach SPENT | the final capture now requires `gate_config == absent AND gate_state == absent`; rehearsal adds the stale-into-final case (claim checks pass on the OLD boot id, the final refusal still stops the stage) | `remove.py` success path; `flow_cases.py` |
| 6 | the seal manifest omitted `authoring_checks.py` and `inspection-r1-predeploy.json` (the latter is read by the rehearsal's World fixture): no drift detection through protect_seal | both added; the manifest is now 45 entries | `offline_checks.py` SEAL_NAMES |
| 7 | inspect_tv.py (and prepare.main) ran with no STOP/SPENT refusal: a stopped packet could still construct the live transport at inspection time | explicit STOP/SPENT refusal before any TV contact in inspect_tv.main and before prepare's bake | `inspect_tv.py` main, `prepare.py` main |

The reviewer's verification (host-only) of the original finding set: driver
suite PASSED (37), agent build 0 warnings / 0 errors, no build/obj/gate
residue, all 52 r6-seal entries matched carried bytes, agent trim
byte-exact, hermeticity confirmed. After the repairs: driver suite PASSED
(38), agent build 0/0, integrity gates ok, ruff/bash -n sweeps ok.

2026-11-09 authoring note: during the FIRST rehearsal run, one fixture
patch error sent a single read-only SDK identity query (uid/boot/ip/mode,
the `context-sdk` receipt pair in the fixture receipts) to the live TV
(boot 4b2c70c7-... at that moment), from the closeout's recovery teardown
path because only `remove.BridgeSDK` was patched. No write path was
exercised and no config state changed; the fixture was completed
(deploy.BridgeSDK also patched) and the rehearsal is now hermetic — the
later runs contain no transport activity. Recorded here and in the session
note for honesty; the packet itself was never armed and has no other TV
contact.

## Second review round: deepseek-v4.1-flash (2026-11-09, read-only) -> r7 repairs

A second read-only pass over the authored packet reproduced the host evidence
(rehearsal 38/38 at the time, agent build 0 warnings / 0 errors, 24/24 ported
digests verified, 45-entry seal list complete) and reported six findings; all
six were repaired host-side the same day. No TV operations were performed.

| # | Finding | r7 repair | Where |
|---|---|---|---|
| 1 | the post-reboot gate evidence was a single shot: the driver returned as soon as tvroot-bridge.service was active, but the `config absent` line is written by the MANAGER app on its own boot schedule, so a startup race would STOP and burn the last packet | bounded wait: the required shape is polled for BOOT_GATE_PROBES (12, ~3 minutes at POLL_SECONDS) with a 200-line tail; gate exceptions, malformed timestamps and unexpected current-boot lines still stop immediately; the rehearsal proves a 3-read lag succeeds and a never-written line expires | `remove.py` `await_boot_gate`; `flow_cases.py` |
| 2 | inspect_tv's probe aborted wholesale (`SDK read failed`) on an absent/symlinked config because `sha256sum`/`stat`/`chsmack` ran unguarded under `set -eu`, making the intended STOP messages unreachable | the four gate captures are guarded command substitutions that emit exactly one `key=value` line each; `gate_config` distinguishes `present`/`symlink`/`absent`; the producer->consumer gate now pins the `%s` forms | `inspect_tv.py` PROBE; `offline_checks.py` pack gates |
| 3 | the "0 warnings" check was vacuous: MSBuild always prints `0 Warning(s)`, so the substring scan always failed and only embedded the log — a build WITH warnings passed too | parse MSBuild's own `N Warning(s)` summary and require 0, in both the authoring pass and the pre-seal pass | `authoring_checks.py`, `offline_checks.py` |
| 4 | prepare baked the label from the SELFROOT directory's smack label, while the script compares the CONFIG's label (latent: both were `_`) | the label is now the packet constant `UEP_LABEL_VALUE` (single source of truth; `UEP_LABEL` keeps the value the inspection verified) | `packet.py`, `prepare.py` |
| 5 | a close failure after the terminal receipt could rewrite the packet as failed (SPENT + STOP + passed:false), because the success path's disconnect sat inside the failure-catching block | the teardown is guarded by a terminal flag: after `succeed()` + SPENT a late close failure is logged only; before it, it still fails the stage | `remove.py` main; `flow_cases.py` |
| 6 | `port_from_r6.py` would overwrite the authored packet (including the r7 stage_lib delta) if re-run | one-shot guard: the script refuses and writes nothing when any destination file it would produce already exists | `port_from_r6.py` |

Verification after the repairs (host-only, zero TV operations): driver suite
PASSED (42 case groups), agent build 0 warnings / 0 errors through the parsed
summary gate, baked-script integrity gates ok, ruff F821 / bash -n / ast
sweeps ok, and the packet is back at its true pre-inspection state (no bake,
no build/, no obj/).

Nits follow-up (2026-11-09): the review's remaining nits were closed in the
r7-authored files only — each shell-case layout is removed after its run, the
seal build keeps MSBuild intermediates in a throwaway tree so the packet holds
only the sealed build/, the port record annotates the one documented
stage_lib delta, dead imports/helpers are gone, and the drift case now also
proves the post-removal closeout baseline refuses. Carried r6 bytes
(stage_lib.py, stage_transport.py) were deliberately NOT touched, so the
52-entry provenance chain stays byte-honest.

## Stage flow, approvals, and the owner's part

1. Review state: git clean on the pinned commit 847443c (verify), TV
   reachable, r6 receipts present on the TV as inspected.
2. Run the r7 read-only inspection (its own light approval) — produces
   inspection.json + protected-register.json; the boot/proof pins become
   the packet identity at that moment.
3. `prepare.py` bakes gate-remove.sh for THAT boot domain (content/meta/
   label pins from the inspection).
4. Build the agent: pinned SDK 3.1.426 (checksum-verified install at
   C:/Users/Kninetimmy/.dotnet-sdks/3.1.426, DOTNET_MULTILEVEL_LOOKUP=0);
   verify build/SamsungTvRootAgent.dll.
5. `offline_checks.py` — full host suite + writes seal.json (one-shot,
   refuses reruns).
6. Stage approval: the owner arms LIVE_ARM_REMOVE. No TV write happens
   before that.
7. The driver removes the config (authenticated root op), verifies the
   same-boot state, tears the relay down, then awaits the OWNER REBOOT
   (the driver never reboots; the packet never opens the UI). After the
   new boot: enforcing-only verification, `succeed()`, the SPENT marker
   written, the marker consumed by success alone.

Failure semantics are the r2-r6 family: failure or cancellation after the
attempt is taken writes STOP + failed status before raising; the closed
relay machinery receipts the exact pending cleanup path if ownership
proof is missing.

## What r7 restores and what remains after it

After r7 the TV returns to the r2-era enforcing-only baseline: config
absent, budget state file absent, gate silent on the absent path
(payload validation skipped; the fingerprint enforcing fdet state; the
25-file register intact; manager v5.18 installed). The next L4-level
decisions still require the owner: the v5.19-class UepGate probe redesign
(root-context execution + new manager version + reinstall, its own review
round before any TV touch) is the only recorded route to completing the
L4 plan on this TV; nobody should re-create the gate config outside such a
reviewed successor packet.
