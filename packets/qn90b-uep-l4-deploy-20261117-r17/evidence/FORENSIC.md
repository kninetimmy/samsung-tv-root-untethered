# r14 stage-2 incident — saved-evidence forensic review

No device contact was made for this review. Line numbers below are 1-based
JSONL records in immutable `../qn90b-uep-l4-deploy-20261114-r14/receipts.jsonl`.
Its SHA-256 at review start is
`bb05e49b6a6c701c3c715d85deab6e40613744f29d9863186d8d2dd521e05436`.
The saved seal verifies all 51 entries. Non-secret sealed and execution-evidence
digests are in `r14-evidence-digests.json`; no credential directory was traversed.

## Proven sequence

| Evidence | Observation |
|---|---|
| r14 `execution/attempts/LIVE_ARM_INSTALL.attempt` | Stage 1 attempt at 11:37:20.610400Z |
| records 294, 310 | Stage 1 started and validated relay directory `45845:13603:901:700`, pid `8998`, birth `12218909`, at 11:37:30Z |
| records 2264–2265 | Stage 1 executed `gate-install` on boot `0404f29a-1277-44bb-bee7-5b77a0b3b6bc`; exit 0 |
| record 2913 | Actual requested cleanup script: verifies directory/process/files, TERM, waits for PID absence, unlinks the three files, changes to sdk_tools, rmdirs the fixed name, then tests absence and prints a receipt |
| record 2921 | At 11:38:07.386798Z the authenticated TV exit trailer is exit 0, output `RECOVERY_RELAY_REMOVED\n` |
| records 2928, 3423; `stage-status-install.json` | Host accepted cleanup; install passed at 11:40:47.901696Z on boot `dc1477b5-295d-452b-90c4-ce10aec2f3c8`, proof `38bcea864cd701b5826bd5a744a43f01b95922234cb2ac9cda6a45567b526f91` |
| readiness `readiness.py`, `readiness.json`; records through 3530 | Read-only preflight passed; JSON timestamp 14:51:07.801524Z is captured at probe start, final proof receipt is 14:51:12.433022Z. It did not inspect the recovery relay path |
| records 3531–3532 | Stage-2 anchor and host prerequisites passed at 15:06:23.949801Z |
| `execution/attempts/LIVE_ARM_ACTIVE.attempt`; `active.py:119–126` | Attempt at 15:06:23.951433Z is **before**, not after, `preflight()` |
| records 3542, 3550 and subsequent preflight captures | Same anchored boot, v5.19 manager pair, read-only gate, absent budget/temp, present module/backup; preflight completed |
| records 3791, 3860 | GateSession baseline (24 protected files, manager, bridge, proof, pairing/service/settings) and runtime reads passed |
| records 3861, 3869 | Start script reached its bare `mkdir -m 700 -- tvroot-quiet-recovery-20261102-r1`; exit 1 at 15:06:32.862585Z with `File exists` |
| records 4029–4034; failed status and STOP | Post-session baseline passed. Local cleanup reported FileNotFoundError; recovery closeout refused due to incomplete root closeout. Stage 2 failed at 15:06:34.406258Z and STOP was written |
| records 4113, 4121, 4131, 4139; readiness `post-failure-state.json` | Post-failure 24-file register, manager/module metadata, read-only gate hash `ef589842…`, absent budget/temp, bridge and anchored proof confirmed |
| record 4150 | Relay directory present, `901:901:700`, exactly the three visible files, pid text `8998 12218909`, no matching relay process and no IPv4 port-26105 entry |
| record 4167 | Directory device/inode still `45845:13603`; DLL inode 13606, size 10240, mtime 11:37:28.904372862Z; pid inode 13614, size 14, mtime 11:37:29.964372862Z |
| record 4184 | Archive-root staging directory absent; ordinary SDK tree/evidence/module state retained, read-only boot module log intact |

There is exactly one active-stage attempt and one failing relay-start request.
That request has `set -euo pipefail`; `mkdir` is a standalone command before
the first `cp` or `dotnet`. No active `gate-op-intent` or `gate-op-receipt`
exists. The control flow never reached archive-root material generation,
uploads, root-agent launch, or the activation op. **No deliberate TV file write
succeeded in stage 2 and no gate operation ran.** This does not assert that
connecting services produced no incidental logs or filesystem bookkeeping.

## Correction: the final absence test is not proven to have passed

The cleanup tail is:

```bash
rmdir -- tvroot-quiet-recovery-20261102-r1
test ! -e /home/owner/share/tmp/sdk_tools/tvroot-quiet-recovery-20261102-r1 && test ! -L /home/owner/share/tmp/sdk_tools/tvroot-quiet-recovery-20261102-r1
printf 'RECOVERY_RELAY_REMOVED\n'
```

Bash `set -e` does not abort on a failed non-final member of an AND list.
If the first `test` is false, the second test is skipped and the following
`printf` still succeeds. Host-only reproduction (exit 0):

```text
Git bash.exe -c 'set -eu; test ! -e . && test ! -L .; printf "REMOVAL_RECEIPT_DESPITE_EXISTING_PATH\n"'
REMOVAL_RECEIPT_DESPITE_EXISTING_PATH
```

Therefore "its own test ! -e passed" is **not established** by the receipt.
The standalone unlink/rmdir commands nevertheless must have completed
successfully for this straight-line script to reach the receipt with exit 0,
assuming the recorded command ran with ordinary Bash semantics. It is not
defensible to say the cleanup was simply never run. Receipts do not include
syscall tracing, however, and they cannot prove which global/persistent view
those successful operations affected.

The same combined absence guard appears before copying relay children in
`start()`, and a combined file/link guard appears in `stop()`. r15 separates
these relay-boundary tests so each failure is independently fatal. This is
within the incident's relay-path defect class, not a change to any gate op.

## What the evidence cannot determine

- The later directory device/inode matches stage 1's identity. The DLL and
  pid-file inodes/mtimes are captured **after** failure, not independently
  captured before cleanup; calling their inode numbers "the same as before"
  overstates the available before/after evidence. The post-failure scripts also
  do not hash the leftover DLL or runtimeconfig. Their old timestamps and pid
  text strongly suggest retained stage-1 files, but are not a new content proof.
- The later empty process match and IPv4 table, plus the intervening reboot,
  support a dead old relay. They do not establish that PID 8998 is currently
  unused, nor rule out an IPv6 listener. r15 checks both explicitly.
- No saved pair of relevant processes' mount namespace IDs/mountinfo exists
  around cleanup and reappearance. The blank exact-mount lookup in record 4167
  does not rule out ancestor mounts, bind mounts, or overlays.
- A per-session mount/overlay asymmetry is plausible; selective restore,
  filesystem/reboot persistence behavior, a namespace/parent-path race, or an
  unrecorded actor recreating/restoring state are not excluded. Other deletions
  persisting weakens a blanket whole-tree restore hypothesis but does not prove
  any one alternative. Even the time of reappearance (immediate vs reboot) is
  not established. **The defensible explanation is a view/persistence mismatch
  left undetected by a non-aborting, same-command-only absence check; its
  underlying mechanism remains undetermined.**
- Chat approval itself is not independently recorded in the provided files.
  The standing marker, one attempt and actual run are consistent with it.
- The brief says a private-material directory exists now. It was not opened,
  traversed, copied, hashed or cleaned. The failing invocation cannot have
  generated its contents: generation follows successful recovery startup.
  Record 4032 reports FileNotFoundError during that invocation's local cleanup;
  existence/origin of later material cannot be attributed from these receipts.
- "Healthy" means the captured software invariants, not a fresh live assessment
  or a video/display check. No new device data is needed for packet authoring.

## Scope findings retained rather than silently fixed

The SaveBudget following/truncating temp writer remains decision 35's stage-2
residual and task 40/v5.20. Other live preflight failures still consume an
attempt, as in r14; only relay reconciliation (including its boot/proof guard)
moves before it. The preallocated local-material path can produce misleading
FileNotFoundError cleanup evidence before material generation; r15 does not
change that separate closeout behavior. The inherited test harness still has
the reviewed broad terminal-message matcher (task 42); no claim of complete
general mutation-test soundness is made.
