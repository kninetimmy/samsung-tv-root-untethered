# L4 packet r1 — deploy closeout post-mortem (2026-11-08)

Unsealed post-hoc document (does not modify any file in `seal.json`).
Owner path: run-after the deploy stage; documents why `deployment-result.json`
was reconstructed and on what evidence each field rests.

## Timeline

- 22:23:03Z — deploy run start; baseline passed over bridge SDK (boot
  `27959362`, v5.17 at TARGET, 23 protected files byte-identical).
- 22:23:04 — temporary recovery relay started (path `tvroot-quiet-recovery-20261102-r1`,
  port 26105, pid receipted); baseline re-passed through it (`recovery-sdk-verified`).
- 22:23:10 — staging owned (`archive-root-a553e5ee83632f83`); transport completed;
  root-context snapshot verified (uid 0x4, caps/namespaces/labels as pinned).
- 22:23:30 — `manager-apply` receipt: `MANAGER_UPDATE_COMPLETE`, v5.18 sha at
  TARGET (`TARGET_METADATA 201:0:755:1`), v5.17 bytes at the backup path.
- 22:23:32 — `fdet-install` receipt: `FDET_INSTALL_COMPLETE`, both payload
  hashes (`FDET_METADATA` prints the dll record only — `fdet.sh:106`; the
  runtimeconfig is `chmod 0644` per `fdet.sh:79`).
- 22:23:33-36 — closout ladder: `authenticated-root-close`,
  `desktop-callback-close`, `desktop-launch-client-exit`,
  `owned-remote-files` (staging + demand tar absence) all verified.
- 22:23:37 — `post-session-baseline` **failed** → `SPENT` written; the post-run
  block of `deploy.py.main()` (which normally runs `recovery.stop` and writes
  `deployment-result.json`) never executed.

## Root cause of the closeout failure (host-side authoring bug, TV untouched)

`Trial.baseline()` (trial.py:37-49) compares the TV's `protected-hashes`
output against `INITIAL['hashes']` from `inspection.json`, which was recorded
when the FDET home was **absent**. After a successful fdet-install,
`deploy.py:110` merges the two FDET paths into `p.EXPECTED`, so the check
list grows — the comparison against the pre-stage snapshot can never pass.
The failure is therefore structural, not a TV-state change. Everything else
in closeout verified.

## Recovery relay cleanup

The relay was left running by the aborted post-run block. The owner-approved
closeout (same session, later) ran the packet's own sealed
`recovery.stop` template (`recovery.py:71-110`): byte-identity checks on the
relay dir/pid/cmdline, `kill -TERM` of the pinned pid, bounded wait, unlink
of its three files, `rmdir`, absence re-verified. Receipt:
`recovery-relay-removed`. A second pass verified `recovery.PATH` absent among
8 absent paths.

## Post-deploy state verification (owner-approved, read-only)

`post-deploy-verification.json` (written once, guarded) verified, via bridge
SDK read-only: TARGET = pinned v5.18 (meta `201:0:755:1`, SMACK label
unchanged; inode/size change is the expected artifact of the in-place
rewrite), v5.17 backup bytes, runtimeconfig hash, all 23 protected files
byte-identical, live relay `ef42c759…` pinned, FDET pair hashes + metadata
per `fdet.sh` (dll 755 / runtimeconfig 644), exactly 2 files in the FDET
home, 8 absentees, port-config absent, bridge active, proof/pairing/unit/
startup unchanged, boot unchanged, uptime grew continuously. Observation:
`manager_pids` empty (v5.18 not relaunched yet) — stage 2's watch territory.

## Notes on the verification runner (transparency)

Two verifier-side false alarms occurred and were corrected before the final
pass; both are documented for the record:

1. A raw string equality on the captured `sha256sum` output failed on a
   missing terminal newline (transport is not newline-stable). A dedicated
   probe proved the register line-for-line identical; the final runner uses
   the same line-wise comparison. No TV state changed between runs.
2. The final fdet metadata check was over-generalized from the single-value
   `FDET_METADATA 0:0:755:1` receipt; the sealed `fdet.sh` writes dll
   `0755` / runtimeconfig `0644` explicitly, and the final assertion matches
   the sealed script.

## `deployment-result.json` reconstruction (owner-approved)

The original write (`deploy.py:153-154`) was skipped by the closeout failure.
The reconstructed file contains exactly the fields deploy.py intended, each
now an independently verified fact:

- `installed: true` / `sha256` — manager receipt + post-deploy verification.
- `boot` — unchanged all session (SDK reads at start and end).
- `backup` — v5.17 bytes verified at the path.
- `recovery_removed: true` — `recovery-relay-removed` receipt + absence check.
- `cleanup_pending: []` — `owned-remote-files` verified + final pass re-check.
- `UI_launches: 0`, `reboots: 0` — no launch/reboot controllers ran; boot pin
  proves no reboot.

Later stage scripts (`stage_lib.protect_seal`) require this file present and
`SPENT` receipted — both hold.
