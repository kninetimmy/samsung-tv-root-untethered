# r17 — QN90B enforcing-only certification (2026-11-10)

Derived offline from the digest-verified r16 seal
`c41976bc39e5c429caf576565f298a531bee368262f92f3ef252c93dbf905f1a` (71 entries),
not the superseded authoring archive. r16's readiness STOP is permanent; never
modify, clear, re-seal, arm or replay it. r15's disable attempt also remains spent.
`evidence/R15-PLAN.md` is historical only; this plan supersedes every gate-op,
reboot, Permission-denied/126 and native_exit=0 assertion in it.

## Scope and order

1. Author/build/test/seal **offline only**. No TV contact, sdb, SDK connection,
   readiness invocation, marker write, arming, gate operation or reboot here.
2. Independent read-only review, then owner-run `certify.py --readiness`.
   It creates no marker or attempt and issues only reads; receipts are host-local.
   A missing/changed shape STOPs permanently rather than polling or retrying.
3. Owner explicitly approves staging a managed helper and the pinned ELF once,
   then arms `LIVE_ARM_CERTIFY` with source commit
   `8f92e54346a6d89ecda4ce540c341d855b8646a6`. `certify.py` certifies read-only,
   performs the one denial attempt, removes its own stage, and certifies again.
   The final certification is a closeout sample, never a retry of a failed read.
4. Optional final **separately armed** `LIVE_ARM_TIDY` / `tidy.py` removes only
   the old task46 directory. Drop this step without disturbing certification.
   It consumes its own attempt and requires successful current certification.

No gate config is ever created/re-created, no gate root op runs, no relay is
started/reconciled, and no reboot is requested or awaited by either r17 driver.
The old install/active/disable/inspection/preparation CLIs refuse. The old gate
scripts, packet agent and pure bake helpers remain only for inherited offline
regression tests, not as live authorization. Markers accept only CERTIFY/TIDY.

## A — one-pass read-only certification

Anchor every pass to boot `299d6f3f-c014-43e5-a487-59c47c833f6f` and proof
`90dd4328ec810b4646745d4940b39652dd4d519e9b247c59ea5f517372aefc29`.
Require SDK uid901, bridge active, manager v5.19
`449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c`,
runtimeconfig `ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38`,
their package metadata/labels, pinned module bytes/metadata, and the root-only
v5.18 backup directory shape (design A below, not child hashes). Require all 24 protected hashes in requested
order; automatic proof boot and all four UID/GID fields must be zero.

Gate config and budget temp must be absent (including symlinks). Budget must
be the byte-exact hashed stale line
`boot=edc9debc-8b83-4ecb-afab-27602cd084fd clear=1 restore=0\n`, regular,
root-owned, single link. It is **never** accepted as a fresh receipt.

The driver reads module-uep-gate.log, the boot-scoped log, not modules.log.
One read (`probes=1`) must give exactly:
```
uep gate (boot) uid=0: config absent (enforcing; no action)
uep gate module exit=0
```
Require the enforcing fingerprint `c07bd300 00000001 00000000 000004e2`.
**Expected enforcing is required here, not a fault**; any nonmatching read,
missing/partial shape, enforcing read in the retained active-stage regression,
boot drift or read error is STOP, never retry. There is no cleared-state stage
in r17. Display/HDMI/GameMode remain an owner visual check, not a driver claim.

## B/C — denial authority and correct execution accounting

Exclusively create a random owned `denial-<16 hex>` stage under the canonical
SDK root. Exclusively upload the sealed 5196-byte ELF (SHA-256
`d1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d`),
the sealed managed DenialRunner.dll and its runtimeconfig. Recheck directory
identity, uid901, ELF mode0700/single-link and every uploaded hash before exec.

DenialRunner uses **direct Process.Start with UseShellExecute=false**, never a
shell fallback. Win32Exception.NativeErrorCode reports the actual execve errno;
the JSON explicitly states `exec_started=false, native_exit=null`. Its protocol
exit77 propagates through an `exec /usr/bin/dotnet ...` SDK command, not `exit 0`.
77 is a wrapper refusal trailer, **not** an expected native `$?`/bash status.
The owner must observe this direct-exec behavior on the actual .NET3.1 TV;
offline tests do not claim a live EPERM/EACCES reproduction.

Any started child is failure regardless of its exit, with captured stdout/stderr.
The owned Process handle has a 5-second wait, kill, 1-second reap and 1-second
output-close bound. Native stdout marker `QN90B_UEP_NATIVE_PROBE_OK` must be
absent. Refused-before-exec can never appear as native_exit=0 or a child success.

EPERM(1) **or** EACCES(13) is acceptable, but neither alone proves UEP denial.
Authoritative acceptance is one exact canonical-path kernel line:
```
[Verification fail] file <canonical staging>/uep-probe.elf is not signed. Sign it.(fsname:vdfs, mnt_flags:1020)
```
Read uptime and dmesg before the single attempt, then uptime and dmesg after it.
The complete dmesg is transported gzip+base64 with `tr -d '\012'` to stay under
the SDK's 128KiB receipt cap, decoded with a strict 1MiB limit; no tail/filter
discards the prefix. Decode/transport failure is terminal.
Require the entire old log as an unchanged prefix, no earlier exact-path hit,
exactly one new timestamped hit, and a timestamp inside that attempt's uptime
window. Other paths, stale lines, rotated/truncated logs, wrong fs/mount flags,
duplicate or missing lines STOP without another execution. Do not pin shell
wording, normalise errno, or read a fabricated native `$?`.

Only after acceptance, validate exact three-file inventory, links, owner and
hashes, unlink those three files and rmdir this attempt's directory, proving
absence with standalone fatal tests. Any failure preserves staging for review;
there is no cleanup fallback that could hide the denial failure.

## D/E — review fold-ins

- Relay fixture uses `dir=driver_shim.REHEARSAL_TEMP` (imported as ds), not the
  inherited 8.3 TEMP. Every relay case is rerun and these bytes are re-sealed.
- Both historical active/disable prerequisites call the shared attempt-existence
  check first, before OpenSSL, anchors, SDK or uid901 cleanup. The exclusive take
  still checks again; a hard-killed packet never gets a cleanup-before-refusal pass.
- Runtime `stage-status-active.json` cannot be sealed by its producing packet.
  Its historical content-only check is explicitly documented, not called a pin.
  r17 uses sealed boot/proof constants. Optional tidy's runtime status is only a
  claim bound to those pins, then re-certifies live before mutation.
- Relay children use separate regular-file/type checks and numeric metadata;
  empty regular children fail at hash/pid checks, not a misleading `%F` message.
- Mutation subprocesses install an interpreter exception hook, recording the
  actual terminal exception's qualified type and message separately from output.
  Only manager_tools.Stop / builtins.AssertionError with the intended message
  fragment can kill a mutant. Traceback source and trailing ResourceWarning
  text cannot satisfy it. Records and seal verification enforce both fields.

## F — discrete optional task46 cleanup

Exact path `/home/owner/share/tmp/sdk_tools/denial-fd9fa25930776ce9`, canonical
`/opt/usr/home/owner/share/tmp/sdk_tools/denial-fd9fa25930776ce9`.
Require uid901 and the anchored boot; canonical root/cwd, nonlinked owned0700
directory and exact one-file inventory. The child must be a nonlinked regular
file, uid901, mode0700, single link, 5196 bytes, pinned ELF hash above and mtime
`2026-11-10T20:50:00Z` (epoch1794343800). Recheck lexical directory identity
before unlink. Any shape mismatch refuses, never guesses or broadens deletion.
Count entries with `find -printf x | wc -c` under pipefail before comparing the
name: a newline-only extra filename cannot disappear in shell substitution.

Then unlink **only** uep-probe.elf, rmdir **only** that directory, prove local
absence, disconnect and require anchored absence from a newly constructed SDK
session. Reappearance is terminal, not a removal retry. Evidence receipts are
not deletion targets. This is tidy-up of an ELF UEP refuses, not hazard recovery.

## G — unresolved observation

"The r8 baseline produced EACCES for the same UEP signature check while boot
299d6f3f produced EPERM. The difference is unresolved; neither result is
canonicalised, and the r8 result is not claimed to be wrong."

`evidence/R15-INCIDENT.md` cites exact receipt lines and preserves the original
measurement, including its trailing-pipe/false-boolean caveat, without laundering
it into a new observation. The new direct helper records, not rewrites, errno.

## r16 readiness incident and design A

At `2026-11-10T23:44:35.106073Z`, owner-run r16 `certify.py --readiness`
failed at `r16-backup-pair` (exit 1, empty output), writing permanent STOP and
`stage-status-certify.json`. No attempt receipt was taken, no arming occurred,
and there were zero TV writes. Earlier anchors passed: boot `299d6f3f`, absent
gate config, stale `edc9debc` budget, module present, pinned v5.19 manager pair,
proof `90dd4328` and 24 protected files. These are historical incident evidence,
not r17 live validation. The owner's separate read-only diagnostic confirmed
the backup directory's `directory:0:0:700:1` shape; no diagnostic is repeated here.

Defect: `gate-install.sh` creates the v5.18 backup as root under `umask 077`.
The bridge SDK is uid901 and cannot traverse that root-only directory. r16 tried
child `test`/hash operations that DAC denies; host-user fixtures did not model
that boundary. r16's seal, STOP, receipts, statuses and complete file/directory
inventory are pinned by `evidence/r16-evidence-digests.json` and checked by the
port ledger. None of those runtime artifacts is copied as a live r17 input.

Owner-selected **design A** changes only backup certification: reject a symlink
or non-directory, require the directory to exist, and require exactly
`stat -c '%F:%u:%g:%a:%h'` = `directory:0:0:700:1`. Every guard explicitly
refuses (`|| ... exit 69`); a failed stat cannot be masked by a later print.
**A uid901 certification never reads a root-only path**: it stats only the
directory itself, never lists, reads, stats or hashes its children. There is no
root session, chmod/chown, permission relaxation or device mutation in this
read-only certification. No new root route or capability is introduced.

The pair's creation-time hashes are evidenced by the sealed **`gate-install.sh`
lines 65-71**, which asserts manager
`e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a` and runtimeconfig
`2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b` before emitting
`GATE_BACKUP_COMPLETE`, under line 1's `set -euo pipefail`.
`evidence/FORENSIC.md` cites historical r14 `receipts.jsonl` records 2264-2265
(gate-install exit 0); the sealed `stage-status-install.json` success is pinned
by SHA-256 `be77d4940030944e8939ca223f66d253864c980de919e0ad6d5a2b8d35794042`.
Certification logs and success status name this receipt evidence; failure status
also names it in the reason. This deliberately proves only **"the root-only
backup directory is the installed shape"**, not present-tense pair bytes. A
future restore gate must re-hash the pair **as root immediately before use**;
r17 neither restores nor implements/authorizes that future gate.

The r17 regression shim explicitly denies uid901 child `cat`, `stat`, `sha256sum`
and directory `ls`/`find`; positive controls prove those denials. With correct
directory metadata, the real production shell passes without any child-read
attempt. Symlink, non-directory, missing directory, wrong owner/group/mode/link
count and stat-error cases must STOP with an explicit refusal. Metadata and DAC
are fixture models because the host user can read those children; this is an
offline boundary test, not a claim that the real TV was exercised.

## Verification, seal and residual boundaries

Run `.venv/Scripts/python.exe -B <packet>/offline_checks.py`. It runs authoring
(pure temporary bake, C# receipt ground truth, embedded resources, bash -n,
ruff F821 and zero-warning agent build), direct-helper build/self-tests, r16+r17
cases, standalone relay, full rehearsal, full session and full mutation suites;
then builds the carried agent again and verifies every artifact, inherited
guard, exhaustive port ledger and immutable predecessor snapshot before sealing.
SDK is the explicit user-local **3.1.426** with DOTNET_MULTILEVEL_LOOKUP=0 and
DOTNET_ROOT pinned. All builds must have zero warnings. No suite result is
inherited green. Counts, commands, outcomes and zero skips are in sealed outputs.
The production denial flow's actual creation/upload/hash/cleanup shell runs on
host files for EPERM/EACCES and missing-kernel cases. POSIX identity/proc and the
exec/kernel event are modeled. Git/MSYS dd lacks oflag=nofollow: the host shim
models that flag with a symlink guard while real conv=excl, decoding, file bytes
and hashing run. This is an explicit fixture boundary, not live validation or
a skipped suite. C# tests include injected errno1/13/2/8, real missing-executable
refusal, a real exit42 child and a real five-second timeout/owned kill/reap.

Packet/evidence/build dirs were created with make_private_directory;
owner+SYSTEM-only ACLs must pass private_acl before review. The exact manifest
entry set is enforced; no STOP/SPENT/attempt/arming marker/secret/receipt log is
carried from r16; no execution/ tree is carried or pre-created. The historical
sealed install status is retained, not the failed r16 certification status.
Inherited session fixtures create then empty an execution/ parent; the offline
flow removes only that empty nonlinked directory before the ledger/seal and
refuses any non-empty or redirected execution tree. The final packet has none.
Build deps/dev JSON files are unsealed compiler byproducts,
not live stage inputs. The ledger lists every carry/delta/addition/removal and
separately identifies regenerated results and binaries. `port_from_r15.py` and
`port-from-r15.json` keep their inherited filenames but now verify r16 -> r17.
`r16_checks.py` / `r16-results.json` likewise retain their names while adding
the r17 cases; this avoids changing inherited mutation-test dispatch.

Failures after a consumed attempt write durable STOP/status; no replay, auto
retry, relaxed guards or config re-creation. A readiness failure also STOPs.
An exclusive attempt receipt remains even across a hard kill. SDK/namespace
shape checks are fail-closed but not atomic exclusion against a concurrent
same-uid actor; fresh-session absence is one sample, not universal persistence.

No shipped manager/host/module bytes changed. Task40/v5.20 exclusive-create
hardening remains deferred: the old **owner-accepted residual** concerns the
following/truncating SaveBudget writer, which r17 never invokes or arms.
No new acceptance of that residual is implied. Other security layers, mid-boot
rearm, picture/hardware claims and reboot safety remain unverified/out of scope.

After host seal: independent read-only review, owner readiness probe, explicit
one-use CERTIFY arming, then optional separately approved TIDY arming. None of
those live steps has occurred merely because this offline packet is sealed.

Only LIVE_ARM_CERTIFY is planned for this packet's certification; optional
LIVE_ARM_TIDY remains a separate owner decision and separate arming. `tidy.py`
is byte-identical to r16 (including historical wording), never run or armed by
authoring. There is no live capability beyond these two inherited stages.
Task48's non-blocking minors (63 mutation cases / 58 distinct source mutations,
and no empty-child relay case) remain open: neither mutation_checks.py nor
recovery.py is changed. EACCES-vs-EPERM and task40 remain unresolved as above.
