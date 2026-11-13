# r18 — QN90B enforcing-only certification (authored offline 2026-11-11)

Derived offline from the digest-verified r17 seal
`0170d27c141ce5332206ae07bdca530e7ee3bf9defdd07ea29737b5e409f1508` (72 entries).
r17's permanent STOP and spent CERTIFY attempt remain untouched. Any later r18
denial is an ADDITIONAL attempt after r17, never its first attempt, a replay,
a retry or retrospective r17 certification. r16's readiness STOP is permanent
too; never modify, clear, re-seal, arm or replay either predecessor. r15's
disable attempt also remains spent.
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
    both task46 and r17 denial directories. Drop this step without disturbing certification.
   It consumes its own attempt and requires successful current certification.

No gate config is ever created/re-created, no gate root op runs, no relay is
started/reconciled, and no reboot is requested or awaited by either r18 driver.
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
in r18. Display/HDMI/GameMode remain an owner visual check, not a driver claim.

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
Read uptime before the one additional attempt, then uptime after it. Read dmesg
ONCE after the attempt/end-uptime read; there is no before-log or prefix comparison.
Save transport and decoded denial-kernel-after before any content assertion,
including the size sanity guard; save retention diagnostics before its verdict.
The complete dmesg is transported gzip+base64 with `tr -d '\012'` to stay under
the SDK's 128KiB receipt cap, decoded with a strict 1MiB limit; no tail/filter
discards endpoints. Decode/transport failure is terminal.
Require exactly one timestamped line in the entire log matching the full
signature and re.escape(canonical) exact path, uptime inside inclusive [start,end].
Other paths, stale lines, unretained windows, wrong fs/mount flags,
duplicate or missing lines STOP without another execution. Do not pin shell
wording, normalise errno, or read a fabricated native `$?`.

Only after acceptance, validate exact three-file inventory, links, owner and
hashes, unlink those three files and rmdir this attempt's directory, proving
absence with standalone fatal tests. Any failure preserves staging for review;
there is no cleanup fallback that could hide the denial failure.

## Decision — retention, not invented capacity policy (task52 clarification)

Kernel ring capacity is not measurable by the tools available to this packet;
no existing reachable packet mechanism reports it. Native `syslog(2)`
`SYSLOG_ACTION_SIZE_BUFFER` could report capacity, but UEP denies unsigned native
execution. r18 adds no native helper or capacity probe. Formatted byte counts
are NON-AUTHORITATIVE: a 505101-byte saturation constant would be invented policy.
This explicitly supersedes task52's earlier capacity-refusal request. The 1 MiB
decoded upper bound remains only a runaway-capture sanity guard.

First and last retained lines must have valid, ordered uptime timestamps
t_oldest/t_newest. Pass requires t_oldest <= start AND t_newest >= end.
t_oldest > start STOPs as **kernel-window-not-retained**, even with a surviving
denial line. t_newest < end STOPs separately as **kernel-window-end-not-retained**.
No polling, reread or second execution. These reject a too-short retention span
without guessing whether capacity, rotation, clearing or logging latency caused
it. Both named refusals carry observed_retention_span, required_span=end-start,
t_oldest/t_newest, start/end, bytes and lines, also saved as structured evidence.
A long span alone cannot pass a window shifted outside that span.

| Historical capture | Bytes | Lines | t_oldest | t_newest | Retention (s) | Observation |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| r17 before, receipts.jsonl:534 | 505101 | 7356 | 16755.012369 | 17486.329850 | 731.317481 | Prefix subsequently lost despite being below 1 MiB |
| r17 after, compressed transport receipts.jsonl:578, decoded offline | 504949 | 7354 | 16755.608247 | 17486.813637 | 731.205390 | Prefix advanced; did not reach end=17487.04; no exact-path denial yet |

This is retention/rotation evidence, NOT a threshold. The second row was decoded
from an existing transport receipt, not a device reread. r17 never saved the
decoded denial-kernel-after event. Its later read-only probe is not retroactive
acceptance: this snapshot would still refuse r18's end-coverage criterion. No
live success is promised. Equal-size synthetic 505101-byte fixtures pass or
refuse solely by window retention, independently of size.

## Decision — keep cleanup after assertions (task52 follow-up)

DEFER moving denial.run() cleanup ahead of assertions. Doing so would erase
staged file/identity evidence on a failed exec/kernel witness and add failure-path
writes. Failure must propagate directly to durable STOP/status; no finally-cleanup
or post-STOP operation is authorized. Raw log evidence is saved first; failed
denials deliberately still leave their staging directory.
Task53 follow-up: design separately reviewed/armed evidence-preserving cleanup for
failed additional denials, all three files and fresh-session absence included,
without weakening STOP. Optional r18 tidy owns only the two known leftovers,
never a new failed r18 stage.

## Decision — inventory mutation unit

The count guard and exact-set comparison are one unit under test. The count
guard is a fail-fast optimization inside it, not an independently observable
defense. The former count-only mutant survived because the sorted exact-set
comparison still refused the extra newline-only entry. That is not a waiver.
One mutation, `tidy-exact-inventory-validation-removed`, now removes BOTH guards
as one distinct transformed source, retaining the existing fixture unchanged.
No comparison-only sibling is counted. Production tidy.py keeps both guards
byte-identically. This rationale is recorded in the mutation case ledger and
the exhaustive port ledger; totals are computed from transformed-source hashes,
not adjusted to a target.

## D/E — review fold-ins

- Relay fixture uses `dir=driver_shim.REHEARSAL_TEMP` (imported as ds), not the
  inherited 8.3 TEMP. Every relay case is rerun and these bytes are re-sealed.
- Both historical active/disable prerequisites call the shared attempt-existence
  check first, before OpenSSL, anchors, SDK or uid901 cleanup. The exclusive take
  still checks again; a hard-killed packet never gets a cleanup-before-refusal pass.
- Runtime `stage-status-active.json` cannot be sealed by its producing packet.
  Its historical content-only check is explicitly documented, not called a pin.
  r18 uses sealed boot/proof constants. Optional tidy's runtime status is only a
  claim bound to those pins, then re-certifies live before mutation.
- Relay children use separate regular-file/type checks and numeric metadata;
  empty regular children fail at hash/pid checks, not a misleading `%F` message.
- Mutation subprocesses install an interpreter exception hook, recording the
  actual terminal exception's qualified type and message separately from output.
  Only manager_tools.Stop / builtins.AssertionError with the intended message
  fragment can kill a mutant. Traceback source and trailing ResourceWarning
  text cannot satisfy it. Records and seal verification enforce both fields.

## F — discrete optional two-directory cleanup (tasks46/52)

Exact path `/home/owner/share/tmp/sdk_tools/denial-fd9fa25930776ce9`, canonical
`/opt/usr/home/owner/share/tmp/sdk_tools/denial-fd9fa25930776ce9`.
Require uid901 and the anchored boot; canonical root/cwd, nonlinked owned0700
directory and exact one-file inventory. The child must be a nonlinked regular
file, uid901, mode0700, single link, 5196 bytes, pinned ELF hash above and mtime
`2026-11-10T20:50:00Z` (epoch1794343800). Recheck lexical directory identity
before unlink. Any shape mismatch refuses, never guesses or broadens deletion.
Count entries with `find -printf x | wc -c` under pipefail before comparing the
name: a newline-only extra filename cannot disappear in shell substitution.

Also cover exact `/home/owner/share/tmp/sdk_tools/denial-5bd20c32c9b13f14`,
canonical `/opt/usr/home/owner/share/tmp/sdk_tools/denial-5bd20c32c9b13f14`.
Require its creation identity 45845:25356 (r17 receipt line445). Its exact
three-file inventory, pinned by r17 uploaded receipts lines463/481/499:

| Asset | Size | Mode | SHA-256 |
| --- | ---: | --- | --- |
| uep-probe.elf | 5196 | 0700 | d1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d |
| DenialRunner.dll | 9216 | 0600 | dca73c8af979de32e27364cd3527ca28c7017b38b47058cfe3cc05896840ab57 |
| DenialRunner.runtimeconfig.json | 154 | 0600 | ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38 |

Every asset: nonlinked regular file, uid901, single link, exact size/mode/hash.
Hashes are recorded receipts, not newly built helper guesses. Modes follow the
recorded umask077 upload/chmod command. No r17 child mtime is invented.
evidence/r17-incident.json extracts receipt authority; the complete original log
is pinned by the snapshot and retained untouched. Inspect/enumerate BOTH paths
before ANY unlink, then re-inspect each with lexical identity checks before
unlinking only its exact inventory and rmdir only its own directory.

Then unlink **only** each directory's verified inventory, rmdir **only** those
two directories, prove local absence, disconnect and require anchored absence from a newly constructed SDK
session, checking BOTH paths. Reappearance is terminal, not a removal retry. Evidence receipts are
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
proof `90dd4328`. The failed r16 run NEVER reached protected_hashes (immediately
after r16-backup-pair); it did NOT verify 24 protected files. This corrects
r17 PLAN.md:152-154's overclaim (task51), not its sealed bytes. These are historical
incident evidence, not r18 live validation. The owner's separate read-only diagnostic confirmed
the backup directory's `directory:0:0:700:1` shape; no diagnostic is repeated here.

Defect: `gate-install.sh` creates the v5.18 backup as root under `umask 077`.
The bridge SDK is uid901 and cannot traverse that root-only directory. r16 tried
child `test`/hash operations that DAC denies; host-user fixtures did not model
that boundary. r16's seal, STOP, receipts, statuses and complete file/directory
inventory are pinned by `evidence/r16-evidence-digests.json` and checked by the
port ledger. Neither r16 nor r17 runtime artifacts are copied as live r18 inputs.

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
r18 neither restores nor implements/authorizes that future gate.

The r17 regression shim explicitly denies uid901 child `cat`, `stat`, `sha256sum`
and directory `ls`/`find`; positive controls prove those denials. With correct
directory metadata, the real production shell passes without any child-read
attempt. Symlink, non-directory, missing directory, wrong owner/group/mode/link
count and stat-error cases must STOP with an explicit refusal. Metadata and DAC
are fixture models because the host user can read those children; this is an
offline boundary test, not a claim that the real TV was exercised.

## Verification, seal and residual boundaries

### r8 v5.18 fixture provenance (authoring receipts)

The first full offline run stopped at F1-gate-script-transitions because its
inherited flow_cases.py named the r8 working tree, pruned on 2026-11-11. No guard
was relaxed. Only r18's fixture paths now name two local, sealed host fixtures;
they are NOT r18's shipped manager/runtimeconfig or SDK upload assets.

Source preference was honored: `.memhub/pruned-r1-r15-20261111.zip` contains both
original r8 assets and its seal, so no packets/ bytes were accessed or changed.
Source packet: `qn90b-uep-l4-deploy-20261109-r8`; member paths are that prefix plus
`artifacts/manager.dll`, `artifacts/manager.runtimeconfig.json`, and `seal.json`.
Verified SHA-256(seal.json) =
`e6e64a7f2e26cdfb41a9f376a42e9bc3798f37994a888f1edc87d15bc4acf7ea`,
exactly as recorded in archive commit
`abef4d7fa394cacf64aa27db444780e95559c32d`'s message. Both assets were then
verified against their OWN entries in that verified r8 seal before copying:

| r18 host-only destination | Bytes | Verified r8 seal digest |
| --- | ---: | --- |
| artifacts/v518-manager.dll | 61952 | e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a |
| artifacts/v518-manager.runtimeconfig.json | 260 | 2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b |

Sealed `evidence/r8-fixture-receipts.json` records source archive/member paths,
source packet, archive commit/message, verified seal and asset digests, sizes,
destinations and pruning/non-shipping rationale. No predecessor was restored or
modified. Production flow fixtures still hash-check the bytes against the v5.18
pins before using them; offline seal checks repeat those hashes.

Run `.venv/Scripts/python.exe -B -u <packet>/authoring_checks.py`, then
`.venv/Scripts/python.exe -B -u <packet>/offline_checks.py`, unbuffered with NO
tool timeout (the full flow exceeds 120 s). It runs authoring
(pure temporary bake, C# receipt ground truth, embedded resources, bash -n,
ruff F821 and zero-warning agent build), direct-helper build/self-tests, r16+r17+r18
cases, standalone relay, full rehearsal, full session and full mutation suites;
then builds the carried agent again and verifies every artifact, inherited
guard, exhaustive port ledger and BOTH immutable predecessor snapshots before sealing.
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
carried from r17; no execution/ tree is carried or pre-created. The historical
sealed install status is retained, not either failed certification status.
Inherited session fixtures create then empty an execution/ parent; the offline
flow removes only that empty nonlinked directory before the ledger/seal and
refuses any non-empty or redirected execution tree. The final packet has none.
Build deps/dev JSON files are unsealed compiler byproducts,
not live stage inputs. The ledger lists every carry/delta/addition/removal and
separately identifies regenerated results and binaries. `port_from_r15.py` and
`port-from-r15.json` keep their inherited filenames but now verify r17 -> r18.
`r16_checks.py` / `r16-results.json` likewise retain their names while adding
the r18 cases; this avoids changing inherited mutation-test dispatch.

Failures after a consumed attempt write durable STOP/status; no replay, auto
retry, relaxed guards or config re-creation. A readiness failure also STOPs.
An exclusive attempt receipt remains even across a hard kill. SDK/namespace
shape checks are fail-closed but not atomic exclusion against a concurrent
same-uid actor; fresh-session absence is one sample, not universal persistence.

No shipped manager/host/module bytes changed. Task40/v5.20 exclusive-create
hardening remains deferred: the old **owner-accepted residual** concerns the
following/truncating SaveBudget writer, which r18 never invokes or arms.
No new acceptance of that residual is implied. Other security layers, mid-boot
rearm, picture/hardware claims and reboot safety remain unverified/out of scope.

After host seal: independent read-only review, owner readiness probe, explicit
one-use CERTIFY arming, then optional separately approved TIDY arming. None of
those live steps has occurred merely because this offline packet is sealed.

Only LIVE_ARM_CERTIFY is planned for this packet's ADDITIONAL certification;
optional LIVE_ARM_TIDY remains a separate owner decision and separate arming.
Neither is run or armed by authoring. No live capability beyond these two stages.
Task48's two minors are covered: inherited 63 cases represented 58 distinct
transformations; results now count distinct transformed sources separately from
fixture executions. Empty DLL/runtimeconfig/PID cases require the hash/PID
refusal from recovery.py's retained numeric guard; mutations restoring %F must
die on those cases. EACCES-vs-EPERM and task40 remain unresolved.
Once r18 supersedes r17, r16 archiving is due under current+predecessor policy;
report it as follow-up, do not archive or touch packets/ during authoring.
