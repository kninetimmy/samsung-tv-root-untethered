# r19 — QN90B committed-record denial certification

Authored offline on 2026-11-11 from r18, seal SHA-256
`7edfc1af5f4a91c51c6aa106dc68430a1b857ab8bb8270aaaf841a71b20eca4d`
(77 members). The design of record and completed read-only probe are carried as
`evidence/r19-proposal.md` and `evidence/r19-probe.json`. Their future-tense gates
describe the design investigation, not the later owner decisions below.

## Authorization and order

Authoring/build/tests/seal are **offline only**: no TV contact, SDK connection,
sdb, readiness, arming, marker, live attempt, cleanup, gate operation or reboot.
No predecessor or packets/ byte is changed. Private host packet/evidence/build
directories require owner+SYSTEM-only ACLs before writing; live seal preflight
verifies privacy before contact. No credentials, runtime receipts, STOP, SPENT,
execution/ or arming marker is inherited as a live input.

After sealing: independent read-only review; separately owner-run
`certify.py --readiness`; separately approved/armed LIVE_ARM_CERTIFY; then only
if desired separately approved/armed LIVE_ARM_TIDY. Neither arming is implied by
this packet. Only these two markers are accepted. Historical install/active/
disable/inspection/preparation entrypoints refuse; retained gate scripts and
agent are for offline regression only. No root session or privilege change.

r17 remains permanently STOPPED and its denial attempt spent. Any r19 denial
is an **additional** attempt after r17, never r17's first attempt, replay, retry
or retrospective certification. r16's unspent readiness STOP remains permanent.
r18's sealed offline result is not live validation or an attempt receipt.

## Owner-accepted task52 replacement (2026-11-11)

The owner explicitly accepted the following clause verbatim before authoring;
memhub pending decision 33 carries the same wording. The old capacity condition
was not implemented by r18; this acceptance is not retroactive r18 certification.

> Denial certification must refuse whenever completeness and ordering of the committed kernel-record bracket around the single direct attempt cannot be established. Use one bounded read-only `/dev/kmsg` cursor with a saved pre-exec sequence fence, a post-exec drain-to-EAGAIN fence, uninterrupted sequence continuity, valid ordered record framing/timestamps, and independently validated raw receipts. Refuse on missing coverage, overrun/EPIPE, sequence loss/reordering, unsupported reader semantics, suppression notices, any bound, or transport/decode incompleteness; never retry execution or reread to recover a pass. Plain dmesg retention endpoints and formatted byte counts are diagnostic only. The historical ~505KB r17 rotated capture must produce a named completeness refusal, not pass because it is below1MiB. Capacity/occupancy may be reported only when actually measured and must otherwise be `unknown`. Unknown or full capacity is never a substitute for affirmative continuity; affirmative continuity for the attempt bracket makes total ring occupancy irrelevant to this acceptance claim. If the required cursor evidence is unavailable, refuse before native execution. Save evidence before verdicts; retain failed stage contents and durable STOP. This certifies committed records, not absence of unlogged/suppressed events.

## Read-only certification anchors

Every pre/post pass pins boot `299d6f3f-c014-43e5-a487-59c47c833f6f`, proof
`90dd4328ec810b4646745d4940b39652dd4d519e9b247c59ea5f517372aefc29`, SDK uid901,
active bridge, v5.19 manager `449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c`
and runtimeconfig `ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38`,
their metadata/labels, installed module bytes, and all 24 protected hashes in
requested order. Automatic proof requires the current boot and all-zero UID/GID.
Gate config and budget temp must be absent including symlinks. The budget must
be the exact stale `boot=edc9debc-8b83-4ecb-afab-27602cd084fd clear=1 restore=0\n`
receipt, root-owned regular single-link; it is never accepted as fresh.

The driver reads module-uep-gate.log, not modules.log. One read (`probes=1`)
requires exactly `uep gate (boot) uid=0: config absent (enforcing; no action)` and
`uep gate module exit=0`. The fingerprint must be
`c07bd300 00000001 00000000 000004e2`. Missing/partial/drifting evidence STOPs;
no poll or retry. Display/HDMI/GameMode remain an owner visual check.

The root-only backup is checked only at its directory:
`stat -c '%F:%u:%g:%a:%h'` must give `directory:0:0:700:1`. Symlink, missing,
wrong type/metadata or failed stat refuse with exit69. uid901 never lists,
reads, stats or hashes backup children. Creation-time pair hashes are evidenced
by sealed gate-install.sh:65-71 GATE_BACKUP_COMPLETE under set -euo pipefail,
r14 receipts 2264-2265 exit0, and stage-status-install.json SHA-256
`be77d4940030944e8939ca223f66d253864c980de919e0ad6d5a2b8d35794042`.
This certifies directory shape, not current pair bytes. A future restore needs
root re-hashing immediately before use; no restore is implemented or authorized.

Historical correction (task51): r16 readiness failed at r16-backup-pair before
protected_hashes. It did **not** verify 24 protected files. r17 PLAN's contrary
claim remains in its immutable historical bytes, not in r19's authority.

## Persistent cursor and execution accounting

Exclusively create random denial-<16 hex> under the canonical SDK root and
upload the sealed ELF, helper and runtimeconfig. Recheck path, directory
creation identity, uid901, nonlinks, ELF mode0700/single-link and all hashes.
The ELF is 5196 bytes, SHA-256
`d1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d`.

Before helper launch, real shell guards require dmesg_restrict=0,
`/dev/kmsg` metadata `character special file:0:1901:660:root:log`, membership in
owning group1901, and node SMACK `access="*"`. Each drift has a named
KERNEL_ACCESS_REFUSAL/exit69. The helper independently records its actual
Uid/Gid/Groups, capability fields, NoNewPrivs, SMACK, boot and restriction.
Require all four UID/GID fields901, CapEff zero, group1901, label System and
pinned boot; recheck the profile after the bracket. No root/capability fallback.
The shell probe does not establish the helper's actual credentials: drift refuses.
Each shell observation checks its command's status separately: a failed cat,
stat, id or chsmack cannot pass by printing an otherwise matching value. Current
packet/evidence ACLs are checked before attempt/SDK construction; inherited
controller privacy checks alone concern the controller's own directory.

The helper opens /dev/kmsg O_RDONLY|O_NONBLOCK once through libc, before Attempt.
Drain that fd to EAGAIN within the limits below; validate arrival order and keep
the last complete raw record as baseline s0. Empty baseline, malformed format,
read error or exhausted bound refuses before native execution. Then call the
existing direct Process.Start Attempt exactly once. Drain the **same fd** to
EAGAIN, requiring s0+1, +1, ... with no gap, duplicate or reversal. No reopen,
seek, resync, recovery read, execution retry, or polling for a convenient pass.
EPIPE remains fatal even if later input would be valid. Close once.

The six-key exec object is unchanged inside version1 outer {exec,kernel_capture}.
Direct Win32Exception errno1/13, exec_started=false, native_exit=null, empty
stdout/stderr, timed_out=false and wrapper77 are required. 77 is not a native
child exit. Any started child fails regardless of exit; retain the inherited
5-second wait, owned kill, 1-second reap and 1-second output-close bounds.
The native success marker must be absent. No shell Permission-denied/$? pin.

Save the encoded transport and decoded raw envelope with SHA-256 before host
semantic assertions. The host independently parses raw record framing, baseline
and sequence steps, ordered integer timestamps, fences, profile, numeric counts,
and exactly one kernel-facility full-signature message for the exact canonical
random stage path. Only '-' flags and one message line are supported; continuation,
dictionary or malformed framing refuses. Escaped bytes are never flattened into
records. Missing or duplicate exact-path signatures refuse. Uptime strings retain
their precision as diagnostics only: rounded timestamps do not grant membership.

## Two independent bounds — owner-settled

**Raw decoded record bytes are limited to 1,048,576 across the entire baseline
drain plus the post-attempt drain combined.** All pre-drain bytes count, not just
the retained baseline. The pre-drain can therefore consume the whole observed
~505KiB ring with headroom to reach EAGAIN. There is no 512KiB raw bound. A raw
overflow is `kernel-capture-raw-bound`; record-count and drain-time exhaustion
have separate named refusals. Each drain is limited to 16,384 records and two
seconds; each read uses 8192 bytes and a full-sized/oversized record refuses.
The SDK request's existing 15-second deadline is the outer bound.

**Transport is independently limited to 131,072 actual reply bytes**, covering
the gzipped-then-base64 envelope and response framing. This cap is on encoded
wire bytes, not the raw stream. Denial overflow raises
`kernel-capture-transport-bound`; it never truncates into a success. The shared
transport owns this boundary and saves its bounded incomplete raw prefix first.
Whichever bound trips first determines refusal. The JSON envelope contains
base64 record framing, so its defensive 2MiB parsing budget is structural
overhead, not a replacement raw-record budget or a capacity estimate.

Capacity/occupancy is **unknown**. No klogctl/syslog capacity call or threshold
is invented. Plain dmesg endpoints and byte counts are diagnostic only. The
historical rotated 505101-byte fixture refuses as
`kernel-capture-completeness-unproved`, capacity_state unknown,
rotation_observed true, even with a surviving witness and good endpoints.
r17's pre/post captures were 505101/504949 bytes; their advancing prefix and
missing end coverage are recorded incident evidence, not a saturation meter.

Sequence continuity proves completeness/order of committed records in this
causal bracket, **not absence of unlogged/suppressed events**. Recognized
suppression/drop notices refuse as kernel-emission-suppressed. No suppression
line does not prove the proprietary UEP call site is unratelimited. Delayed
asynchronous events beyond the post fence, vendor ABI deviations, kernel
deception and concurrent same-uid/privileged actors are not ruled out.

## Partial transport evidence

Only the denial-evidence request opts in. After the accepted peer's verified
initial tag, retain at most131072 raw response bytes and separately count all
observed bytes, slicing before append. On any terminal request/closure failure,
including EOF/no trailer, overflow, invalid UTF8/trailer, OSError, timeout or
cancellation, emit exactly one sdk-reply-incomplete before propagating failure.
Receipt fields include internal request ID, exact base64 prefix, prefix-only
SHA-256, retained/observed-at-least counts, truncation and trailer-seen state;
transport_complete, capture_complete and usable_as_kernel_authority are false.
A trailer alone is not success: local exit and closure must validate too.
Receipt/fsync failure reports both the original and persistence failure and
propagates toward durable host STOP; failed storage cannot promise durability.

Never save rejected-peer/tag bodies, bootstrap argv, desktop stdout/stderr,
tokens or environment. Ordinary logs retain tag redaction and desktop diagnostic
categories only. A narrow owner-reviewed exception permits the single-use
response trailer nonce in this private byte-exact prefix; it is correlation
framing, not a reusable management credential. No diagnostic partial decode,
normal denial-kernel-after authority, retry or failure-path cleanup.

## Inventory and cleanup policy

Task53 is unchanged: cleanup stays **after** successful exec/kernel assertions.
Failure retains all staged identity/file evidence and propagates directly to
durable STOP/status. No finally-cleanup, post-STOP operation or replay. A new
failed r19 stage requires separately designed/reviewed/armed evidence-preserving
cleanup; the optional tidy owns only the two older known directories.

Tidy retains both independent production guards: entry count via find -printf x
and exact rendered-name comparison. Split count-only and comparison-only mutants
are killed separately. A single composite-LF filename renders the three expected
names but count1 must refuse inventory-count. A wrong simple name with count3
must refuse inventory. Tests execute the actual generated prefix and full
command, require exact TIDY_REFUSAL tokens/exit69, no unlink, unchanged bytes and
directory identities. The LF-only extra fixture remains. No NUL-safe rewrite.

Optional separately armed tidy verifies BOTH exact directories before any unlink:
denial-fd9fa25930776ce9 (task46; one ELF, mtime1794343800) and
denial-5bd20c32c9b13f14 (r17; creation identity45845:25356). The latter retains
receipt-pinned original ELF/DLL/runtimeconfig hashes and sizes5196/9216/154,
modes700/600/600; no newly built helper substitutes for the staged r17 DLL.
Require exact canonical paths, owned0700 nonlinked directories, nonlinked regular
single-link uid901 children, exact metadata/hashes and applicable mtime. Recheck
lexical directory identity before unlinking only the known children and rmdir.
Require absence from a fresh ordinary SDK session; reappearance refuses, never
retries. This is tidy-up, not hazard recovery. Receipts are not deletion targets.

Task48 remains covered: mutation totals count distinct transformed-source hashes
separately from fixture executions; empty relay DLL/runtimeconfig/PID cases reach
their hash/PID refusals, not the old %F comparison. The v5.20 exclusive-create
fix (task40) remains deferred. The historical **owner-accepted residual** is the
following/truncating SaveBudget writer; r19 never invokes or arms that writer.
EACCES versus EPERM remains unresolved and is never normalized.

## Offline verification and remaining device claims

Run authoring_checks.py, r16_checks.py, relay_checks.py, mutation_checks.py and
offline_checks.py with .venv/Scripts/python.exe -B -u, unbuffered and no timeout.
Pinned SDK3.1.426, DOTNET_MULTILEVEL_LOOKUP=0, all builds zero warnings. Isolated
Ruff explicitly uses py312, matching pyproject.toml requires-python>=3.12; no
repository target change or per-line suppression. Every mutant must die with its
intended terminal exception type/message; no minima or suppressed survivors.
The seal flow reruns every suite and verifies all predecessor member hashes and
whole-tree snapshots. The exhaustive inherited-name port ledger now covers
r18 -> r19. Compiler auxiliary files are not live inputs. No execution/ remains.

Windows streams and injected fd transcripts do **not** prove Linux ABI behavior.
Unproven on device: libc binding/open/read/close, actual managed credentials,
persistent-fd cursor continuity and EAGAIN fences across an attempt, vendor
overrun/record semantics, timing headroom and complete helper-envelope transport.
The read-only shell probe proved access/sample sequences, not these claims.
Readiness, arming and certification remain separate owner operations after review.

After r19 supersedes r18, r17 archiving is due under current+predecessor policy.
Report only: authoring does not archive, delete or modify any predecessor.

### Authoring corrections, not hidden green results

- Initial authoring failed Ruff F821 for BaseExceptionGroup because --isolated
  discarded the project's Python>=3.12 metadata. Explicit py312 in the packet's
  two isolated check commands fixes this; no project config or suppression changed.
- A draft 512KiB post-drain bound was rejected by the owner and removed. The
  settled combined 1MiB raw / 128KiB encoded-wire model above is authoritative.
- Adding counter validation exposed stale pre_bytes in the old-witness fixture;
  that fixture now accounts for its longer baseline record, preserving its
  intended missing-witness refusal instead of dying at an unrelated counter.
- The first UTF8 decoder fixture attempted to alter plaintext inside base64
  records and injected nothing. It now injects invalid bytes into actual JSON
  text and explicitly asserts that the injection occurred before exercising it.
- Final preflight inspection found inherited local_checks validates the
  controller directory, not this packet. Explicit packet/evidence ACL checks
  and independent killed-mutant fixtures cover that boundary. Failed shell
  observations also require named refusals even if stdout matches the profile.
- The first complete seal-flow attempt passed every suite/build but stopped
  before sealing at the new clause check: Windows CP1252 could not decode the
  UTF8 proposal. New source/document reads now explicitly select UTF8. Only the
  inspected empty host fixture execution/ parent was removed before restarting
  the full flow; no runtime evidence, predecessor or sealed result was removed.
