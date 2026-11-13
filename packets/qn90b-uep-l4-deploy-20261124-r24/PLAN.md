# r24 — decision-50 pre-baseline resynchronisation amendment

Offline successor to permanently STOPPED r23, 89 members, seal SHA-256
`c4db777e5ab97ff69e0c02552b7e493f50c8145ae5eff042f5f43511ea595804`.
r23's single armed attempt refused pre-execution with `kernel-overrun-EPIPE`:
Process.Start never ran. No device execution attempt has occurred since r17.
Never modify, re-arm or replay r23. r24 is not a retrospective pass for r23.
The exhaustive `port_from_r15.py` / `port-from-r15.json` lineage is r23 -> r24.
The 91-member seal includes the complete `evidence/r23-evidence-digests.json`
snapshot of all r23 files and directories, including unsealed runtime receipts,
STOP, LIVE_ARM_CERTIFY and execution/attempts. No such runtime file is carried.
Historical install bytes move unchanged to `evidence/inherited-install.json`,
not a current stage-status file. NuGet.Config clears network package feeds.

## Authorization and inherited readiness

Authoring, builds, tests and sealing are **offline only**: no SDK connection,
device contact, readiness run, armed attempt, LIVE_ARM_* file, gate operation,
cleanup or reboot. No sealed r16-r23 bytes, packets/, src/, payloads/ or modules/
bytes are changed. Host packet/evidence/build directories are private before writes.
Runtime receipts, refusals, STOP/SPENT, execution trees and markers are not carried
as current authority. No commits, pushes or tracked-file changes are part of this task.

The owner's r21 readiness probe passed at 2026-11-12T03:02Z. The source is the
**unsealed** r21 `receipts.jsonl`, read without modification. Its whole-stream hash,
exact selected rows and 1-based line citations are sealed in
`evidence/r21-readiness.json`; the r21 whole-tree snapshot binds it too.
The inherited event names are preserved verbatim: `r20-read-only-certified` and
`r20-readiness-passed` were emitted by r21, not by r20. Supporting rows record
uid901, manager/module/backup state, proof and 24 protected hashes. There were
0 TV writes and 0 attempts; the predecessor snapshot records no STOP, SPENT,
refusal stream or execution tree. The readiness evidence is exactly r21's probe,
carried byte-for-byte through r23, not an r24 readiness run. r23 also passed an
owner-run read-only readiness probe on 2026-11-12 before its stopped attempt;
its evidence is bound by the r23 whole-tree snapshot, not promoted to r24 authority.
This packet has no new live readiness evidence.

After sealing: independent review, then only separately authorized owner-run
readiness and separately approved arming. Accepted markers remain exclusively
LIVE_ARM_CERTIFY and LIVE_ARM_TIDY. Historical install/active/disable/inspection/
preparation CLIs refuse; their retained methods and gate scripts are regression-only.
r16's readiness STOP and r17's spent denial remain permanent. r19 STOPped before
opening /dev/kmsg or executing the native control; its local attempt is consumed.
Any future authorized r24 denial is an additional attempt after r17, never a replay.

## Unchanged anchors and source boundary

Every live pre/post pass still requires:

- Boot `299d6f3f-c014-43e5-a487-59c47c833f6f`; proof
  `90dd4328ec810b4646745d4940b39652dd4d519e9b247c59ea5f517372aefc29`.
- SDK uid901, active bridge, v5.19 manager
  `449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c`, runtimeconfig
  `ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38`, exact
  metadata/labels, module bytes and ordered 24-file protected set.
- Gate config and budget temp absent, including symlinks. Exact stale budget
  `boot=edc9debc-8b83-4ecb-afab-27602cd084fd clear=1 restore=0\n`, root-owned
  regular single-link; never treat it as fresh.
- The driver reads module-uep-gate.log, not modules.log. A single probe requires
  the absent-config receipt plus exit0; enforcing fingerprint is
  `c07bd300 00000001 00000000 000004e2`. Display/HDMI/GameMode is an owner visual check.
- Backup directory `directory:0:0:700:1`. uid901 does not traverse/read/hash its
  children. Creation-time pair hashes come from gate-install.sh GATE_BACKUP_COMPLETE,
  r14 receipts 2264-2265 and inherited install receipt SHA-256
  `be77d4940030944e8939ca223f66d253864c980de919e0ad6d5a2b8d35794042`.
  This certifies directory shape, not current pair bytes; any future restore needs
  root re-hashing immediately before use. No restore is implemented or authorized.

SOURCE_SHA remains
`ab82a876ad0f9a045a4cf0cb2b008a9f6cc9f9707a19de416fe4b06177125902`.
SOURCE_COMMIT/COMMIT remains `6659874826351b983e65fcadc27804c4ecc40133` for
authoring and marker provenance. Authoring refuses stale HEAD; live preflight uses
the dependency digest over src/samsung_tv_root, payloads and modules, not exact HEAD.
The canonical sorted ASCII JSON path->SHA map is documented by source_manifest()
and sealed in evidence/source-digests.json. Ignored bytecode is not in that digest.

## M1 — bootstrap cache selection before packet import

r21's packet-body guard was too late: Python could load an adjacent header-valid
packet.pyc before any packet.py instruction executed. r22 introduced a stdlib-only
prologue at the start of every sealed Python module except packet.py and the
stdlib-only port tool. Before any local import, it imports sys/tempfile and, when
packet is not already loaded, disables bytecode writes and assigns sys.pycache_prefix
to a fresh tempfile.mkdtemp(prefix='qn90b-r24-pycache-') directory in r24. packet is the
first local import, including the indirect SDK/rehearsal entry surfaces. Later
imports in that process retain the established prefix. No environment prefix is reused.

An entry script is executed from source as __main__, not loaded from its adjacent
cache. packet.py then **adopts the same prefix**, checks its absolute canonical
location immediately under the platform temp directory outside REPO, and requires
an empty directory with the expected name prefix. It hardens the existing leaf
with the same owner+SYSTEM-only Windows PowerShell ACL recipe as the pinned
controller and verifies it with private_acl. It does not create a replacement.
The already hash-checked inherited controller is compiled from source, never cache.
The empty private prefix is retained, never reused or automatically removed.
No machine-wide environment is changed. Failed ACL setup/verification fails closed.

The unchanged source-cache preflight refuses missing/redirected source roots or
directories, scan failures and populated __pycache__ directories, naming the
observed paths without deleting evidence. This task requires **no __pycache__ or
.pyc anywhere in src/, payloads/ or modules/** at start/end and creates none there.
The runtime scanner specifically detects populated __pycache__ trees; it does not
claim to inventory every conceivable bytecode filename. Cache selection protection
comes from the fresh prefix. Ordinary unrelated Python tooling can repopulate caches.

r21_checks.import_graph compares the prologue AST at the start of every covered
module, checks every import/from-import packet occurs afterwards, and retains the
source-import/controller graph checks. Missing or reordered prologues fail the suite.
The eight inherited real entrypoint bodies are executed from their script paths in
fresh isolated subprocesses, with __main__ dispatch intentionally disabled so no
live stage can run. A header-valid timestamp packet.cpython-*.pyc is planted beside
an unchanged copy of the sealed packet.py. The clean case must execute real packet
source, retain a non-None prefix, emit no FORGED_CACHE and write no refusal. Removing
only certify's prologue is the positive control: the same forged cache prints
FORGED_CACHE and exits0, proving it is load-bearing without the protection.
The older source-module poison/prefix-only and populated-cache refusal tests remain.
All poison lives in private disposable copies, never the real source tree.

Scope: fresh operator script processes, not arbitrary unguarded `python -c 'import
packet'`, hostile interpreter startup/preloaded modules, stdlib replacement or
concurrent same-user/privileged source/ACL replacement. Structural and subprocess
tests cover this boundary; a seal does not make untrusted startup code safe.

## m1 — private-before-write refusal persistence

record_refusal verifies packet-directory privacy **before** opening refusals.jsonl.
If that directory check fails, it selects the established prefix and independently
verifies its privacy before opening the fallback refusals.jsonl. Redirection and
single-link file checks, append-only newline rows, flush and fsync remain required.
The rejected directory receives no refusal write. The original raised exception
gets a note naming the absolute fallback stream path. If storage/privacy cannot
be verified or persistence fails, a BaseExceptionGroup exposes the original and
persistence failures; no durability is claimed when storage itself fails.

The existing schema remains stage/kind/reason/UTC utc/consumed:false. Refusals do
not create STOP, SPENT, an attempt stamp, marker, runtime receipt or stage status.
Successful correction can resume an otherwise eligible packet, never revive a
stopped/spent packet. Consuming stage errors retain their existing STOP/status rules.
The real Windows ACL regression first confirms its fixture directory is rejected,
then requires that directory remain empty, a fallback row survive reopen after
real fsync, and its exact path appear in the raised error's notes. Append/fsync/
failure propagation, readiness/certify/tidy resumption and retired-CLI cases remain.

## Receipt audit labels

certify's 11 packet-specific capture/log labels now consistently say r24, including
r24-read-only-certified, r24-readiness-passed and r24-backup-evidence. Every covered
module's bootstrap prefix and packet.py's prefix check also say r24. Inherited suite
names, fixture prefixes and evidence event names are not rewritten. r16_checks tests
the current readiness event; r21_checks retains certify's exact 11-label inventory.

The directly registered packet_attribution_case additionally parses every Python
module in SEAL_ENTRIES. It discovers positional label/event argument slots from
sealed function declarations (matching callee basenames), and checks literal
arguments in those slots or label/event/evidence_label keywords. It also checks
direct literal write_text/write_bytes data, including the space-delimited r24
SPENT text. At these sites, strings beginning rNN- or rNN followed by whitespace
must name the packet revision derived from its directory, not an allowlist of
emitting modules or complete labels. Calls with a packet keyword or a literal rNN
predecessor keyword must have both as exact literal revisions matching the current
directory and port ledger's actual PRIOR directory. Directory-valued predecessor
metadata in the ledger is not a receipt revision pair. The guard requires nonempty label,
file-output and attribution categories; it cannot pass vacuously.

Five added mutants independently stale a label in denial.py, the attempt's packet,
its predecessor, and tidy's SPENT text, or remove this guard's direct registration.
Each must fail its named terminal assertion, not merely exit nonzero. Existing
case-registration policy automatically includes this *_case and future *_case
declarations. No per-file emission list needs extension in a future packet.

Scope is literal sites in the stated Python AST forms, not general dataflow.
Computed/variable/f-string values, aliased callees, indirect keyword dictionaries,
other file/stream APIs, embedded revision tokens not at the string start and
non-Python emitters are not covered by this attribution guard. Method-name matching
is conservative, not binding resolution; a future collision or historical emission
at a matched site requires explicit review, not a silent allowlist exemption.
The bootstrap guard separately covers its embedded pycache revision prefix.
Historical suite/evidence references outside emission slots are not current labels.

## Original accepted contract and explicit owner-approved amendment

Owner-accepted task52 replacement (2026-11-11), verbatim from evidence/r19-proposal.md:

> Denial certification must refuse whenever completeness and ordering of the committed kernel-record bracket around the single direct attempt cannot be established. Use one bounded read-only `/dev/kmsg` cursor with a saved pre-exec sequence fence, a post-exec drain-to-EAGAIN fence, uninterrupted sequence continuity, valid ordered record framing/timestamps, and independently validated raw receipts. Refuse on missing coverage, overrun/EPIPE, sequence loss/reordering, unsupported reader semantics, suppression notices, any bound, or transport/decode incompleteness; never retry execution or reread to recover a pass. Plain dmesg retention endpoints and formatted byte counts are diagnostic only. The historical ~505KB r17 rotated capture must produce a named completeness refusal, not pass because it is below1MiB. Capacity/occupancy may be reported only when actually measured and must otherwise be `unknown`. Unknown or full capacity is never a substitute for affirmative continuity; affirmative continuity for the attempt bracket makes total ring occupancy irrelevant to this acceptance claim. If the required cursor evidence is unavailable, refuse before native execution. Save evidence before verdicts; retain failed stage contents and durable STOP. This certifies committed records, not absence of unlogged/suppressed events.

The original clause above did **not** permit recovery from EPIPE. Do not read its
"never ... reread" sentence as if it always contained an exception. Decision 50,
"Allow one pre-baseline /dev/kmsg resynchronisation in r24", owner-approved on
2026-11-12 after the read-only probe, explicitly amends only that pre-baseline case:

> CHANGE: r24 may allow exactly one recorded resynchronisation of the /dev/kmsg reader before any successful read, and only when all of these hold: no record has been accepted yet, no baseline or sequence fence exists, no execution has occurred, the same file descriptor is reused, the event is recorded durably with its errno, the original time and byte budgets are not reset, and valid contiguous records plus a real drain-to-EAGAIN are still required before Process.Start. Every later EPIPE, sequence gap, framing failure or bound violation remains fatal, and a pre-fence resync may never be repeated.

Non-permissions: no execution retry; no seek-to-tail; no continuity reset across
a gap; no empty baseline after SEEK_END (indeed no seek at all); no larger byte
limits as a fix; no plain-dmesg fallback. No reopen, credential change or expansion
of the certified interval is authorized. A second pre-fence EPIPE is fatal with
`kernel-pre-acquisition-EPIPE`. Every post-fence EPIPE is fatal with
`kernel-mid-bracket-overrun-EPIPE`, never resynchronised. Both still return79.

Authority and evidence: memhub decision50 and fact
`qn90b.kmsg_epipe_probe_20261112`. The read-only 2026-11-12 probe (no helper,
staging or execution) observed immediate reads 0/8 EPIPE; after500ms, 6/10 first
reads EPIPE and 6/6 next reads on the same fd valid. 2000 records/188662 bytes
drained in21ms without EAGAIN. These small, bursty, message-text-classified samples
had no strace/raw errno and cannot exclude vendor CLR deviations. They support
cursor eviction on a full ring and kernel cursor reset inside the failing call;
they do not demonstrate r24, a latency guarantee or a complete bracket.

Implementation: `DenialRunner.Capture` handles EPIPE only inside the pre-drain.
`CanResync` requires accepted==0, baseline==null, previous==null, both fence flags
false, executionInvoked==false, fd>=0, fd==openedFd and used==false. The same fd
is retried once without seek/reopen; no accepted record or counter is cleared.
The original begun clock and byte/count budgets are retained. The elapsed bound
is checked after the failing call and after persistence, before another read.
An accepted record immediately disqualifies resync even before drain-to-EAGAIN.

Durable means **before the next read and before execution**, not merely inclusion
in the final envelope: a CreateNew `DenialRunner.resync.json` journal in the exact
new denial stage is written, FileStream.Flush(true) is required, then its parent
directory is opened O_DIRECTORY, fsynced and closed. Any creation/write/flush/
sync/close failure refuses; no success or durability is claimed if storage fails.
The event contains read, raw_return=-1, captured errno32, pre-fence, invoked=false,
fd, zero accepted/byte counters, absent baseline/fences and elapsed_ms. The envelope
retains the event even on later failure and marks resync_durable only after sync.
The host saves/hashes the encoded and decoded envelope before verdicts, validates
the event's gates, and independently hashes the optional on-device journal against
the event before successful guarded cleanup. Failed stages retain the journal.
The optional journal is removed only with the newly successful stage, never by
the inherited three-directory tidy. No owner-approved execution retry is implied.

Interpretations chosen: "before any successful read" means no accepted record,
and malformed/empty reads are fatal, never a route back to eligibility. "Exactly
one" is a maximum on EPIPE, not a required resync when the first read succeeds.
The event is durably stored on the device before resuming, then copied into saved
host evidence, rather than trusting a final in-memory envelope as durable.
Decision50 did not specify a persistence medium; this is the stricter interpretation.

The measured-helper owner-accepted residual is unchanged: UID/GID901, group1901,
CapEff `0000000000200040` (CAP_SETGID|CAP_SYS_ADMIN), SMACK User, dmesg_restrict0,
pinned boot. Read access rests on node `0:1901`, mode660 and SMACK access="*",
not the helper label. This certifies denial for that measured credential profile,
not a general absence of capability fallback. Exact named constants and post-profile
comparison remain. No privilege change is introduced.

The helper opens one O_RDONLY|O_NONBLOCK /dev/kmsg cursor, drains to EAGAIN,
saves baseline s0, calls Process.Start once, drains the same fd to EAGAIN and
requires uninterrupted s0+1 sequence continuity. The sole resync exception is
the decision50 pre-baseline case above; no execution retry or post-baseline recovery.
The helper validates every pre-drain record; only the final pre record (baseline)
and post records are retained. The host independently parses their framing,
ordered timestamps, counters, profile,
fences and exactly one kernel-facility signature for the exact canonical stage.
Unsupported flags/dictionaries, suppression notices, malformed records and gaps refuse.
Direct Win32Exception errno1/13, exec_started=false, native_exit=null, empty
stdout/stderr, timed_out=false and wrapper77 are required. 77 is not a child exit.
The inherited 5-second wait, owned kill, 1-second reap/output-close bounds remain.

Raw record budget is 1,048,576 bytes over pre+post combined; wire budget is independently
131,072 actual reply bytes. Count bound16384 per drain, two-second drain bounds,
8192-byte read buffer and 15-second SDK deadline remain. Both two-second limits
are checked before and after each read, including the final EAGAIN. A slow final
call cannot grant a fence. The buffer and initial clock are allocated before open;
this shortens the exposure window but does not remove the race. Distinct raw/wire refusals;
transport/decode incompleteness takes precedence if the helper's refusal envelope
cannot arrive completely. Capacity/occupancy stays unknown. The rotated 505101-byte
historical fixture must refuse completeness, not pass on size alone.

Save encoded transport SHA-256 over the exact saved string's UTF-8 bytes and decoded
raw-envelope SHA-256 before semantic assertions. This does not hash discarded SDK
framing. Failure observations/post-profile survive their verdicts. The opt-in partial
reply stream retains a bounded raw prefix and counts observed bytes before failure;
it is never decoded as authority. Never save rejected-peer data, credentials or
bootstrap argv. No failed-stage cleanup, evidence erasure or retry.

Optional tidy remains separately armed for exactly the three receipt-pinned older
directories: denial-fd9fa25930776ce9, denial-5bd20c32c9b13f14 and
denial-ec6cf65890501d00. Exact metadata/identity/hashes, entry count and rendered-name
guards precede every unlink; the third directory's failure leaves the first two
untouched. Fresh-session absence is required. No newly built helper replaces an
old receipt pin. The fourth leftover `denial-1996fae788d64149`, creation receipt
`45845:36733`, stays outside TARGETS, command(), absence_command() and removal
receipts. Its path/receipt and uploaded hashes occur in r23 evidence, but this
packet does not assert a fresh exact inventory/metadata set for it. Do not invent
that metadata. It is a named residual for the separate task53 cleanup design.
Its absence, presence or failure cannot gate or alter cleanup of the first three;
host tidy fixtures leave a named fourth directory untouched. Any new failed r24
stage also requires separately designed cleanup.
The v5.20 exclusive-create fix (task40) remains deferred: the owner-accepted residual
is UepGate.SaveBudget's following/truncating temporary writer. r24 never arms it;
the script precheck does not close its check-to-write race. EPERM versus EACCES
remains unresolved, never normalized.

## Verification and remaining claims

Run authoring_checks, r16_checks, r21_checks, relay_checks, mutation_checks,
offline_checks, in that order, with `.venv/Scripts/python.exe -B -u`, unbuffered,
no tool timeout, waiting for each actual process exit. The final seal flow reruns
its suites/builds and verifies exact catalog membership, intended terminal mutant
exceptions, source/HEAD pins and r16-r23 complete snapshots before sealing.
Pinned .NET SDK3.1.426 / DOTNET_MULTILEVEL_LOOKUP=0; all builds require zero warnings.
Ruff F821 uses isolated py312. No new dependencies or broad repository test run
that could repopulate source caches is required by this packet-only change.

The r24 authoring/regression/relay/session catalogs are14/217/36/73. The managed
catalog retains the seven direct-exec checks and expands the named capture cases.
authoring_checks builds and tests the changed helper before host flow fixtures;
offline_checks rebuilds it again with SDK3.1.426 and zero warnings.
r21_checks runs 19 named cases per round, twice (38 executions). The inherited 18
are joined by the directly registered packet-attribution result.
The packet-cache and ACL checks no longer run inside another case. case_registration
introspects this module's function declarations and requires every *_case, including
future additions, to have a direct run() registration. This is the strict policy,
not general call-graph inference: supported registrations are named callbacks or
lambdas directly calling named functions, at run() top level or inside nonempty
literal-tuple loops. An indirect-only case must be explicitly registered or renamed.
The guard itself must also be registered. Four mutants remove the packet/ACL/guard
registrations or add an unwired future case; each must fail with its named missing
registration. A fifth registration mutant removes packet-attribution. The seal flow
requires case-registration, packet-bytecode, refusal-acl and packet-attribution
in both complete rounds.
Mutation totals are computed from exact transformed-source
hashes, separately from fixture executions; missing and forged-cache bootstrap
fixtures intentionally exercise the same transform. Actual outcomes are recorded
in the regenerated result files, not inferred from this plan. No skipped survivor
or wrong-reason death counts as a kill. The independent final rehash covers every
seal entry; git status and real source-cache absence must remain clean.

Inherited readiness proves the observed r21 read-only pins, not an r24 live run or
Linux helper behavior. Offline fixtures cannot prove libc bindings, actual continuing
helper identity, persistent-fd/EAGAIN continuity across execution, vendor overrun
semantics, timing headroom or complete on-device envelope transport. No claim rules
out unlogged/suppressed/delayed events, kernel deception or concurrent privileged
actors. Review, readiness and an armed certification remain distinct owner decisions.

The preceding offline/live residual applies to r24, including the new file/directory
durability calls. Windows transcripts cannot validate Linux fsync or vendor CLR
bindings. No r24 readiness run, armed attempt or TV contact is claimed by this seal.
