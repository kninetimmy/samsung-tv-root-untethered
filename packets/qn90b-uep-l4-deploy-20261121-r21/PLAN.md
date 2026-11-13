# r21 — QN90B bytecode-isolated committed-record denial certification

Authored offline from sibling r20, seal SHA-256
`a6988f7bcc6d23e27181a958971b1c5c6041d8ce77a5b1a2ec69b1faac9e9367`
(83 members). This successor closes exactly the independent r20 review's one
major and two minor findings. The design of record and completed historical read-only shell probe are carried as
`evidence/r19-proposal.md` and `evidence/r19-probe.json`. Their future-tense gates
describe the design investigation, not the later owner decisions below.

## Authorization and order

Authoring/build/tests/seal are **offline only**: no TV contact, SDK connection,
sdb, readiness, arming, marker, live attempt, cleanup, gate operation or reboot.
No predecessor or packets/ byte is changed. No shipped src/, payloads/ or modules/
byte is changed. Private host packet/evidence/build
directories require owner+SYSTEM-only ACLs before writing; live seal preflight
verifies privacy before contact. No credentials, runtime receipts, STOP, SPENT,
execution/ or arming marker is inherited as a live input.

After sealing: independent read-only review; separately owner-run
`certify.py --readiness`; separately approved/armed LIVE_ARM_CERTIFY; then only
if desired separately approved/armed LIVE_ARM_TIDY. Neither arming is implied by
this packet. Only these two markers are accepted. Historical install/active/
disable/inspection/preparation entrypoints refuse; retained gate scripts and
agent are for offline regression only. No root session or privilege change.

r17 remains permanently STOPPED and its denial attempt spent. Any r21 denial
is an **additional** attempt after r17, never r17's first attempt, replay, retry
or retrospective certification. r16's unspent readiness STOP remains permanent.
r18's sealed offline result is not live validation or an attempt receipt.
r19's readiness passed at 2026-11-11T19:41:45Z, but its one armed certification
run permanently STOPPED at 19:44:59Z: kernel-access-helper-identity-drift,
wrapper79, exec=null, baseline=null, pre_bytes=0, records=[], errno=0. Its
ValidateProfile ran before open and Attempt: no /dev/kmsg open or kernel read,
and no native execution attempt. The local certification attempt is consumed;
never retry r19. Historical creation/upload/refusal extracts and decoded envelope
are bound by evidence/r19-incident.json and the complete immutable r19 snapshot.

## Owner-accepted task52 replacement (2026-11-11)

The owner explicitly accepted the following clause verbatim on 2026-11-11 before
r19 authoring. The proposal (evidence/r19-proposal.md) and this PLAN carry that
verbatim clause. Accepted memhub decision47 is a summary, not verbatim approval
wording; decision33 is unrelated exclusive-create history and is not this
approval's citation. The old capacity condition was not implemented by r18;
this acceptance is not retroactive r18 certification.

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
claim remains in its immutable historical bytes, not in r21's authority.

## Provenance and source pin guard rail (task58)

COMMIT remains provenance: authoring HEAD is
`6659874826351b983e65fcadc27804c4ecc40133`. Both authoring_checks and the
offline seal flow refuse before builds unless repo_head() == p.COMMIT. A stale
copied pin cannot silently acquire a new seal. r16-r19's old 8f92e54 pin remains
in their immutable bytes; no detached checkout is used to satisfy r21.

Live marker and certification/readiness preflight instead require SOURCE_SHA,
a canonical SHA-256 of the dependency directories src/samsung_tv_root,
payloads and modules. Enumerate tracked plus nonignored untracked files with
git ls-files -z --cached --others --exclude-standard scoped to those directories;
sort/deduplicate names, reject unsafe or redirected/non-file paths, require each
root nonempty, hash actual working bytes, then SHA-256 the ASCII canonical JSON
map of repo-relative forward-slash path to file SHA-256 (sorted keys, separators
comma/colon, ensure_ascii=True). Ignored compiler/cache output is not source;
the executable-bytecode gap is closed separately below, not by this enumeration.
The exact manifest, digest and provenance are sealed in evidence/source-digests.json.
Changed/deleted/added/renamed source fails closed; an archive/doc/test-only HEAD
change outside those directories does not strand this reviewed packet. Marker
contents still name COMMIT. This does not authorize source changes or any live act.

SOURCE_SHA remains
`ab82a876ad0f9a045a4cf0cb2b008a9f6cc9f9707a19de416fe4b06177125902`.

## r20 review findings and r21 closures

### Finding 1 — MAJOR: executable bytecode outside the digest

Git ignores __pycache__/ and *.pyc, so source_manifest() does not hash them.
A header-valid cache can execute instead of the pinned .py, and r20 imported
samsung_tv_root before require_source_integrity(). dont_write_bytecode suppresses
writes only, not reads. Environment cleanup alone would be unsealed and unprovable:
the executable-code guarantee must live in the sealed code, not in a purge receipt.

packet.py sets sys.dont_write_bytecode=True in its module body and calls
isolate_source_bytecode() before returning to any caller. That function exclusively
creates a random per-process qn90b-r21-pycache-<32 hex> directory below the platform
temporary directory returned by tempfile.gettempdir(), outside REPO, using
make_private_directory. The check suite uses that same platform facility; no
agent harness scratch directory is a runtime prerequisite.
The inherited helper uses Windows PowerShell 5.1 to set and verify owner+SYSTEM-only
ACLs. The new prefix is assigned to sys.pycache_prefix even if the launching
environment specified a different prefix. It is never reused. These empty private
directories are retained in host temp; the packet performs no automatic deletion.
The owner may remove them separately after review. No machine-wide environment
variable is changed. This targets fresh packet processes, not hostile interpreter
startup, preloaded modules or concurrent same-user/privileged source replacement.

Next, require_empty_source_caches() walks all SOURCE_ROOTS with an error-raising
os.walk onerror handler. Missing/redirected roots or directories refuse; populated
__pycache__ directories refuse as **source-cache-populated**, naming every observed
populated path. No cache is deleted or repaired. This is a consumption precondition:
__pycache__ under SOURCE_ROOTS must be unpopulated. The owner performed the one-time
30-file purge before r21 authoring; its inventory is at
`C:/Users/Kninetimmy/AppData/Local/Temp/opencode/r21-pycache-purge-20261111.json`.
That path is historical owner evidence, not a runtime dependency.
The guarantee does not rest on that purge. The fresh private prefix prevents loading
repo caches; the preflight is the fail-closed backstop. Packet runs suppress bytecode
writes, but ordinary pytest/CLI use can repopulate repo caches. Repopulation is a
named refusal at the next probe, never silently accepted or removed.

Import coverage is exhaustive over the sealed Python files:

- certify.py, tidy.py, install.py, active.py, disable.py, deploy.py, denial.py,
  inspect_tv.py, prepare.py, recovery.py, stage_common.py, stage_lib.py,
  stage_session.py, stage_transport.py, trial.py, bootstrap_sdk.py,
  authoring_checks.py, offline_checks.py, session_checks.py, relay_checks.py,
  r16_checks.py and r21_checks.py import packet before any source-importing path.
- sdk.py first imports bootstrap_sdk.py, which imports packet before inserting
  REPO/src and importing samsung_tv_root.sdb.
- driver_shim.py first imports prepare.py -> packet; flow_cases.py and
  mutation_checks.py reach that same path. driver_checks.py dynamically imports
  flow_cases only after its host Ruff subprocess; that path reaches packet too.
- packet.py itself imports only stdlib and the pin-verified controller. The actual
  controller imports only hashlib/json/os/re/sqlite3/subprocess/pathlib. r21 executes
  its checked .py source directly rather than using a sibling controller cache.
- port_from_r15.py imports only stdlib; its derivation loads the same pin-checked
  controller source and never imports REPO/src.

The only three direct source-importing files are bootstrap_sdk.py, inspect_tv.py
and stage_session.py. r21_checks.import_graph checks these edges and the controller
import set. r21_checks.bytecode_case exercises actual module bodies of certify,
tidy, inspect_tv, bootstrap_sdk, stage_session, install, active and disable in fresh
subprocesses. Private isolated copies retain the real sdb.py mtime/size and a
16-byte matching timestamp .pyc header; the poisoned implementation changes
build_shell_injection. With only the preflight call patched off, the real function
still returns its expected command through every entrypoint import. Disabling the
prefix too is a load-bearing poison positive control. A separate case leaves the
preflight enabled and requires the named cache-path refusal before imports, with
unchanged poison bytes. No fixture poison is planted in the real repository.
Temporary copies (including private local configuration) are removed; explicit
post-checks require real SOURCE_ROOTS cache absence. The entire suite runs twice
consecutively. Removed-prefix, removed-preflight, removed-ACL and removed-write-
suppression mutants must fail their intended behavioral tests.

### Finding 2 — MINOR: fatal preflights bypass durable failure records

r20 certify.py:85-98 and tidy.py:93-108 performed fatal host preflights outside
their record_failure handlers (certify.py:118-123). A refusal could leave neither
STOP nor status. The owner chose a distinct append-only **refusals.jsonl** stream,
not a failed stage outcome. packet.preflight and packet.record_refusal implement
that decision: one newline-terminated, flushed and fsynced row with exactly stage,
kind, reason, UTC utc, and consumed:false, then re-raise the original refusal.
A persistence error raises a BaseExceptionGroup containing both the original and
storage failures; it cannot be swallowed into the original exception.

Covered non-consuming boundaries are certify.main (readiness and armed modes),
tidy.main, certify CLI argument validation, the initial marker/seal checks in
install/active/disable main, all five retired CLI refusals (install, active,
disable, inspect_tv, prepare), and packet's bytecode import preflight. Import-time
bytecode rows use the invoking script basename as stage and import-preflight as
kind. The live-stage rows use their existing STAGE and readiness/certify/tidy kind.
No refusal writes STOP, SPENT, an attempt stamp, a marker, receipts.jsonl or any
stage-status-*.json. The refusal stream is runtime evidence, not a seal member.
It does not make a previously stopped/spent packet usable again; it leaves an
otherwise eligible packet eligible after the cause is corrected.

The historical active/disable prerequisites include relay reconciliation with
possible device effects. They are **not** classified as non-consuming host
preflights: those regression-only routines remain unchanged and unreachable by
r21's accepted marker set and retired CLI guards. Historical inspect/prepare main
bodies also remain regression-only. Attempt.take() for certify/tidy is now inside
the existing stage-failure try: a failed/partial attempt stamp is not mislabeled
consumed:false. SDK/runtime failures keep their existing durable STOP/status policy.

r21_checks.refusal_case models a fatal preflight through each real current main,
checks exactly one row and unchanged stage status/no STOP/SPENT/attempt, then runs
the same packet successfully with the modeled SDK. Readiness remains unconsumed;
armed certify/tidy exercise the real attempt/status machinery without creating an
arming marker. refusal_storage proves fsync, append preservation and loud storage
failure. retired_case exercises every disabled CLI. Dedicated mutants remove the
writer, fsync, append mode, consumed:false, persistence error propagation, current
stage boundaries and every retired entrypoint boundary; each must be killed.

### Finding 3 — MINOR: transport hash overclaim

r20 PLAN.md:164-165 promised encoded transport and decoded envelope SHA-256,
but denial.py:25-27 saved only encoded=encoded; only the decoded envelope was
hashed. r21 kernel_log adds sha256=hashlib.sha256(encoded.encode('utf-8')).hexdigest()
in that same first save call. The digest covers the **exact saved string's UTF-8
bytes**, without newline insertion or normalization, not the surrounding JSON
serialization or SDK trailer. At the production call site output.strip() has
already selected this encoded string; this is not a claim to hash discarded framing.
The decoded raw-envelope hash is unchanged. r16_checks retains its raw-evidence
ordering assertion (formerly line238) and now checks the encoded hash on malformed
transport as well. r21_checks.encoded_hash and its removed-digest mutant prove the
new digest covers the representation saved before decoding/semantic verdicts.

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
Require all four UID/GID fields901, exact CapEff `0000000000200040`, group1901,
exact label `User`, restriction0 and pinned boot. Named constants ExpectedCapEff /
ExpectedSmack in C# and EXPECTED_CAP_EFF / EXPECTED_SMACK on the host enforce
these measured values, never any-capability or any-label wildcards. The post-bracket
FileProfileChanged calls the same ValidateProfile and compares every recorded
field; the host independently compares post_profile with profile. Each drift
retains its named refusal; no root session or added capability operation exists.
The shell probe does not establish the helper's actual credentials: drift refuses.
Each shell observation checks its command's status separately: a failed cat,
stat, id or chsmack cannot pass by printing an otherwise matching value. Current
packet/evidence ACLs are checked before attempt/SDK construction; inherited
controller privacy checks alone concern the controller's own directory.
The same explicit packet/evidence privacy preflight applies to optional tidy,
before taking its local attempt or constructing either SDK session.

### Owner-accepted measured-helper residual (task59, 2026-11-11)

The certification accepts that the denial helper inherits CapEff 0000000000200040 (CAP_SETGID|CAP_SYS_ADMIN) and SMACK label User from the uid901 bridge SDK context that spawns it, rather than the previously assumed zero capability set and System label. This is accepted because the /dev/kmsg read gate is the node's SMACK access="*" grant together with group 1901 membership and dmesg_restrict=0, all separately asserted; because no helper code path depends on a capability; and because the privilege belongs to the spawning bridge, not to the denial attempt being tested. Consequence stated honestly: this certifies that unsigned native execution is refused for a uid901 process that holds CAP_SYS_ADMIN and label User. It does not certify 'no capability fallback' in the general case.

Owner chose option(a); this authoring run does not re-open that decision. Memhub
propose_decision staged it as pending proposal34 with owner-accepted 2026-11-11
source. Pending is not active/durable acceptance in the database; human review
remains required. The actual launched helper profile, not the older shell's
CapEff0/System observation, is the measurement used by the new exact constants.

The helper opens /dev/kmsg O_RDONLY|O_NONBLOCK once through libc, before Attempt.
Drain that fd to EAGAIN within the limits below; validate arrival order and keep
the last complete raw record as baseline s0. Empty baseline, malformed format,
read error or exhausted bound refuses before native execution. Then call the
existing direct Process.Start Attempt exactly once. Drain the **same fd** to
EAGAIN, requiring s0+1, +1, ... with no gap, duplicate or reversal. No reopen,
seek, resync, recovery read, execution retry, or polling for a convenient pass.
EPIPE remains fatal even if later input would be valid. Close once.

On a failed successful read, retain failure_record before pre/post count, raw-byte,
parse, sequence or timestamp assertions: phase, observed count, raw_b64 prefix,
retained_bytes and truncated flag, bounded by the existing 8192-byte read buffer.
It is diagnostic only and never restores completeness or authorizes execution.
Pre-drain malformed input and post-drain bound-triggering input therefore survive
in the failure envelope. Save post_profile before its validation/comparison so
changed values also survive the same named fail-closed refusal. No recovery read,
new threshold or expanded raw/wire budget is introduced.

The six-key exec object is unchanged inside version1 outer {exec,kernel_capture}.
Direct Win32Exception errno1/13, exec_started=false, native_exit=null, empty
stdout/stderr, timed_out=false and wrapper77 are required. 77 is not a native
child exit. Any started child fails regardless of exit; retain the inherited
5-second wait, owned kill, 1-second reap and 1-second output-close bounds.
The native success marker must be absent. No shell Permission-denied/$? pin.

Save the encoded transport string (exact UTF-8 bytes) and decoded raw envelope with SHA-256 before host
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
Transport/decode completeness takes precedence at the host: a helper raw-bound
refusal can itself yield an encoded failure envelope beyond the wire bound, so
the host may observe kernel-capture-transport-bound (or decode-incomplete) before
it can obtain the unavailable inner refusal. Do not claim the inner failure was
observed unless its complete envelope was received and decoded. Partial prefixes
remain non-authoritative evidence, not a decoded diagnosis. The JSON envelope contains
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
failed r21 stage requires separately designed/reviewed/armed evidence-preserving
cleanup; the optional tidy owns only the three explicitly known older directories.

Tidy retains both independent production guards: entry count via find -printf x
and exact rendered-name comparison. Split count-only and comparison-only mutants
are killed separately. A single composite-LF filename renders the three expected
names but count1 must refuse inventory-count. A wrong simple name with count3
must refuse inventory. Tests execute the actual generated prefix and full
command, require exact TIDY_REFUSAL tokens/exit69, no unlink, unchanged bytes and
directory identities. The LF-only extra fixture remains. No NUL-safe rewrite.

Optional separately armed tidy verifies ALL THREE exact directories before any unlink:
denial-fd9fa25930776ce9 (task46; one ELF, mtime1794343800) and
denial-5bd20c32c9b13f14 (r17; creation identity45845:25356). The latter retains
receipt-pinned original ELF/DLL/runtimeconfig hashes and sizes5196/9216/154,
modes700/600/600; no newly built helper substitutes for the staged r17 DLL.
The third is denial-ec6cf65890501d00 (r19; creation identity45845:32788), with
ELF SHA-256 d1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d,
DLL fb14c09f962f04ce0fac430a191a7842d6481328413313c5286dbf61a0e79566,
runtimeconfig ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38,
sizes5196/22016/154 and modes700/600/600. These are the receipt-pinned original
r19 files, never newly built r21 bytes. A failure in the third directory must
leave the first two untouched. All directory/file identities and hashes are
checked before the first unlink; lexical identity and inspection repeat before
each removal. The independent entry-count and rendered-name guards stay intact.
Require exact canonical paths, owned0700 nonlinked directories, nonlinked regular
single-link uid901 children, exact metadata/hashes and applicable mtime. Recheck
lexical directory identity before unlinking only the known children and rmdir.
Require absence from a fresh ordinary SDK session; reappearance refuses, never
retries. This is tidy-up, not hazard recovery. Receipts are not deletion targets.

Task48 remains covered: mutation totals count distinct transformed-source hashes
separately from fixture executions; empty relay DLL/runtimeconfig/PID cases reach
their hash/PID refusals, not the old %F comparison. The v5.20 exclusive-create
fix (task40) remains deferred. The historical **owner-accepted residual** is the
following/truncating SaveBudget writer; r21 never invokes or arms that writer.
EACCES versus EPERM remains unresolved and is never normalized.

## Offline verification and remaining device claims

Run authoring_checks.py, r16_checks.py, r21_checks.py, relay_checks.py, mutation_checks.py and
offline_checks.py with .venv/Scripts/python.exe -B -u, unbuffered and no timeout.
Pinned SDK3.1.426, DOTNET_MULTILEVEL_LOOKUP=0, all builds zero warnings. Isolated
Ruff explicitly uses py312, matching pyproject.toml requires-python>=3.12; no
repository target change or per-line suppression. Every mutant must die with its
intended terminal exception type/message; no minima or suppressed survivors.
The exec-schema and timeout/output-shape guards have malformed-result fixtures
and independent catalog mutants. Multiple timeout/stdout/stderr fixture executions
of one transformed source count as one distinct transformation, not four mutants.
The inherited r20 catalog has 154 distinct transformed sources across 164 named
fixture executions. r21 adds 17 named guard-removal executions, giving171 distinct
transformations over181 executions. Actual totals are recorded in mutation-results.json and checked
against the entire regenerated catalog, never a minimum. For comparison,
r19's actual sealed mutation-results.json records 141 distinct transformations
and 148 fixture executions; calling that 148 distinct mutants is inaccurate.
The inherited authoring/regression/relay catalogs are13/192/36 respectively;
the managed helper catalog is50. r21 adds15 named cases repeated in two consecutive
rounds (30 executions); its bytecode cases each exercise eight real import paths.
The seal flow reruns every suite and verifies all predecessor member hashes and
whole-tree snapshots. The exhaustive inherited-name port ledger now covers
r20 -> r21. Its derive command carries only predecessor seal-listed inputs,
withholding generated builds/results and runtime files, and verifies immutable
r16-r20 whole-tree snapshots. Compiler auxiliary files are not live inputs.
No execution/ remains in the authored r21 packet. The 86-member seal adds the
r21 checks, their results and the r20 whole-tree snapshot to r20's 83-member set.

Windows streams and injected fd transcripts do **not** prove Linux ABI behavior.
Unproven for r21 on device: libc binding/open/read/close, continuing managed identity,
persistent-fd cursor continuity and EAGAIN fences across an attempt, vendor
overrun/record semantics, timing headroom and complete helper-envelope transport.
The read-only shell probe proved access/sample sequences, not these claims.
Readiness, arming and certification remain separate owner operations after review.

With r21 current and r20 predecessor, older-packet archiving is outside this authoring task.
Report only: authoring does not archive, delete or modify any predecessor.

### r21 authoring observations

Owner review rejected the initial harness-specific cache parent. Both the runtime
prefix and fixture parent now use tempfile.gettempdir(); the private leaf ACL,
freshness, outside-repository checks and cache-absence post-checks are unchanged.
The superseded pre-fix outputs were removed from the candidate and retained
privately outside it. The complete authoring sequence and final seal flow are
rerun against this correction; no pre-fix result is used as final authority.

The first isolated-suite run failed in its no-device audit hook: Windows reports
executable=None plus a command line for subprocess.Popen. The hook now checks
that platform shape against the exact PowerShell ACL-helper executable; no SDK
process or network access is permitted. A subsequent run exposed install's local
asyncio event-loop bootstrap before its retired marker refusal. Its CLI now emits
the same retired-install refusal directly inside the non-consuming boundary,
before any event loop; the regression-only main remains available to fixtures.
Neither failure reached a device. After those corrections, the new suite passed
both consecutive rounds (30/30), and the unchanged managed helper tests passed50
with zero-warning SDK3.1.426 builds. Full seal-flow outcomes live in the sealed
offline-results.json and mutation-results.json; these standalone observations
are not a substitute for that rerun or for an independent review.

### Inherited r20 authoring observations, not r21 verification

The first standalone regression run passed192 cases but emitted two Python
SyntaxWarnings for non-raw C# regex strings in the new uid/gid mutant literals.
Those literals were corrected to raw Python strings before the mutation run;
no predicate or expected exception was relaxed, no survivor was suppressed, and
no test expectation was changed to hide a failure. All164 mutant fixtures then
died as intended, covering154 distinct transformations. This is host-only
verification; no r20 readiness, TV validation, arming or live operation occurred.
The first complete seal flow passed every suite/build but correctly stopped at
the exhaustive port ledger: undocumented delta: port_from_r15.py. The new port
tool's own reason was missing from REASONS. It was added explicitly; the ledger
assertion and test expectations were not weakened. No seal/offline-results had
been written. The entire flow is rerun rather than bypassing the failed check.

### Inherited r19 authoring history, not new r21 failures

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
