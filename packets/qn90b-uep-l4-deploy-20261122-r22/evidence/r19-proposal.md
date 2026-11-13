# r19 design proposal — r18 review findings

2026-11-11. **Design only; not a packet, implementation, seal, readiness result, or authorization.**

## Recommendation and authorization boundary

1. Replace endpoint-only acceptance with **sequence-bracketed `/dev/kmsg` capture in the already-staged managed DenialRunner**, conditional on a separately approved read-only access/toolkit probe. If unavailable or unproved, refuse; do not fall back to accepting `dmesg` endpoints.
2. Obtain explicit approval for the task52 replacement clause below. r18 did not implement its literal capacity requirement, and this proposal does not retroactively amend the task.
3. Keep both existing inventory guards; restore split mutants and add the composite-newline filename fixture. Delete the equivalence claim.
4. Save a bounded, byte-preserving, explicitly incomplete receipt at the shared SDK transport failure boundary, opt-in for the denial evidence request.

No TV connection, SDK construction, sdb invocation, device socket, marker, attempt, cleanup, or packet test runner was used in this investigation. No packet or `packets/` file was edited. The only authored file is this proposal, under the new directory ignored by `.gitignore:22` (`.memhub/`). No commit is requested or made.

The actual predecessor directories are `qn90b-uep-l4-deploy-20261116-r16`, `qn90b-uep-l4-deploy-20261117-r17`, and `qn90b-uep-l4-deploy-20261118-r18`, all under `.memhub/prep/`. All proposed code line references below are to **r18**, to identify successor change sites, not permission to modify those bytes.

## Evidence classification

### Verified from recorded evidence / offline examination

| Evidence | Supported conclusion | Does NOT establish |
| --- | --- | --- |
| r17 `STOP:1`; `receipts.jsonl:586`; r18 `evidence/r17-incident.json:5-6,57-64` | r17 permanently stopped; its CERTIFY attempt is spent. | Permission to replay, clean, or repair r17. |
| r17 receipts `10,204,224`; r18 `certify.py:41-81,96-102` | The certifying SDK shell is uid901; its root proof is historical evidence, not the identity of this shell. No root session is used. | The shell's or managed process's current effective capabilities. |
| `.memhub/prep/qn90b-uep-denial-errno-20261110/measure-receipts.jsonl:9,25,41`; r18 `evidence/measurement.json:11,25` | A read-only observation on boot299d6f3f reported SMACK `System`, `dmesg_restrict=0`, and successful plain `dmesg` output. The original raw receipt removes the derived JSON's trailing-pipe ambiguity. | `/dev/kmsg` node permissions, successful open, or a present-tense access guarantee. |
| r17 receipts `509,526,534,544,551,561,578,586`; r18 `PLAN.md:127-137` | Pre-read: 505101 bytes, 7356 rendered lines, timestamps16755.012369..17486.329850. Recorded post-read transport decoded offline during r18 authoring: 504949 bytes, timestamps16755.608247..17486.813637. Start17486.10, end17487.04. Prefix advanced; post-read did not reach end. Direct refusal was errno1, `exec_started:false`, wrapper77. | Exact physical ring allocation/occupancy, an atomic read, or proof that loss happened *during* either read rather than between them. |
| r18 `evidence/r17-incident.json:4`; hash checked in this investigation | r17 receipts SHA256 is `0d953e3506d854de40fc1581ce85a9749d2cd684f1e2ba7f5fd6be73a510a5eb`, matching the incident extract. | Authentication of facts not contained in those receipts. |
| `.memhub/prep/qn90b-uep-l1-20261108-r1/tool-path-diagnostic.json:3`, receipts159 | `/bin/timeout`, `/usr/bin/timeout`, `/bin/busybox`, `/usr/bin/busybox` were absent in that observation. | That no BusyBox applet exists anywhere, or that `dmesg` is util-linux. Do not prescribe `timeout` as an available tool. |
| Same L1 receipts436,444; relay-port-r5 receipts1992-2008,2500,2508 | Device executions successfully used `find -mindepth 1 -maxdepth 1 -printf '%f\n'` and ordinary `sort`. | `find -print0`, `sort -z`, or their versions. |
| r18 `inspection.json:23`, decoded | Historical file capabilities: `/usr/bin/dotnet = cap_setgid,cap_sys_admin+ei`; tarlauncher has setgid/setuid capabilities. | That DenialRunner is root, has CAP_SYSLOG, or has any particular CapEff. File capability metadata is not process CapEff. |
| r18 `DenialRunner.cs:11-54`; `sdk.py:248-280`; `inspect_tv.py:15-19` | A managed .NET3.1 helper already participates in the denial stage; transport overflow precedes the caller's raw-save; existing receipt writes flush/fsync. | That a new libc interop reader has been exercised on this TV. |
| r17 `evidence/FORENSIC.md:72-102` (targeted search/read) | Historical same-view absence did not prove persistence; namespace/restore explanations remain unresolved. | A basis for automatic failure cleanup or post-STOP operations. This document concerns the earlier r14 incident, not a second r17 kernel measurement. |

The prescribed task52/51/48/46/53 recall and full task rows were read. Task53 requires failed stages to remain intact pending separately reviewed/armed evidence-preserving cleanup; this proposal leaves that policy unchanged. Task51's historical correction and task48's distinct-source counting/empty-child checks must remain in the successor.

A scoped evidence search found no saved `dmesg --help`/version, `/dev/kmsg` access result, `find -print0`/`sort -z` success, or UEP call-site ratelimit implementation. This is a search result, not proof that the device lacks those facilities.

### Assumed Linux ABI / design premises, NOT verified TV behavior

The following describes the ordinary Linux `/dev/kmsg` interface expected on the recorded Linux5.4.77/glibc2.30 system. No kernel source or new external reference was fetched. Vendor conformity must not be represented as a measured fact.

- Each successful sufficiently large read returns a record with a header resembling `priority,sequence,timestamp_us,flags;message`, with escaped message bytes and possible dictionary/continuation detail. A record is not necessarily one rendered `dmesg` line.
- A read-only, nonblocking open has its own cursor; `EAGAIN` means no currently available record. Reader overrun can report `EPIPE` and resynchronize. A too-small record buffer can report `EINVAL`. None may be silently swallowed.
- Read access requires device DAC and SMACK/LSM permission as well as applicable syslog permission checks. With restriction enabled, CAP_SYSLOG (or a supported legacy CAP_SYS_ADMIN path) may be needed. `dmesg_restrict=0` does not bypass device DAC/SMACK. Do not add root, capabilities, chmod, or a new privileged route.
- Consecutive record sequence numbers establish absence of missing **committed ring records** within a bracket, not absence of log events suppressed before insertion. Clock timestamps alone do not establish causal execution boundaries.

### Requires a separately approved read-only device probe

The principal unknown is whether **the same uid901/System execution route can read sequence-bearing `/dev/kmsg` records**. Also unknown: actual tool implementations/options, current process capabilities, and vendor record formatting. Section “Probe specification” supplies exact shell commands. They have **not** been run.

## Findings 1 and 2 — complete capture, ordering, and task52 capacity

### Root cause and reproduced counterexamples

`denial.assess_kernel`, `denial.py:75-108`, validates timestamps on only the first/last rendered lines and counts surviving exact-path witnesses. Endpoint preservation does not authenticate the interior or its ordering. `PLAN.md:117-125` therefore overstates the result. `PLAN.md:109-115` also substitutes policy for task52's explicit capacity refusal without implementing it.

I extracted only the `assess_kernel` AST into memory, supplied a minimal `p.require`/`p.Stop`, and executed it without importing packet modules or writing bytecode:

| Input, otherwise valid | Actual r18 result |
| --- | --- |
| Window[95,96], endpoints94/97, same-path denials95.25 and95.75 | Duplicate refusal |
| Same input, omit only denial95.25; endpoints unchanged | **Accepted** |
| Start95.24, witness95.244381, endpoints94/97 | **Accepted** |
| Endpoints94/97; interior noise95.9 followed by witness95.75 | **Accepted** |

The rounding example is not proof that a real attempt started after that witness: it proves r18 cannot exclude that possibility when its start reading has only two decimals.

### Alternatives evaluated

| Approach | Evaluation |
| --- | --- |
| Retention endpoints plus a byte threshold | Necessary diagnostics, insufficient completeness proof. Formatted505101 bytes do not equal internal ring storage. Repeating that number as capacity would invent a measurement. |
| Plain/BusyBox/util-linux `dmesg`, `-r`, larger `-s`, `--syslog` | Build/options not recorded. “Raw” can mean preserving priority, not sequence numbers. Larger userspace buffers do not prove no mid-read loss; `-s` is not an occupancy query. A legacy READ_ALL path could differ from a `/dev/kmsg` reader; do not assert either path is atomic without implementation evidence. Never use clear/read-clear options (`-c`, `-C`, `--clear`, `--read-clear`). |
| Direct `/dev/kmsg` with preserved sequence numbers | Supplies the missing observable. A single non-atomic stream can still prove its interval complete if all sequence numbers are present and ordered and its boundaries are causally anchored. Access, record format, and error handling must be demonstrated first. |
| Toolkit-only `cat`/`dd` drain | `cat` can block; ordinary shell `read` is not a demonstrated record reader. A `dd iflag=nonblock` sample is useful for access probing, but normal EAGAIN and fatal overrun can both be nonzero exits. Do not turn a nonzero exit into success by matching an English stderr string, or hide EPIPE behind a later printf. No installed `timeout` is evidenced. |
| Managed libc interop in existing DenialRunner | **Recommended production mechanism**, after the probe gate. Reuse the already staged DLL/runtime and direct-exec flow; use read-only open/read/close with numeric errno. No additional native executable, package, root route, device file, or background service. Adds reviewed managed code and ABI risk; it is not “already tested.” |
| `SYSLOG_ACTION_SIZE_BUFFER` | Not proven reachable, but r18's blanket “unmeasurable” assertion is too strong: a reviewed managed helper could in principle call libc **klogctl**, action10, without executing a new native binary. This is a possibility, not a measured capability. Allocation size alone still does not prove occupancy or complete capture. Do not confuse libc `syslog(3)` (a logger) with klogctl/syslog(2). Do not add this syscall merely to get an irrelevant number. |
| Before/after unique sentinel writes to `/dev/kmsg` | Two visible sentinels in plain text are still just endpoints; they do not prove the interior survived. Sequence continuity between their records would help, but already provides the essential guarantee without writes. Sentinels mutate the log, may require extra permission, may themselves be rate-limited, and cross the explicit no-device-writes boundary. **Rejected; separately authorized mutation if ever considered.** |
| Retention plus explicit incompleteness refusal | Safe fallback **only if refusal is real**: an unsequenced snapshot cannot certify denial uniqueness. This is preferable to weakening authorization if `/dev/kmsg` is unusable, but is not a usable positive certification method. |

### Recommended capture contract

Implement one bounded record stream around the **one** existing direct Process.Start, inside DenialRunner. This replaces “one post-attempt dmesg invocation”; it does not claim to satisfy that old implementation prescription unchanged.

1. Open `/dev/kmsg` read-only/nonblocking before the direct exec. Capture actual helper uid/gid, relevant process capability fields, SMACK label and boot identity in the receipt; compare with the separately reviewed profile. Never change them. Fail before exec if opening/identity/format cannot be validated.
2. Drain to the first EAGAIN within fixed record/byte/time bounds. Keep the last complete record as baseline `s0`, plus observed first/last metadata. Validate records in arrival order; do not sort or renumber. An empty baseline, malformed record, EPIPE, unexpected errno, or exhausted bound refuses before exec. Pre-window payload need not be transported wholesale; the retained baseline record anchors the cursor.
3. Call the existing `Attempt` exactly once, preserving its direct-exec errno, wrapper77 and started-child refusal semantics. There is no native execution retry. Messages arriving between the baseline drain and Process.Start are conservatively included.
4. Drain the **same fd** after the attempt to EAGAIN, bounded again. Require the first new sequence to be `s0+1` and every subsequent sequence to increment by exactly one. EPIPE, missing/duplicate/reversed sequence, malformed record, read failure, limit hit, or transport/decode failure means **incomplete**, never a partial success. No reopen/resync/poll until a convenient answer appears. Multiple reads on this one fd are normal stream consumption, not retries of a failed snapshot.
5. Save baseline and every record between the fences, their raw framing, capture outcome, numeric errno, counts and boot binding **before** semantic assertions. Reuse gzip/base64 in the .NET standard library and existing host receipts; preserve the existing128KiB transport/1MiB decoded bounds. Bound individual reads (initial proposed8KiB, reject an oversized record rather than silently truncate), records (e.g.16384), total raw data (1MiB), and each drain (e.g.2seconds). These are explicit limits, not capacity estimates. Exact values require review against the probe; the existing15second request deadline remains the outer ceiling, including the owned-child timeout/reap.
6. Require nondecreasing timestamps for all parsed records in the bracket, kernel-origin facility for the UEP witness, and exactly one exact canonical-path/full-signature message in the causally bracketed records. Unsupported flags, fragmented witness reconstruction, or dictionary/framing ambiguity refuse until explicitly supported by tests. Do not flatten escaped record text into fake records.
7. `assess_exec` still validates the original six-key exec object; use a versioned outer envelope containing `exec` and `kernel_capture`, rather than weakening its key/errno checks. A capture-complete flag is necessary but never sufficient: the host independently validates raw sequence continuity and the s0 boundary. EAGAIN at the post fence is reported by the reviewed reader, not inferred from absence of a last log line.

**Why causal fences:** `/proc/uptime` reads are rounded and may use a different suspend/clock basis from printk. Keep their strings/precision and timestamps as diagnostics, but do not accept a witness merely because95.244381 >=95.24. The same-process read-to-EAGAIN before exec and after exec brackets records without guessing sub-centisecond time. No traffic after the attempt is needed to manufacture a last timestamp >= rounded end. If a timestamp-based fallback is ever proposed, it needs verified clock-domain/rounding bounds and a definite inner interval for the witness, not an epsilon widening acceptance; it is not recommended here.

### What sequence continuity does and does not prove

- **Wrap during chunked reading:** an old endpoint can already be in userspace while unread interior records wrap out and newer endpoints remain in the ring. Plain text may look valid. A correctly checked `/dev/kmsg` cursor exposes overrun as EPIPE and/or a sequence jump. The first post-baseline sequence check prevents loss immediately after the pre-fence from disappearing unnoticed. Even if the reader sees EPIPE then later returns records, the entire capture is refused.
- **FIFO rotation before the bracket:** does not invalidate records captured after a sound baseline. Full historical boot retention is not required. This is why total capacity need not be known to prove this bounded interval.
- **Printk rate limiting:** it cannot retroactively remove an already committed older ring record. It can suppress the *earlier event in this attempt window* if its call site's token bucket was already exhausted, while later events and unrelated endpoints appear. “N callbacks suppressed” can itself appear later, be overwritten, or never be observed in this bracket. Suppressed events need not consume sequence numbers. Thus **no gap and no suppression line do not prove no suppressed UEP event**. Global ratelimit sysctls do not establish the UEP call site's policy.
- Conservatively refuse any recognized suppression/drop notice in the bracket, with a separate `kernel-emission-suppressed` reason. Do not claim that checking for this text solves source-side suppression. The positive claim must be **one direct attempt and one matching committed kernel record in a complete record bracket**, not “only one denial event could have happened.” If certification needs the latter stronger claim, it remains blocked on exact-build UEP logging/source evidence; no read-only shell probe can establish an absence of call-site suppression.
- This is not an adversarial guarantee against a concurrent same-uid/privileged actor, kernel deception, asynchronous logging beyond the post fence, or vendor ABI deviations. Kernel-origin priority and exact random stage path narrow ambiguity but are not cryptographic authenticity. Known missing/delayed witnesses refuse; there is no reread or retry.

### Capacity finding and proposed task52 replacement clause

**Status of the old requirement:** not implemented by r18. A formatted505KB capture and rotating prefix are evidence of bounded retention, not a calibrated occupancy meter. Keep task52 open under its existing wording until the owner explicitly accepts a replacement. Do not silently edit memory/tasks or call the review finding resolved by a PLAN assertion.

Proposed replacement, requiring approval before successor authoring:

> Denial certification must refuse whenever completeness and ordering of the committed kernel-record bracket around the single direct attempt cannot be established. Use one bounded read-only `/dev/kmsg` cursor with a saved pre-exec sequence fence, a post-exec drain-to-EAGAIN fence, uninterrupted sequence continuity, valid ordered record framing/timestamps, and independently validated raw receipts. Refuse on missing coverage, overrun/EPIPE, sequence loss/reordering, unsupported reader semantics, suppression notices, any bound, or transport/decode incompleteness; never retry execution or reread to recover a pass. Plain dmesg retention endpoints and formatted byte counts are diagnostic only. The historical ~505KB r17 rotated capture must produce a named completeness refusal, not pass because it is below1MiB. Capacity/occupancy may be reported only when actually measured and must otherwise be `unknown`. Unknown or full capacity is never a substitute for affirmative continuity; affirmative continuity for the attempt bracket makes total ring occupancy irrelevant to this acceptance claim. If the required cursor evidence is unavailable, refuse before native execution. Save evidence before verdicts; retain failed stage contents and durable STOP. This certifies committed records, not absence of unlogged/suppressed events.

Use `kernel-capture-completeness-unproved` as the named refusal for the unsequenced historical505KB fixture, with `capacity_state:unknown` and `rotation_observed:true`; do not label a guessed505101-byte threshold “measured saturation.” A sequenced equal-size bracket is judged on its actual continuity, not its length. If the owner retains the literal “at capacity -> refuse” rule instead, **do not implement this relaxation**: capacity/occupancy proof remains a separate blocking requirement even with a contiguous bracket. This proposal is the explicit decision point r18 omitted.

### Exact successor change sites and checks

| File / current lines | Proposed change |
| --- | --- |
| `DenialRunner.cs:11-42,44-54` (`Attempt`, `Main`) | Keep one direct exec; add minimal read-only interop/capture functions and envelope assembly around it. No shell fallback or unsigned native helper. |
| `DenialSelfTest.cs:9-72` (`Main`) | Keep all real refusal/child/timeout tests; add injected read/open/errno/clock/fence transcripts, zero-exec on preflight failure, EPIPE followed by valid data still refuses, bound tests and exact one exec on all post-attempt outcomes. Windows mocks do not prove the Linux ABI. |
| `denial.py:22-39,75-108,126-175` (`KERNEL_COMMAND`, `kernel_log`, `assess_kernel`, `run`) | Demote/remove plain dmesg acceptance; decode/persist versioned raw envelope before assertions; validate sequence/fences/record order and exec independently. Keep legacy capture only as diagnostic/refusal input if needed for fixtures. Uptime no longer grants causal membership. |
| `certify.py:99-114` (`main`) | Success wording must describe complete committed-record bracket, not retained endpoint window. Leave pre/post certification, attempt accounting and STOP ordering unchanged. |
| `r16_checks.py:41-49,52-55,81-161,446-517,520-546` | Add sequenced positive controls; replace endpoint-only positive/505KB-pass assumptions; add gaps, reversed interior, incomplete/missing fences, suppression and rounding cases. Update fake helper envelope and preserve save-before-verdict/no-cleanup-on-failure tests. |
| `mutation_checks.py:335-349` | Keep applicable path/signature/window diagnostics; replace endpoint-as-completeness mutants with independently killable sequence-step, baseline-step, complete-fence, EPIPE and record-order mutants. Exact terminal reason required. |
| `PLAN.md:84-137`; `offline_checks.py:89-113,151-159,434-445` | Correct the claims; wire all new helper/host tests into the existing build/check flow, retaining zero warnings and explicit distinct-source counts. No manufactured minimum count as a substitute for a named case. |

Successor manifest/build/port-ledger entries will need to reflect any changed source/binary/test outputs during a later authorized authoring task. No seal generation belongs to this investigation.

## Finding 3 — inventory correctness and non-equivalent mutants

### Recommendation: option(ii), keep the guards and test them separately

`tidy.inspect`, `tidy.py:29-49`, currently has useful distinct checks: an entry-count check at35 and a rendered-name comparison at36-38. A filename with embedded LF can impersonate multiple rendered names, whereas trailing-LF stripping can hide an extra LF-only entry. A count check is not equivalent to the comparison.

The in-memory filename `DenialRunner.dll\nDenialRunner.runtimeconfig.json\nuep-probe.elf` has one directory entry, but its `find '%f\n'` output after shell newline stripping equals the three-name expected string. This was independently reproduced as a byte/string counterexample. It is **not** claimed that the entire current tidy accepts that directory: the count guard refuses, and later named-file checks also matter.

Keep production guards and existing uid/hash/link/type/identity requirements unchanged. Remove `PLAN.md:151-162`'s equivalence/fail-fast-only rationale; split `mutation_checks.py:311-316,354-357` into **count-only removed** and **comparison-only removed** transformations. Retain distinct transformed-source hash accounting at416-448 and typed-exception matching at400-402. A surviving mutant must be reported, never combined away to achieve a target count.

**Why not NUL-safe enumeration now:** it is a valid eventual simplification, but `-print0`/`sort -z` support is not recorded. Correct NUL comparison must preserve bytes (e.g. base64 to host, split NUL then compare exact byte names); NULs must not go through shell command substitution. That changes production inventory/receipt plumbing unnecessarily for this finding. Keeping both guards needs no new toolkit assumption. If NUL enumeration is adopted later, host sorting eliminates a dependency on device `sort -z`; a rendered pretty listing must never become the authority again.

### New/changed checks and exact sites

- `r16_checks.py:373-431` (`tidy_fixture`),442-443 (`tidy_newline_refusal`),537-543 (`run`): keep the real-Bash LF-only extra fixture. Add an r17-target fixture containing **only one composite-LF filename** whose bytes render as the expected three names, and a same-count wrong-name fixture. Create LF names through the existing MSYS Bash fixture technique, not Windows Path APIs. All host writes belong to a later disposable successor test tree, never the predecessors.
- Exercise the **actual generated inventory-prefix bytes** through the comparison (before child metadata/hashes). Assert composite-LF count=1, rendered comparison=expected, then require exact `TIDY_REFUSAL: inventory-count`, exit69. With only the count guard removed that prefix must accept, making the test fail. This is the independent counterexample the combined mutant concealed.
- For comparison-only removal, use correct entry count with one wrong simple name. Require exact `TIDY_REFUSAL: inventory`; the count-only predicate must demonstrably pass. Deleting only comparison must break this case.
- Also run the full production command on both fixtures: require the intended inventory refusal **before** child checks, no unlink calls, unchanged file bytes and directory identities. A later `file-type`/hash failure is **not** an acceptable inventory-test pass. Add trace assertions or explicit expected-message assertions, rather than the current generic `TIDY_REFUSAL` acceptance at430.
- Preserve positive two-directory removal and fresh-session absence tests. `relay_checks.py:160-163,208-212,374-378` empty-child coverage remains untouched; do not let an inventory fix erase task48's regression checks.
- Residual risk: two predicates are still a line-oriented protocol, not an atomic directory snapshot. Existing per-child/lexical identity rechecks remain necessary. Concurrent same-uid modification is not solved. No additional device probe is needed for option(ii); NUL-option probes below are informational, not a reason to block this host-only correction.

## C — concrete endpoint-preserving-loss regression

Add `kernel_endpoint_preserving_loss` in `r16_checks.py` next to `kernel_duplicate` (current160-161), dispatch it in `run`, and give it dedicated sequence-step/baseline-step mutants in `mutation_checks.py`.

Use a fixed canonical random-shaped stage and committed-record fixture:

```text
priority seq  timestamp_us  message
6        100  94000000      left endpoint / saved pre-exec baseline
6        101  95250000      exact-path UEP denial A
6        102  95400000      ordinary noise
6        103  95750000      exact-path UEP denial B
6        104  97000000      right endpoint
```

Encode these as raw kmsg records (`6,100,94000000,-;...\n`, etc.), not as the table. Set a valid pre-fence s0=100 and a post-exec EAGAIN fence after104; diagnostic uptime window[95,96]. Include successful transport/decode, same boot, proper capture version, kernel facility and valid exec77/errno1/no-start accounting.

1. **Unique positive control:** replace denialA's message with ordinary noise, preserving every sequence/timestamp; this must accept denialB. It prevents a universally-refusing parser from “passing” the regression.
2. **Complete duplicate control:** restore denialA; require the exact duplicate-signature refusal. Framing/completeness validation must have passed first.
3. **Lost-interior case:** remove only record101 from the duplicate fixture. Baseline100, last104 and surviving denialB remain byte-identical. Assert one surviving exact-path signature, valid ordered timestamps and good endpoints; require `kernel-sequence-gap` with expected101/observed102 **before** witness-count acceptance. Raw incomplete capture must already be saved. This specifically tests loss immediately after the retained baseline.
4. **Middle-gap sibling:** retain101 as ordinary noise, make102 a second denial, then omit102; expect sequence-gap102/103, keeping first post-fence record intact. This prevents a baseline-only implementation from passing.
5. Removing only the relevant continuity guard must make the lost-interior case accept the survivor (or fail the test's precise expected reason), and therefore kill that mutant with the intended AssertionError. Do not use a malformed gzip, oversized reply, old timestamp, wrong path, invalid metadata, or missing end-fence to manufacture the kill. Require the actual terminal exception type/message, not arbitrary traceback text.
6. Keep a raw legacy-text version: the actual r18 function accepted its lost-interior variant in this investigation. The successor must refuse it as `kernel-capture-completeness-unproved`, even if endpoints cover the window. Add separate all-interior-order and rounded-start fixtures; these cannot stand in for the gap fixture.

## Finding 4 / D — bounded incomplete raw receipt

### Recommendation and location

Fix the shared transport layer, not just `denial.kernel_log`: `sdk.TracedSDK.request` at202-285,337-403 owns the bytes before a caller can save them. `denial.py:28-29` never executes its save if capture raises. Set an explicit evidence label/opt-in for the denial request, propagated by `DirectSDK.capture` (`sdk.py:427-430`); after the recommended helper integration this is the combined denial-execute/kernel-envelope request, not a second log capture.

Write one event into the **new successor packet's host-local `receipts.jsonl`**, through existing `inspect_tv.save` (`inspect_tv.py:15-19`), before returning/raising failure to `certify.main`'s durable STOP path. No TV receipt file, staging cleanup or fallback connection. Use an internal per-request ID to correlate the event; never construct a filename from a remote label/path. No new raw-output file or directory is necessary.

Proposed event fields:

```json
{
  "event": "sdk-reply-incomplete",
  "request": "denial-evidence",
  "transport_complete": false,
  "capture_complete": false,
  "usable_as_kernel_authority": false,
  "reason": "reply-limit",
  "prefix_limit_bytes": 131072,
  "retained_bytes": 131072,
  "observed_bytes_at_least": 131073,
  "truncated": true,
  "raw_prefix_encoding": "base64",
  "raw_prefix_b64": "<exact retained response bytes, not replacement-decoded text>",
  "prefix_sha256": "<hash of retained bytes ONLY>",
  "exit_trailer_seen": false
}
```

The numeric example corresponds to the review's131073-byte injection; actual `observed_bytes_at_least` can be larger because reads are4096-byte chunks. Do not label it the total TV reply size. A truncated prefix's SHA is not a complete-capture digest. The sample placeholders above are schema notation, not fabricated recorded evidence.

### Bounds, secrecy, and lifecycle

- Maintain a request-scope prefix of **at most MAX_REPLY=131072 raw bytes**, slicing before append, plus a count of all bytes actually observed. The crossing chunk is counted but only the remaining prefix budget retained. No unlimited “save whatever we got” path. Base64 expands the maximum prefix to174764 ASCII characters; this fixed host receipt budget is separate from the wire reply cap. Hash incrementally or hash the bounded prefix, never retain the full oversized response.
- Capture only response bytes **after the accepted callback's verified initial tag**. Never save rejected-peer/tag bodies, bootstrap argv, SDB stdout/stderr, commands containing uploaded data, root-agent tokens, or environment values. Preserve existing diagnostic-category-only handling of desktop streams.
- Raw failure evidence is opt-in only for the reviewed denial evidence command; do not enable universal raw logging. Its payload is the kernel/direct-exec envelope, not credentials. A partial exit trailer can contain its single-use correlation nonce. Exact raw bytes and silent nonce redaction are incompatible: explicitly review a narrow exception to `sdk.py:377` for this private raw receipt, while retaining ordinary-log tag redaction. Do not call a redacted prefix byte-exact, and do not retain the secret management token. The request nonce is correlation framing, not a reusable credential.
- Keep the successor packet/evidence ACL owner+SYSTEM-only and fail closed if privacy verification fails before contact. Treat raw kernel data as private. No external upload or publication.
- Emit at most one incomplete event per accepted opted-in request. Cover overflow, EOF without trailer, invalid UTF8/trailer, OSError, timeout/cancellation, and outer/local-exit/transport-close failures after response bytes were received. The final success decision must wait for request and closure validation; a seen trailer alone is not transport completion. Keep prefix state outside the nested callback so cancellation does not discard it.
- Persist on failure before propagating the terminal error; do not let an evidence-write failure become success. If receipt storage/fsync itself fails, report that secondary failure as well as the original error and proceed to the existing host STOP attempt. Durability cannot be promised on a failed disk or abrupt power loss. No await/poll of the device is introduced to improve evidence.
- Incomplete receipts have no normal `denial-kernel-after`/`denial-passed` event name and can never reach `assess_kernel` as authoritative input. Do not gzip-decode an incomplete base64 prefix for acceptance. A separately labelled best-effort diagnostic decode is unnecessary for this fix.

### Exact successor changes and checks

| File/function / lines | Required change/test |
| --- | --- |
| `sdk.py` `TracedSDK.request:202-285,337-403` | Bound and retain request-scope accepted response prefix, count observed bytes, emit exactly-once incomplete receipt on all terminal failure paths, preserve the original refusal and transport teardown. |
| `sdk.py` `DirectSDK.capture:427-430`; `denial.py` `kernel_log:25-39` / `run:168-175` | Thread an explicit request label and narrowly scoped partial-evidence opt-in; update fake SDK signatures. No blanket raw logging or retry. |
| `inspect_tv.py` `save:15-19` | Reuse existing flushed/fsynced JSONL sink; no new storage mechanism needed. Validate privacy through the existing packet preflight, not a path chosen by remote data. |
| `r16_checks.py` `denial_saved_before_assertion:516-517`, `run:520-546` | Add transport tests using fake asyncio streams/server/processes only, with no real SDK/socket. Test131072 vs131073 bytes, arbitrary4096-byte chunk boundaries, EOF/no trailer, split multibyte invalid UTF8, timeout/cancel, error after trailer, and raw evidence before stage failure. Exact prefix bytes/base64/hash/length and at-most-once persistence required. |
| `mutation_checks.py:345-349` and additions near it | Separate saved-complete-before-content-assertion from saved-partial-before-transport-raise coverage; remove incomplete-save or permit overlong prefix as independent defects and require intended terminal assertions. |

The131073-byte fixture must assert the **same** limit error, no returned output, no `denial-passed`, no retry or cleanup, and a131072-byte explicitly incomplete raw prefix whose bytes equal the injected prefix. Add a successful complete under-limit control with no incomplete event, plus a complete reply followed by local transport failure that produces only failure authority. Merely observing `callback-error` or matching a traceback is not sufficient.

## Probe specification — future read-only owner operation only

**Not executed.** Obtain separate owner approval and use a new reviewed diagnostic route, not any STOPped packet entrypoint. No native-denial exec, helper upload, marker, gate operation, log clearing, privilege change, or cleanup. Save host receipts. Run in the same ordinary uid901 Bash SDK context. No installed `timeout` is assumed.

### P1: identity and actual tools (small, non-mutating output)

```bash
set -u
test "$(id -u)" = 901 || exit 69
id
cat /proc/sys/kernel/random/boot_id
grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb|NoNewPrivs):' /proc/$$/status
cat /proc/$$/attr/current
getcap /usr/bin/dotnet
cat /proc/sys/kernel/dmesg_restrict
stat -c '%F:%u:%g:%a:%t:%T' /dev/kmsg
chsmack /dev/kmsg
for tool in dmesg find sort dd; do
    printf 'TOOL=%s\n' "$tool"
    path=$(command -v "$tool") || exit 69
    printf 'PATH=%s\n' "$path"
    readlink -f "$path"
    sha256sum "$path"
    "$path" --version 2>&1
    printf 'VERSION_RC=%s\n' "$?"
    "$path" --help 2>&1
    printf 'HELP_RC=%s\n' "$?"
done
```

Expected: uid901 and reviewed boot/profile; readable node metadata; actual version/help output. `dmesg from util-linux ...` identifies util-linux, `BusyBox v...` identifies an applet; paths alone do not. Record supported options, especially whether any mode truly preserves record sequence headers. Missing version/help is inconclusive about implementation, not permission to guess. Do not invoke any advertised mutating flag. Permission/identity/boot drift or oversized diagnostic output stops the probe; no privilege escalation or retry. Historical `dmesg_restrict=0` is only an expectation, not a forced setting.

### P2: bounded raw kmsg sample — the most important probe

After P1 confirms `/usr/bin/dd` supports **`iflag=nonblock`** and the stated operands, run once:

```bash
set -u
test "$(id -u)" = 901 || exit 69
printf 'KMSG_SAMPLE_MIXED_B64_BEGIN\n'
{
    /usr/bin/dd if=/dev/kmsg iflag=nonblock bs=8192 count=8 status=noxfer
    rc=$?
    printf '\nKMSG_DD_EXIT=%s\n' "$rc"
} 2>&1 | base64 | tr -d '\012'
codes=("${PIPESTATUS[@]}")
printf '\nKMSG_SAMPLE_MIXED_B64_END\nPIPE_RC=%s,%s,%s\n' "${codes[0]}" "${codes[1]}" "${codes[2]}"
```

This is deliberately a **diagnostic mixture of sample records, dd diagnostics and an explicit dd exit**, base64-protected to prevent stderr interleaving with encoded output. It is not a complete-capture receipt. The group printf does not grant success to a failed dd: the authoritative dd status is the embedded `KMSG_DD_EXIT`, and encoding statuses must also be0. Eight8KiB reads bound raw sample payload to65536 bytes (plus small diagnostics), keeping its encoded response below128KiB. No output file is created on the device.

Expected decoded content: up to8 headers such as `6,12345,17486123456,-;...`, with adjacent increasing sequences/timestamps; normally dd exit0 after8 records. Actual numbers are not pinned. A readable sample supports this uid901 access route, **not** the whole production ABI/overrun proof.

- `Permission denied`/`Operation not permitted`/missing node: current route is unavailable; do not infer root is authorized.
- Unsupported `iflag`/operand: toolkit probe cannot establish access; do not fall back to blocking `cat`, shell one-byte reads, or English-error-based production acceptance.
- EAGAIN after fewer than8 valid records: some read access is demonstrated, but the sample is partial; not a complete capture and not a denial certification. No polling.
- EPIPE/record error or sequence disorder: refuse this reader result; retain it. A successful sample does not exercise wrap under load, and no load/sentinel writes are authorized.
- No full success claim follows until the reviewed managed reader is later exercised read-only in its actual context. If a shell read fails but dotnet permissions differ, the shell result does not prove dotnet cannot read; that requires a separately approved helper-context test, not a new root route.

### P3: optional NUL/tool and suppression-policy checks

Not needed for the recommended split-mutant correction, but these settle the unrecorded options without creating a device filename:

```bash
set -u -o pipefail
find /proc/sys/kernel/random/boot_id -maxdepth 0 -print0 | base64 | tr -d '\012'
printf '\nFIND_NUL_RC=%s\n' "$?"
printf 'b\000a\000' | LC_ALL=C sort -z | base64 | tr -d '\012'
printf '\nSORT_NUL_RC=%s\n' "$?"
cat /proc/sys/kernel/printk_ratelimit
cat /proc/sys/kernel/printk_ratelimit_burst
```

Expected successful find decoding: exact bytes `/proc/sys/kernel/random/boot_id\0`; successful sort encoding: `YQBiAA==` (`a\0b\0`); both statuses0. Unsupported flags/nonzero/malformed output leave the NUL design unproven. Ratelimit values are policy observations only; neither0 nor the absence of a suppression message proves the proprietary UEP logging path is unratelimited. Resolving that stronger claim requires exact-build code/implementation evidence, not more executions of the probe ELF.

## Verification performed and remaining gates

Performed: prescribed instructions/memory/task/source/evidence reads; targeted receipt searches (not wholesale receipt dumps); initial clean `git status`; ignored-path check; isolated AST baseline cases shown above; in-memory filename counterexample; r17 receipt digest comparison. `.venv/Scripts/python.exe -B -` was used for the in-memory checks; all four kernel cases and the inventory counterexample produced the recorded results. No successor implementation or full packet suite was run: those suites write packet results, mutate sources, build artifacts and/or seal, which is forbidden here.

Remaining gates, in order: owner approves the read-only probe; evidence settles access/tool identity; owner accepts the precise committed-record guarantee and task52 replacement (or preserves the stricter capacity blocker); separately author a successor offline and run its deterministic suites; independent review; only then separately authorized readiness/arming. This proposal grants none of those actions. Failed-stage cleanup stays task53, separately reviewed/armed, never an automatic recovery path.
