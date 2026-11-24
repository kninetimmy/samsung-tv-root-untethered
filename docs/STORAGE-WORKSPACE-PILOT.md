# Private offline storage pilot

This optional Windows pilot builds and runs only the existing host-only
`tools/reboot-helper/selftest/PowerGateSelfTest.csproj`. It does not contact
a TV, migrate packet runners or evidence, modify archives, certify a packet,
install prerequisites, or provision host security policy. Task 105's later
work and the deduplication/archive phases are not implemented.

## Run

Use Python 3.12 or newer, an installed .NET SDK that understands net6.0, an
installed .NET 6 runtime, and the already-extracted net6.0 reference pack
`6.0.36` in the current user's `.nuget/packages/microsoft.netcore.app.ref`.
Missing cached prerequisites produce an incomplete result, not a download.
The pilot reads that pack and installed tools without modifying them.

Supply an existing, physical, private E: directory outside the checkout.
Missing directories are refused by the pilot. If needed, explicitly create
each **new** directory first (omit the first command if that parent exists):

```powershell
python -B tools/evidence_workspace.py --create E:/samtv-workspaces
python -B tools/evidence_workspace.py --create E:/samtv-workspaces/pilot-example
$env:SAMTV_EVIDENCE_WORKSPACE = 'E:/samtv-workspaces/pilot-example'
python -B tools/run_storage_pilot.py --workspace "$env:SAMTV_EVIDENCE_WORKSPACE" --batch storage-pilot --budget-gib 20
```

Creation is exclusive and provisions only the specified new directory with
current-owner and SYSTEM full control, including inheritance for children.
It never rewrites an existing directory's access control list (ACL).
The pilot inspects pre-existing directories; inherited Administrators access
does **not** qualify as private. Missing drives, non-E: paths, substituted
drives, junctions, reparse points, hardlinked files, named data streams,
and inspection failures are refused. These checks do not defend against
an administrator or the current owner deliberately racing the runner.

The fixed pilot does not encode MSBuild path syntax. It refuses `%`, `$`,
`@`, `'`, `(`, `)`, `;`, `?`, `,` and `*` anywhere in the selected workspace
path or cached-reference root, including every ancestor component. MSBuild
uses [special characters and percent escapes](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-special-characters);
its [`-p:name=value` grammar](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-command-line-reference)
also separates assignments at semicolons or commas. Process argument arrays
do not escape that grammar. Ordinary spaces and `=` in a path remain
supported. The workspace check runs before batch creation; `execute_pilot`
checks both roots before worker admission or any child command. This covers
all four variable MSBuild path properties, not just creator-CLI leaf names.
The restriction belongs to this fixed pilot, not the reusable workspace
creator or other repository tools.

### Ownership and supported creators

Before the ownership fix, ordinary `os.open` creation of batch control and
evidence files inherited an elevated token's Administrators default owner.
The DACL could still contain exactly user+SYSTEM, but the owner was wrong
and correctly refused. Raw `mkdir`/file creation inherits permissions, not
necessarily ownership; the old test assumption that both always inherit
was incorrect. The native probe now inspects the actual owner and proves
that incorrectly owned raw descendants are refused, not made acceptable.

After the fix, controlled files use exclusive [CreateFileW(CREATE_NEW)](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) with
an explicit current-user owner and protected user+SYSTEM-only DACL, just as
new directories use explicit security at `CreateDirectoryW`. Existing
objects are inspected and refused if unsuitable; ownership is never repaired.
This covers batch metadata, evidence, copied inputs, and the Git view.

External .NET/MSBuild tools create their own outputs. The fixed CLI `main`
calls `execute_pilot`, which checks the process token user/default owner
before **any** external command, including Git. A mismatch or unreadable or
unknown identity produces an incomplete worker/batch and retained
`creation-token.json`, without launching that unsupported route. Normal
non-elevated execution remains the supported end-to-end pilot. The guard
compares owners; it does not simply ban an elevation flag or modify tokens.
No impersonation, privilege grant, host-policy change or after-the-fact
builder-output ownership rewriting is performed.

`Batch`, `create_private_file`, directory creation and the workspace-creation
CLI do not need this default-owner guard: they explicitly set ownership.
The lower-level `run_command`, `ProcessJob.spawn` and `git_identity` do not
apply the fixed-pilot admission policy. Regression tests call those primitives
for raw process capture, read-only Git and containment, with any task-owned
fixture files created explicitly. They do not claim an elevated external
build is supported. Other repository runners and direct dotnet calls retain
their prior behavior.

The four project/source/resource inputs are copied byte-for-byte into the
worker's E: tree. Original bytes are hashed before and after execution.
The copy is built with explicit E: intermediate/final paths, a fresh E:
CLI home, package/cache directories and temp directories. User MSBuild
overrides and proxy settings are not inherited. SDK workload updates,
telemetry, build servers and first-use certificate creation are disabled.
The SDK is pinned to the observed installed version for this worker.
Restore and build both pass [`-noAutoResponse`](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-response-files),
disabling automatic `MSBuild.rsp` and ancestor `Directory.Build.rsp` loading.
Disabling `Directory.Build.props`/`targets` and filtering the environment
alone did not disable those response files. No explicit `@response` argument
is supplied. This is a fixed trusted build, not isolation of arbitrary
projects or an OS filesystem write sandbox.
Restore has only an empty local filesystem feed, package downloads disabled,
and NuGet auditing disabled; build uses `--no-restore`. No package signature
verification or security policy is disabled: no packages are unpacked.

Git identity collection also uses the monitored, job-contained command path.
Its environment does not inherit Git overrides, tracing, user/system config
or attributes. A metadata-only `rev-parse` reads the assigned checkout's
HEAD and administrative locations with optional locks and fsmonitor disabled.
Status uses an E: administrative view containing copies of its index, shared
indexes and repository-local ignore/attribute files, with read-only access
to the original objects. It never loads the original repository's executable
filters or fsmonitor settings. Optional index writes are disabled there too.
Dirty status deliberately excludes submodule inspection and user/global
ignore settings; it describes the main checkout, not arbitrary nested repos.
Unsupported metadata or failed inspection makes the pilot incomplete.

## Shared budget and failure behavior

One batch is the pair **workspace root + batch name**. Every cooperating
process using that pair shares the same integer byte budget. Reopening it
with a different budget is refused. GiB means 1,073,741,824 bytes.

- The 20 GiB limit includes retained files, build output, caches, copied
  inputs and a physically written 64 KiB control file. Accounting uses
  logical file lengths, not filesystem allocation, directory/ACL overhead
  or compression savings. Free disk space is also checked conservatively.
- Each admitted pilot worker reserves 1 GiB **from** that aggregate limit.
  At most 32 MiB of its reservation is available for controlled evidence
  writes. Every such write is checked under the shared lock before writing;
  failed/partial writes consume their reserved evidence bytes too.
- Admission includes every active worker's unspent reservation and every
  retained worker's bytes. Successful workers release unused capacity,
  not their retained files. There are at most 64 retained worker slots.
- The fixed-size `batch.json` is locked across processes and flushed on
  transitions. Its capacity is reserved separately from worker output.
  A worker starts with `status: incomplete` and remains so if interrupted,
  including a hard kill that prevents finalization.
- File usage, privacy and checkout scratch are inspected before commands,
  around controlled writes, during subprocess execution (with a 100 ms
  process-wait interval between scans), and after commands. Build processes
  use a Windows job that terminates descendants on exit/interruption.
  Windows 10 / Server 2016 or newer is required: `CreateProcessW` receives
  `PROC_THREAD_ATTRIBUTE_JOB_LIST` in `STARTUPINFOEXW`, so job membership
  exists at creation, not after a running child is returned. The job handle
  is not inherited; only the three standard-I/O handles are inherited.
  Unsupported APIs or job assignment failures refuse launch without an
  uncontained fallback. This uses the documented [job-list attribute](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
  and [kill-on-close job behavior](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
  not host policy or a suspended-then-assigned orphan window.
- Detected reservation/aggregate overruns, admission refusal, output
  exhaustion, inspection errors and failures latch a batch stop. No more
  work launches, active workers stop at their next check, and completion
  is refused. The ledger retains the sampled peak and stop reason.
  The final stop check and native process creation hold the same ledger
  lock as every stop writer. A stop already recorded by another worker
  therefore cannot race a later launch. A controlled write also raises
  when its final scan records a stop, while preserving the written bytes.

This is a **trusted-runner guard, not an OS quota**. Uncontrolled build
output can overshoot before a scan notices; short-lived files between
scans can escape measurement. Reported peak means observed logical bytes,
not a claim about the true instantaneous or allocated peak. Inspections
are not atomic filesystem snapshots. No fallback output is written on C:.

Checkout scratch is measured separately from a pre-run inventory: new files,
replacements, and growth beyond pre-existing lengths count toward 5 GiB.
The pilot scans all checkout paths without following redirects or ignoring
read errors. Any limit violation or inspection error is incomplete. A
successful run also requires the final checkout inventory to equal the
initial inventory: the fixed build must produce no checkout output.
Linked-worktree indexes and common Git administration live outside that
checkout inventory. Zero measured checkout scratch does **not** prove they
were untouched; the isolated Git view and real linked-worktree regression
establish that boundary separately.

There is no automatic cleanup, reset, or resume. Already-written stdout,
stderr, build products and evidence survive failures and interruption.
Keep failed/active directories for review; do not delete them to retry.
Use a new explicitly supplied private workspace or batch name for a fresh
attempt. A stopped or interrupted batch must not be presented as complete.

## Review evidence

The command exits 0 only for a complete batch snapshot; refusal/incomplete
execution exits 2 and prints its reason. Within `WORKSPACE/BATCH/WORKER/`:

- `identity.json` records full Git HEAD, dirty status, Python identity,
  dotnet executable hash, runner hashes, and the four original input hashes.
- `creation-token.json` records the read-only token identity/admission result.
  A supported identity is not a batch completion claim. A refused worker may
  have only this evidence and its incomplete ledger, with no Git/tool output.
- `commands.jsonl` records argument arrays, working directory, filtered
  environment and exit codes. `sdk-version`, `toolchain`, `runtimes`,
  `restore`, `build` and `selftest` each retain raw `.stdout`/`.stderr`.
- `cached-references.json` records the read-only pack location and key hashes.
- `result.json` records `selftest-passed`, reported passes and
  `real_native_calls: 0`, sampled checkout scratch, and sizes/SHA-256 hashes
  of all earlier worker files. It is not independently a completion seal.

The authoritative completion check is `batch.json`: no stop reason and
**all** workers complete. A surviving `result.json` alone never overrides an
incomplete ledger. Later admissions can change that batch snapshot. For
review tied to a commit, run from a clean checkout at that full HEAD.

Before diagnostic refinement, a native rejection said "workspace owner or
DACL is not private" without distinguishing those states. Rejections now
name owner mismatch, null DACL or the existing ACL violation, and attach
bounded read-only security metadata: expected token-user and actual-owner
SIDs, DACL presence, up to 16 ACE types/masks/flags and standard allow/deny
SIDs, token default owner and elevation. Other ACE layouts are not guessed;
truncation or metadata-query errors are explicit. No object contents, secrets
or environment dump are logged. Successful checks remain quiet.
A native descendant probe runs before Batch fixtures and preserves the full
rejection in pytest failure output. It does not repair ownership or ACLs;
these diagnostics do not relax any refusal or identify a remote host cause
until that host actually reports its native state.

## Blast radius and before/after behavior

Before review, this document said, "No existing behavior or restriction is
removed." That remains true for pre-existing runners, not for the three
earlier pilot bug paths or the response-file/path bugs corrected below.
In particular, the old
direct `dotnet run --project tools/reboot-helper/selftest/PowerGateSelfTest.csproj`
path used normal build/cache locations before this change; it still does
after this change. Only the new optional pilot refuses those locations.

Before the fix, "No more work launches" overstated the guarantee: a persisted
stop could race a launch and a final write scan could return after detecting
an overrun. After the fix, launch and stop recording share a lock, and that
write raises while retaining evidence. Before, "Build processes use a Windows
job" omitted a running-before-assignment interval. After, job membership is
set atomically at creation for **every** pilot child, including Git, and
descendants inherit containment. Real synchronized interruption tests kill
only their own launcher and inspect their own child/descendant handles.

Before the second review fix, "No fallback output is written on C:"
overstated output containment: automatic `MSBuild.rsp`/`Directory.Build.rsp`
could add loggers writing outside the batch, despite disabled directory
props/targets and filtered environment. After the fix, **both** restore and
build disable automatic response files with `-noAutoResponse`. Direct
dotnet calls elsewhere retain normal response-file behavior.

Before, "explicit E: intermediate/final paths" did not account for
MSBuild parsing path values as property syntax. A `;tag=one` ancestor could
truncate output properties; commas, percent escapes and item syntax also
have nonliteral meanings. After, the fixed pilot refuses the precise
character set listed above in the entire workspace and cache roots before
launch, rather than adding an escaping framework or changing general path
policy. Spaces and `=` remain literal and supported. The sampled-budget
limitation above is unchanged; these fixes do not create an OS quota.

| Structure touched or consumed | Before and after |
| --- | --- |
| `tools/evidence_workspace.py` | New opt-in creation, traversal, scratch measurement and shared batch ledger. Controlled file creation now explicitly sets ownership instead of inheriting token defaults; existing-file validation is retained. The shared launch/stop lock, final-write refusal, reservations, privacy checks and retained failures still hold for every worker in a batch. |
| `tools/workspace_windows.py` | New Windows path, ACL, data-stream and process-job adapters. Review fix replaces post-start assignment with atomic job-list creation for every pilot child; no uncontained fallback. New-directory ACL rules and stream checks still hold. Existing ACLs, installed tools and host policy are unchanged. |
| `tools/workspace_acl_diagnostics.py` | New failure-only, bounded native security metadata. Replaces no security rule and grants no access; precise rejection errors replace the old conflated wording described above. No ownership, token or ACL changes. |
| `tools/workspace_creation.py` | New narrow Windows explicit-owner creation attributes, exclusive file creator and read-only token query. Shared directory/file creation sets current-user+SYSTEM access at creation, never rewrites existing objects or changes a token. No previous helper outside this opt-in pilot is replaced. |
| `tools/workspace_git.py` | New narrow identity adapter. Replaces original-repository status calls with an E: administrative view, filtered environment and disabled optional writes. Original index, refs, objects and linked-worktree administration are read-only inputs; no original Git settings are rewritten. Main-checkout dirty identity intentionally omits user/global ignores and submodule inspection. |
| `tools/run_storage_pilot.py` | Fixed project/offline behavior remains. `main` via `execute_pilot` refuses incompatible/unknown process default owners before Git or .NET children, retaining incomplete evidence. Both MSBuild commands now disable automatic response files; full workspace/cache roots now reject the documented unsupported path syntax before launch. Lower-level process/Git primitives do not enforce fixed-pilot admission or MSBuild syntax rules. The E: restriction remains scoped to this pilot and workspace creator, not all repository runners. |
| `tests/test_evidence_workspace.py` | Ledger, reservation, synchronization and refusal assertions remain. Corrects only the false ownership-inheritance assumption: explicit directories must pass; raw descendants with measured wrong ownership must fail. Overrun fixtures use genuinely private initial objects. |
| `tests/test_storage_pilot.py` | New fixed-runner tests and real host-process capture tests, without a .NET/network/TV dependency. Before this review fix, the missing-workspace test assumed a global E: path was absent and could write there if it existed. After, a test-owned missing directory and controlled volume-validation seam prove missing-directory refusal before batch/build writes. Response-file flags and path refusal are tested through production CLI/execution seams, with spaces/equals controls. Tests that predate this pilot remain unchanged. |
| `tests/test_storage_review.py` | New real linked-worktree, synchronized stop/launch, final-write and real Windows process-tree interruption/failure tests. Portable fixtures resolve the physical interpreter and create private output; no production restriction is relaxed. Diagnostic-unit injections test error distinction, not the GitHub cause. Only test-owned resources; no .NET/network/TV dependency. |
| `tests/test_workspace_creation.py` | New explicit file/control/evidence ownership, exclusive preservation, unchanged existing-object refusal and actual native admission tests. Both supported and incompatible native identities are asserted by measured state, not skipped or accepted indiscriminately. No token reconfiguration. |
| This usage document | New opt-in procedure, limitations and evidence interpretation. Review corrections preserve the old claims as labeled before/after statements rather than silently deleting them. Existing direct-run instructions still hold. |
| Four inputs: `PowerGateSelfTest.csproj`, `PowerGateSelfTest.cs`, `LinuxRebootHelper.cs`, `snapshot.sh` | Consumed read-only and copied unchanged; target framework, startup object, embedded resource and existing native-call guards retain their behavior. The fake-native guarantee belongs specifically to `PowerGateSelfTest.Main`, **not** `LinuxRebootHelper.Main`, every helper, or every self-test. |
| Installed SDK/runtime and cached reference pack | Read-only prerequisite inputs before and after. No install, cache repair or download is added. |
| MSBuild response files and path-property parser | Before, implicit response files could introduce outside logging, and tool syntax could reinterpret paths despite shell-safe argument arrays. After, both fixed commands disable automatic response files and all variable path-property roots are checked. Installed/ancestor files are neither edited nor removed. Other builds retain their own defaults. |
| Checkout and linked/common Git administration | Before review the claim was "Read-only inputs/inspection only," but Git status could refresh an index outside scratch measurement. After the fix, checkout bytes are inspected and original Git administration is read only; possible Git administrative output is isolated on E:. Zero checkout scratch alone never proved administrative non-writes. `ordinary` still rejects redirects/hardlinks and unaccounted streams for **every** traversed file/directory, not merely the workspace root. |
| Existing evidence, packets and archives | No migration, rewriting or packet-runner integration before or after the review fix. Existing seal gates and certification status are unchanged. |
| CI, package dependencies, release audit and existing CLI | Unchanged. CI's existing pytest/Ruff discovery includes the new tests/tools, but does not run the live E: pilot or Ruff format check. |

## Checks

```powershell
python -B -m pytest tests/test_evidence_workspace.py tests/test_storage_pilot.py
python -B -m pytest tests/test_storage_review.py tests/test_workspace_creation.py
python -B -m ruff check tools/evidence_workspace.py tools/workspace_windows.py tools/workspace_creation.py tools/workspace_acl_diagnostics.py tools/workspace_git.py tools/run_storage_pilot.py tests/test_evidence_workspace.py tests/test_storage_pilot.py tests/test_storage_review.py tests/test_workspace_creation.py
python -B -m ruff format --check tools/evidence_workspace.py tools/workspace_windows.py tools/workspace_creation.py tools/workspace_acl_diagnostics.py tools/workspace_git.py tools/run_storage_pilot.py tests/test_evidence_workspace.py tests/test_storage_pilot.py tests/test_storage_review.py tests/test_workspace_creation.py
python -B tools/audit_release.py
```

For local checks, disable pytest/Ruff checkout caches and set pytest's
`--basetemp` plus `TEMP`/`TMP` to a **new** E: test directory. Do not point
`--basetemp` at evidence: pytest removes an existing basetemp. These test
fixtures are separate from the live pilot's batch and its 20 GiB budget.
