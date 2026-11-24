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

The four project/source/resource inputs are copied byte-for-byte into the
worker's E: tree. Original bytes are hashed before and after execution.
The copy is built with explicit E: intermediate/final paths, a fresh E:
CLI home, package/cache directories and temp directories. User MSBuild
overrides and proxy settings are not inherited. SDK workload updates,
telemetry, build servers and first-use certificate creation are disabled.
The SDK is pinned to the observed installed version for this worker.
Restore has only an empty local filesystem feed, package downloads disabled,
and NuGet auditing disabled; build uses `--no-restore`. No package signature
verification or security policy is disabled: no packages are unpacked.

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
- Detected reservation/aggregate overruns, admission refusal, output
  exhaustion, inspection errors and failures latch a batch stop. No more
  work launches, active workers stop at their next check, and completion
  is refused. The ledger retains the sampled peak and stop reason.

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

## Blast radius and before/after behavior

No existing behavior or restriction is removed. In particular, the old
direct `dotnet run --project tools/reboot-helper/selftest/PowerGateSelfTest.csproj`
path used normal build/cache locations before this change; it still does
after this change. Only the new optional pilot refuses those locations.

| Structure touched or consumed | Before and after |
| --- | --- |
| `tools/evidence_workspace.py` | New opt-in creation, traversal, scratch measurement and shared batch ledger. It replaces no existing helper. Its reservations apply to every worker in the same batch, not one worker's private copy of the limit. |
| `tools/workspace_windows.py` | New Windows path, ACL, data-stream and process-job adapters. They change only newly requested workspace directories and pilot child processes, not existing ACLs, installed tools or host policy. |
| `tools/run_storage_pilot.py` | New fixed entry point; cannot run an arbitrary project or command. Its private physical E: restriction applies to this pilot and the new workspace-creation entry point, not every runner in the repository. |
| `tests/test_evidence_workspace.py` | New deterministic ledger, reservation, failure, synchronization and platform tests. Existing tests are unchanged. |
| `tests/test_storage_pilot.py` | New fixed-runner tests and real host-process capture tests, without a .NET/network/TV dependency. Existing tests are unchanged. |
| This usage document | New opt-in procedure, limitations and evidence interpretation; no prior instructions are deleted or superseded. |
| Four inputs: `PowerGateSelfTest.csproj`, `PowerGateSelfTest.cs`, `LinuxRebootHelper.cs`, `snapshot.sh` | Consumed read-only and copied unchanged; target framework, startup object, embedded resource and existing native-call guards retain their behavior. The fake-native guarantee belongs specifically to `PowerGateSelfTest.Main`, **not** `LinuxRebootHelper.Main`, every helper, or every self-test. |
| Installed SDK/runtime and cached reference pack | Read-only prerequisite inputs before and after. No install, cache repair or download is added. |
| Checkout, existing evidence, packets and archives | Read-only inputs/inspection only. No migration or packet-runner integration; all existing seal gates and certification status remain unchanged. `ordinary` rejects redirects/hardlinks and unaccounted streams for **every** traversed file/directory, not merely the named workspace root. |
| CI, package dependencies, release audit and existing CLI | Unchanged. CI's existing pytest/Ruff discovery includes the new tests/tools, but does not run the live E: pilot or Ruff format check. |

## Checks

```powershell
python -B -m pytest tests/test_evidence_workspace.py tests/test_storage_pilot.py
python -B -m ruff check tools/evidence_workspace.py tools/workspace_windows.py tools/run_storage_pilot.py tests/test_evidence_workspace.py tests/test_storage_pilot.py
python -B -m ruff format --check tools/evidence_workspace.py tools/workspace_windows.py tools/run_storage_pilot.py tests/test_evidence_workspace.py tests/test_storage_pilot.py
python -B tools/audit_release.py
```

For local checks, disable pytest/Ruff checkout caches and set pytest's
`--basetemp` plus `TEMP`/`TMP` to a **new** E: test directory. Do not point
`--basetemp` at evidence: pytest removes an existing basetemp. These test
fixtures are separate from the live pilot's batch and its 20 GiB budget.
