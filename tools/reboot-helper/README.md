# Experimental QN90B reboot helper

Temporary research helper for the QN55QN90BAFXZA on Tizen 6.5 / .NET 3.1.3.
This is not part of the release payloads or an installed boot service. Its TV
caller, transport, baselines, approvals, credentials and execution records stay
in private local preparation directories.

The helper checks its own code/configuration hashes, root identity, host PID/user
namespaces, private mount namespace, reboot capability, boot ID and developer
settings. The expected desktop developer host is bound into the hashed private
configuration; this experiment does not change it to localhost.

`--inspect` collects context without power calls. `--wait` requires its own
session/process group, publishes readiness, then waits up to 30 seconds for an
arming record bound to that readiness and configuration. The exclusive consumed
record prevents reuse. `mode=rehearse` runs the gates without calling `sync` or
`reboot`. An explicitly prepared `mode=reboot` calls libc `sync()` followed by
`reboot(RB_AUTOBOOT)` once, retaining errno immediately if the call returns.
Any returned call or dropped connection still requires independent boot proof.

## Offline checks

```sh
dotnet build tools/reboot-helper/LinuxRebootHelper.csproj --configuration Release
dotnet run --project tools/reboot-helper/selftest/PowerGateSelfTest.csproj --configuration Release
```

The helper targets the TV's .NET 3.1 runtime. The self-check targets the .NET 6
runtime already used by CI; its delegates model both modes and never enter the
native functions. With only a newer host runtime installed, build the self-check
and use `dotnet exec --roll-forward Major` on its output assembly.

The tests cover valid/invalid caller context, one-use consumption, retained
returned errno, expired preparation and failures before native entry. They do
not qualify the TV's actual helper process, controller, transfer or cleanup.
Those require the private no-power rehearsal and its recorded final baseline.

## Live qualification boundary

Keep the first live rehearsal in `mode=rehearse`. Before any separately approved
real reboot, verify the actual helper's context, archive readiness before arming,
and establish current storage/update activity and recovery access. A real reboot
must be proven by a new boot ID, reduced uptime and returning SDK access while
the developer host remains the desktop's address. Do not retry an ambiguous attempt.

Direct kernel reboot bypasses normal application shutdown. Storage measurements
and `sync()` do not establish application/database consistency or exclude a new
writer. The staging pathname checks also assume no hostile concurrent swaps in
the shared SDK parent. Hardware reboot behavior and these risks remain
unresolved; using the TV remote when physically present is the fallback.

## Separate experimental cutover helper

`cutover/LinuxCutoverHelper.csproj` prepares a two-acknowledgement developer-host
transition without changing the qualified reboot-only helper. It is not installed
or hardware-qualified. Its exact configuration, controller, baseline, private
credentials and execution records belong in a new private packet.

The helper validates its own code, configuration, boot, root context and original
desktop IP before publishing `cutover-ready`. The first acknowledgement binds
that readiness and configuration before one localhost write. A separate
`cutover-ip-ready` record contains the typed readback and actual caller context.
The desktop must save it durably before acknowledging power. Both waits expire;
acknowledgements are bound to their phase and consumed exclusively.

Before accepting power, failure or expiry may restore the original desktop IP
once, only after checking the same boot, code, configuration, root context and
one of the two expected IP values. An unreadable or unexpected state refuses
restoration. From acceptance of the power acknowledgement onward, every failure,
native return or channel loss forbids automatic restoration and power retry.
Independent boot proof is still required. This deliberately leaves physical
menu recovery necessary for some failures.

`mode=rehearse` follows both acknowledgements at the original desktop IP, with
zero setting writes, global sync calls or reboot calls. It does not simulate a
successful live localhost write or prove callback survival across that write.
`mode=cutover` is a distinct, separately approved experiment. No persistent
rollback timer or service is installed. The existing shared-directory pathname
race limitation also applies to this helper.

```sh
dotnet build tools/reboot-helper/cutover/LinuxCutoverHelper.csproj --configuration Release
dotnet run --project tools/reboot-helper/cutover/selftest/CutoverSelfTest.csproj --configuration Release
```

The self-check uses fake settings, clocks and native delegates. It tests phase
ordering, expired and mismatched acknowledgements, write/readback failures,
guarded pre-power restoration and refusal to restore after power commitment.
It never enters the TV helper's native or settings APIs.
