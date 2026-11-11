"""Port manifest: what r9 carries byte-for-byte from the spent r8 seal.

Verifies every verbatim carry against r8's seal.json, then records the deltas
with a reason. Host-only; reads r8 (never writes it) and writes
port-from-r8.json in this packet.
"""
import json
import sys

import packet as p

R8 = p.HERE.parent / 'qn90b-uep-l4-deploy-20261109-r8'

CARRIED = (
    'stage.sh', 'snapshot.sh', 'sdk.py', 'bootstrap_sdk.py', 'stage_transport.py',
    'trial.py', 'recovery.py', 'protected-register-20261108.json',
    'artifacts/FdetProbe.dll', 'artifacts/FdetProbe.runtimeconfig.json',
    'artifacts/uep-probe.elf',
)

DELTAS = {
    'packet.py': 'r9 constants: v5.18 baseline vs v5.19 install, absent-config inspection, three markers, v5.19 receipts',
    'deploy.py': 'manager sha is a per-stage parameter (v5.18 pre-install, v5.19 after)',
    'stage_lib.py': 'v5.19 uid-bearing receipt shapes and module-log stage names',
    'stage_common.py': 'new: shared SDK state, module-gate wait, flag read, boot wait',
    'stage_session.py': 'new: one-op authenticated root session for the three gate ops',
    'install.py': 'new: stage 1 driver (install + read-only + manual proof + reboot)',
    'active.py': 'new: stage 2 driver (activate + clear + late rearm reads)',
    'disable.py': 'new: stage 3 driver (remove + baseline + denial + SPENT)',
    'denial.py': 'new: driver-side uid 901 denial control ported from the L1 packet',
    'inspect_tv.py': 'pins v5.18 dll+rc, absent config/state/module/backup; emits target_rc_hash and module_dir',
    'prepare.py': 'new: three single-edge gate scripts (install/active/remove)',
    'authoring_checks.py': 'rewritten for the three scripts and the three-op agent',
    'offline_checks.py': 'rewritten seal list, build and integrity gates for r9',
    'driver_checks.py': 'rewritten runner: r9 sources + script transitions',
    'driver_shim.py': 'layout/bake extended for the three scripts and the fake dotnet',
    'flow_cases.py': 'rewritten: 13 host script-transition cases under the real shim',
    'port_from_r8.py': 'new port manifest (this file)',
    'port-from-r8.json': 'new port manifest output',
    'PLAN.md': 'rewritten r9 plan',
    'UepGateAgent.cs': 'replaces BridgeRepairAgent.cs: three ops, one per session, 12-180 s bound',
    'UepGateAgent.csproj': 'replaces BridgeRepairAgent.csproj: embeds the three scripts',
    'artifacts/manager.dll': 'v5.19 manager (449cf034...), replaces v5.18',
    'artifacts/manager.runtimeconfig.json': 'v5.19 manager runtimeconfig (ed69fdc8...)',
    'artifacts/UepGateHost.dll': 'new root-context host (3b1e3a80...)',
    'artifacts/UepGateHost.runtimeconfig.json': 'new host runtimeconfig (ed69fdc8...)',
    'module/boot.sh': 'new module runner entry (canonical LF, 1afd5b7c...)',
    'module/module.json': 'new module metadata (canonical LF, 63b13c84...)',
}


def main():
    seal = json.loads((R8 / 'seal.json').read_text(encoding='utf-8'))
    carried = {}
    for name in CARRIED:
        p.require(name in seal, 'r8 seal lacks carried file: ' + name)
        current = p.digest(p.HERE / name)
        p.require(current == seal[name], 'carried file drifted from r8: ' + name)
        carried[name] = current
    delta = {}
    for name, reason in DELTAS.items():
        path = p.HERE / name
        if name == 'port-from-r8.json':
            delta[name] = {'reason': reason, 'sha256': None}
            continue
        p.require(path.is_file(), 'delta target missing: ' + name)
        delta[name] = {'reason': reason, 'sha256': p.digest(path)}
    document = {
        'source_packet': 'qn90b-uep-l4-deploy-20261109-r8',
        'source_commit': p.SOURCE_COMMIT,
        'carried_verbatim': carried,
        'deltas': delta,
    }
    out = p.HERE / 'port-from-r8.json'
    p.require(not out.exists(), 'port manifest already written')
    out.write_text(json.dumps(document, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'carried': len(carried), 'deltas': len(delta),
                      'written': str(out)}, indent=1))


if __name__ == '__main__':
    main()
