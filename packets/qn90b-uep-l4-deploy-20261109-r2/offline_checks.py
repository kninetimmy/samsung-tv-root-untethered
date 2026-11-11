"""r2 SEAL FLOW — runs at TV-contact prep time, AFTER the fresh r2 inspection.
Refuses without inspection.json + protected-register.json + rehearsal green;
writes nothing until every host check passes; seals in one shot (reruns
refuse). No TV operations of any kind.
"""
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p

PACK = p.HERE
REPO = p.REPO
VENV_PY = REPO / '.venv/Scripts/python.exe'
SDK = Path(r'C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')

SEAL_NAMES = [
    'PLAN.md', 'packet.py', 'deploy.py', 'dirread.py', 'watch.py', 'activate.py',
    'disable.py', 'stage_lib.py', 'trial.py', 'recovery.py', 'sdk.py',
    'bootstrap_sdk.py', 'stage_transport.py', 'inspect_tv.py', 'prepare.py',
    'offline_checks.py', 'driver_checks.py', 'driver_shim.py',
    's1_cases.py', 's2_cases.py', 's3_cases.py', 's4_cases.py',
    's5s6_cases.py', 's7_cases.py', 's8_cases.py', 'flow_cases.py', 'port_from_r1.py',
    'port_proof_source.py', 'port-proof-source.json',
    'inspection-r1-predeploy.json', 'inspection.json', 'protected-register-20261108.json',
    'protected-register.json', 'deployment-result.json', 'post-deploy-verification.json',
    'post-mortem-20261108.md', 'stage.sh', 'snapshot.sh',
    'gate-readonly.sh', 'gate-active.sh', 'gate-remove.sh',
    'BridgeRepairAgent.cs', 'BridgeRepairAgent.csproj',
    'artifacts/manager.dll', 'artifacts/manager.runtimeconfig.json',
    'artifacts/FdetProbe.dll', 'artifacts/FdetProbe.runtimeconfig.json',
    'artifacts/uep-probe.elf',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'rehearsal-results.json', 'offline-results.json',
]
PY_CHECKED = tuple(n for n in SEAL_NAMES if n.endswith('.py'))
SHELL_SCRIPTS = ('stage.sh', 'snapshot.sh', 'gate-readonly.sh',
                 'gate-active.sh', 'gate-remove.sh')


def step(text):
    print('offline-checks:', text, flush=True)


def seal_packet():
    p.require(not (PACK / 'seal.json').exists() and not (PACK / 'offline-results.json').exists(),
              'seal or offline results already exist; inspect the previous attempt before proceeding')
    entries = {}
    for name in SEAL_NAMES:
        if name == 'offline-results.json':
            continue
        path = PACK / name
        p.require(path.is_file(), 'seal target missing: ' + name)
        entries[name] = p.digest(path)
    results = {
        'offline_checks': 'passed', 'seal_entries': len(SEAL_NAMES),
        'agent_sha256': entries['build/SamsungTvRootAgent.dll'],
        'agent_runtimeconfig_sha256': entries['build/SamsungTvRootAgent.runtimeconfig.json'],
        'boot': p.BOOT, 'proof': p.PROOF_SHA,
        'protected_files': len(p.expected_set()), 'TV_operations': 0,
    }
    with (PACK / 'offline-results.json').open('x', encoding='utf-8') as stream:
        json.dump(results, stream, indent=2)
    entries['offline-results.json'] = p.digest(PACK / 'offline-results.json')
    with (PACK / 'seal.json').open('x', encoding='utf-8') as stream:
        json.dump(entries, stream, indent=2)
    return results


def main():
    step('preconditions')
    p.require((PACK / 'inspection.json').is_file(),
              'the r2 inspection has not run; run inspect_tv.py first (own light approval)')
    p.require((PACK / 'protected-register.json').is_file(),
              'the fresh protected register is missing; STOP')
    p.require(not (PACK / 'seal.json').exists() and not (PACK / 'offline-results.json').exists(),
              'seal or offline results already exist; offline_checks refuses reruns')
    p.require(not (PACK / 'SPENT').exists() and not (PACK / 'STOP').exists(),
              'debris or consumption happened; STOP')

    step('rehearsal rerun (fresh host case results)')
    result = subprocess.run([str(VENV_PY), '-B', str(PACK / 'driver_checks.py')],
                            capture_output=True, cwd=str(REPO))
    p.require(result.returncode == 0, 'the host rehearsal must pass before sealing; output:\n'
              + result.stdout.decode()[-2000:] + result.stderr.decode()[-400:])

    step('prepared artifacts')
    for name, expected in p.ARTIFACT_SHAS.items():
        p.require(p.digest(PACK / name) == expected, 'artifact drift: ' + name)
    p.require(p.digest(p.NEW) == p.NEW_SHA, 'staged manager digest mismatch')

    step('root-agent build (pinned SDK, offline)')
    command = [str(SDK / 'dotnet.exe'), 'build', str(PACK / 'BridgeRepairAgent.csproj'),
               '-c', 'Release', '-f', 'netcoreapp3.1',
               '-p:BaseIntermediateOutputPath=' + str(PACK / 'obj') + str(Path('/')),
               '-p:OutputPath=' + str(PACK / 'build') + str(Path('/'))]
    build_env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    built = subprocess.run(command, capture_output=True, cwd=str(REPO), env=build_env)
    p.require(built.returncode == 0, 'agent build failed:\n'
              + built.stdout.decode()[-3000:] + built.stderr.decode()[-800:])
    step('built agent verified')
    agent = PACK / 'build/SamsungTvRootAgent.dll'
    p.require(agent.is_file(), 'no SamsungTvRootAgent.dll produced')
    runtimeconfig = PACK / 'build/SamsungTvRootAgent.runtimeconfig.json'
    p.require(runtimeconfig.is_file(), 'no runtimeconfig produced')

    step('syntax and guard sweep')
    for name in PY_CHECKED:
        path = PACK / name
        if path.is_file():
            ast.parse(path.read_text(encoding='utf-8'), filename=name)
    for name in SHELL_SCRIPTS:
        path = PACK / name
        p.require(b'\r' not in path.read_bytes(), 'script not normalized: ' + name)
        parsed = subprocess.run([r'C:\Program Files\Git\bin\bash.exe', '-n', str(path)],
                                capture_output=True)
        p.require(parsed.returncode == 0,
                  'bash -n failed: ' + name + ' ' + parsed.stderr.decode()[:300])
    steps = subprocess.run([str(VENV_PY), '-B', '-m', 'ruff', 'check', '--no-cache',
                            '--isolated', '--select', 'F821', str(PACK)],
                           capture_output=True)
    p.require(steps.returncode == 0, 'undefined names survived: ' + steps.stdout.decode()[:1200])

    step('pack integrity gates')
    p.require(not (PACK / 'LIVE_ARM_DEPLOY').exists(),
              'the spent deploy marker must not exist in r2')
    p.require(p.BOOT is not None and len(p.BOOT) == 36, 'the inspection boot pin is not standing')

    step('sealing ' + str(len(SEAL_NAMES)) + ' entries')
    results = seal_packet()
    print(json.dumps(results), flush=True)


if __name__ == '__main__':
    main()
