"""r7 SEAL FLOW — runs at TV-contact prep time, AFTER the fresh r7 inspection.
Refuses without inspection.json + protected-register.json + rehearsal green;
writes nothing until every host check passes; seals in one shot (reruns
refuse). No TV operations of any kind.
"""
import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p

PACK = p.HERE
REPO = p.REPO
VENV_PY = REPO / '.venv/Scripts/python.exe'
SDK = Path(r'C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')

SEAL_NAMES = [
    'PLAN.md', 'packet.py', 'deploy.py', 'remove.py',
    'stage_lib.py', 'trial.py', 'recovery.py', 'sdk.py',
    'bootstrap_sdk.py', 'stage_transport.py', 'inspect_tv.py', 'prepare.py',
    'offline_checks.py', 'driver_checks.py', 'driver_shim.py',
    'flow_cases.py', 'authoring_checks.py', 'port_from_r6.py', 'port-from-r6.json',
    'inspection-r1-predeploy.json', 'r6-stage-status-watch.json', 'r6-stage-status-dirread.json',
    'r6-seal.json', 'r6-port-from-r5.json', 'r6-STOP.txt',
    'protected-register-20261108.json', 'deployment-result.json',
    'post-deploy-verification.json', 'post-mortem-20261108.md',
    'inspection.json', 'protected-register.json',
    'stage.sh', 'snapshot.sh', 'gate-remove.sh',
    'BridgeRepairAgent.cs', 'BridgeRepairAgent.csproj',
    'artifacts/manager.dll', 'artifacts/manager.runtimeconfig.json',
    'artifacts/FdetProbe.dll', 'artifacts/FdetProbe.runtimeconfig.json',
    'artifacts/uep-probe.elf',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'rehearsal-results.json', 'offline-results.json',
]
PY_CHECKED = tuple(n for n in SEAL_NAMES if n.endswith('.py'))
SHELL_SCRIPTS = ('stage.sh', 'snapshot.sh', 'gate-remove.sh')


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
        'gate_stage': 'remove-only (owner decision 2026-11-09)',
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
              'the r7 inspection has not run; run inspect_tv.py first (own light approval)')
    p.require((PACK / 'protected-register.json').is_file(),
              'the fresh protected register is missing; STOP')
    p.require(not (PACK / 'seal.json').exists() and not (PACK / 'offline-results.json').exists(),
              'seal or offline results already exist; offline_checks refuses reruns')
    p.require(not (PACK / 'SPENT').exists() and not (PACK / 'STOP').exists(),
              'debris or consumption happened; STOP')
    # No stage marker may exist before the seal: the owner arms the single
    # r7 marker (LIVE_ARM_REMOVE) only after preparation completed.
    for path in PACK.iterdir():
        p.require(not path.name.startswith('LIVE_ARM_'),
                  'a stage marker pre-exists the seal: ' + path.name)
    # r6 debris that must never be re-imported into r7:
    for legacy in ('dirread.py', 'watch.py', 'activate.py', 'disable.py',
                   'gate-readonly.sh', 'gate-active.sh'):
        p.require(not (PACK / legacy).exists(),
                  'r2-r6 module or script carried into r7: ' + legacy)

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
    build_env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    # MSBuild's intermediates stay outside the packet (the same shape
    # authoring_checks uses): only the sealed build/ output is retained, so a
    # later manual rebuild cannot pick up stale obj state from this seal.
    with tempfile.TemporaryDirectory(prefix='r7-seal-build-') as intermediates:
        command = [str(SDK / 'dotnet.exe'), 'build', str(PACK / 'BridgeRepairAgent.csproj'),
                   '-c', 'Release', '-f', 'netcoreapp3.1',
                   '-p:BaseIntermediateOutputPath=' + str(Path(intermediates) / 'obj')
                   + str(Path('/')),
                   '-p:OutputPath=' + str(PACK / 'build') + str(Path('/'))]
        built = subprocess.run(command, capture_output=True, cwd=str(REPO), env=build_env)
    p.require(built.returncode == 0, 'agent build failed:\n'
              + built.stdout.decode()[-3000:] + built.stderr.decode()[-800:])
    warnings_summary = re.search(r'(\d+) Warning\(s\)', built.stdout.decode()[-4000:])
    p.require(warnings_summary is not None and warnings_summary.group(1) == '0',
              'agent build reported warnings:\n' + built.stdout.decode()[-3000:])
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
    p.require(p.BOOT is not None and len(p.BOOT) == 36, 'the inspection boot pin is not standing')
    # Producer -> consumer shape gate: the r7 packet's lazy gates and prepare
    # read exactly these inspection key names, so the probe MUST emit them
    # and NOT the r2-r6 era uep_* spellings (the 2026-11-09 review's
    # schema-mismatch blocker). The %s form also pins the guarded capture:
    # an unguarded `printf 'gate_meta='; stat ...` would abort the whole probe
    # on the absent/foreign state the check exists to report.
    probe_source = (PACK / 'inspect_tv.py').read_text(encoding='utf-8')
    for required_capture in ("printf 'gate_config=%s\\n'", "printf 'gate_state=%s\\n'",
                             "printf 'gate_hash=%s\\n'", "printf 'gate_meta=%s\\n'",
                             "printf 'gate_label=%s\\n'"):
        p.require(required_capture in probe_source,
                  'inspection producer/consumer key drift: missing ' + required_capture)
    for retired_capture in ("printf 'uep_config='", "printf 'uep_state='"):
        p.require(retired_capture not in probe_source,
                  'retired r2-r6 capture name still emitted: ' + retired_capture)
    # The single removal stage must be reachable: the baked body accepts only
    # the read-only content, and the tail asserts absence unconditionally
    # (no surviving-file fallback, no active-hash algebra).
    baked = (PACK / 'gate-remove.sh').read_text(encoding='ascii')
    p.require(p.UEP_READONLY_SHA in baked, 'baked removal script lost the read-only pin')
    p.require(p.UEP_ACTIVE_SHA not in baked, 'baked removal script permits the active content; refuse path required')
    p.require('GATE_ABSENT' in baked, 'baked removal script lost the absence assertion')
    p.require('GATE_METADATA' not in baked and 'H_END' not in baked,
              'baked removal script kept a surviving-file fallback')

    step('sealing ' + str(len(SEAL_NAMES)) + ' entries')
    results = seal_packet()
    print(json.dumps(results), flush=True)


if __name__ == '__main__':
    main()
