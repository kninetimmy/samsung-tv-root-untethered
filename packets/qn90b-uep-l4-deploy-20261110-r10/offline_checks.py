"""r10 SEAL FLOW — runs at TV-contact prep time, AFTER the fresh r10 inspection
and after `prepare.py` baked the three gate scripts.

Refuses without inspection.json + protected-register.json + a green rehearsal
AND a green session-layer suite; writes nothing until every host check passes;
seals in one shot (reruns refuse). No TV operations. The openssl and pinned-SDK
provenance are recorded because the r7 burn was a host-side toolchain gap.

r10 additions after the independent r9 review: the sealed entry list lives in
packet.py (one source of truth), the session layer is exercised before sealing,
and the port ledger must explain every difference from r9.
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
import stage_lib

PACK = p.HERE
REPO = p.REPO
VENV_PY = REPO / '.venv/Scripts/python.exe'
SDK = Path(r'C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')

SEAL_NAMES = list(p.SEAL_ENTRIES)
PY_CHECKED = tuple(n for n in SEAL_NAMES if n.endswith('.py'))
SHELL_SCRIPTS = ('stage.sh', 'snapshot.sh', 'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh')
LEGACY = ('remove.py', 'BridgeRepairAgent.cs', 'BridgeRepairAgent.csproj',
          'port_from_r7.py', 'port-from-r7.json', 'port_from_r8.py', 'port-from-r8.json',
          'gate-readonly.sh', 'r6-stage-status-dirread.json', 'r7-seal.json')


def step(text):
    print('offline-checks:', text, flush=True)


def seal_packet(openssl, rehearsal, session_results):
    p.require(not (PACK / 'seal.json').exists() and not (PACK / 'offline-results.json').exists(),
              'seal or offline results already exist; inspect the previous attempt')
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
        'openssl': openssl, 'sdk': str(SDK),
        'boot': p.BOOT, 'proof': p.PROOF_SHA,
        'protected_files': len(p.expected_set()), 'TV_operations': 0,
        'stages': ['LIVE_ARM_INSTALL', 'LIVE_ARM_ACTIVE', 'LIVE_ARM_DISABLE'],
        'artifact_shas': p.ARTIFACT_SHAS,
        'rehearsal': rehearsal,
        'session': session_results,
    }
    with (PACK / 'offline-results.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(results, stream, indent=2)
    entries['offline-results.json'] = p.digest(PACK / 'offline-results.json')
    with (PACK / 'seal.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(entries, stream, indent=2)
    return results


def main():
    step('host toolchain (openssl must resolve before the seal)')
    openssl = p.require_openssl()
    step('preconditions')
    p.require((PACK / 'inspection.json').is_file(),
              'the r10 inspection has not run; run inspect_tv.py first (own light approval)')
    p.require((PACK / 'protected-register.json').is_file(),
              'the fresh protected register is missing; STOP')
    p.require(not (PACK / 'seal.json').exists() and not (PACK / 'offline-results.json').exists(),
              'seal or offline results already exist; offline_checks refuses reruns')
    p.require(not (PACK / 'SPENT').exists() and not (PACK / 'STOP').exists(),
              'debris or consumption happened; STOP')
    for path in PACK.iterdir():
        p.require(not path.name.startswith('LIVE_ARM_'), 'a stage marker pre-exists the seal: ' + path.name)
    for legacy in LEGACY:
        p.require(not (PACK / legacy).exists(), 'legacy module or receipt carried into r10: ' + legacy)
    for name in SHELL_SCRIPTS:
        p.require((PACK / name).is_file(), 'prepare.py has not baked ' + name)

    step('rehearsal rerun (fresh host case results)')
    result = subprocess.run([str(VENV_PY), '-B', str(PACK / 'driver_checks.py')],
                            capture_output=True, cwd=str(REPO))
    p.require(result.returncode == 0, 'the host rehearsal must pass before sealing; output:\n'
              + result.stdout.decode()[-2000:] + result.stderr.decode()[-400:])
    rehearsal = json.loads((PACK / 'rehearsal-results.json').read_text(encoding='utf-8'))
    p.require(rehearsal.get('verdict') == 'PASSED' and not rehearsal.get('failures'),
              'rehearsal results are not a clean pass')

    step('session-layer coverage (staging, closeout, parsing, stage.sh)')
    session = subprocess.run([str(VENV_PY), '-B', str(PACK / 'session_checks.py')],
                             capture_output=True, cwd=str(REPO))
    p.require(session.returncode == 0, 'session-layer coverage failed; output:\n'
              + session.stdout.decode()[-2500:] + session.stderr.decode()[-1200:])
    session_results = json.loads((PACK / 'session-results.json').read_text(encoding='utf-8'))
    p.require(session_results.get('verdict') == 'PASSED' and not session_results.get('failures'),
              'session results are not a clean pass')

    step('prepared artifacts')
    for name, expected in p.ARTIFACT_SHAS.items():
        p.require(p.digest(PACK / name) == expected, 'artifact drift: ' + name)

    step('root-agent build (pinned SDK, offline)')
    build_env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    with tempfile.TemporaryDirectory(prefix='r9-seal-build-') as intermediates:
        command = [str(SDK / 'dotnet.exe'), 'build', str(PACK / 'UepGateAgent.csproj'),
                   '-c', 'Release', '-f', 'netcoreapp3.1',
                   '-p:BaseIntermediateOutputPath=' + str(Path(intermediates) / 'obj') + str(Path('/')),
                   '-p:OutputPath=' + str(PACK / 'build') + str(Path('/'))]
        built = subprocess.run(command, capture_output=True, cwd=str(REPO), env=build_env)
    p.require(built.returncode == 0, 'agent build failed:\n'
              + built.stdout.decode()[-3000:] + built.stderr.decode()[-800:])
    warnings_summary = re.search(r'(\d+) Warning\(s\)', built.stdout.decode()[-4000:])
    p.require(warnings_summary is not None and warnings_summary.group(1) == '0',
              'agent build reported warnings:\n' + built.stdout.decode()[-3000:])
    agent = PACK / 'build/SamsungTvRootAgent.dll'
    p.require(agent.is_file(), 'no SamsungTvRootAgent.dll produced')
    p.require((PACK / 'build/SamsungTvRootAgent.runtimeconfig.json').is_file(),
              'no runtimeconfig produced')
    agent_bytes = agent.read_bytes()
    for name in ('gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh'):
        p.require(name.encode('ascii') in agent_bytes, 'agent does not embed ' + name)

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
        p.require(parsed.returncode == 0, 'bash -n failed: ' + name + ' ' + parsed.stderr.decode()[:300])
    steps = subprocess.run([str(VENV_PY), '-B', '-m', 'ruff', 'check', '--no-cache',
                            '--isolated', '--select', 'F821', str(PACK)],
                           capture_output=True)
    p.require(steps.returncode == 0, 'undefined names survived: ' + steps.stdout.decode()[:1200])

    step('pack integrity gates')
    p.require(p.BOOT is not None and len(p.BOOT) == 36, 'the inspection boot pin is not standing')
    p.require(p.PROOF_SHA is not None and len(p.PROOF_SHA) == 64, 'the inspection proof pin is not standing')
    probe_source = (PACK / 'inspect_tv.py').read_text(encoding='utf-8')
    for required_capture in ("printf 'gate_config=%s\\n'", "printf 'gate_state=%s\\n'",
                             "printf 'module_dir=%s\\n'", "printf 'backup_dir=%s\\n'",
                             "printf 'target_rc_hash='"):
        p.require(required_capture in probe_source,
                  'inspection producer/consumer key drift: missing ' + required_capture)
    install = (PACK / 'gate-install.sh').read_text(encoding='ascii')
    active = (PACK / 'gate-config-active.sh').read_text(encoding='ascii')
    remove = (PACK / 'gate-remove.sh').read_text(encoding='ascii')
    p.require(p.PREV_MANAGER_SHA in install and p.NEW_MANAGER_SHA in install,
              'install lost a manager pin')
    p.require(p.UEP_READONLY_SHA in install and p.UEP_ACTIVE_SHA not in install,
              'install transition surface changed')
    p.require(p.UEP_READONLY_SHA in active and p.UEP_ACTIVE_SHA in active,
              'activation transition surface changed')
    p.require(p.UEP_ACTIVE_SHA in remove and p.UEP_READONLY_SHA not in remove,
              'removal transition surface changed')
    for name, text in (('install', install), ('active', active), ('remove', remove)):
        for line in text.splitlines():
            if '&& test' in line:
                p.require('|| return 1' in line, name + ' non-aborting guard: ' + line)
    # denial.py pins the native control through the packet constant, so the
    # literal hash never appears in its source; ARTIFACT_SHAS ties the constant
    # to the sealed bytes above. Guard the pin mechanism and the exact denial
    # verdict instead of a hard-coded digest.
    denial = (PACK / 'denial.py').read_text(encoding='utf-8')
    for pin in ('import packet as p',
                'p.require(p.digest(p.NATIVE) == p.NATIVE_SHA',
                "MARKER = 'QN90B_UEP_NATIVE_PROBE_OK'",
                'p.require(MARKER not in output',
                "== ['native_exit=126'] and 'Permission denied' in output"):
        p.require(pin in denial, 'denial control pins changed: missing ' + pin)
    p.require('denial.run(sdk, save)' in (PACK / 'disable.py').read_text(encoding='utf-8'),
              'disable stage does not run the denial control')
    for receipt, shape in (
            (p.RECEIPT_ABSENT_BOOT, stage_lib.ABSENT_SUMMARY),
            (p.RECEIPT_READONLY_MANUAL, stage_lib.READONLY_SUMMARY),
            (p.LOG_READONLY.format('manual', p.FINGERPRINT), stage_lib.READONLY_DETAIL),
            (p.RECEIPT_CLEARED_BOOT, stage_lib.CLEARED_SUMMARY),
            (p.LOG_CLEARED, stage_lib.CLEARED_DETAIL)):
        p.require(shape.search(receipt), 'receipt/shape mismatch: ' + receipt)

    step('r10 fix guards (each maps to an independent-review blocker)')
    # B1: the upload contract and stage.sh must carry the module assets.
    for name in ('manager.runtimeconfig.json', 'UepGateHost.dll',
                 'UepGateHost.runtimeconfig.json', 'boot.sh', 'module.json'):
        p.require(name in (PACK / 'sdk.py').read_text(encoding='utf-8'),
                  'upload whitelist lost ' + name)
    stage_sh = (PACK / 'stage.sh').read_text(encoding='ascii')
    p.require('files=(' not in stage_sh, 'stage.sh still uses a hardcoded file list')
    for pin in ('while read -r hash name', 'awk \'{print $2}\' files.sha256'):
        p.require(pin in stage_sh, 'stage.sh is not manifest-driven: missing ' + pin)
    # B2: the transport staging directory is created before any route decision.
    transport = (PACK / 'stage_transport.py').read_text(encoding='utf-8')
    p.require('def ensure_host_dir()' in transport, 'transport staging dir is not pre-created')
    p.require('    ensure_host_dir()\n    manifest_path' in transport,
              'stage_files does not create the transport staging directory')
    # B3: both manager files are out of the pre-install protected baseline.
    p.require(p.TARGET not in p.expected_set() and p.TARGET_RC not in p.expected_set(),
              'protected set still pins a file the install replaces')
    p.require(len(p.expected_set()) == 24, 'post-install protected set is not 24 entries')
    # B4/B5: module capture is keyed per path and the directory is pinned.
    common = (PACK / 'stage_common.py').read_text(encoding='utf-8')
    for key in ('boot_mode=', 'json_mode=', 'host_mode=', 'rc_mode=', 'dir_meta='):
        p.require(key in common, 'module capture lost ' + key)
    p.require("stat -c '%u:%a' \" + ' '.join(paths)" not in common,
              'module capture still uses the unparseable modes form')
    p.require("p.MODULE_DIR_META" in common, 'module directory metadata is not verified')
    # M1: the active stage waits for the boot receipt before requiring the store.
    active_py = (PACK / 'active.py').read_text(encoding='utf-8')
    p.require(active_py.index("module_gate(sdk, 'active'") < active_py.index("'active-post-boot'"),
              'active stage still requires the budget before the gate receipt')
    # M2: temp-name collisions are refused before the first write.
    p.require(install.count('test ! -e "$target.r9-tmp"') == 1
              and install.count('test ! -e "$cfg.r9-tmp"') >= 1,
              'install does not refuse temp collisions before writing')
    p.require(install.index('test ! -e "$target.r9-tmp"') < install.index('mkdir -- "$backup"'),
              'temp-collision refusal sits after the first write')
    # B5: the module directory shape is established and asserted.
    for pin in ("chown '" + p.MODULE_DIR_OWNER + "' \"$mod\"",
                "chmod '" + p.MODULE_DIR_MODE + "' \"$mod\"",
                "\"$(stat -c '%F:%u:%g:%a' -- \"$mod\")\" = '" + p.MODULE_DIR_META + "'"):
        p.require(pin in install, 'install does not establish the module directory shape: ' + pin)
    # M5: removal requires the active-boot budget receipt.
    disable_py = (PACK / 'disable.py').read_text(encoding='utf-8')
    p.require("p.require(st['budget'] == 'present'" in disable_py,
              'disable still accepts an absent budget receipt')

    step('port ledger (every difference from r9 explained)')
    ledger_path = PACK / 'port-from-r9.json'
    p.require(ledger_path.is_file(), 'port-from-r9.json is missing; run port_from_r9.py ledger')
    ledger = json.loads(ledger_path.read_text(encoding='utf-8'))
    p.require(ledger.get('successor_of') == 'qn90b-uep-l4-deploy-20261109-r9',
              'port ledger names the wrong predecessor')
    undocumented = [n for n, e in ledger['entries'].items()
                    if e['status'] in ('delta', 'removed', 'added') and not e.get('reason')]
    p.require(not undocumented, 'undocumented r10 differences: ' + str(undocumented[:6]))
    for name, entry in ledger['entries'].items():
        path = PACK / name
        if entry['status'] == 'carried' and path.is_file():
            p.require(p.digest(path) == entry['sha256'],
                      'carried file drifted from its ledger entry: ' + name)
        if entry['status'] == 'delta' and path.is_file():
            p.require(p.digest(path) == entry['r10'],
                      'delta file changed after the ledger was written: ' + name)
        if entry['status'] == 'added' and path.is_file():
            p.require(p.digest(path) == entry['sha256'],
                      'added file changed after the ledger was written: ' + name)

    step('sealing ' + str(len(SEAL_NAMES)) + ' entries')
    results = seal_packet(openssl, rehearsal, session_results)
    print(json.dumps(results), flush=True)


if __name__ == '__main__':
    main()
