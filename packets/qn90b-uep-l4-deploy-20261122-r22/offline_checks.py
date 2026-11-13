"""r22 HOST-ONLY SEAL FLOW using inherited inspection and production gate scripts.

Refuses without inspection.json + protected-register.json + a green rehearsal
AND green session/mutation suites; regenerates results/builds during checks and
seals only after every check passes (sealed reruns refuse). No TV operations. The openssl and pinned-SDK
provenance are recorded because the r7 burn was a host-side toolchain gap.

Carries every r14 guard and adds inherited install integrity, pre-attempt relay
reconciliation, independently aborting relay tests and fresh-session cleanup.
"""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r22-pycache-')

import ast
import hashlib
import json
import os
import re
import subprocess
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
import stage_lib

PACK = p.HERE
REPO = p.REPO
VENV_PY = REPO / '.venv/Scripts/python.exe'
SDK = Path(r'C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')

SEAL_NAMES = list(p.SEAL_ENTRIES)
PHASES = []
PY_CHECKED = tuple(n for n in SEAL_NAMES if n.endswith('.py'))
SHELL_SCRIPTS = ('stage.sh', 'snapshot.sh', 'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh')
LEGACY = ('remove.py', 'BridgeRepairAgent.cs', 'BridgeRepairAgent.csproj',
          'port_from_r7.py', 'port-from-r7.json', 'port_from_r8.py', 'port-from-r8.json',
          'port_from_r9.py', 'port-from-r9.json', 'port_from_r10.py', 'port-from-r10.json',
          'port_from_r11.py', 'port-from-r11.json', 'port_from_r12.py', 'port-from-r12.json',
          'gate-readonly.sh', 'r6-stage-status-dirread.json', 'r7-seal.json')


def step(text):
    PHASES.append(text)
    print('offline-checks:', text, flush=True)


def seal_packet(openssl, rehearsal, session_results, mutation_results, authoring_results, build_record):
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
        'boot': p.CERTIFY_BOOT, 'proof': p.CERTIFY_PROOF,
        'protected_files': len(p.expected_set()), 'TV_operations': 0,
        'stages': list(p.MARKERS),
        'artifact_shas': p.ARTIFACT_SHAS,
        'source_commit': p.COMMIT, 'source_sha256': p.SOURCE_SHA, 'source_roots': p.SOURCE_ROOTS,
        'rehearsal': rehearsal,
        'session': session_results,
        'mutation': {key: mutation_results[key] for key in
                      ('mutants', 'killed', 'cases_exercised', 'cases_killed', 'counting', 'survived', 'verdict')},
        'budget_writer_residual': p.BUDGET_WRITER_RESIDUAL,
        'authoring': authoring_results,
        'build': build_record,
        'inherited_install_sha256': p.INHERITED_INSTALL_SHA,
        'stage_2_boot': json.loads((PACK / 'stage-status-install.json').read_text())['fresh_boot'],
        'stage_1': 'historical only; every gate entrypoint refused in r22',
        'r16': R16_RESULTS,
        'r21': R21_RESULTS,
        'r17_backup_certification': 'directory metadata only; creation hashes evidenced by gate-install.sh:65-71 GATE_BACKUP_COMPLETE',
        'relay_standalone': RELAY_RESULTS,
        'denial_managed': DENIAL_BUILD,
        'skipped': 0,
        'offline_passed_phases': len(PHASES), 'offline_failed_phases': 0,
    }
    with (PACK / 'offline-results.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(results, stream, indent=2)
    entries['offline-results.json'] = p.digest(PACK / 'offline-results.json')
    with (PACK / 'seal.json').open('x', encoding='utf-8', newline='\n') as stream:
        json.dump(entries, stream, indent=2)
    return results


def build_denial():
    env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    version = subprocess.check_output([str(SDK / 'dotnet.exe'), '--version'], env=env).decode().strip()
    p.require(version == '3.1.426', 'wrong pinned SDK: ' + version)
    builds = []
    with tempfile.TemporaryDirectory(prefix='r16-denial-build-') as temp:
        for name in ('DenialRunner', 'DenialSelfTest', 'selftest'):
            p.make_private_directory(Path(temp) / name)
        for name in ('DenialRunner', 'DenialSelfTest'):
            p.make_private_directory(Path(temp) / name / 'obj')
        for project in ('DenialRunner', 'DenialSelfTest'):
            output = PACK / 'build' if project == 'DenialRunner' else Path(temp) / 'selftest'
            command = [str(SDK / 'dotnet.exe'), 'build', str(PACK / (project + '.csproj')),
                       '-c', 'Release', '-f', 'netcoreapp3.1',
                       '-p:BaseIntermediateOutputPath=' + str(Path(temp) / project / 'obj') + os.sep,
                       '-p:OutputPath=' + str(output) + os.sep]
            built = subprocess.run(command, capture_output=True, cwd=str(REPO), env=env)
            text = built.stdout.decode() + built.stderr.decode()
            warnings = re.search(r'(\d+) Warning\(s\)', text)
            p.require(built.returncode == 0 and warnings is not None and warnings[1] == '0',
                      project + ' build failed or warned:\n' + text[-4000:])
            builds.append({'command': command, 'exit': 0, 'warnings': 0, 'stdout': text})
        tested = subprocess.run([str(SDK / 'dotnet.exe'), str(Path(temp) / 'selftest/DenialSelfTest.dll')],
                                capture_output=True, env=env, cwd=str(REPO))
        p.require(tested.returncode == 0, 'managed denial self-test failed:\n' + tested.stdout.decode() + tested.stderr.decode())
        selftest = json.loads(tested.stdout.decode())
        capture_cases = ['good', 'pre-empty', 'open', 'restrict', 'identity', 'group', 'smack', 'boot',
            'pre-epipe', 'post-epipe', 'post-einval', 'post-errno', 'baseline-gap', 'middle-gap', 'pre-gap',
            'post-order', 'pre-order', 'suppression', 'malformed', 'oversize', 'pre-record-bound', 'post-record-bound',
            'pre-byte-bound', 'post-byte-bound', 'pre-time', 'post-time', 'close', 'profile-drift',
            'flags', 'dictionary', 'priority', 'raw-exact', 'raw-combined-over', 'utf8',
            'pre-malformed', 'pre-utf8', 'pre-oversize', 'uid', 'gid', 'zero-cap', 'system-label',
            'post-cap-drift', 'post-smack-drift']
        p.require(selftest == dict(passed=50, failed=0, skipped=0, capture_cases=capture_cases),
                  'managed self-test named set is incomplete')
    return {'SDK': version, 'DOTNET_MULTILEVEL_LOOKUP': '0', 'builds': builds, 'selftest': selftest}


def main():
    global R16_RESULTS, R21_RESULTS, RELAY_RESULTS, DENIAL_BUILD
    stage_lib.require_authoring_pin()
    step('host toolchain (openssl must resolve before the seal)')
    openssl = p.require_openssl()
    step('preconditions')
    for directory in (PACK, PACK / 'evidence', PACK / 'build', PACK / 'artifacts', PACK / 'module'):
        p.private_acl(directory)
    source = json.loads((PACK / 'evidence/source-digests.json').read_text(encoding='utf-8'))
    p.require(source['source_commit'] == p.COMMIT and source['source_sha256'] == p.SOURCE_SHA
              and source['source_roots'] == list(p.SOURCE_ROOTS) and source['files'] == p.source_manifest(),
              'source provenance manifest differs from authoring inputs')
    p.require((PACK / 'inspection.json').is_file(),
              'the digest-carried historical inspection is missing; refuse')
    p.require((PACK / 'protected-register.json').is_file(),
              'the fresh protected register is missing; STOP')
    p.require(not (PACK / 'seal.json').exists() and not (PACK / 'offline-results.json').exists(),
              'seal or offline results already exist; offline_checks refuses reruns')
    p.require(not (PACK / 'SPENT').exists() and not (PACK / 'STOP').exists(),
              'debris or consumption happened; STOP')
    p.require(not (PACK / 'execution').exists() and not (PACK / 'execution').is_symlink(),
              'execution tree pre-exists offline authoring; refuse')
    for path in PACK.iterdir():
        p.require(not path.name.startswith('LIVE_ARM_'), 'a stage marker pre-exists the seal: ' + path.name)
    for legacy in LEGACY:
        p.require(not (PACK / legacy).exists(), 'legacy module or receipt carried into r14: ' + legacy)
    for name in SHELL_SCRIPTS:
        p.require((PACK / name).is_file(), 'prepare.py has not baked ' + name)

    step('authoring suite (carried bake, receipt ground truth, 0-warning pinned build)')
    authoring = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'authoring_checks.py')],
                               capture_output=True, cwd=str(REPO))
    p.require(authoring.returncode == 0, 'authoring checks failed:\n'
              + authoring.stdout.decode()[-2000:] + authoring.stderr.decode()[-1000:])
    authoring_results = json.loads(authoring.stdout.decode())
    p.require(authoring_results.get('warnings') == 0, 'authoring warnings are not zero')
    p.require(p.digest(PACK / 'stage-status-install.json') == p.INHERITED_INSTALL_SHA,
              'inherited install evidence digest changed')

    step('direct-exec helper and actual refused-before-exec self-tests (pinned SDK)')
    DENIAL_BUILD = build_denial()

    step('inherited cases plus r20 identity, diagnostics, exec, source, inventory and privacy contracts')
    extra = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'r16_checks.py')],
                           capture_output=True, cwd=str(REPO))
    p.require(extra.returncode == 0, 'r16 checks failed:\n' + extra.stdout.decode()[-2000:] + extra.stderr.decode()[-3000:])
    R16_RESULTS = json.loads((PACK / 'r16-results.json').read_text())
    p.require(R16_RESULTS['passed'] == 192 and len(set(R16_RESULTS['cases'])) == 192
              and R16_RESULTS['failed'] == 0 and R16_RESULTS['skipped'] == 0,
               'inherited+r20 suite not clean or incomplete')
    p.require({'kernel_endpoint_preserving_loss', 'kernel_middle_gap', 'denial_good', 'kernel_duplicate',
               'kernel_size_is_diagnostic', 'tidy-composite-lf', 'tidy-wrong-name', 'transport-overflow',
                'transport-limit', 'transport-cancel', 'transport-close', 'r19-privacy-root', 'r19-privacy-evidence',
                'exec-shape-schema', 'exec-shape-timeout', 'exec-shape-stdout', 'exec-shape-stderr',
                'r20-tidy-privacy-root', 'r20-tidy-privacy-evidence', 'authoring-stale-pin',
                'source-digest-unrelated', 'source-preflight-certify', 'r19-tidy-receipt'}
               <= set(R16_RESULTS['cases']), 'required named r20 regressions did not run')

    step('standalone relay suite using resolved rehearsal TEMP')
    relay = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'relay_checks.py')],
                           capture_output=True, cwd=str(REPO))
    p.require(relay.returncode == 0, 'relay checks failed:\n' + relay.stdout.decode()[-1000:] + relay.stderr.decode()[-2000:])
    RELAY_RESULTS = json.loads(relay.stdout.decode())
    p.require(RELAY_RESULTS.get('passed') == 36, 'relay suite incomplete')

    step('r21 isolated poisoned bytecode, refusal/resumption and encoded digest; two consecutive rounds')
    extra = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'r21_checks.py')],
                           capture_output=True, cwd=str(REPO))
    p.require(extra.returncode == 0, 'r21 checks failed:\n' + extra.stdout.decode()[-2000:] + extra.stderr.decode()[-3000:])
    R21_RESULTS = json.loads((PACK / 'r21-results.json').read_text())
    p.require(R21_RESULTS['passed'] == 36 and R21_RESULTS['failed'] == R21_RESULTS['skipped'] == 0
              and len(R21_RESULTS['rounds']) == 2 and R21_RESULTS['rounds'][0] == R21_RESULTS['rounds'][1]
              and len(set(R21_RESULTS['rounds'][0])) == 18
              and {'case-registration', 'packet-bytecode', 'refusal-acl'} <= set(R21_RESULTS['rounds'][0])
              and R21_RESULTS['real_source_caches_absent'] is True,
              'r21 suite did not pass two complete rounds')

    step('rehearsal rerun (fresh host case results)')
    result = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'driver_checks.py')],
                            capture_output=True, cwd=str(REPO))
    p.require(result.returncode == 0, 'the host rehearsal must pass before sealing; output:\n'
              + result.stdout.decode()[-2000:] + result.stderr.decode()[-400:])
    rehearsal = json.loads((PACK / 'rehearsal-results.json').read_text(encoding='utf-8'))
    p.require(rehearsal.get('verdict') == 'PASSED' and not rehearsal.get('failures'),
              'rehearsal results are not a clean pass')

    step('session-layer coverage (staging, closeout, parsing, stage.sh)')
    session = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'session_checks.py')],
                             capture_output=True, cwd=str(REPO))
    p.require(session.returncode == 0, 'session-layer coverage failed; output:\n'
              + session.stdout.decode()[-2500:] + session.stderr.decode()[-1200:])
    session_results = json.loads((PACK / 'session-results.json').read_text(encoding='utf-8'))
    p.require(session_results.get('verdict') == 'PASSED' and not session_results.get('failures'),
              'session results are not a clean pass')
    p.require(session_results.get('passed') == 73 and len(session_results['cases']) == 73
              and all(case['verdict'] == 'passed' for case in session_results['cases']),
              'complete inherited 73-case session catalog did not pass')

    step('mutation coverage (each case must kill its defect)')
    mutation = subprocess.run([str(VENV_PY), '-B', '-u', str(PACK / 'mutation_checks.py')],
                              capture_output=True, cwd=str(REPO))
    p.require(mutation.returncode == 0, 'mutation coverage failed; output:\n'
              + mutation.stdout.decode()[-2500:] + mutation.stderr.decode()[-1200:])
    mutation_results = json.loads((PACK / 'mutation-results.json').read_text(encoding='utf-8'))
    p.require(mutation_results.get('verdict') == 'PASSED'
              and not mutation_results.get('survived'), 'mutation results are not a clean pass')
    import mutation_checks
    catalog = mutation_checks.MUTANTS
    p.require([case['name'] for case in mutation_results['cases']] == [row[0] for row in catalog],
              'mutation results do not match the entire named catalog')
    for row, case in zip(catalog, mutation_results['cases']):
        name, filename, old, new, runner, reason, expected = row
        source = (PACK / filename).read_bytes().decode('utf-8')
        p.require(old in source, 'restored mutant source missing: ' + name)
        transformed = source.replace(old, new).encode('utf-8')
        expected_sha = hashlib.sha256(filename.encode() + b'\0' + transformed).hexdigest()
        p.require(case['mutation_sha256'] == expected_sha and case['runner'] == runner
                  and case['expected'] == expected and case['killed'] is True,
                  'mutation was omitted, miscounted or failed: ' + name)
    distinct = {case['mutation_sha256'] for case in mutation_results['cases']}
    p.require(mutation_results['cases_exercised'] == mutation_results['cases_killed'] == len(catalog)
              and mutation_results['mutants'] == mutation_results['killed'] == len(distinct),
              'mutation totals differ from exact cases/distinct transformations; no minima accepted')

    step('prepared artifacts')
    for name, expected in p.ARTIFACT_SHAS.items():
        p.require(p.digest(PACK / name) == expected, 'artifact drift: ' + name)
    for name, expected in (('artifacts/v518-manager.dll', p.PREV_MANAGER_SHA),
                           ('artifacts/v518-manager.runtimeconfig.json', p.PREV_MANAGER_RC_SHA)):
        p.require(p.digest(PACK / name) == expected, 'r8 host fixture drift: ' + name)

    step('root-agent build (pinned SDK, offline)')
    build_env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(SDK))
    with tempfile.TemporaryDirectory(prefix='r14-seal-build-') as intermediates:
        p.make_private_directory(Path(intermediates) / 'obj')
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
    build_record = {'command': command, 'exit': built.returncode, 'warnings': 0,
                    'DOTNET_MULTILEVEL_LOOKUP': '0',
                    'stdout': built.stdout.decode(), 'stderr': built.stderr.decode()}
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
                            '--isolated', '--target-version', 'py312', '--select', 'F821', str(PACK)],
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
                "result['errno'] in (1, 13)", 'native_exit=None', 'assess_kernel(after, canonical',
                'kernel-capture-completeness-unproved', 'kernel-sequence-gap', 'kernel-capture-raw-bound',
                "result['native_exit'] is None"):
        p.require(pin in denial, 'denial control pins changed: missing ' + pin)
    p.require('denial.run(sdk, save)' in (PACK / 'certify.py').read_text(encoding='utf-8'),
                'certification stage does not run the denial control')
    p.require(denial.count("await sdk.capture(execute, evidence_label='denial-evidence')") == 1
              and denial.count('after = kernel_log(output.strip(), save)') == 1
              and 'dmesg |' not in denial, 'denial must use one combined cursor/exec request; no dmesg authority')
    runner = (PACK / 'DenialRunner.cs').read_text(encoding='utf-8')
    p.require(runner.count('code = Attempt(start, result)') == 1
              and 'preBytes + postBytes > ByteLimit' in runner and 'ByteLimit / 2' not in runner,
              'single attempt or combined raw bound changed')
    p.require('kernel-capture-transport-bound' in (PACK / 'sdk.py').read_text(encoding='utf-8'),
              'encoded transport overflow lost its distinct named refusal')
    clause = next(line for line in (PACK / 'evidence/r19-proposal.md').read_text(encoding='utf-8').splitlines()
                  if line.startswith('> Denial certification must refuse'))
    p.require(clause in (PACK / 'PLAN.md').read_text(encoding='utf-8'), 'owner-accepted task52 clause is not verbatim')
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

    step('r11 fix guards (second independent review)')
    # B1: the host's overwrite-before-rename temp path is refused everywhere.
    for name, text in (('install', install), ('active', active)):
        for pin in ('test ! -e "$state.tmp"', 'test ! -L "$state.tmp"'):
            p.require(pin in text, name + ' does not refuse the budget temp path')
    p.require("out['state_tmp'] == 'absent'" in common,
              'state() does not refuse a present budget temp path')
    p.require('state_tmp=' in common, 'state() does not capture the budget temp path')
    # M2: a final manifest row without a newline is still verified.
    p.require(stage_sh.count('while read -r hash name || test -n "$hash"; do') == 2,
              'stage.sh manifest loops still skip an unterminated final row')
    # M3: removal requires the receipt at the root boundary, not only in Python.
    p.require('test -e "$state"' in remove, 'gate-remove.sh does not require the budget receipt')
    # m1: a nonzero module exit cannot satisfy the module-gate wait.
    p.require('uep gate module exit=0' in common,
              'module_gate does not require a zero module exit')

    step('r12 fixes carried (third independent review)')
    # B1: the writer's real metadata is accepted; no 0644 state-mode equality.
    p.require("test \"$(stat -c '%F:%u:%g:%a:%h' -- \"$state\")\" = 'regular file:0:0:644:1'"
              not in remove,
              'gate-remove.sh still pins a state mode the writer does not promise')
    p.require("test \"$(stat -c '%F:%u:%g:%h' -- \"$state\")\" = 'regular file:0:0:1'"
              in remove, 'gate-remove.sh does not check the writer-shaped state file')
    p.require('current_boot=$(cat /proc/sys/kernel/random/boot_id)' in remove,
              'gate-remove.sh does not read the current boot id')
    # M2: the budget-temp pre-check is a residual, not a write guarantee.
    p.require('task 40' in p.BUDGET_WRITER_RESIDUAL
              and 'exclusive-create' in p.BUDGET_WRITER_RESIDUAL.lower(),
              'the budget-writer residual is not recorded')
    plan = (PACK / 'PLAN.md').read_text(encoding='utf-8')
    p.require('owner-accepted residual' in plan and 'v5.20' in plan,
              'PLAN does not record the owner-accepted budget-writer residual')
    # m2: PLAN uses the boot-scoped module log and marks display as owner-visual.
    p.require('module-uep-gate.log' in plan,
              'PLAN does not name the boot-scoped module log')
    p.require('driver reads module-uep-gate.log' in plan,
              'PLAN still claims the runner modules.log is read')
    p.require('owner visual' in plan,
              'PLAN still implies the driver performs the display check')

    step('r13 fixes carried (fourth independent review)')
    # minor: the removal receipt is a byte-exact hash of the current-boot line.
    p.require("receipt_sha=$(printf 'boot=%s clear=1 restore=0\\n' \"$current_boot\" | sha256sum)"
              in remove, 'gate-remove.sh does not hash the expected receipt bytes')
    p.require('test "$(hash "$state")" = "${receipt_sha%% *}"' in remove,
              'gate-remove.sh does not compare the state file by digest')
    p.require('wc -l < "$state"' not in remove and 'cat -- "$state"' not in remove,
              'gate-remove.sh still uses the non-byte-exact wc/cat check')
    # major: a partial first log is polled; duplicate/nonzero exit is terminal.
    p.require('p.require(len(exits) <= 1,' in common,
              'module_gate does not reject a duplicated exit immediately')
    p.require('if complete and exits and exit_complete:' in common,
              'module_gate does not wait for both the shapes and the exit')
    p.require('receipt or exit is missing' in common,
              'module_gate does not require the exit at the end of the poll')
    p.require('len(exits) == 1' not in common,
              'module_gate still STOPs on the first missing exit line')
    p.require(mutation_results.get('killed') == mutation_results.get('mutants')
              and all(item.get('expected') and item.get('killed')
                      for item in mutation_results.get('cases', [])),
              'the mutation harness did not kill every defect with its intended assertion')

    step('r14 fix guards (fifth independent review)')
    p.require('ends_with_newline = raw.endswith' in common,
              'module_gate does not keep the raw trailing-newline signal')
    p.require('exit_complete = (exits[0] is not lines[-1]) or ends_with_newline' in common,
              'module_gate does not distinguish a partial exit suffix from a complete one')
    p.require("uep gate(?: \\([^)]+\\))? EXCEPTION" in common,
              'module_gate does not match the host\'s real exception format')
    mutation_text = (PACK / 'mutation_checks.py').read_text(encoding='utf-8')
    p.require('exception = outcome.exception' in mutation_text,
               'the mutation harness does not consume the actual terminal exception')
    p.require("'terminal': terminal" in mutation_text,
              'the mutation harness does not record the terminal line')
    bad_terminal = [item.get('name') for item in mutation_results.get('cases', [])
                    if not item.get('killed')
                     or item.get('exception_type') not in ('manager_tools.Stop', 'builtins.AssertionError')
                     or item.get('expected', '').lower() not in item.get('exception_message', '').lower()]
    p.require(not bad_terminal,
              'mutants did not match on the terminal line: ' + str(bad_terminal[:4]))
    p.require(mutation_results.get('killed') == mutation_results.get('mutants'),
              'the mutation harness did not kill every r14 defect')

    step('remove only the empty host session fixture parent; refuse runtime evidence')
    execution = PACK / 'execution'
    if execution.exists() or execution.is_symlink():
        p.require(not execution.is_symlink() and execution.is_dir()
                  and not list(execution.iterdir()),
                  'host session fixture left non-empty or redirected execution tree; refuse')
        execution.rmdir()

    step('inherited relay gates and exhaustive r21 -> r22 ledger; r16-r21 immutable')
    stage_lib.require_authoring_pin()  # HEAD/source must still match immediately before sealing.
    import port_from_r15
    port_from_r15.ledger()
    port_from_r15.verify()
    p.require('await prerequisites()' in active_py and 'await prerequisites()' in disable_py,
              'remaining stages lost their asynchronous relay prerequisites')
    for text in (active_py, disable_py):
        p.require(text.index('await prerequisites()') < text.index('attempt.take()'),
                  'relay prerequisites must run before the attempt')

    step('sealing ' + str(len(SEAL_NAMES)) + ' entries')
    results = seal_packet(openssl, rehearsal, session_results, mutation_results,
                          authoring_results, build_record)
    print(json.dumps(results), flush=True)


if __name__ == '__main__':
    main()
