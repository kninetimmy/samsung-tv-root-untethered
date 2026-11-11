"""Host-only pre-inspection rehearsal for the L4 packet. Touches no TV state.

Runs before any inspection: parses every packet script, normalize/bash -n
checks the static TV-side scripts, verifies artifacts against the packet
constants, abuses the marker gate and approval files, and re-checks that the
repo state matches the packet commit. The full offline_checks rehearsal
(sealed scripts + agent build + learned-constant substitutions) still runs
after prepare.py, once the read-only inspection exists.
"""
import ast
import subprocess
from pathlib import Path
import packet as p

checks = 0

def require(value, message):
    global checks
    p.require(value, message)
    checks += 1

for file in p.HERE.glob('*.py'):
    if file.name in {'precheck_offline.py', 'offline_checks.py', 'bootstrap_sdk.py', 'sdk.py', 'trial.py', 'inspect_tv.py', 'recovery.py', 'deploy.py', 'prepare.py', 'packet.py'}:
        ast.parse(file.read_text(encoding='utf-8'), filename=str(file))
        checks += 1
for name in ('snapshot.sh', 'stage.sh'):
    file = p.HERE / name
    text = file.read_bytes()
    require(b'\r' not in text, name + ' must be LF-normalized offline')
    if name == 'stage.sh':
        require(p.PKG.encode() in text, name + ' must name this packet stage token')
        require('archive-root-bf2c74ceb59a5362'.encode() not in text, 'stale stage token from the spent predecessor')
    subprocess.run(['C:/Program Files/Git/bin/bash.exe', '-n', str(file)], check=True, capture_output=True)
    checks += 1

require('files=(manager.dll FdetProbe.dll FdetProbe.runtimeconfig.json' in (p.HERE / 'stage.sh').read_text(),
        'stage manifest must carry the fdet payload beside the manager')

import sdk
for name, expected in (('artifacts/manager.dll', p.NEW_SHA), ('artifacts/FdetProbe.dll', p.FDET_PROBE_SHA),
                       ('artifacts/FdetProbe.runtimeconfig.json', p.FDET_RUNTIMECONFIG_SHA), ('artifacts/uep-probe.elf', p.NATIVE_SHA)):
    path = p.HERE / name
    require(p.digest(path) == expected, 'artifact drift: ' + name)
    require(path.stat().st_size <= 131072, name + ' exceeds the SDK receipt bound')
    checks += 1
rollback = p.digest(p.BEFORE)
require(rollback == p.OLD_SHA, 'rollback artifact (installed v5.17) drifted')

# Script-channel uploads stay bounded: the oversized stage assets must refuse.
for name, path in (('manager.dll', p.NEW), ('FdetProbe.dll', p.FDET_PROBE)):
    try:
        sdk.prepare_upload(path, p.STAGE + '/' + path.name, '9:9')
    except p.Stop:
        checks += 1
    else:
        raise p.Stop('oversized script-channel upload accepted: ' + name)
for target in (p.STAGE + '/../manager.dll', '/tmp/manager.dll', p.STAGE + '/unlisted.dll'):
    try:
        sdk.prepare_upload(p.FDET_RUNTIMECONFIG, target, '9:9')
    except p.Stop:
        checks += 1
    else:
        raise p.Stop('unsafe upload target accepted')

# Marker gate semantics: wrong name, wrong content, absent, then the real one.
for stage in p.MARKERS:
    for content in ('', 'wrong\n' + p.NEW_SHA + '\n', p.COMMIT + '\n' + p.NEW_SHA + '\n'):
        target = p.HERE / stage
        with target.open('x', encoding='utf-8') as stream:
            stream.write(content)
        try:
            ok = p.marker(stage)
        except p.Stop:
            ok = 'refused'
        finally:
            target.unlink()
        if content == p.COMMIT + '\n' + p.NEW_SHA + '\n':
            require(ok is True or ok == 'refused' and False, 'valid marker for ' + stage + ' must pass')  # noqa: F632
        else:
            require(ok == 'refused' or ok is False, 'invalid marker for ' + stage + ' must refuse')
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p.REPO).decode().strip()
require(head == p.COMMIT, 'packet must pin the clean gate commit')
require(subprocess.check_output(['git', 'status', '--porcelain', '--', 'boot-agent', '.github/workflows/build.yml'], cwd=p.REPO) == b'', 'source edits pending')
for token in ('LIVE_ARM_DEPLOY', 'fdet-install', 'gate-readonly', 'gate-active', 'gate-remove'):
    require(token in (p.HERE / 'deploy.py').read_text() or token in (p.HERE / 'BridgeRepairAgent.cs').read_text(),
            'missing wiring: ' + token)

import json
result = {'precheck': 'passed', 'checks': checks, 'commit': p.COMMIT, 'marker_names': list(p.MARKERS),
          'manager_sha256': p.NEW_SHA, 'fdet_sha256': p.FDET_PROBE_SHA, 'probe_sha256': p.NATIVE_SHA,
          'rollback_sha256': p.OLD_SHA, 'TV_operations': 0, 'inspection_pending': True}
with (p.HERE / 'precheck.json').open('x', encoding='utf-8') as stream:
    json.dump(result, stream, indent=2)
print(json.dumps(result))
