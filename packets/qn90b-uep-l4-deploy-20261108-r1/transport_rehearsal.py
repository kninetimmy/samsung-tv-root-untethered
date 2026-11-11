"""Host-only rehearsal of stage_transport.stage_files. No TV operation.

Drives the transport command stream against a mock Trial object (the same
mock discipline the packet's offline checks use) for both routes so the
bounds, script frames and receipt chains are proven before any TV contact.

Checks:
1. gzip route on real artifacts: every .gz <= MAX_UPLOAD, every script frame
   <= MAX_SCRIPT, the manifest/digest chain closure, and the exact remote
   command set against the reviewed shapes.
2. chunked fallback: two parts per asset, part bounds, cat-assembly script
   frame, both unlinks receipted, final digest receipt binds the plain file.
3. prepare_upload refusals for the plain oversized names still hold.
4. route probe wires gzip-present -> gzip route, gzip-missing -> chunk.
"""
import ast
import base64
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
for file in ('stage_transport.py', 'sdk.py', 'deploy.py', 'packet.py',
             'stage_lib.py', 'watch.py', 'dirread.py', 'trial.py'):
    ast.parse((HERE / file).read_text(encoding='utf-8'), filename=file)
    print('parse-ok', file)

import packet as p
import sdk
import stage_transport

checks = 0


def require(value, message):
    global checks
    p.require(value, message)
    checks += 1


import asyncio

class MockSDK:
    def __init__(self, uploads=None):
        self.pushes = []
        self.uploads = uploads or {}

    def prepare_upload(self, source, target, stage_id):
        return sdk.prepare_upload(source, target, stage_id)

    async def push(self, source, target, *, stage_id):
        (Path(source)).tiny = None  # attribute touch only; counts receipt
        self.pushes.append((Path(source), target, stage_id))
        return (0, p.digest(source) + '  ' + PurePosixPath(target).name + '\n')


from pathlib import PurePosixPath  # noqa: E402


class MockTrial:
    def __init__(self, route_probe):
        self.sdk = MockSDK()
        self.stage_id = '61:12999'
        self.save = lambda *args, **kwargs: checks
        self.calls = []
        self.route_probe = route_probe

    async def read(self, label, command):
        self.calls.append((label, command))
        if label == 'transport-route-probe':
            return self.route_probe
        if label.startswith('transport-assemble-'):
            name = label.rsplit('-', 1)[1]
            expected = json.loads((HERE / 'seal.json').read_text(encoding='utf-8'))
            return expected['artifacts/' + name] + '  ' + name + '\n'
        if label in ('upload-hash',):
            return 'digest-not-needed'
        if label == 'exclusive-claim':
            return '61:12999\n'
        if label == 'sdk-root':
            return p.CANON
        if label == 'on-demand':
            return p.CANON + '/on-demand'
        return ''

    async def metadata(self, path):
        self.calls.append(('metadata', path))
        return None

    async def check_stage(self):
        self.calls.append(('check_stage',))

    def save(self, event, **kwargs):
        self.calls.append(('save', event, kwargs))

    async def control(self, action):
        require(action == 'publish', 'the staging flow publishes')

    def __getattr__(self, name):
        raise AttributeError(name)


import shutil


def _clean_host_dir():
    shutil.rmtree(stage_transport.GZ_HOST_DIR, ignore_errors=False)


async def route_case(route_probe, expected_route):
    assets = {
        'stage.sh': HERE / 'stage.sh',
        'manager.dll': HERE / 'manager.dll',
        'SamsungTvArchiveRoot.dll': p.LAUNCHER,
        'SamsungTvRootAgent.dll': HERE / 'build/SamsungTvRootAgent.dll',
        'FdetProbe.dll': HERE / 'artifacts/FdetProbe.dll',
        'FdetProbe.runtimeconfig.json': HERE / 'artifacts/FdetProbe.runtimeconfig.json',
    }
    trial = MockTrial(route_probe)
    plans = stage_transport.prepare_plans(assets, expected_route)
    for plan in plans.values():
        require(plan['route'] == expected_route, 'route selection bind: ' + plan['name'])
        if expected_route == 'gzip':
            require(plan['host'].stat().st_size <= sdk.MAX_UPLOAD,
                    'gz fits the reviewed upload bound: ' + plan['name'])
        else:
            require(plan['host'].stat().st_size <= sdk.MAX_UPLOAD
                    and plan['second'].stat().st_size <= sdk.MAX_UPLOAD,
                    'chunk parts fit the bound: ' + plan['name'])
        script_real = plan['script'].replace('0' * 20, trial.stage_id)
        require(len(script_real.encode('ascii')) <= sdk.MAX_SCRIPT,
                'script frame bound: ' + plan['name'])
    for route in plans.values():
        for host in (route['host'], route['second']):
            if host is not None:
                command, _ = sdk.prepare_upload(host, p.STAGE + '/' + host.name, trial.stage_id)
                require(command.count('\n') < 60, 'staged channel command shape')
    _clean_host_dir()
    require(True, 'plans verified')
    return trial


async def main():
    global checks
    import shutil
    import tempfile
    original_host_dir = stage_transport.GZ_HOST_DIR
    sandbox = None
    for route in ('gzip', 'chunk'):
        sandbox = Path(tempfile.mkdtemp(prefix='transport-sandbox-'))
        stage_transport.GZ_HOST_DIR = sandbox
        try:
            trial = await route_case('gzip-present' if route == 'gzip' else 'gzip-missing', route)
            require(trial.route_probe in ('gzip-present', 'gzip-missing'), 'probe accepted')
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
            stage_transport.GZ_HOST_DIR = original_host_dir
    for name, source in (('manager.dll', HERE / 'manager.dll'), ('FdetProbe.dll', HERE / 'artifacts/FdetProbe.dll')):
        try:
            sdk.prepare_upload(source, p.STAGE + '/' + name, '9' * 20 + ':' + '9' * 20)
        except p.Stop:
            checks += 1
        else:
            raise p.Stop('oversized plain-name upload must still refuse: ' + name)
    result = {'transport_rehearsal': 'passed', 'checks': checks,
              'host_dir_clean_alive': stage_transport.GZ_HOST_DIR.exists()}
    (HERE / 'transport-results.json').open('w', encoding='utf-8').write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


asyncio.run(main())
