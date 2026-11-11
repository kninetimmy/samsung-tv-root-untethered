"""Host-only driver flows. SDK/root transport is simulated; driver validation and closeout run unchanged."""
import asyncio
import base64
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import activate
import deploy
import dirread
import disable
import offline_checks
import packet as p
import recovery
import s4_cases
import s5s6_cases
import s7_cases
import stage_lib
import watch

SOURCE = p.HERE
BOOTS = ('a1111111-2222-3333-4444-555555555555',
         'b1111111-2222-3333-4444-555555555555',
         'c1111111-2222-3333-4444-555555555555')


class World:
    def __init__(self, directory):
        self.directory = directory
        self.boot_index = 0
        self.epoch = int(datetime(2026, 11, 9, 1, 2, tzinfo=timezone.utc).timestamp())
        self.boot_epoch = self.epoch - 120
        self.config = None
        self.budget = None
        self.flag = p.FINGERPRINT
        self.logs = ''
        self.events = []
        self.probes = []
        self.sdk_count = 0
        self.relay = False
        self.root_closed = False
        self.op_error = None
        self.shutdown_error = False
        self.receipt_missing = False
        self.sdk_error = None
        self.omit_boot_gate = False
        self.waiting_readonly = False
        self.initial = json.loads((SOURCE / 'inspection-r1-predeploy.json').read_text())
        self.append('uep gate (reopen): config absent (enforcing; no action)')

    @property
    def boot(self):
        return BOOTS[self.boot_index]

    def proof(self):
        return ('SELFROOT-PROOF uid=0 gid=0\nBOOT_ID=' + self.boot
                + '\nUid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\n').encode()

    def proof_hash(self):
        return hashlib.sha256(self.proof()).hexdigest()

    def append(self, message):
        stamp = datetime.fromtimestamp(self.epoch, timezone.utc).strftime('%Y-%m-%dT%H:%M:%S')
        self.logs += '[' + stamp + '.1234567Z] ' + message + '\n'

    async def sleep(self, seconds):
        self.epoch += seconds
        if self.waiting_readonly:
            self.waiting_readonly = False
            self.append('uep gate: read-only reopen: enforcing ' + p.FINGERPRINT + ' (zero stores)')
            self.append('uep gate (reopen): read-only: enforcing')

    def reboot(self):
        assert not self.relay, 'driver awaited reboot before removing its recovery relay'
        self.boot_index += 1
        self.epoch += 120
        self.boot_epoch = self.epoch - 30
        self.events.append('reboot')
        if self.config == 'active':
            self.flag = p.CLEARED
            self.budget = 'boot=' + self.boot + ' clear=1 restore=0'
            if not self.omit_boot_gate:
                self.append('uep gate: cleared boot: ' + p.CLEARED + ' (one word, neighbourhood pinned)')
                self.append('uep gate (boot): cleared (boot)')
        else:
            self.flag = p.FINGERPRINT
            self.append('uep gate (boot): config absent (enforcing; no action)')

    def capture(self, command):
        if "printf 'uid='" in command:
            values = {'uid': '901', 'boot': self.boot}
            if "printf 'target_hash='" in command:
                values.update(service='active', target_hash=p.NEW_SHA + '  ' + p.TARGET,
                              proof_hash=self.proof_hash() + '  ' + p.EV + '/selfroot-proof.txt',
                              log_size=str(len(self.logs)), manager_pids='',
                              gate_config='present' if self.config else 'absent',
                              gate_state='present' if self.budget else 'absent', port_config='absent')
            else:
                values.update(ip=self.initial['ip'], mode=self.initial['mode'])
            return '\n'.join(key + '=' + value for key, value in values.items())
        if command.startswith('sha256sum '):
            hashes = dict(p.INHERITED)
            hashes[p.TARGET] = p.NEW_SHA
            hashes[p.EV + '/selfroot-proof.txt'] = self.proof_hash()
            path = '/opt/usr/share/selfroot/bridge.conf'
            hashes[path] = self.initial['pairing_hash'].split()[0]
            return '\n'.join(hashes[path] + '  ' + path for path in command.split()[1:])
        if 'systemctl cat tvroot-bridge.service' in command:
            return self.initial['unit']
        if command == p.tools.STARTUP:
            return self.initial['startup']
        if command == 'systemctl is-active tvroot-bridge.service':
            return 'active'
        if "printf 'epoch='" in command:
            return 'epoch=%d\nuptime=%d 0.0' % (self.epoch, self.epoch - self.boot_epoch)
        if "printf 'boot='" in command:
            self.reboot()
            return 'boot=' + self.boot + '\nservice=active'
        if "printf 'proof='" in command:
            assert r"tr -d '\n'" in command, 'proof capture lost normalization'
            return 'proof=' + base64.b64encode(self.proof()).decode()
        if command.startswith('tail -n '):
            return self.logs
        if command.startswith('tail -c +'):
            cut = int(command.split()[2][1:]) - 1
            return self.logs[cut:]
        if "printf 'log_size='" in command:
            return 'log_size=' + str(len(self.logs))
        if "printf 'meta='" in command:
            return 'meta=0:0:644:1\nlabel=' + p.UEP_CONFIG + ' access="_"'
        if command == 'cat -- ' + p.UEP_CONFIG:
            assert self.config is not None
            return self.config
        if command.startswith('cat -- ' + stage_lib.UEP_STATE):
            return self.budget or 'budget-absent'
        if command.startswith('/usr/bin/dotnet ' + p.FDET_HOME):
            return ('read_words physical=0x208c26c0 page=0x208c2000 offset=0x6c0 words=4\n'
                    'words word=0 ' + self.flag)
        if command.startswith("printf 'receipt="):
            return 'receipt=45845:100001'
        if 'probe_exit=$?' in command:
            code = 42 if self.flag == p.CLEARED else 126
            self.probes.append((self.boot, code))
            payload = activate.MARKER_OK if code == 42 else 'Operation not permitted'
            return payload + '\nnative_exit=' + str(code) + '\nprobe-stage-clean'
        if command.startswith('test ! -e '):
            if p.UEP_CONFIG in command:
                assert self.config is None
            if stage_lib.UEP_STATE in command:
                assert self.budget is None
            return 'plain-absent' if 'plain-absent' in command else 'absent'
        raise AssertionError('unmodelled SDK command: ' + command[:100])


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix='l4-r2-driver-flow-') as temp:
        directory = Path(temp)
        world = World(directory)
        for name in ('deployment-result.json', 'post-deploy-verification.json', 'post-mortem-20261108.md'):
            (directory / name).write_bytes((SOURCE / name).read_bytes())
        (directory / 'seal.json').write_text('{}')
        for marker in p.MARKERS:
            (directory / marker).write_text(p.COMMIT + '\n')

        class SDK:
            def __init__(self, save, port=26103):
                world.sdk_count += 1

            async def present(self):
                return False

            async def connect(self):
                pass

            async def disconnect(self):
                pass

            async def capture(self, command, **kwargs):
                if world.sdk_error is not None:
                    raise world.sdk_error
                return 0, world.capture(command).strip()

        class Connection:
            async def execute(self, command, timeout):
                if world.op_error is not None:
                    raise world.op_error
                if command == 'gate-readonly':
                    assert world.config is None
                    world.config = 'read-only'
                    world.waiting_readonly = True
                    receipt = 'GATE_CONFIG_READONLY_COMPLETE\nGATE_METADATA 0:0:644:1\n'
                elif command == 'gate-active':
                    assert world.config == 'read-only'
                    world.config = 'active'
                    receipt = 'GATE_CONFIG_ACTIVE_COMPLETE\nGATE_METADATA 0:0:644:1\n'
                else:
                    assert command == 'gate-remove:' + world.boot
                    assert world.config == 'active'
                    world.config = None
                    receipt = 'GATE_CONFIG_REMOVED_COMPLETE\nGATE_ABSENT\n'
                return SimpleNamespace(exit_code=0, timed_out=False, stdout=receipt, stderr='')

            async def shutdown(self, timeout):
                if world.shutdown_error:
                    raise OSError('injected root shutdown failure')
                world.root_closed = True
                world.events.append('root-closed')

        async def root_transport(session):
            await session.sdk.connect()
            session.owned_sdk = True
            await session.baseline()
            session.baseline_passed = True
            session.recovery_attempted = True
            session.recovery_receipt = None if world.receipt_missing else {'fixture': True}
            world.relay = True
            world.root_closed = False
            session.connection = Connection()
            await session.run_gate()

        async def stop_relay(sdk, save, receipt):
            assert receipt == {'fixture': True}
            assert world.root_closed, 'relay teardown preceded root shutdown'
            assert world.relay
            world.relay = False
            world.events.append('relay-removed')

        with ExitStack() as patches:
            for owner, name, value in (
                (p, 'HERE', directory), (p, 'BOOT', world.boot),
                (p, 'PROOF_SHA', world.proof_hash()), (p, 'EXPECTED', dict(p.INHERITED)),
                (p.tools, 'local_checks', lambda: None), (deploy, 'INSPECTION', world.initial),
                (dirread.DirRead, 'run', root_transport), (recovery, 'stop', stop_relay),
                (asyncio, 'sleep', world.sleep),
            ):
                patches.enter_context(patch.object(owner, name, value))
            for owner in (dirread, activate, disable, watch, deploy):
                patches.enter_context(patch.object(owner, 'BridgeSDK', SDK))
            yield world


def passed(world, kind):
    return json.loads((world.directory / ('stage-status-' + kind + '.json')).read_text())


def prepare_dirread(world):
    (world.directory / 'stage-status-watch.json').write_text(json.dumps(
        {'stage': 'watch', 'passed': True, 'boot': world.boot}))


def run():
    results = []
    with fixture() as world:
        for driver in (watch, dirread, activate, disable):
            asyncio.run(driver.main())
            assert passed(world, driver.KIND)['passed'] is True
        assert world.probes == [(BOOTS[1], 42), (BOOTS[2], 126)]
        assert world.boot == BOOTS[2] and world.config is None and not world.relay
        assert (world.directory / 'SPENT').is_file()
        assert len(list((world.directory / 'execution/attempts').glob('*.attempt'))) == 4
        assert not any((world.directory / name).exists() for name in p.MARKERS)
        assert world.events.count('relay-removed') == 3
    results.append('complete watch -> read-only -> active -> disable flow, three boot anchors and both probe outcomes')

    for error in (p.Stop('injected gate refusal'), asyncio.CancelledError('injected interruption')):
        with fixture() as world:
            prepare_dirread(world)
            world.op_error = error
            with pytest.raises(type(error)):
                asyncio.run(dirread.main())
            assert (world.directory / 'STOP').is_file()
            assert passed(world, 'dirread')['passed'] is False
            assert not world.relay and world.events == ['root-closed', 'relay-removed']
            count = world.sdk_count
            with pytest.raises(p.Stop):
                asyncio.run(activate.main())
            assert world.sdk_count == count, 'STOP did not prevent SDK construction'
        results.append('refusal/interruption records STOP, removes owned relay after root close, blocks later stages: '
                       + type(error).__name__)

    with fixture() as world:
        prepare_dirread(world)
        world.shutdown_error = True
        with pytest.raises(p.Stop):
            asyncio.run(dirread.main())
        assert world.relay and 'relay-removed' not in world.events
        assert (world.directory / 'STOP').is_file()
    results.append('unverified root shutdown retains the recovery relay and stops the packet')

    with fixture() as world:
        prepare_dirread(world)
        world.receipt_missing = True
        with pytest.raises(p.Stop):
            asyncio.run(dirread.main())
        assert world.relay and 'relay-removed' not in world.events
        receipts = [json.loads(line) for line in (world.directory / 'receipts.jsonl').read_text().splitlines()]
        assert any(recovery.PATH in row.get('cleanup_pending', []) for row in receipts)
    results.append('missing relay ownership proof retains and receipts the exact pending cleanup path')

    for driver, prior in ((watch, ()), (dirread, (watch,)),
                          (activate, (watch, dirread)), (disable, (watch, dirread, activate))):
        with fixture() as world:
            for earlier in prior:
                asyncio.run(earlier.main())
            world.sdk_error = OSError('injected SDK failure')
            with pytest.raises(OSError):
                asyncio.run(driver.main())
            assert (world.directory / 'STOP').is_file()
            assert passed(world, driver.KIND)['passed'] is False
        results.append(driver.KIND + ' records STOP on unexpected SDK failure')

    for driver, prior in ((activate, (watch, dirread)),
                          (disable, (watch, dirread, activate))):
        with fixture() as world:
            for earlier in prior:
                asyncio.run(earlier.main())
            world.op_error = p.Stop('injected gate refusal')
            with pytest.raises(p.Stop):
                asyncio.run(driver.main())
            assert not world.relay and passed(world, driver.KIND)['passed'] is False
            assert world.events[-2:] == ['root-closed', 'relay-removed']
        results.append(driver.KIND + ' removes the owned relay even when its gate operation refuses')

    with fixture() as world:
        asyncio.run(watch.main())
        asyncio.run(dirread.main())
        world.omit_boot_gate = True
        with pytest.raises(p.Stop):
            asyncio.run(activate.main())
        assert world.flag == p.CLEARED and world.config == 'active'
        assert passed(world, 'active')['passed'] is False
        assert world.probes == [] and (world.directory / 'STOP').is_file()
    results.append('cleared flag plus old gate logs cannot substitute for fresh boot-clear evidence')

    with fixture() as world:
        prepare_dirread(world)
        with patch.object(dirread, 'DEADLINE_SECONDS', 0):
            with pytest.raises(p.Stop, match='no confirming read-only launch'):
                asyncio.run(dirread.main())
        assert world.config == 'read-only' and not world.relay
        assert passed(world, 'dirread')['passed'] is False
    results.append('read-only observation timeout leaves read-only config, clean relay and failed status')

    async def no_reboot(old_boot):
        return None

    for driver, prior in ((activate, (watch, dirread)),
                          (disable, (watch, dirread, activate))):
        with fixture() as world:
            for earlier in prior:
                asyncio.run(earlier.main())
            with patch.object(driver, 'await_new_boot', no_reboot):
                with pytest.raises(p.Stop, match='no new boot'):
                    asyncio.run(driver.main())
            assert not world.relay and passed(world, driver.KIND)['passed'] is False
            assert world.config == ('active' if driver is activate else None)
        results.append(driver.KIND + ' reboot timeout records STOP and preserves the explicit config state')

    with fixture() as world:
        (world.directory / 'seal.json').unlink()
        with patch.object(offline_checks, 'PACK', world.directory):
            with pytest.raises(p.Stop, match='seal target missing'):
                offline_checks.seal_packet()
            assert not (world.directory / 'offline-results.json').exists()
            for name in offline_checks.SEAL_NAMES:
                if name == 'offline-results.json':
                    continue
                file = world.directory / name
                if not file.exists():
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text('host-only seal fixture\n')
            report = offline_checks.seal_packet()
            seal = json.loads((world.directory / 'seal.json').read_text())
            assert report['seal_entries'] == len(seal) == len(offline_checks.SEAL_NAMES)
            assert all(p.digest(world.directory / name) == value for name, value in seal.items())
            with pytest.raises(p.Stop):
                offline_checks.seal_packet()
    results.append('first seal hashes the completed report, missing inputs write nothing, replay refuses')

    with patch.object(s7_cases, 'gate_event_assessment', lambda *args, **kwargs: []), \
            patch.object(s7_cases, 'gate_stamp_seconds', lambda *args, **kwargs: 0):
        with pytest.raises(pytest.fail.Exception):
            s7_cases.run()
    results.append('replacing both log validators with no-ops now fails the rejection tests')

    async def no_baseline(self):
        pass

    with patch.object(deploy.Deployment, 'baseline', no_baseline):
        with pytest.raises(AssertionError, match='drift accepted'):
            s4_cases.run()
    with patch.object(stage_lib, 'refuse_if_stopped', lambda: None):
        with pytest.raises(AssertionError, match='STOP file accepted'):
            s5s6_cases.run()
    results.append('disabling baseline or STOP validation now fails their negative tests')
    return results
