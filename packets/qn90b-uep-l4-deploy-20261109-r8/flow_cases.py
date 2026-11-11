"""Host-only r8 driver flows + removal-script transitions.

SDK/root transport is simulated; driver validation and closeout run unchanged.
The removal script runs against the real Git-Bash shim (true hashes, real
rm/symlinks, modelled uid/mode/links/smack).
"""
import asyncio
import base64
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import deploy
import driver_shim
import offline_checks
import packet as p
import recovery
import remove
import stage_lib

SOURCE = p.HERE
BOOTS = ('a1111111-2222-3333-4444-555555555555',
         'b1111111-2222-3333-4444-555555555555',
         'c1111111-2222-3333-4444-555555555555')


# ---------------------------------------------------------------------------
# Part 1: the baked gate-remove.sh under the real shell shim.
# ---------------------------------------------------------------------------
# One composite bash run per case: shim + stage identity + setup fragment +
# (optional agent prefix) + dot-sourced baked script + labelled state checks.
# Nothing persists across bash -c invocations, so a case's setup and its
# probes must run in the same shell, and every case gets a fresh layout.

def _rehearsal():    # one fresh layout + baked script per case
    lay = driver_shim.new_layout()
    baked = driver_shim.bake_for(lay)
    script_path = lay['tmp'] / 'gate-remove.sh'
    script_path.write_text(baked['gate-remove.sh'], encoding='ascii', newline='\n')
    return lay, script_path


def _readonly_setup(lay, content='read-only', owner='0:0', mode='0644'):
    return ("printf '%s\\n' " + content + " > " + lay['cfg'] + '\n'
            'chown ' + owner + ' ' + lay['cfg'] + '; chmod ' + mode + ' ' + lay['cfg'] + '\n'
            'chsmack -a _ ' + lay['cfg'] + '\n')


def _readonly_setup_for(content='read-only', owner='0:0', mode='0644'):
    def factory(lay):
        return _readonly_setup(lay, content=content, owner=owner, mode=mode)
    return factory


CHECKS_PRESENT = ('post_a', 'test -e CFG && echo PRESENT || echo ABSENT')
CHECKS_CONTENT = ('post_a2', 'cat CFG 2>/dev/null || echo ABSENT')
CHECKS_LINK = ('post_a3', 'test -L CFG && echo SYMLINK || echo PLAIN')
CHECKS_TEMP = ('post_a4', 'test -e CFG.prepared && echo TEMP || echo NO_TEMP')


def run_shell_case(lay, script_path, setup=None, boot=None, prefix=None, checks=()):
    """Compose and run one full rehearsal case; return (result, outputs).

    lay/script_path : the case's own layout and baked script (one per case).
    setup           : shell lines executed BEFORE the baked script (must
                      create exactly the state under test); None = the config
                      does not exist.
    prefix          : text prepended to the dot-source (the agent's boot
                      assertion).
    checks          : (key, expression) pairs emitting KEY=<value> after the
                      body; like the TV-side verification captures, they run
                      regardless of the body's exit status.
    """
    pieces = [driver_shim.shim_text(boot if boot is not None else driver_shim.REHEARSAL_BOOT),
              driver_shim.stage_prelude(lay)]
    if setup:
        pieces.append(setup)
    # The body runs in a SUBSHELL (like the agent's own /bin/sh -c execute):
    # its exit code and captured stdout are receipted without terminating the
    # parent shell, so the labelled state checks always run afterwards.
    body = ((prefix + ' ') if prefix else '') + '. ' + driver_shim.to_posix(script_path)
    outfile = lay['tmp'] / 'case-body-out'
    pieces.append('( ' + body + ' ) > ' + driver_shim.to_posix(outfile))
    pieces.append("printf 'case_rc=%s\\n' \"$?\"")
    pieces.append("printf 'completed=%s\\n' \"$( base64 < " + driver_shim.to_posix(outfile)
                  + " | tr -d '\\n' )\"")
    for key, expression in checks:
        pieces.append("printf '%s=%s\\n' '" + key + "' \"$( " + expression + " )\"")
    result = driver_shim.bash('\n'.join(pieces) + '\n')
    outputs = {}
    for line in result.stdout.splitlines():
        key, sep, value = line.partition('=')
        if sep:
            outputs[key] = value
    if outputs.get('completed'):
        outputs['completed'] = base64.b64decode(outputs['completed']).decode('utf-8', 'replace')
    expected_keys = ('case_rc', 'completed') + tuple(key for key, _ in checks)
    p.require(all(key in outputs for key in expected_keys),
              'a rehearsal case stopped emitting labels; improper composition')
    p.require(result.returncode == 0, 'the rehearsal wrapper itself failed')
    return outputs['case_rc'], outputs


def _shell_cases():
    labels = []
    template = {'post_a': CHECKS_PRESENT, 'post_a2': CHECKS_CONTENT,
                'post_a3': CHECKS_LINK, 'post_a4': CHECKS_TEMP}

    def checks_for(keys, lay):
        return tuple((template[k][0], template[k][1].replace('CFG', lay['cfg'])) for k in keys)

    def case(setup_lines, keys=('post_a',), boot=None, prefix=None):
        lay, script_path = _rehearsal()
        try:
            setup = setup_lines(lay) if callable(setup_lines) else setup_lines
            return run_shell_case(lay, script_path, setup=setup, boot=boot,
                                  prefix=prefix, checks=checks_for(keys, lay))
        finally:
            # One layout per case; the assertions read captured stdout, so the
            # tree can go as soon as its bash run finished.
            shutil.rmtree(lay['tmp'], ignore_errors=True)

    # happy: exact verified read-only state -> removed, no temp, absent tail
    rc, outputs = case(_readonly_setup, keys=('post_a', 'post_a2', 'post_a3', 'post_a4'))
    assert rc == '0', (rc, outputs)
    assert 'GATE_CONFIG_REMOVED_COMPLETE' in outputs['completed']
    assert 'GATE_ABSENT' in outputs['completed'] and 'GATE_METADATA' not in outputs['completed']
    assert outputs['post_a'] == 'ABSENT' and outputs['post_a2'] == 'ABSENT'
    assert outputs['post_a3'] == 'PLAIN' and outputs['post_a4'] == 'NO_TEMP'
    labels.append('happy removal: read-only config disappears, temp never left over')

    # absent state aborts before any write
    rc, outputs = case(None)
    assert rc != '0' and 'GATE_CONFIG_REMOVED_COMPLETE' not in outputs['completed']
    assert outputs['post_a'] == 'ABSENT'
    labels.append('absent state aborts before any write (current check)')

    # active content is a refuse path
    rc, outputs = case(_readonly_setup_for('active'), keys=('post_a', 'post_a2'))
    assert rc != '0' and 'GATE_CONFIG_REMOVED_COMPLETE' not in outputs['completed']
    assert outputs['post_a'] == 'PRESENT' and outputs['post_a2'] == 'active'
    labels.append('active content is a refuse path (nothing deleted)')

    # foreign content is a refuse path
    rc, outputs = case(_readonly_setup_for('tampered'), keys=('post_a', 'post_a2'))
    assert rc != '0' and outputs['post_a'] == 'PRESENT' and outputs['post_a2'] == 'tampered'
    labels.append('foreign content is a refuse path (nothing deleted)')

    # wrong mode is a refuse path
    rc, outputs = case(_readonly_setup_for(mode='0600'))
    assert rc != '0' and outputs['post_a'] == 'PRESENT'
    labels.append('wrong mode is a refuse path')

    # wrong owner is a refuse path
    rc, outputs = case(_readonly_setup_for(owner='901:0'))
    assert rc != '0' and outputs['post_a'] == 'PRESENT'
    labels.append('wrong owner is a refuse path')

    # hard-linked config (link count 2) is a refuse path
    def hardlink_setup(lay):
        return _readonly_setup(lay) + 'ln ' + lay['cfg'] + ' ' + lay['cfg'] + '.sibling\n'
    rc, outputs = case(hardlink_setup)
    assert rc != '0' and outputs['post_a'] == 'PRESENT'
    labels.append('hard-linked config (link count 2) is a refuse path')

    # symlinked config is a refuse path; the real content survives
    def symlink_setup(lay):
        return (_readonly_setup(lay) + 'mv ' + lay['cfg'] + ' ' + lay['cfg'] + '.real\n'
                'ln -s ' + lay['cfg'] + '.real ' + lay['cfg'] + '\n')
    rc, outputs = case(symlink_setup)
    assert rc != '0' and outputs['post_a'] == 'PRESENT'
    labels.append('symlinked config is a refuse path; the real content survives')

    # dangling symlink is a refuse path
    def dangling_setup(lay):
        return 'ln -s ' + lay['cfg'] + '.gone ' + lay['cfg'] + '\n'
    rc, outputs = case(dangling_setup)
    assert rc != '0' and 'GATE_CONFIG_REMOVED_COMPLETE' not in outputs['completed']
    labels.append('dangling symlink is a refuse path')

    # leftover temp file is a refuse path
    def temp_setup(lay):
        return _readonly_setup(lay) + 'touch ' + lay['cfg'] + '.prepared\n'
    rc, outputs = case(temp_setup)
    assert rc != '0' and outputs['post_a'] == 'PRESENT'
    labels.append('leftover temp file is a refuse path')

    # the agent's boot assertion prefix rejects a different boot with exit 74;
    # the modelled boot keeps its default identity (a11...) — the agent's
    # injected expectation (b11...) mismatches and the assert must fire first.
    mismatch_prefix = ("set -euo pipefail\ntest \"$(cat /proc/sys/kernel/random/boot_id)\" = '"
                       + 'b1111111-2222-3333-4444-555555555555' + "' || exit 74\n")
    rc, outputs = case(_readonly_setup, prefix=mismatch_prefix)
    assert rc == '74', (rc, outputs)
    assert outputs['post_a'] == 'PRESENT'
    labels.append('agent-injected boot mismatch exits 74 before touching anything')

    # the stage-dir identity guard holds on the canonical layout (happy path)
    rc, outputs = case(_readonly_setup)
    assert rc == '0', (rc, outputs)
    assert outputs['post_a'] == 'ABSENT'
    labels.append('stage-dir identity guard accepts the genuine canonical layout')

    return labels


# ---------------------------------------------------------------------------
# Part 2: remove.main() driver flows against a simulated SDK/root transport.
# ---------------------------------------------------------------------------

class World:
    def __init__(self, directory):
        self.directory = directory
        self.boot_index = 0
        self.epoch = int(datetime(2026, 11, 9, 1, 2, tzinfo=timezone.utc).timestamp())
        self.boot_epoch = self.epoch - 120
        self.config = 'read-only'
        self.budget = None
        self.flag = p.FINGERPRINT
        self.logs = ''
        self.events = []
        self.sdk_count = 0
        self.relay = False
        self.root_closed = False
        self.op_error = None
        self.op_receipt = {'std': True}
        self.shutdown_error = False
        self.receipt_missing = False
        self.sdk_error = None
        self.reappear_armed = False
        self.budget_claims_fresh = False
        self.stale_budget_old_boot = False
        self.omit_boot_gate = False
        self.gate_line_never = False
        self.inject_post_boot_bad_line = False
        self.fingerprint_cleared_early = False
        self.drift = False
        self.drift_after_removal = False
        self.withhold_gate_polls = 0     # tackle: hold the boot gate line N tail reads back
        self.held_gate = None
        self.held_polls = 0
        self.disconnect_after_spent = False
        self.initial = json.loads((SOURCE / 'inspection-r1-predeploy.json').read_text())

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

    def reboot(self):
        assert not self.relay, 'driver awaited reboot before removing its recovery relay'
        self.boot_index += 1
        self.epoch += 120
        self.boot_epoch = self.epoch - 30
        self.events.append('reboot')
        if self.budget_claims_fresh:
            self.budget = 'boot=' + self.boot + ' clear=1 restore=0'
        elif self.stale_budget_old_boot:
            self.budget = 'boot=' + BOOTS[max(0, self.boot_index - 1)] + ' clear=1 restore=0'
        before = len(self.logs)
        if self.gate_line_never:
            pass
        elif self.omit_boot_gate:
            self.append('uep gate (boot): sneaky line nothing asked for')
        elif self.config == 'read-only':
            self.append('uep gate (boot): read-only: enforcing')
            self.append('uep gate: read-only boot: enforcing ' + p.FINGERPRINT + ' (zero stores)')
        else:
            self.append('uep gate (boot): config absent (enforcing; no action)')
            if self.inject_post_boot_bad_line:
                self.append('uep gate: payload check failed: dotnet missing (/usr/bin/dotnet) - fail closed (no action)')
        if self.withhold_gate_polls:
            self.held_gate = self.logs[before:]
            self.held_polls = 0
            self.logs = self.logs[:before]

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
            drifted = self.drift or (self.drift_after_removal and self.config is None)
            if drifted and 'FdetProbe.dll' in command:
                hashes[p.FDET_HOME + '/FdetProbe.dll'] = '0' * 64
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
            if self.reappear_armed:
                self.config = 'read-only'
            return 'boot=' + self.boot + '\nservice=active'
        if "printf 'proof='" in command:
            assert r"tr -d '\n'" in command, 'proof capture lost normalization'
            return 'proof=' + base64.b64encode(self.proof()).decode()
        if command.startswith('tail -n '):
            if self.held_gate is not None:
                self.held_polls += 1
                if self.held_polls > self.withhold_gate_polls:
                    self.logs += self.held_gate
                    self.held_gate = None
            return self.logs
        if "printf 'meta='" in command:
            assert self.config is not None
            return 'meta=0:0:644:1\nlabel=' + p.UEP_CONFIG + ' access="_"'
        if command == 'cat -- ' + p.UEP_CONFIG:
            assert self.config is not None
            return self.config
        if command.startswith('cat -- ' + stage_lib.UEP_STATE):
            return self.budget or 'budget-absent'
        if command.startswith('/usr/bin/dotnet ' + p.FDET_HOME):
            if self.fingerprint_cleared_early:
                self.flag = p.CLEARED
            return ('read_words physical=' + p.UEP_PAGE + ' page=0x208c2000 offset=0x6c0 words=4\n'
                    'words word=0 ' + self.flag)
        if command.startswith('test ! -e '):
            if p.UEP_CONFIG in command:
                assert self.config is None
            if stage_lib.UEP_STATE in command:
                assert self.budget is None
            return 'plain-absent' if 'plain-absent' in command else 'absent'
        raise AssertionError('unmodelled SDK command: ' + command[:100])


@contextmanager
def fixture():
    with tempfile.TemporaryDirectory(prefix='l4-r7-driver-flow-', dir=driver_shim.REHEARSAL_TEMP) as temp:
        directory = Path(temp)
        world = World(directory)
        for name in ('deployment-result.json', 'post-deploy-verification.json', 'post-mortem-20261108.md',
                     'r6-stage-status-dirread.json'):
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
                # Targets only the post-SPENT teardown: earlier closes happen
                # while no terminal receipt exists and must keep working.
                if (world.disconnect_after_spent
                        and (world.directory / 'SPENT').is_file()):
                    raise OSError('injected post-SPENT close failure')

            async def capture(self, command, **kwargs):
                if world.sdk_error is not None:
                    raise world.sdk_error
                return 0, world.capture(command).strip()

        class Connection:
            async def execute(self, command, timeout):
                if world.op_error is not None:
                    raise world.op_error
                assert command == 'gate-remove:' + world.boot
                assert world.config == 'read-only'
                if not world.op_receipt['std']:
                    return SimpleNamespace(exit_code=1, timed_out=False,
                                           stdout='boom', stderr='refused')
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
                (remove.RemoveSession, 'run', root_transport), (recovery, 'stop', stop_relay),
                (asyncio, 'sleep', world.sleep),
            ):
                patches.enter_context(patch.object(owner, name, value))
            patches.enter_context(patch.object(remove, 'BridgeSDK', SDK))
            patches.enter_context(patch.object(deploy, 'BridgeSDK', SDK))
            yield world


def passed(world, kind):
    return json.loads((world.directory / ('stage-status-' + kind + '.json')).read_text())


def run():
    results = list(_shell_cases())

    with fixture() as world:
        asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is True
        assert world.boot == BOOTS[1] and world.config is None and not world.relay
        assert (world.directory / 'SPENT').is_file()
        assert not any((world.directory / name).exists() for name in p.MARKERS)
        assert world.events.count('reboot') == 1
        assert world.events.count('relay-removed') == 1
        assert world.events[-3:] == ['root-closed', 'relay-removed', 'reboot']
    results.append('happy chain: read-only config removed, one owner reboot observed, '
                   'enforcing-only re-verified, SPENT written, marker consumed')

    with fixture() as world:
        # The manager app gates on its own boot schedule, independent of the
        # bridge service the reboot poll watched: the required line may lag.
        world.withhold_gate_polls = 3
        asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is True
        assert (world.directory / 'SPENT').is_file()
        assert world.config is None and not world.relay
    results.append('a lagging boot gate line (3 withheld reads) is waited for; the removal still receipts success')

    with fixture() as world:
        world.disconnect_after_spent = True
        asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is True
        assert (world.directory / 'SPENT').is_file()
        assert not (world.directory / 'STOP').exists()
    results.append('a late SDK close failure after the SPENT receipt cannot rewrite the packet as failed')

    with fixture() as world:
        asyncio.run(remove.main())
        (world.directory / 'LIVE_ARM_REMOVE').write_text(p.COMMIT + '\n')
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert world.boot == BOOTS[1]
    results.append('a second invocation of the single stage refuses (one attempt per packet)')

    with fixture() as world:
        # The r7 burn: a missing host openssl surfaced only after the one
        # attempt was taken. r8 resolves it in prerequisites(), so the refusal
        # must land before OneAttempt.take() - no STOP, no attempt file, no TV
        # contact, config untouched.
        with patch.object(p, 'OPENSSL_CANDIDATES', ()), \
                patch.object(p.shutil, 'which', lambda name: None):
            with pytest.raises(p.Stop, match='openssl'):
                asyncio.run(remove.main())
        assert not (world.directory / 'execution/attempts/LIVE_ARM_REMOVE.attempt').exists()
        assert not (world.directory / 'STOP').exists()
        assert world.events == [] and not world.relay
        assert world.config == 'read-only'
    results.append('missing openssl refuses BEFORE the attempt is taken: no STOP, no TV '
                   'contact, packet stays re-runnable')

    for world_config in ('active', 'tampered'):
        with fixture() as world:
            world.config = world_config
            with pytest.raises(p.Stop):
                asyncio.run(remove.main())
            assert (world.directory / 'STOP').is_file()
            assert passed(world, 'remove')['passed'] is False
            assert world.config == world_config and not world.relay
            assert not (world.directory / 'SPENT').is_file()
        results.append('preflight refuses a ' + world_config + ' content without any root session or deletion')

    with fixture() as world:
        (world.directory / 'STOP').write_text('injected\n')
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
    results.append('STOP file refuses the stage (no TV work)')

    with fixture() as world:
        (world.directory / 'SPENT').write_text('injected\n')
        (world.directory / 'LIVE_ARM_REMOVE').write_text(p.COMMIT + '\n')
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
    results.append('SPENT packet refuses the stage (no TV work)')

    with fixture() as world:
        world.budget = 'boot=' + BOOTS[0] + ' clear=1 restore=0'
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert world.config == 'read-only' and world.budget is not None
        assert (world.directory / 'STOP').is_file()
    results.append('pre-existing budget state file refuses the stage (dirread state changed)')

    with fixture() as world:
        world.boot_index = 1
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert world.config == 'read-only' and not world.relay
    results.append('boot drifted from the inspected pin refuses before any removal')

    with fixture() as world:
        world.sdk_error = OSError('injected SDK failure')
        with pytest.raises(OSError):
            asyncio.run(remove.main())
        assert (world.directory / 'STOP').is_file()
        assert passed(world, 'remove')['passed'] is False
        assert not world.relay
    results.append('unexpected SDK failure records STOP')

    for injected in (p.Stop('injected gate refusal'), asyncio.CancelledError('injected interruption')):
        with fixture() as world:
            world.op_error = injected
            with pytest.raises(type(injected)):
                asyncio.run(remove.main())
            assert (world.directory / 'STOP').is_file()
            assert passed(world, 'remove')['passed'] is False
            assert not world.relay and world.events == ['root-closed', 'relay-removed']
            assert world.config == 'read-only'
        results.append('op refusal/interruption records STOP, removes owned relay after root close: '
                       + type(injected).__name__)

    with fixture() as world:
        world.op_receipt = {'std': False}
        with pytest.raises(p.Stop, match='gate-remove did not complete'):
            asyncio.run(remove.main())
        assert (world.directory / 'STOP').is_file()
        assert not world.relay and world.events == ['root-closed', 'relay-removed']
        assert world.config == 'read-only'
    results.append('non-zero op receipt without the completion mark refuses and removes the relay')

    with fixture() as world:
        world.shutdown_error = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert world.relay and 'relay-removed' not in world.events
        assert (world.directory / 'STOP').is_file()
        assert world.config is None, 'the root op completed; the config state must be receipted truthfully'
    results.append('unverified root shutdown retains the recovery relay and stops the packet')

    with fixture() as world:
        world.receipt_missing = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert world.relay and 'relay-removed' not in world.events
        receipts = [json.loads(line) for line in (world.directory / 'receipts.jsonl').read_text().splitlines()]
        assert any(recovery.PATH in row.get('cleanup_pending', []) for row in receipts)
    results.append('missing relay ownership proof retains and receipts the exact pending cleanup path')

    async def no_reboot(old_boot):
        return None

    with fixture() as world:
        with patch.object(remove, 'await_new_boot', no_reboot):
            with pytest.raises(p.Stop, match='no new boot'):
                asyncio.run(remove.main())
        assert not world.relay and passed(world, 'remove')['passed'] is False
        assert world.config is None
    results.append('reboot timeout records STOP and preserves the removed (absent) config state')

    with fixture() as world:
        world.reappear_armed = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert world.config == 'read-only'
        assert passed(world, 'remove')['passed'] is False
    results.append('a fresh boot with the config back refuses (state re-introduced)')

    with fixture() as world:
        world.budget_claims_fresh = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
    results.append('budget state claiming the fresh boot refuses (absent path must not store)')

    with fixture() as world:
        world.stale_budget_old_boot = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
    results.append('a genuinely stale budget file passes the claim check but the final state refusal stops the stage')

    with fixture() as world:
        world.fingerprint_cleared_early = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
    results.append('cleared fingerprint after the config removal refuses: no payload may have run')

    with fixture() as world:
        world.omit_boot_gate = True
        with pytest.raises(p.Stop, match='unexpected gate event'):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
    results.append('fresh boot without the absent-config gate line refuses')

    with fixture() as world:
        world.gate_line_never = True
        with pytest.raises(p.Stop, match='gate line is missing'):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
    results.append('a boot with no gate line at all expires the bounded wait and refuses')

    with fixture() as world:
        world.inject_post_boot_bad_line = True
        with pytest.raises(p.Stop, match='unexpected gate event'):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
    results.append('any unexpected current-boot gate line stops the stage for owner review')

    with fixture() as world:
        world.drift = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
        assert world.config == 'read-only', 'drift preflight must refuse before the root session'
    results.append('protected register drift refuses the preflight before any root session')

    with fixture() as world:
        world.drift_after_removal = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
        assert world.config is None, 'the removal ran; the post-removal baseline must be what refuses'
        assert world.relay and 'relay-removed' not in world.events, \
            'the relay is retained for reviewed cleanup'
        assert not (world.directory / 'SPENT').is_file()
    results.append('protected register drift after the removal refuses at closeout (post-remove baseline)')

    def noop_assessment(*args, **kwargs):
        # A truthful-looking no-op: the required shape is "present" without
        # any validation, which is precisely the vulnerability this pairing
        # demonstrates.
        return ['[2026-11-09T01:04:00.1234567Z] uep gate (boot): config absent (enforcing; no action)']

    with fixture() as world:
        world.omit_boot_gate = True
        with pytest.raises(p.Stop):
            asyncio.run(remove.main())
        assert passed(world, 'remove')['passed'] is False
        assert not (world.directory / 'SPENT').is_file()
    with patch.object(remove, 'gate_event_assessment', noop_assessment), \
            patch.object(stage_lib, 'gate_event_assessment', noop_assessment):
        with fixture() as world:
            world.omit_boot_gate = True
            asyncio.run(remove.main())
            assert (world.directory / 'SPENT').is_file(), 'no-op validator accepted a gate-less boot'
    results.append('gate-line validator is load-bearing: real code refuses, a no-op would reach SPENT')

    def noop_refuse():
        return None

    with patch.object(remove, 'refuse_if_stopped', noop_refuse), \
            patch.object(stage_lib, 'refuse_if_stopped', noop_refuse):
        with fixture() as world:
            (world.directory / 'STOP').write_text('injected\n')
            asyncio.run(remove.main())
            assert (world.directory / 'SPENT').is_file(), 'no-op STOP validator let a stopped packet close'
    results.append('STOP validator is load-bearing: a disabled guard lets a stopped packet close (refused above)')

    with fixture() as world:
        (world.directory / 'seal.json').unlink()
        with patch.object(offline_checks, 'PACK', world.directory):
            with pytest.raises(p.Stop, match='seal target missing'):
                offline_checks.seal_packet('fixture-openssl')
            assert not (world.directory / 'offline-results.json').exists()
            for name in offline_checks.SEAL_NAMES:
                if name == 'offline-results.json':
                    continue
                file = world.directory / name
                if not file.exists():
                    file.parent.mkdir(parents=True, exist_ok=True)
                    file.write_text('host-only seal fixture\n')
            report = offline_checks.seal_packet('fixture-openssl')
            seal = json.loads((world.directory / 'seal.json').read_text())
            assert report['seal_entries'] == len(seal) == len(offline_checks.SEAL_NAMES)
            assert report['openssl'] == 'fixture-openssl'
            assert all(p.digest(world.directory / name) == value for name, value in seal.items())
            with pytest.raises(p.Stop):
                offline_checks.seal_packet('fixture-openssl')
    results.append('first seal hashes the completed report, missing inputs write nothing, replay refuses')

    return results
