"""Shared authenticated root session for the three r9 gate ops.

One op per session: the session stages exactly the assets the op needs, opens
the recovery relay, launches the pinned archive-root chain, verifies the root
context, executes `gate-<op>:<boot id>` once, and receipts the result. Cleanup
and closeout are Trial.finish's reviewed mechanics.
"""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r23-pycache-')

from pathlib import Path

import packet as p
from deploy import Deployment
from inspect_tv import BridgeSDK, save
import recovery
from stage_lib import fields
from samsung_tv_root.archive_root import _prepare_artifacts
from samsung_tv_root.root_agent import RootAgentServer, generate_secret

GATE_OPS = ('gate-install', 'gate-config-active', 'gate-remove')


class GateSession(Deployment):
    def __init__(self, sdk, save, expected_boot, expected_proof_hash, op,
                 extra_assets, timeout, manager_sha=None):
        super().__init__(sdk, save, expected_boot, expected_proof_hash, manager_sha)
        p.require(op in GATE_OPS, 'unsupported gate op: ' + str(op))
        p.require(12 <= timeout <= 180, 'gate op timeout out of the agent bound')
        self.op = op
        self.extra_assets = dict(extra_assets)
        self.timeout = timeout
        self.materials = Path(p.HERE / 'execution' / ('gate-materials-' + op.lstrip('gate-')))
        self.result = None

    async def run(self):
        p.require(not await self.sdk.present(), 'SDK slot present')
        self.owned_sdk = True
        await self.sdk.connect()
        await self.baseline()
        await self.check_runtime()
        self.baseline_passed = True
        self.recovery_attempted = True
        self.recovery_receipt = await recovery.start(self.sdk, self.save)
        await recovery.validate(self.sdk, self.save, self.recovery_receipt)
        self.disconnected = True
        await self.sdk.disconnect()
        self.sdk = BridgeSDK(save, port=recovery.PORT)
        await self.sdk.connect()
        self.disconnected = False
        await self.baseline()
        self.save('recovery-sdk-verified', port=recovery.PORT)
        secret = generate_secret()
        self.server = RootAgentServer(p.PC, 0, p.TV, secret, require_root=True)
        await self.server.start()
        p.make_private_directory(self.materials)
        _prepare_artifacts(self.materials, '3.1', p.PKG, p.PC,
                           self.server.listening_port, secret)
        (self.materials / 'launcher.log').touch(exist_ok=False)
        assets = {'stage.sh': p.HERE / 'stage.sh',
                  'SamsungTvArchiveRoot.dll': p.LAUNCHER,
                  'SamsungTvRootAgent.dll': p.HERE / 'build/SamsungTvRootAgent.dll'}
        assets.update(self.extra_assets)
        for name in sorted(p.MATERIALS - {'private.pem', 'files.sha256'}):
            assets[name] = self.materials / name
        with (self.materials / 'files.sha256').open('x', encoding='ascii', newline='\n') as stream:
            for name, path in assets.items():
                stream.write(p.digest(path) + '  ' + name + '\n')
        import stage_transport
        await stage_transport.stage_files(self, {'files.sha256': self.materials / 'files.sha256', **assets})
        await self.current()
        await self.control('launch')
        self.connection = await self.server.accept(30)
        self.agent_pid = self.connection.identity.pid
        p.require(self.agent_pid > 1, 'invalid root PID')
        await self.root_snapshot(self.expected_boot)
        self.save('gate-op-intent', op=self.op, boot=self.expected_boot)
        self.result = await self.connection.execute(self.op + ':' + self.expected_boot, self.timeout)
        self.save('gate-op-receipt', op=self.op, exit=self.result.exit_code,
                  timed_out=self.result.timed_out, stdout=self.result.stdout,
                  stderr=self.result.stderr)
        p.require(not self.result.timed_out, self.op + ' timed out; no retry')
        p.require(self.result.exit_code == 0, self.op + ' failed; no retry')
        p.require(not self.result.stderr, self.op + ' wrote stderr: ' + self.result.stderr[:200])
        # finish() re-runs the baseline AFTER the op; the install op replaced
        # the manager, so the session's own anchor must move with it.
        if self.op == 'gate-install':
            self.manager_sha = p.NEW_MANAGER_SHA

    def require_stdout(self, *markers):
        for marker in markers:
            p.require(marker in self.result.stdout, self.op + ' receipt missing ' + marker)

    async def root_snapshot(self, expected_boot):
        result = await self.connection.execute('phase1-snapshot', 12)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr,
                  'root snapshot failed')
        value = fields(result.stdout)
        p.require(value['agent'] == str(self.agent_pid) and value['boot'] == expected_boot,
                  'root identity/boot mismatch')
        p.require(value['uid'].split() == value['gid'].split() == ['0'] * 4,
                  'complete root identity missing')
        p.require(value['label'] == 'User' and value['Seccomp'] == value['NoNewPrivs'] == '0',
                  'root context changed')
        INITIAL = p.inspection()
        p.require(value['ip'] == INITIAL['ip'] and value['mode'] == INITIAL['mode'],
                  'root settings changed')
        for ns in ('pid', 'user'):
            p.require(value['caller_' + ns] == value['init_' + ns], 'root namespace changed')
        p.require(value['caller_mnt'] != value['init_mnt'], 'private root mount missing')
        for key, path in (('host_passwd', '/etc/passwd'), ('host_key', '/usr/share/sdbd/public.pem')):
            p.require(value[key] == p.BASE['files'][path] + '  /proc/1/root' + path,
                      'global system hash drift')
        self.save('root-context-verified', snapshot=result.stdout)
