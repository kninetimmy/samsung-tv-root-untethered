"""Stage 3: DIRREAD — install the `read-only` gate config in the manager's
root context, then bind the next launch's read-only fingerprint line to this
session and observe it with zero stores.

Root context via the archive-root machinery (recovery relay, staging, root
agent session) exactly as r1's qualified deploy; the single root op is
`gate-readonly`, one attempt, one gate change per session (the agent's own
guard). Returns the TV to: config present (content `read-only`, 0:0:644,
label `_`), no budget state file (the read-only path inside UepGate never
reaches a store), recovery relay removed, and the enforcing fingerprint
printed into agent.log on the observed relaunch.

Session binding is by log byte offset: the confirming evidence must lie in
the agent.log bytes written AFTER this session's gate op, never in an older
tail region.
"""
import asyncio
import json
import re
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
from deploy import Deployment
from inspect_tv import BridgeSDK, save
import recovery
from stage_lib import (agent_log_lines, agent_log_lines_from_offset, capture,
                       record_failure, fields, marker_for, log, OneAttempt, protect_seal,
                       refuse_if_stopped, sdk_state, succeed, protected_hashes,
                       gate_event_assessment, boot_clock, GATE_EVENT_SHAPES, UEP_STATE)
from samsung_tv_root.archive_root import _prepare_artifacts
from samsung_tv_root.root_agent import RootAgentServer, generate_secret

STAGE = 'LIVE_ARM_DIRREAD'
STATUS = 'stage-status-dirread.json'
KIND = 'dirread'
POLL_SECONDS = 20
DEADLINE_SECONDS = 100 * 60


def prerequisites():
    refuse_if_stopped()
    receipt = json.loads((p.HERE / 'deployment-result.json').read_text(encoding='utf-8'))
    p.require(receipt.get('installed') is True and receipt.get('sha256') == p.DEPLOY_RECEIPT_SHA,
              'r1 deploy receipt missing or wrong; stage 1 provenance required')
    p.require(receipt.get('boot') == p.DEPLOY_RECEIPT_BOOT, 'r1 deploy receipt boot mismatch')
    p.require(p.BOOT is not None, 'the fresh r2 inspection must establish the current boot')
    watch = json.loads((p.HERE / 'stage-status-watch.json').read_text(encoding='utf-8'))
    p.require(watch.get('stage') == 'watch' and watch.get('passed') is True, 'the watch stage did not pass')
    p.require(watch.get('boot') == p.BOOT, 'watch receipt differs from the inspected boot')
    log('dirread-prerequisites-verified', inspection_boot=p.BOOT)


class DirRead(Deployment):
    applied = True
    GATE_OP = 'gate-readonly'
    MATERIALS = Path(p.HERE / 'execution/gate-materials-dirread')

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
        self.materials = self.MATERIALS
        p.make_private_directory(self.materials)
        _prepare_artifacts(self.materials, '3.1', p.PKG, p.PC,
                           self.server.listening_port, secret)
        (self.materials / 'launcher.log').touch(exist_ok=False)
        assets = {'stage.sh': p.HERE / 'stage.sh',
                  'manager.dll': p.HERE / 'artifacts/manager.dll',
                  'SamsungTvArchiveRoot.dll': p.LAUNCHER,
                  'SamsungTvRootAgent.dll': p.HERE / 'build/SamsungTvRootAgent.dll',
                  'FdetProbe.dll': p.FDET_PROBE,
                  'FdetProbe.runtimeconfig.json': p.FDET_RUNTIMECONFIG}
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
        self.save('gate-config-intent', op=self.GATE_OP, boot=self.expected_boot)
        await self.run_gate()

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

    async def run_gate(self):
        result = await self.connection.execute('gate-readonly', 12)
        self.save('gate-readonly-receipt', exit=result.exit_code, timed_out=result.timed_out,
                  stdout=result.stdout, stderr=result.stderr)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr
                  and 'GATE_CONFIG_READONLY_COMPLETE\n' in result.stdout,
                  'gate-readonly did not complete; no retry')
        p.require(re.search(r'^GATE_METADATA 0:0:644:1$', result.stdout, re.M), 'gate metadata receipt missing')
        p.require(re.search(r'^GATE_ABSENT$', result.stdout, re.M) is None, 'gate removal cannot happen here')


async def main():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            state = await sdk_state(sdk, 'dirread-baseline')
            p.require(state['boot'] == p.BOOT, 'boot left the inspected boot; STOP')
            p.require(state['gate_config'] == state['gate_state'] == 'absent',
                      'gate config or budget pre-exists; STOP')
            await protected_hashes(sdk)
            cut = int(state['log_size'])
            boot_epoch, epoch = await boot_clock(sdk)
            prelude = await agent_log_lines(sdk, 80)
            gate_event_assessment(prelude, 'watch', needle_required=False,
                                  boot_epoch=boot_epoch, epoch_at_fetch=epoch)
        finally:
            await sdk.disconnect()
        session = DirRead(BridgeSDK(save), save, p.BOOT, p.PROOF_SHA)
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            state = await sdk_state(sdk, 'dirread-post-op')
            content = await capture(sdk, 'gate-config-content', 'cat -- ' + p.UEP_CONFIG)
            p.require(content == 'read-only', 'gate config content changed; STOP')
            meta = fields(await capture(sdk, 'gate-config-meta', (
                "printf 'meta='; stat -c '%u:%g:%a:%h' -- " + p.UEP_CONFIG + "\n"
                "printf 'label='; chsmack " + p.UEP_CONFIG + "\n")))
            p.require(meta['meta'] == '0:0:644:1', 'gate config metadata changed; STOP')
            p.require(meta['label'] == p.UEP_CONFIG + ' access="_"', 'gate config label changed; STOP')
            p.require(state['gate_state'] == 'absent', 'budget state file after a read-only op; STOP')
            p.require(state['boot'] == p.BOOT, 'boot changed during dirread; STOP')
            # The exclusive create proves new read-only events after this pre-op offset belong to this stage.
            observed = None
            deadline = time.monotonic() + DEADLINE_SECONDS
            while time.monotonic() < deadline - POLL_SECONDS:
                poll = fields(await capture(sdk, 'dirread-poll',
                                            "printf 'log_size='; stat -c %s " + p.EV + "/agent.log\n"))
                size = int(poll['log_size'])
                p.require(size >= cut, 'agent.log shrank during dirread')
                if size > cut:
                    lines = await agent_log_lines_from_offset(sdk, cut)
                    _, epoch = await boot_clock(sdk)
                    gate = gate_event_assessment(lines, 'dirread', needle_required=False,
                                                  regime='legacy', boot_epoch=boot_epoch,
                                                  epoch_at_fetch=epoch)
                    if all(any(shape.search(line) for line in gate)
                           for shape in GATE_EVENT_SHAPES['dirread']):
                        observed = gate[-1]
                        log('dirread-fingerprint-observed', line=observed[-160:])
                        break
                await asyncio.sleep(POLL_SECONDS)
            p.require(observed is not None,
                      'no confirming read-only launch within the bound; config remains read-only; STOP')
            end = await sdk_state(sdk, 'dirread-final')
            await protected_hashes(sdk)
            final_state = await capture(sdk, 'gate-state-final-absence',
                                        'test ! -e ' + UEP_STATE + ' && test ! -L ' + UEP_STATE
                                        + ' && echo plain-absent')
            p.require(final_state == 'plain-absent', 'budget state file exists at closeout; STOP')
            p.require(await capture(sdk, 'gate-config-final', 'cat -- ' + p.UEP_CONFIG) == 'read-only',
                      'gate config changed during observation; STOP')
            p.require(state['boot'] == end['boot'] == p.BOOT, 'boot changed; STOP')
            succeed(STAGE, STATUS, KIND, observed_line=observed[-160:], boot=p.BOOT,
                    attempt_utc=attempt.path.read_text().strip())
        finally:
            await sdk.disconnect()
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
