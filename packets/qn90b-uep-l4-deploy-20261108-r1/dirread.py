"""Stage 3: DIRREAD — install the `read-only` gate config in the manager's
root context, then watch the next launch produce the read-only fingerprint
line with zero stores.

Root context via the archive-root machinery (recovery relay, staging, root
agent session) exactly as deploy.py; the single root op is `gate-readonly`,
one attempt, one gate change per session (the agent's own guard). Returns
the TV to: config present (content `read-only`, 0:0:644, label `_`), no
budget state file (the read-only path inside UepGate never reaches a store),
recovery relay removed, and the enforcing fingerprint printed into agent.log.
"""
import asyncio
import json
import os
import re
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
from deploy import Deployment
from inspect_tv import BridgeSDK, save
import recovery
from stage_lib import (agent_log_lines, capture, fail, fields, marker_for,
                       log, protect_seal, sdk_state, succeed, protected_hashes,
                       UEP_STATE)
from samsung_tv_root.archive_root import _prepare_artifacts
from samsung_tv_root.root_agent import RootAgentServer, generate_secret

INITIAL = json.loads((p.HERE / 'inspection.json').read_text(encoding='utf-8'))
STAGE = 'LIVE_ARM_DIRREAD'
STATUS = 'stage-status-dirread.json'
KIND = 'dirread'
POLL_SECONDS = 20
DEADLINE_SECONDS = 100 * 60


def prerequisites():
    receipt = json.loads((p.HERE / 'deployment-result.json').read_text(encoding='utf-8'))
    p.require(receipt.get('installed') is True and receipt.get('sha256') == p.NEW_SHA,
              'deploy receipt missing or wrong')
    p.require(receipt.get('boot') == p.BOOT, 'deploy receipt boot mismatch')
    watch = json.loads((p.HERE / 'stage-status-watch.json').read_text(encoding='utf-8'))
    p.require(watch.get('passed') is True, 'the watch stage did not pass')
    log('dirread-prerequisites-verified')


class DirRead(Deployment):
    applied = True
    MATERIALS = Path(p.HERE / 'execution/gate-materials-dirread')

    async def run(self):
        p.require(not await self.sdk.present(), 'SDK slot present')
        self.owned_sdk = True
        await self.sdk.connect()
        await self.baseline()
        await self.check_runtime()
        self.baseline_passed = True
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
                  'manager.dll': p.HERE / 'manager.dll',
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
        await self.root_snapshot()
        self.save('gate-config-intent', op='gate-readonly', boot=p.BOOT)
        await self.run_gate()

    async def root_snapshot(self):
        result = await self.connection.execute('phase1-snapshot', 12)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr,
                  'root snapshot failed')
        value = fields(result.stdout)
        p.require(value['agent'] == str(self.agent_pid) and value['boot'] == p.BOOT,
                  'root identity/boot mismatch')
        p.require(value['uid'].split() == value['gid'].split() == ['0'] * 4,
                  'complete root identity missing')
        p.require(value['label'] == 'User' and value['Seccomp'] == value['NoNewPrivs'] == '0',
                  'root context changed')
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
    session = DirRead(BridgeSDK(save), save)
    try:
        await session.run()
    finally:
        await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
    # Recovery relay teardown + final baseline, mirroring deploy.main().
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        session.sdk = sdk
        await session.baseline()
        await recovery.stop(sdk, save, session.recovery_receipt)
        await session.baseline()
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
        log_size_start = int(state['log_size'])
        observed = None
        polls = 0
        deadline = time.monotonic() + DEADLINE_SECONDS
        while time.monotonic() < deadline - POLL_SECONDS:
            polls += 1
            poll = fields(await capture(sdk, 'dirread-poll-' + str(polls),
                                        "printf 'log_size='; stat -c %s " + p.EV + "/agent.log\n"))
            size = int(poll['log_size'])
            p.require(size >= log_size_start, 'agent.log shrank during dirread')
            if size > log_size_start:
                lines = await agent_log_lines(sdk, 100)
                summaries = [line for line in lines if
                             re.search(r'uep gate \((?:boot|reopen)\): read-only: enforcing$', line)]
                details = [line for line in lines if re.search(
                    r'uep gate: read-only (?:boot|reopen): enforcing '
                    + re.escape(p.FINGERPRINT) + r' \(zero stores\)$', line)]
                if details:
                    p.require(summaries, 'read-only summary line missing beside the detail line')
                    gate = [line for line in lines if 'uep gate ' in line and 'EXCEPTION' not in line]
                    for line in gate:
                        p.require('absent' not in line.split('(zero')[0][-24:]
                                  or 'config absent' in line or 'read-only' in line,
                                  'unexpected gate verb beside read-only: ' + line[-160:])
                    observed = details[-1]
                    log('dirread-fingerprint-observed', line=observed[-160:], polls=polls)
                    break
            await asyncio.sleep(POLL_SECONDS)
        if observed is None:
            await fail(STAGE, STATUS, KIND,
                       'no confirming read-only launch within the bound; the config remains read-only and the packet stops')
        end = await sdk_state(sdk, 'dirread-final')
        await protected_hashes(sdk)
        final_state = await capture(sdk, 'gate-state-final-absence',
            'test ! -e ' + UEP_STATE + ' && test ! -L ' + UEP_STATE + ' && echo plain-absent')
        p.require(final_state == 'plain-absent', 'budget state file exists at closeout; a store happened; STOP')
        p.require(state['boot'] == end['boot'] == p.BOOT, 'boot changed; STOP')
        succeed(STAGE, STATUS, KIND, observed_line=observed[-160:], boot=p.BOOT)
    finally:
        await sdk.disconnect()


if __name__ == '__main__':
    asyncio.run(main())
