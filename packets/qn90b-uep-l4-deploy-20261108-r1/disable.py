"""Stage 5: DISABLE path — remove the gate config, reboot, verify enforcing
restored. May be deferred past this packet's session.

One archive-root root session runs the single `gate-remove` op (refuses any
config content other than `read-only`/`active` and produces a removed-state
receipt). After the reboot the driver verifies: fresh automatic proof, an
absent-config boot gate line, the budget state file either absent or carrying
a stale boot id (the gate never touches it on the absent-config path), the
fdet fingerprint back to enforcing, and the hash-locked uep-probe DENIED by
UEP (`Operation not permitted`, native_exit=126) exactly as recorded live on
this build.
"""
import asyncio
import base64
import json
import re
import sys
import time
from pathlib import Path
from shlex import quote

sys.dont_write_bytecode = True
import packet as p
from stage_lib import (agent_log_lines, capture, fail, fields, marker_for,
                       log, protect_seal, sdk_state, succeed, protected_hashes,
                       UEP_STATE)
import activate as activate_module

STAGE = 'LIVE_ARM_DISABLE'
STATUS = 'stage-status-disable.json'
KIND = 'disable'
MARKER_OK = 'QN90B_UEP_NATIVE_PROBE_OK'
DENIAL_EXIT = 'native_exit=126'
AWAIT_BOOT_DEADLINE = 8 * 60 * 60


def prerequisites():
    watch = json.loads((p.HERE / 'stage-status-watch.json').read_text(encoding='utf-8'))
    p.require(watch.get('passed') is True, 'the watch stage did not pass')
    dirread = json.loads((p.HERE / 'stage-status-dirread.json').read_text(encoding='utf-8'))
    p.require(dirread.get('passed') is True, 'the dirread stage did not pass')
    active = json.loads((p.HERE / 'stage-status-active.json').read_text(encoding='utf-8'))
    p.require(active.get('passed') is True, 'the active stage did not pass')
    p.require(active.get('fresh_boot') is None or re.fullmatch(r'[0-9a-f-]{36}', active['fresh_boot']),
              'malformed active-stage boot receipt')
    log('disable-prerequisites-verified')


class DisableSession(activate_module.ActiveSession):
    MATERIALS = Path(p.HERE / 'execution/gate-materials-disable')

    async def run_gate(self):
        result = await self.connection.execute('gate-remove', 12)
        self.save('gate-remove-receipt', exit=result.exit_code, timed_out=result.timed_out,
                  stdout=result.stdout, stderr=result.stderr)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr
                  and 'GATE_CONFIG_REMOVED_COMPLETE\n' in result.stdout,
                  'gate-remove did not complete; no retry')
        p.require(re.search(r'^GATE_ABSENT$', result.stdout, re.M), 'removal must end absent')


async def main():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    session = DisableSession(BridgeSDK(save), save)
    try:
        await session.run()
    finally:
        await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        state = await sdk_state(sdk, 'disable-post-op')
        p.require(state['gate_config'] == 'absent', 'gate config present after removal; STOP')
        prior_boot = state['boot']
        p.require(prior_boot == p.BOOT, 'boot identity changed during disable; STOP')
        stale = (await capture(sdk, 'gate-state-pre', 'cat -- ' + UEP_STATE + ' 2>/dev/null || echo budget-absent')).strip()
        log('disable-pre-boot-budget', budget=stale[:80])
        log('disable-armed', boot=prior_boot)
    finally:
        await sdk.disconnect()
    fresh = await activate_module.await_new_boot(prior_boot)
    if fresh is None:
        await fail(STAGE, STATUS, KIND,
                   'no new boot within the awaiting bound; enforcing stays as the packaged default and the packet stops')
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        post = await sdk_state(sdk, 'disable-post-boot')
        p.require(post['gate_config'] == 'absent', 'gate config reappeared; STOP')
        p.require(post['boot'] == fresh, 'boot poll lost the fresh boot')
        await protected_hashes(sdk)
        lines = await agent_log_lines(sdk, 120)
        p.require([line for line in lines if
                   re.search(r'uep gate \((?:boot|reopen)\): ' +
                             'config absent \\(enforcing; no action\\)$', line)],
                  'the absent-config boot gate line is missing; the disable stage cannot continue')
        stale = (await capture(sdk, 'gate-state-post', 'cat -- ' + UEP_STATE + ' 2>/dev/null || echo budget-absent')).strip()
        if stale != 'budget-absent':
            stale_boot = re.match(r'boot=([0-9a-f-]{36})', stale)
            p.require(stale_boot and stale_boot[1] != fresh,
                      'budget state claims the fresh boot boot; the absent-config path must not have touched it')
            log('disable-stale-budget-verified', claimed_boot=stale_boot[1])
        else:
            log('disable-budget-absent-verified')
        await activate_module.assert_flag_read(sdk, p.FINGERPRINT)
        out = fields(await capture(sdk, 'proof-capture',
                                   "printf 'proof='; base64 < " + p.EV + "/selfroot-proof.txt\n"))
        activate_module.assert_proof(fresh, base64.b64decode(out['proof']).decode())
        end = await sdk_state(sdk, 'disable-final')
        await protected_hashes(sdk)
        p.require(post['boot'] == end['boot'] == fresh, 'boot changed inside the disable stage')
        succeed(STAGE, STATUS, KIND, fresh_boot=fresh)
    finally:
        await sdk.disconnect()


if __name__ == '__main__':
    asyncio.run(main())
