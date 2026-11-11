"""Stage 2: WATCH — the absent-config negative control. SDK reads only.

Waits for the first v5.18 gate event after the deploy close, then requires
agent.log to show `uep gate (boot|reopen): config absent (enforcing; no
action)`, no gate budget state file on /opt, no gate config, and the whole
protected register (23 files + the two fdet payload files) byte-identical.
Neither stage nor awaiting driver writes anything to the TV.
"""
import asyncio
import json
import sys
import time
from shlex import quote

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK
from stage_lib import (agent_log_lines, capture, fail, fields, marker_for,
                       log, protect_seal, sdk_state, succeed, protected_hashes,
                       UEP_STATE)

STAGE = 'LIVE_ARM_WATCH'
STATUS = 'stage-status-watch.json'
KIND = 'watch'
GATE_NEEDLE = 'config absent (enforcing; no action)'
POLL_SECONDS = 20
DEADLINE_SECONDS = 100 * 60


def prerequisites():
    receipt = json.loads((p.HERE / 'deployment-result.json').read_text(encoding='utf-8'))
    p.require(receipt.get('installed') is True and receipt.get('sha256') == p.NEW_SHA,
              'deploy receipt missing or wrong')
    p.require(receipt.get('boot') == p.BOOT, 'deploy receipt boot mismatch')
    log('watch-prerequisites-verified')


def assess_tail(lines):
    """All gate event lines must be the absent-config one; the newest must appear."""
    gate = [line for line in lines if 'uep gate ' in line and 'uep gate EXCEPTION' not in line]
    p.require(gate, 'no gate event line in the log tail yet')
    for line in gate:
        p.require(GATE_NEEDLE in line and re.match(r'^\[\d{4}-\d{2}-\d{2}T', line),
                  'unexpected gate event while config is absent: ' + line[:160])
    log('watch-gate-lines-verified', count=len(gate), first=gate[-1][-160:])
    return gate[-1]


async def wait_for_gate_line(sdk, offset):
    deadline = time.monotonic() + DEADLINE_SECONDS
    polls = 0
    last_size = offset
    while time.monotonic() < deadline - POLL_SECONDS:
        polls += 1
        out = fields(await capture(sdk, 'watch-poll-' + str(polls), (
            "printf 'log_size='; stat -c %s " + p.EV + "/agent.log\n"
            "printf 'manager_pids='; pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll' | tr '\\n' ','; echo\n")))
        size = int(out['log_size'])
        p.require(size >= last_size, 'agent.log shrank during watch')
        last_size = size
        if size > offset and out['manager_pids']:
            line = assess_tail(await agent_log_lines(sdk, 80))
            log('watch-relaunch-observed', log_size=size, polls=polls)
            return line, size
        await asyncio.sleep(POLL_SECONDS)
    await fail(STAGE, STATUS, KIND, 'no v5.18 gate event within the watch bound')


async def main():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    sdk = BridgeSDK(log)
    try:
        p.require(not await sdk.present(), 'owned proxy SDK slot already present')
        await sdk.connect()
        state = await sdk_state(sdk, 'watch-baseline')
        await protected_hashes(sdk)
        offset = int((await capture(sdk, 'log-size-baseline',
                                    'stat -c %s ' + p.EV + '/agent.log')).strip())
        for where in (p.UEP_CONFIG, UEP_STATE):
            verdict = await capture(sdk, 'absent-' + where.rsplit('/', 1)[1],
                                    'test ! -e {0} && test ! -L {0} && echo plain-absent'.format(where))
            p.require(verdict == 'plain-absent',
                      where + ' pre-exists before the watch stage; STOP')
        line, size = await wait_for_gate_line(sdk, offset)
        end = await sdk_state(sdk, 'watch-final')
        await protected_hashes(sdk)
        for where in (p.UEP_CONFIG, UEP_STATE):
            verdict = await capture(sdk, 'final-absent-' + where.rsplit('/', 1)[1],
                                    'test ! -e {0} && test ! -L {0} && echo plain-absent'.format(where))
            p.require(verdict == 'plain-absent',
                      where + ' exists after the watch stage; a store happened; STOP')
        p.require(state['boot'] == end['boot'] == p.BOOT, 'boot changed during watch; STOP')
        log('watch-absent-both-times', config='absent', state='absent')
        succeed(STAGE, STATUS, KIND, observed_line=line[-160:], log_size=size)
    finally:
        await sdk.disconnect()


if __name__ == '__main__':
    asyncio.run(main())
