"""Stage 2: WATCH — the absent-config negative control, receipted from
durable evidence. SDK reads only.

r1's live-catch design required a manager relaunch alive at a poll instant;
the headless relaunches live under one poll interval, so the catch was
structurally impossible (memhub decision 22, task 35). r2 instead receipts
the durable evidence the boot itself writes:

1. agent.log's gate-event lines on THIS boot: every accepted line is the
   absent-config summary `uep gate (boot|reopen): config absent (enforcing;
   no action)` written after the current boot started; any other gate shape,
   any `uep gate EXCEPTION`, and any malformed line stops the stage. The
   acceptance is bound to the observation by refetching within the interval
   and by the boot-start epoch captured in the same session.
2. uptime evidence that the boot has actually been running long enough to
   have produced the gate lines (the automatic proof already did).
3. no gate config, no budget state file, the whole 25-file protected
   register byte-identical, v5.18 installed, bridge active, boot identical
   on both sides of the observation.

Neither stage nor awaiting driver writes anything to the TV.
"""
import asyncio
import json
import sys

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
from stage_lib import (agent_log_lines, agent_log_lines_from_offset, capture,
                       record_failure, marker_for, log, OneAttempt, protect_seal,
                       refuse_if_stopped, sdk_state, succeed, protected_hashes,
                       gate_event_assessment, gate_stamp_seconds, boot_clock, UEP_STATE)

STAGE = 'LIVE_ARM_WATCH'
STATUS = 'stage-status-watch.json'
KIND = 'watch'
POLL_SECONDS = 20
OBSERVE_SECONDS = 3 * 60


def prerequisites():
    refuse_if_stopped()
    for name in ('deployment-result.json', 'post-deploy-verification.json', 'post-mortem-20261108.md'):
        p.require((p.HERE / name).is_file(), 'r1 stage-1 provenance receipt missing: ' + name)
    receipt = json.loads((p.HERE / 'deployment-result.json').read_text(encoding='utf-8'))
    p.require(receipt.get('installed') is True and receipt.get('sha256') == p.DEPLOY_RECEIPT_SHA,
              'r1 deploy receipt wrong')
    p.require(receipt.get('boot') == p.DEPLOY_RECEIPT_BOOT, 'r1 deploy receipt boot mismatch')
    p.require(p.BOOT is not None, 'the fresh r2 inspection must establish the current boot')
    closeout = json.loads((p.HERE / 'post-deploy-verification.json').read_text(encoding='utf-8'))
    p.require(closeout.get('verdict') == 'stage1-state-verified', 'r1 closeout verification lacks its verdict')
    p.require(closeout.get('bridge_service') == 'active', 'r1 closeout lacks the bridge state')
    log('watch-prerequisites-verified', inspection_boot=p.BOOT)


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
            state = await sdk_state(sdk, 'watch-baseline')
            p.require(state['boot'] == p.BOOT, 'boot left the inspected boot; re-inspect before stage 2; STOP')
            await protected_hashes(sdk)
            boot_epoch, interval_epoch = await boot_clock(sdk)
            for where in (p.UEP_CONFIG,):
                verdict = await capture(sdk, 'absent-' + where.rsplit('/', 1)[1],
                                        'test ! -e {0} && test ! -L {0} && echo plain-absent'.format(where))
                p.require(verdict == 'plain-absent',
                          where + ' pre-exists before the watch stage; STOP')
            p.require(state['gate_state'] == 'absent', 'budget state pre-exists before watch; STOP')
            log_size = int(state['log_size'])
            # The receipt slice: everything this boot wrote into agent.log.
            lines = await agent_log_lines(sdk, 200)
            gate = gate_event_assessment(lines, 'watch',
                                          boot_epoch=boot_epoch, epoch_at_fetch=interval_epoch)
            p.require(gate, 'no durable absent-config gate evidence on this boot')
            stamps = [gate_stamp_seconds(line, boot_epoch, interval_epoch) for line in gate]
            absent_count = len(gate)
            log('watch-durable-evidence-verified',
                gate_lines=absent_count, first_stamp=stamps[0], last_stamp=stamps[-1])
        finally:
            await sdk.disconnect()
        # Observation interval: any growth during the window is re-fetched and
        # re-assessed with the same rules, independent of process sampling.
        await asyncio.sleep(OBSERVE_SECONDS)
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            end = await sdk_state(sdk, 'watch-final')
            p.require(end['boot'] == p.BOOT, 'boot changed during watch; STOP')
            await protected_hashes(sdk)
            grew = int(end['log_size']) > log_size
            p.require(int(end['log_size']) >= log_size, 'agent.log shrank during watch; STOP')
            _, final_epoch = await boot_clock(sdk)
            if grew:
                growth_lines = await agent_log_lines_from_offset(sdk, log_size)
                growth_gate = gate_event_assessment(growth_lines, 'watch', needle_required=False,
                                                     boot_epoch=boot_epoch, epoch_at_fetch=final_epoch)
                [gate_stamp_seconds(line, boot_epoch, final_epoch) for line in growth_gate]
                log('watch-interval-growth-assessed', lines=len(growth_lines))
                absent_count += len(growth_gate)
            verdict = await capture(sdk, 'final-absent-gate-config',
                                    'test ! -e {0} && test ! -L {0} && echo plain-absent'.format(p.UEP_CONFIG))
            p.require(verdict == 'plain-absent',
                      p.UEP_CONFIG + ' exists after the watch stage; a store happened; STOP')
            verdict = await capture(sdk, 'final-absent-budget-state',
                                    'test ! -e ' + UEP_STATE + ' && test ! -L ' + UEP_STATE + ' && echo plain-absent')
            p.require(verdict == 'plain-absent',
                      UEP_STATE + ' exists after the watch stage; a store happened; STOP')
            log('watch-absent-both-ends', config='absent', state='absent')
            succeed(STAGE, STATUS, KIND, absent_lines=absent_count, boot=p.BOOT,
                    observed_growth=bool(grew), attempt_utc=attempt.path.read_text().strip())
        finally:
            await sdk.disconnect()
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise

if __name__ == '__main__':
    asyncio.run(main())

