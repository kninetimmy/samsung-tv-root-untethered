"""Stage 5: DISABLE — remove the gate config, owner-approved reboot, verify
enforcing restored. May be deferred past this packet's session.

The removal runs on the boot the ACTIVE stage receipted (its `fresh_boot` and
`fresh_proof_sha256`), never on the original spent r1 boot: the r2 agent
takes the expected boot through the authenticated op command
(`gate-remove:<boot id>`) and asserts it inside the root shell before the
removal body (review finding 2; the baked script itself no longer pins a
boot that was unknown at prep time). After the removal the owner reboots
once more; the driver verifies a THIRD, distinct boot: fresh automatic proof
(one normalized line, digest-equal to the receipted capture, content-locked
to the new boot and the zero identity), an absent-config boot gate line, the
budget state file absent or stale (never claiming the fresh boot), the fdet
fingerprint back to enforcing, and the hash-locked uep-probe DENIED by UEP
(native_exit=126, exact marker absent) with the same staged, owned, bounded
probe machinery the admission round used (review finding 4d, owner-approved
acceptance criterion).
"""
import asyncio
import json
import re
import sys
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
from activate import (ActiveSession, await_new_boot, read_proof, assert_proof,
                      assert_flag_read, staged_probe_run)
from stage_lib import (agent_log_lines, capture, record_failure, fields, marker_for,
                       log, OneAttempt, protect_seal, refuse_if_stopped,
                       sdk_state, succeed, protected_hashes,
                       gate_event_assessment, boot_clock, UEP_STATE)

STAGE = 'LIVE_ARM_DISABLE'
STATUS = 'stage-status-disable.json'
KIND = 'disable'


def prerequisites():
    refuse_if_stopped()
    for name in ('stage-status-watch.json', 'stage-status-dirread.json'):
        status = json.loads((p.HERE / name).read_text(encoding='utf-8'))
        p.require(status.get('passed') is True, name + ' stage did not pass')
    active = json.loads((p.HERE / 'stage-status-active.json').read_text(encoding='utf-8'))
    p.require(active.get('stage') == 'active' and active.get('passed') is True,
              'the active stage did not pass')
    fresh_boot = active.get('fresh_boot')
    p.require(isinstance(fresh_boot, str) and re.fullmatch('[0-9a-f-]{36}', fresh_boot),
              'the active stage did not receipt a valid fresh boot; the disable stage cannot anchor; STOP')
    digest = active.get('fresh_proof_sha256')
    p.require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest),
              'the active stage did not receipt its fresh proof digest; STOP')
    p.require(fresh_boot != p.BOOT, 'active-stage receipt must name a new boot')
    log('disable-prerequisites-verified', fresh_boot=fresh_boot)
    return fresh_boot, digest


class DisableSession(ActiveSession):
    GATE_OP = 'gate-remove'
    MATERIALS = Path(p.HERE / 'execution/gate-materials-disable')

    async def run_gate(self):
        # The expected boot travels through the authenticated op command; the
        # r2 root agent asserts it inside the root shell (review finding 2).
        result = await self.connection.execute('gate-remove:' + self.expected_boot, 12)
        self.save('gate-remove-receipt', exit=result.exit_code, timed_out=result.timed_out,
                  stdout=result.stdout, stderr=result.stderr)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr
                  and 'GATE_CONFIG_REMOVED_COMPLETE\n' in result.stdout,
                  'gate-remove did not complete; no retry')
        p.require(re.search(r'^GATE_ABSENT$', result.stdout, re.M), 'removal must end absent')



async def main():
    marker_for(STAGE)
    protect_seal()
    fresh_boot, fresh_proof_digest = prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        # Preflight (SDK only): the removal binds to the active-stage boot by
        # re-collecting its complete root proof right here.
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            state = await sdk_state(sdk, 'disable-baseline-state')
            p.require(state['boot'] == fresh_boot,
                      'the TV did not boot into the active-stage boot; the disable stage cannot anchor; STOP')
            await protected_hashes(sdk)
            content = await capture(sdk, 'gate-config-content', 'cat -- ' + p.UEP_CONFIG)
            p.require(content == 'active', 'the active gate state (config content active) is required first; STOP')
            proof_text, digest = await read_proof(sdk, fresh_proof_digest)
            assert_proof(fresh_boot, proof_text)
            meta = fields(await capture(sdk, 'gate-config-meta', (
                "printf 'meta='; stat -c '%u:%g:%a:%h' -- " + p.UEP_CONFIG + "\n"
                "printf 'label='; chsmack " + p.UEP_CONFIG + "\n")))
            p.require(meta['meta'] == '0:0:644:1', 'gate config metadata changed; STOP')
            p.require(meta['label'] == p.UEP_CONFIG + ' access="_"', 'gate config label changed; STOP')
        finally:
            await sdk.disconnect()
        session = DisableSession(BridgeSDK(save), save, fresh_boot, fresh_proof_digest)
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
        prior_boot = fresh_boot
        # Relay teardown after root shutdown + ordinary verification.
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            session.sdk = sdk
            await session.baseline()
            state = await sdk_state(sdk, 'disable-post-op')
            p.require(state['gate_config'] == 'absent', 'gate config present after removal; STOP')
            p.require(state['boot'] == prior_boot, 'boot identity changed during disable; STOP')
            stale = await capture(sdk, 'gate-state-pre',
                                  'cat -- ' + UEP_STATE + ' 2>/dev/null || echo budget-absent')
            log('disable-pre-boot-budget', budget=stale.strip()[:80])
        finally:
            await sdk.disconnect()
        fresh = await await_new_boot(prior_boot)
        p.require(fresh is not None,
                  'no new boot within the awaiting bound; config is absent, current enforcement unverified; STOP')
        p.require(fresh != prior_boot, 'the removal must be observed on a distinct boot')
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            post = await sdk_state(sdk, 'disable-post-boot')
            p.require(post['gate_config'] == 'absent', 'gate config reappeared; STOP')
            p.require(post['boot'] == fresh, 'boot poll lost the fresh boot')
            await protected_hashes(sdk)
            proof_text, digest = await read_proof(sdk)
            assert_proof(fresh, proof_text)
            lines = await agent_log_lines(sdk, 120)
            boot_epoch, epoch = await boot_clock(sdk)
            gate = gate_event_assessment(lines, 'disable', regime='legacy',
                                          boot_epoch=boot_epoch, epoch_at_fetch=epoch)
            p.require(gate, 'the absent-config boot gate line is missing; the disable stage cannot continue')
            stale = (await capture(sdk, 'gate-state-post',
                                   'cat -- ' + UEP_STATE + ' 2>/dev/null || echo budget-absent')).strip()
            if stale != 'budget-absent':
                stale_boot = re.match(r'boot=([0-9a-f-]{36})', stale)
                p.require(stale_boot and stale_boot[1] != fresh,
                          'budget state claims the fresh boot; the absent-config path must not have touched it')
                log('disable-stale-budget-verified', claimed_boot=stale_boot[1])
            else:
                log('disable-budget-absent-verified')
            await assert_flag_read(sdk, p.FINGERPRINT)
            # The documented denial test: the same staged, hash-locked probe
            # must be refused by the restored enforcer (native_exit=126, no
            # marker) with identical owned/bounded staging (review 4d).
            await staged_probe_run(sdk, fresh, 'l5-', 126, None)
            end = await sdk_state(sdk, 'disable-final')
            await protected_hashes(sdk)
            p.require(post['boot'] == end['boot'] == fresh, 'boot changed inside the disable stage')
            succeed(STAGE, STATUS, KIND, fresh_boot=fresh, attempt_utc=attempt.path.read_text().strip())
            # Terminal stage of the packet: write the one-use receipt.
            (p.HERE / 'SPENT').write_text('All r2 stage attempts consumed; the packet never replays.\n',
                                          encoding='ascii', newline='\n')
            log('packet-spent', stage=KIND)
        finally:
            await sdk.disconnect()
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
