"""Stage 3 LIVE_ARM_DISABLE: remove the active config, owner reboot, verify the
enforcing-only baseline, then run the hash-locked unsigned denial control once.

The removal op only deletes the verified active bytes. The fresh boot must
show the absent-config module receipt, an enforcing fingerprint, no fresh-boot
budget claim, and the 25-file register intact; the denial control then runs in
the SDK context (uid 901) and must exit 126 with no success marker. Stage 3 is
terminal and writes SPENT.
"""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r22-pycache-')

import asyncio
import json
import re

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
import denial
import stage_common as sc
import recovery
from stage_lib import (log, marker_for, OneAttempt, protect_seal, protected_hashes,
                       record_failure, refuse_if_stopped, succeed)
from stage_session import GateSession

STAGE = 'LIVE_ARM_DISABLE'
STATUS = 'stage-status-disable.json'
KIND = 'disable'
BOOT = None
PROOF_SHA = None


def anchor_from_prior():
    """Historical driver only. Runtime stage-status-active.json cannot be sealed
    in its producing packet; this content check is NOT a digest attestation.
    r16 never consumes it: certify.py uses the sealed CERTIFY_BOOT/PROOF pins.
    """
    global BOOT, PROOF_SHA
    path = p.HERE / 'stage-status-active.json'
    p.require(path.is_file(), 'stage 2 (active) status is missing; run active first')
    prior = json.loads(path.read_text(encoding='utf-8'))
    p.require(prior.get('stage') == 'active' and prior.get('passed') is True,
              'stage 2 did not pass; the disable stage cannot anchor')
    BOOT = prior['fresh_boot']
    PROOF_SHA = prior['fresh_proof_sha256']
    p.require(re.fullmatch(r'[0-9a-f-]{36}', BOOT), 'stage 2 boot anchor malformed')
    p.require(re.fullmatch(r'[0-9a-f]{64}', PROOF_SHA), 'stage 2 proof anchor malformed')
    log('disable-anchor', boot=BOOT, proof=PROOF_SHA)


async def prerequisites():
    OneAttempt(STAGE).require_unused()
    refuse_if_stopped()
    openssl = p.require_openssl()
    anchor_from_prior()
    p.require(p.digest(p.NATIVE) == p.NATIVE_SHA, 'native denial probe hash changed; STOP')
    await recovery.reconcile(lambda: BridgeSDK(save), save, BOOT, PROOF_SHA)
    log('disable-prerequisites-verified', stage_boot=BOOT, openssl=openssl)


async def preflight():
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'disable-baseline')
        p.require(st['boot'] == BOOT, 'boot left the inspected boot; re-inspect; STOP')
        p.require(st['gate'] == 'present' and st['module'] == 'present',
                  'active install state missing; STOP')
        gate = await sc.gate_config(sdk, 'disable-gate-config')
        p.require(gate['content'] == p.UEP_ACTIVE_CONTENT, 'removal requires active content; STOP')
        p.require(gate['hash'] == p.UEP_ACTIVE_SHA + '  ' + p.UEP_CONFIG,
                  'active content hash mismatch; STOP')
        # r10 M5: the active-boot budget receipt is REQUIRED here. r9 accepted
        # an absent budget, so the disappearance of the safety state that the
        # active stage necessarily created did not stop the removal.
        p.require(st['budget'] == 'present',
                  'active-boot budget receipt is missing; STOP')
        claimed_boot, clears, restores = sc.parse_budget(await sc.budget(sdk, 'disable-budget-pre'))
        p.require(claimed_boot == BOOT and (clears, restores) == (1, 0),
                  'budget state is not the active-boot receipt; STOP')
        await sc.module_files(sdk, 'disable-module-files')
        await sc.manager_files(sdk, 'disable-manager-files')
        await protected_hashes(sdk)
        await sc.read_proof(sdk, PROOF_SHA)
    finally:
        await sdk.disconnect()


async def post_boot_checks(fresh):
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'disable-post-boot')
        p.require(st['boot'] == fresh, 'boot poll lost the fresh boot')
        p.require(st['gate'] == 'absent', 'gate config reappeared; STOP')
        p.require(st['module'] == 'present', 'module vanished; STOP')
        if st['budget'] == 'present':
            claimed_boot, clears, restores = sc.parse_budget(await sc.budget(sdk, 'disable-budget-post'))
            p.require(claimed_boot != fresh, 'budget state claims the fresh boot; STOP')
            p.require((clears, restores) == (1, 0), 'stale budget state is not the active boot receipt; STOP')
            log('disable-stale-budget-verified', claimed_boot=claimed_boot)
        await protected_hashes(sdk)
        proof_text, proof_digest = await sc.read_proof(sdk)
        sc.assert_proof(fresh, proof_text)
        await sc.module_gate(sdk, 'disable', 'module-gate-disable')
        await sc.assert_flag_read(sdk, p.FINGERPRINT)
        await denial.run(sdk, save)
        end = await sc.state(sdk, p.NEW_MANAGER_SHA, 'disable-final')
        p.require(end['boot'] == fresh, 'boot changed inside the disable stage')
        p.require(end['gate'] == 'absent', 'final gate config is not absent; STOP')
        await protected_hashes(sdk)
    finally:
        await sdk.disconnect()
    return proof_digest


async def main():
    with p.preflight(STAGE, KIND):
        marker_for(STAGE)
        protect_seal()
    await prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        await preflight()
        session = GateSession(
            BridgeSDK(save), save, BOOT, PROOF_SHA, 'gate-remove', {},
            60, manager_sha=p.NEW_MANAGER_SHA)
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'removal closeout incomplete; retain evidence')
        session.require_stdout('GATE_CONFIG_REMOVED_COMPLETE', 'GATE_ABSENT')
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'disable-post-op')
            p.require(st['boot'] == BOOT, 'boot changed during removal; STOP')
            p.require(st['gate'] == 'absent', 'gate config present after removal; STOP')
        finally:
            await sdk.disconnect()
        prior_boot = BOOT
        fresh = await sc.await_new_boot(prior_boot, lambda: BridgeSDK(save))
        p.require(fresh is not None,
                  'no new boot within the awaiting bound; config is absent and current enforcement '
                  'is unverified; STOP')
        p.require(fresh != prior_boot, 'the removal must be observed on a distinct boot')
        proof_digest = await post_boot_checks(fresh)
        succeed(STAGE, STATUS, KIND, fresh_boot=fresh, fresh_proof_sha256=proof_digest,
                denial_exit=126, attempt_utc=attempt.path.read_text().strip())
        (p.HERE / 'SPENT').write_text(
            'The v5.19 gate config was removed, the enforcing-only baseline and the unsigned '
            'denial control were verified; the packet never replays.\n',
            encoding='ascii', newline='\n')
        log('packet-spent', stage=KIND)
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    with p.preflight(STAGE, KIND):
        raise p.Stop('r16 never removes a gate or waits for reboot; use certify.py after review')
