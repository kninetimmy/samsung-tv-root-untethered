"""Stage 2 LIVE_ARM_ACTIVE: replace read-only with active, owner reboot,
verify the guarded clear and confirm it survives the boot.

The activation op only rewrites the verified read-only bytes. The post-reboot
boot must show the module's clear receipt, the exact cleared fingerprint, a
fresh-boot budget entry `clear=1 restore=0`, and a still-cleared fingerprint at
+10 and +30 minutes. Any re-enforcing read is a STOP: v5.19 has one invocation
per boot and no retry.
"""
import asyncio
import json
import re
import sys

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
import stage_common as sc
from stage_lib import (log, marker_for, OneAttempt, protect_seal, protected_hashes,
                       record_failure, refuse_if_stopped, succeed)
from stage_session import GateSession

STAGE = 'LIVE_ARM_ACTIVE'
STATUS = 'stage-status-active.json'
KIND = 'active'
LATE_READ_DELAYS = (600, 1200)   # +10 min, then +30 min from the first clear read
BOOT = None
PROOF_SHA = None


def anchor_from_prior():
    """Stage 2 runs on the boot stage 1 verified, never the inspection boot."""
    global BOOT, PROOF_SHA
    path = p.HERE / 'stage-status-install.json'
    p.require(path.is_file(), 'stage 1 (install) status is missing; run install first')
    prior = json.loads(path.read_text(encoding='utf-8'))
    p.require(prior.get('stage') == 'install' and prior.get('passed') is True,
              'stage 1 did not pass; the active stage cannot anchor')
    BOOT = prior['fresh_boot']
    PROOF_SHA = prior['fresh_proof_sha256']
    p.require(re.fullmatch(r'[0-9a-f-]{36}', BOOT), 'stage 1 boot anchor malformed')
    p.require(re.fullmatch(r'[0-9a-f]{64}', PROOF_SHA), 'stage 1 proof anchor malformed')
    log('active-anchor', boot=BOOT, proof=PROOF_SHA)


def prerequisites():
    refuse_if_stopped()
    openssl = p.require_openssl()
    anchor_from_prior()
    log('active-prerequisites-verified', stage_boot=BOOT, openssl=openssl)


async def preflight():
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'active-baseline')
        p.require(st['boot'] == BOOT, 'boot left the inspected boot; re-inspect; STOP')
        p.require(st['gate'] == 'present' and st['module'] == 'present', 'install state missing; STOP')
        p.require(st['budget'] == 'absent', 'budget state exists before activation; STOP')
        gate = await sc.gate_config(sdk, 'active-gate-config')
        p.require(gate['content'] == p.UEP_READONLY_CONTENT, 'activation requires read-only content; STOP')
        p.require(gate['hash'] == p.UEP_READONLY_SHA + '  ' + p.UEP_CONFIG,
                  'read-only content hash mismatch; STOP')
        await sc.module_files(sdk, 'active-module-files')
        await sc.manager_files(sdk, 'active-manager-files')
        await protected_hashes(sdk)
        await sc.read_proof(sdk, PROOF_SHA)
    finally:
        await sdk.disconnect()


async def post_boot_checks(fresh):
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'active-post-boot')
        p.require(st['boot'] == fresh, 'boot poll lost the fresh boot')
        p.require(st['gate'] == 'present' and st['budget'] == 'present' and st['module'] == 'present',
                  'active boot state is incomplete; STOP')
        gate = await sc.gate_config(sdk, 'active-gate-post-boot')
        p.require(gate['content'] == p.UEP_ACTIVE_CONTENT, 'boot changed the active content; STOP')
        claimed_boot, clears, restores = sc.parse_budget(await sc.budget(sdk, 'active-budget'))
        p.require(claimed_boot == fresh, 'budget state does not claim the fresh boot; STOP')
        p.require((clears, restores) == (1, 0), 'budget does not record exactly one clear; STOP')
        await protected_hashes(sdk)
        proof_text, proof_digest = await sc.read_proof(sdk)
        sc.assert_proof(fresh, proof_text)
        await sc.module_gate(sdk, 'active', 'module-gate-active')
        await sc.assert_flag_read(sdk, p.CLEARED, 'active-first-flag-read')
    finally:
        await sdk.disconnect()
    # Late rearm reads hold no idle SDK session across the long waits.
    for index, delay in enumerate(LATE_READ_DELAYS):
        await asyncio.sleep(delay)
        late = BridgeSDK(save)
        try:
            await late.connect()
            await sc.assert_flag_read(late, p.CLEARED, 'active-late-flag-read-' + str(index + 1))
        finally:
            await late.disconnect()
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        end = await sc.state(sdk, p.NEW_MANAGER_SHA, 'active-final')
        p.require(end['boot'] == fresh, 'boot changed inside the active stage')
        await protected_hashes(sdk)
    finally:
        await sdk.disconnect()
    return proof_digest


async def main():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        await preflight()
        session = GateSession(
            BridgeSDK(save), save, BOOT, PROOF_SHA, 'gate-config-active', {},
            120, manager_sha=p.NEW_MANAGER_SHA)
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'activation closeout incomplete; retain evidence')
        session.require_stdout('GATE_CONFIG_ACTIVE_VERIFIED', 'GATE_ACTIVE_COMPLETE')
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'active-post-op')
            p.require(st['boot'] == BOOT, 'boot changed during activation; STOP')
            gate = await sc.gate_config(sdk, 'active-gate-post-op')
            p.require(gate['content'] == p.UEP_ACTIVE_CONTENT, 'active content not written; STOP')
            p.require(gate['hash'] == p.UEP_ACTIVE_SHA + '  ' + p.UEP_CONFIG,
                      'active content hash mismatch; STOP')
            p.require(st['budget'] == 'absent', 'activation must not run the gate; STOP')
        finally:
            await sdk.disconnect()
        prior_boot = BOOT
        fresh = await sc.await_new_boot(prior_boot, lambda: BridgeSDK(save))
        p.require(fresh is not None,
                  'no new boot within the awaiting bound; the active config is present and the '
                  'clear is unverified; STOP')
        p.require(fresh != prior_boot, 'the active boot must be a distinct boot')
        proof_digest = await post_boot_checks(fresh)
        succeed(STAGE, STATUS, KIND, fresh_boot=fresh, fresh_proof_sha256=proof_digest,
                cleared=p.CLEARED, late_reads='+10min/+30min',
                attempt_utc=attempt.path.read_text().strip())
        log('stage-complete', stage=KIND, boot=fresh)
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
