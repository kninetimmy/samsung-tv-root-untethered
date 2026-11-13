"""Stage 1 LIVE_ARM_INSTALL: deploy v5.19, create the read-only config, prove
root-context execution with one read, owner reboot, verify the boot-time module.

The install op is a single reviewed script: it refuses on any state other than
the inspected baseline, backs up the v5.18 manager, installs the v5.19 manager +
root module, creates the read-only config and runs the host once as root. The
post-reboot boot must show the module's read-only receipt, an untouched
enforcing fingerprint and an absent budget state. No flag value is written in
this stage.
"""
import asyncio
import sys

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
import stage_common as sc
from stage_lib import (log, marker_for, OneAttempt, protect_seal, protected_hashes,
                       record_failure, refuse_if_stopped, succeed)
from stage_session import GateSession

STAGE = 'LIVE_ARM_INSTALL'
STATUS = 'stage-status-install.json'
KIND = 'install'


def prerequisites():
    p.require(False, 'r15 inherits the completed r14 install; stage 1 must never replay')
    refuse_if_stopped()
    openssl = p.require_openssl()
    p.require(p.BOOT is not None, 'the fresh r9 inspection must establish the current boot')
    log('install-prerequisites-verified', inspection_boot=p.BOOT, openssl=openssl)


async def preflight():
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.PREV_MANAGER_SHA, 'install-baseline')
        p.require(st['boot'] == p.BOOT, 'boot left the inspected boot; re-inspect; STOP')
        for key in ('gate', 'budget', 'module', 'backup'):
            p.require(st[key] == 'absent', 'install baseline is not clean: ' + key + ' present; STOP')
        await protected_hashes(sdk)
        await sc.read_proof(sdk, p.PROOF_SHA)
    finally:
        await sdk.disconnect()


async def same_boot_checks():
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'install-post-op')
        p.require(st['boot'] == p.BOOT, 'boot changed during install; STOP')
        p.require(st['gate'] == 'present' and st['module'] == 'present' and st['backup'] == 'present',
                  'install did not land the expected state; STOP')
        p.require(st['budget'] == 'absent', 'the read-only install wrote budget state; STOP')
        gate = await sc.gate_config(sdk, 'install-gate-config')
        p.require(gate['content'] == p.UEP_READONLY_CONTENT, 'install must leave read-only content; STOP')
        p.require(gate['hash'] == p.UEP_READONLY_SHA + '  ' + p.UEP_CONFIG,
                  'read-only content hash mismatch; STOP')
        await sc.module_files(sdk, 'install-module-files')
        await sc.manager_files(sdk, 'install-manager-files')
        await protected_hashes(sdk)
    finally:
        await sdk.disconnect()


async def post_boot_checks(fresh):
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'install-post-boot')
        p.require(st['boot'] == fresh, 'boot poll lost the fresh boot')
        p.require(st['gate'] == 'present' and st['module'] == 'present' and st['backup'] == 'present',
                  'installed state vanished after reboot; STOP')
        p.require(st['budget'] == 'absent', 'the read-only boot created budget state; STOP')
        gate = await sc.gate_config(sdk, 'install-gate-post-boot')
        p.require(gate['content'] == p.UEP_READONLY_CONTENT, 'boot changed the read-only content; STOP')
        await protected_hashes(sdk)
        proof_text, proof_digest = await sc.read_proof(sdk)
        sc.assert_proof(fresh, proof_text)
        await sc.module_gate(sdk, 'install', 'module-gate-install')
        await sc.assert_flag_read(sdk, p.FINGERPRINT)
        end = await sc.state(sdk, p.NEW_MANAGER_SHA, 'install-final')
        p.require(end['boot'] == fresh, 'boot changed inside the install stage')
        p.require(end['budget'] == 'absent', 'final budget state drifted; STOP')
        await protected_hashes(sdk)
    finally:
        await sdk.disconnect()
    return proof_digest


async def main():
    with p.preflight(STAGE, KIND):
        marker_for(STAGE)
        protect_seal()
    prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        await preflight()
        session = GateSession(
            BridgeSDK(save), save, p.BOOT, p.PROOF_SHA, 'gate-install',
            {'manager.dll': p.NEW,
             'manager.runtimeconfig.json': p.NEW_RC,
             'UepGateHost.dll': p.HOST,
             'UepGateHost.runtimeconfig.json': p.HOST_RC,
             'boot.sh': p.MODULE_BOOT,
             'module.json': p.MODULE_JSON},
            180, manager_sha=p.PREV_MANAGER_SHA)
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'install closeout incomplete; retain evidence')
        session.require_stdout(
            'GATE_BACKUP_COMPLETE', 'GATE_MANAGER_INSTALLED', 'GATE_MODULE_INSTALLED',
            'GATE_READONLY_CREATED', 'GATE_MANUAL_READ_OK', 'GATE_INSTALL_COMPLETE',
            p.RECEIPT_READONLY_MANUAL, p.LOG_READONLY.format('manual', p.FINGERPRINT))
        await same_boot_checks()
        prior_boot = p.BOOT
        fresh = await sc.await_new_boot(prior_boot, lambda: BridgeSDK(save))
        p.require(fresh is not None,
                  'no new boot within the awaiting bound; v5.19 is installed but its boot path is '
                  'unverified; STOP')
        p.require(fresh != prior_boot, 'the installed boot path must be observed on a distinct boot')
        proof_digest = await post_boot_checks(fresh)
        succeed(STAGE, STATUS, KIND, fresh_boot=fresh, fresh_proof_sha256=proof_digest,
                manager_sha=p.NEW_MANAGER_SHA, attempt_utc=attempt.path.read_text().strip())
        log('stage-complete', stage=KIND, boot=fresh)
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    with p.preflight(STAGE, KIND):
        raise p.Stop('r15 inherits the completed r14 install; stage 1 must never replay')
