"""r16: anchored read-only certification, then one kernel-witnessed denial.

No gate operation, config creation, relay reconciliation, root session or reboot.
--readiness is owner-run later: reads only, no attempt or marker creation.
"""
import asyncio
import sys
from shlex import quote

import packet as p
import denial
import stage_common as sc
from inspect_tv import BridgeSDK, save
from stage_lib import (OneAttempt, capture, fields, log, marker_for, protect_seal,
                       protected_hashes, record_failure, refuse_if_stopped, repo_head, succeed)

STAGE = 'LIVE_ARM_CERTIFY'
STATUS = 'stage-status-certify.json'


async def read_only(sdk):
    """A single pass. Missing/partial/mismatched evidence is STOP, never polled."""
    st = await sc.state(sdk, p.NEW_MANAGER_SHA, 'r16-certification')
    p.require(st['boot'] == p.CERTIFY_BOOT, 'certification boot changed; STOP')
    p.require(st['gate'] == 'absent', 'gate config is not absent; STOP')
    p.require(st['module'] == 'present' and st['backup'] == 'present',
              'module or v5.18 backup missing; STOP')
    p.require(st['budget'] == 'present', 'pinned stale budget missing; STOP')
    proof_text, proof_digest = await sc.read_proof(sdk, p.CERTIFY_PROOF)
    sc.assert_proof(p.CERTIFY_BOOT, proof_text)
    expected_budget = p._content_hash('boot=' + p.STALE_BOOT + ' clear=1 restore=0')
    budget = fields(await capture(sdk, 'r16-stale-budget',
        'set -eu\ntest ! -L ' + quote(p.UEP_STATE)
        + '\ntest -f ' + quote(p.UEP_STATE)
        + "\nprintf 'meta='; stat -c %F:%u:%g:%h " + quote(p.UEP_STATE)
        + "\nprintf 'sha='; sha256sum " + quote(p.UEP_STATE)))
    p.require(budget == {'meta': 'regular file:0:0:1',
                        'sha': expected_budget + '  ' + p.UEP_STATE},
              'budget is not the exact stale edc9debc clear=1 restore=0 receipt; STOP')
    p.require(p.STALE_BOOT != st['boot'], 'stale budget was accepted as fresh; STOP')
    await sc.module_files(sdk, 'r16-module-files')
    await sc.manager_files(sdk, 'r16-manager-files')
    # -f and ! -L before hashing the original backup pair; never restore it.
    backups = {'com.samsung.tv.ghservice.dll': p.PREV_MANAGER_SHA,
               'com.samsung.tv.ghservice.runtimeconfig.json': p.PREV_MANAGER_RC_SHA}
    command = 'set -eu\ntest ! -L ' + quote(p.BACKUP_DIR) + '\ntest -d ' + quote(p.BACKUP_DIR) + '\n'
    for name, digest in backups.items():
        path = p.BACKUP_DIR + '/' + name
        command += ('test ! -L ' + quote(path) + '\ntest -f ' + quote(path)
                    + '\ntest "$(sha256sum ' + quote(path) + ')" = '
                    + quote(digest + '  ' + path) + '\n')
    p.require((await capture(sdk, 'r16-backup-pair', command + 'echo BACKUP_PAIR_PINNED')).strip()
              == 'BACKUP_PAIR_PINNED', 'v5.18 backup verification missing; STOP')
    await protected_hashes(sdk)
    lines = await sc.module_gate(sdk, 'disable', 'r16-module-log', probes=1)
    p.require(lines == [p.RECEIPT_ABSENT_BOOT, 'uep gate module exit=0'],
              'module log is not the exact absent-config boot receipt and exit=0; STOP')
    await sc.assert_flag_read(sdk, p.FINGERPRINT, 'r16-enforcing-read')
    end = await sc.state(sdk, p.NEW_MANAGER_SHA, 'r16-certification-end')
    p.require(all(end[key] == st[key] for key in
                  ('boot', 'gate', 'budget', 'module', 'backup', 'proof_hash')),
              'certification anchor changed during read-only pass; STOP')
    log('r16-read-only-certified', boot=p.CERTIFY_BOOT, proof=proof_digest,
        budget='stale; never fresh', protected_files=24, TV_writes=0)
    return proof_digest


async def main(readiness=False):
    OneAttempt(STAGE).require_unused()  # before SDK construction or any cleanup
    refuse_if_stopped()
    if not readiness:
        marker_for(STAGE)
    protect_seal()
    p.require(repo_head() == p.COMMIT, 'source HEAD changed; STOP')
    attempt = OneAttempt(STAGE)
    if not readiness:
        attempt.take()
    try:
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            proof = await read_only(sdk)
            if not readiness:
                await denial.run(sdk, save)
                await read_only(sdk)  # no retry: final independent read pass
        finally:
            await sdk.disconnect()
        if readiness:
            log('r16-readiness-passed', boot=p.CERTIFY_BOOT, attempts=0, TV_writes=0)
        else:
            succeed(STAGE, STATUS, 'certify', boot=p.CERTIFY_BOOT, proof_sha256=proof,
                    denial='kernel exact path + append-only uptime window + EPERM/EACCES',
                    native_exit=None, protected_files=24, no_gate_op=True, no_reboot=True)
    except BaseException as error:
        record_failure(STAGE, STATUS, 'readiness' if readiness else 'certify',
                       type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    p.require(sys.argv[1:] in ([], ['--readiness']), 'usage: certify.py [--readiness]')
    asyncio.run(main(readiness=sys.argv[1:] == ['--readiness']))
