"""Optional two-directory tidy, separately armed; never edits evidence receipts."""
import asyncio
import json
from shlex import quote

import packet as p
import certify
from inspect_tv import BridgeSDK, save
from stage_lib import (OneAttempt, capture, marker_for, protect_seal,
                       record_failure, refuse_if_stopped, succeed)

STAGE = 'LIVE_ARM_TIDY'
STATUS = 'stage-status-tidy.json'
PATH = p.ROOT + '/denial-fd9fa25930776ce9'
CANONICAL = p.CANON + '/denial-fd9fa25930776ce9'
MTIME = '1794343800'  # 2026-11-10T20:50:00Z
TARGETS = (
    dict(path=PATH, canonical=CANONICAL, receipt=None, assets={
        'uep-probe.elf': (p.NATIVE_SHA, '700', 5196, MTIME)}),
    dict(path=p.ROOT + '/denial-5bd20c32c9b13f14',
         canonical=p.CANON + '/denial-5bd20c32c9b13f14', receipt='45845:25356', assets={
        # r17 receipts.jsonl:463,481,499, bound by evidence/r17-incident.json.
        'uep-probe.elf': (p.NATIVE_SHA, '700', 5196, None),
        'DenialRunner.dll': ('dca73c8af979de32e27364cd3527ca28c7017b38b47058cfe3cc05896840ab57', '600', 9216, None),
        'DenialRunner.runtimeconfig.json': ('ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38', '600', 154, None)}),
)


def inspect(target):
    path, canonical, assets = target['path'], target['canonical'], target['assets']
    text = ('test ! -L ' + quote(path) + ' || refuse symlink\n'
        + 'test -d ' + quote(path) + ' || refuse directory\n'
        + 'cd -P ' + quote(path) + '\ntest "$PWD" = ' + quote(canonical) + ' || refuse cwd\n'
        + 'test "$(stat -c %F:%u:%a .)" = directory:901:700 || refuse directory-metadata\n'
        + 'test "$(find . -mindepth 1 -maxdepth 1 -printf x | wc -c)" -eq ' + str(len(assets)) + ' || refuse inventory-count\n'
        + 'inventory=$(find . -mindepth 1 -maxdepth 1 -printf \'%f\\n\' | sort)\n'
        + 'printf \'TIDY_INVENTORY %s\\n%s\\n\' ' + quote(path) + ' "$inventory"\n'
        + 'test "$inventory" = ' + quote('\n'.join(sorted(assets))) + ' || refuse inventory\n')
    if target['receipt'] is not None:
        text += 'test "$(stat -c %d:%i .)" = ' + quote(target['receipt']) + ' || refuse creation-receipt\n'
    for name, (sha, mode, size, mtime) in assets.items():
        text += ('test ! -L ' + quote(name) + ' || refuse child-symlink\n'
            + 'test -f ' + quote(name) + ' || refuse file-type\n'
            + 'test "$(stat -c %u:%a:%h:%s ' + quote(name) + ')" = '
            + quote('901:' + mode + ':1:' + str(size)) + ' || refuse file-metadata\n'
            + 'test "$(sha256sum ' + quote(name) + ')" = ' + quote(sha + '  ' + name) + ' || refuse hash\n')
        if mtime is not None:
            text += 'test "$(stat -c %Y ' + quote(name) + ')" = ' + quote(mtime) + ' || refuse mtime\n'
    return text


def command():
    """All shape checks precede the first unlink. No rm -r, glob, or retry."""
    text = ('set -eu -o pipefail\nrefuse() { echo "TIDY_REFUSAL: $*" >&2; exit 69; }\n'
        + 'test "$(id -u)" = 901 || refuse uid\n'
        + 'test "$(cat /proc/sys/kernel/random/boot_id)" = ' + quote(p.CERTIFY_BOOT) + ' || refuse boot\n'
        + 'cd -P ' + quote(p.ROOT) + '\ntest "$PWD" = ' + quote(p.CANON) + ' || refuse root\n')
    # Inspect BOTH directories before any unlink; re-inspect before each removal.
    for index, target in enumerate(TARGETS):
        text += inspect(target) + 'identity' + str(index) + '=$(stat -c %d:%i:%u:%a .)\n'
    for index, target in enumerate(TARGETS):
        path = quote(target['path'])
        text += (inspect(target)
            + 'test ! -L ' + path + ' || refuse redirected-before-unlink\n'
            + 'test "$(stat -c %d:%i:%u:%a ' + path + ')" = "$identity' + str(index) + '" || refuse identity\n'
            + ''.join('unlink -- ' + quote(name) + '\n' for name in target['assets'])
            + 'cd /\nrmdir -- ' + path + '\ntest ! -e ' + path + ' || refuse remains\n'
            + 'test ! -L ' + path + ' || refuse link-remains\n')
    return text + 'echo DENIAL_STAGES_REMOVED_PROVISIONAL\n'


def removal_receipt():
    inventories = ['TIDY_INVENTORY ' + target['path'] + '\n' + '\n'.join(sorted(target['assets']))
                   for target in TARGETS]
    return '\n'.join(inventories + inventories + ['DENIAL_STAGES_REMOVED_PROVISIONAL'])


def absence_command():
    return ('set -eu\ntest "$(id -u)" = 901\n'
            + 'test "$(cat /proc/sys/kernel/random/boot_id)" = ' + quote(p.CERTIFY_BOOT)
            + '\ncd -P ' + quote(p.ROOT) + '\ntest "$PWD" = ' + quote(p.CANON)
            + '\n' + ''.join('test ! -e ' + quote(target['path']) + '\ntest ! -L '
                            + quote(target['path']) + '\n' for target in TARGETS)
            + 'echo DENIAL_STAGES_ABSENT_FRESH_SESSION\n')


async def main():
    OneAttempt(STAGE).require_unused()
    refuse_if_stopped()
    marker_for(STAGE)
    protect_seal()
    # Runtime output is not sealed; bind its claims to immutable pins and then
    # re-certify live. Never use this output alone as device-state authority.
    prior = json.loads((p.HERE / certify.STATUS).read_text())
    p.require(prior.get('stage') == 'certify' and prior.get('passed') is True
              and prior.get('boot') == p.CERTIFY_BOOT and prior.get('proof_sha256') == p.CERTIFY_PROOF,
              'successful anchored certification required before optional tidy; STOP')
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            await certify.read_only(sdk)
            out = await capture(sdk, 'denial-stages-unlink-rmdir', command())
            p.require(out.strip() == removal_receipt(), 'two-directory provisional receipt missing')
        finally:
            await sdk.disconnect()
        fresh = BridgeSDK(save)
        try:
            await fresh.connect()
            out = await capture(fresh, 'denial-stages-fresh-absence', absence_command())
            p.require(out.strip() == 'DENIAL_STAGES_ABSENT_FRESH_SESSION', 'two-directory fresh absence missing; STOP')
        finally:
            await fresh.disconnect()
        succeed(STAGE, STATUS, 'tidy', paths=[target['path'] for target in TARGETS], fresh_session_absence=True)
        (p.HERE / 'SPENT').write_text('r18 certified and optional two-directory tidy completed; never replay.\n')
    except BaseException as error:
        record_failure(STAGE, STATUS, 'tidy', type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
