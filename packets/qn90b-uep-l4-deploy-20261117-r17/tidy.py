"""Optional, separately armed final task-46 cleanup; never edits evidence receipts."""
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


def command():
    """All shape checks precede the first unlink. No rm -r, glob, or retry."""
    return ('set -eu -o pipefail\nrefuse() { echo "TIDY_REFUSAL: $*" >&2; exit 69; }\n'
        + 'test "$(id -u)" = 901 || refuse uid\n'
        + 'test "$(cat /proc/sys/kernel/random/boot_id)" = ' + quote(p.CERTIFY_BOOT) + ' || refuse boot\n'
        + 'cd -P ' + quote(p.ROOT) + '\ntest "$PWD" = ' + quote(p.CANON) + ' || refuse root\n'
        + 'test ! -L ' + quote(PATH) + ' || refuse symlink\n'
        + 'test -d ' + quote(PATH) + ' || refuse directory\n'
        + 'cd -P ' + quote(PATH) + '\ntest "$PWD" = ' + quote(CANONICAL) + ' || refuse cwd\n'
        + 'test "$(stat -c %F:%u:%a .)" = directory:901:700 || refuse directory-metadata\n'
        + 'identity=$(stat -c %d:%i:%u:%a .)\n'
        + 'test "$(find . -mindepth 1 -maxdepth 1 -printf x | wc -c)" -eq 1 || refuse inventory-count\n'
        + 'test "$(find . -mindepth 1 -maxdepth 1 -printf \'%f\\n\')" = uep-probe.elf || refuse inventory\n'
        + 'test ! -L uep-probe.elf || refuse child-symlink\ntest -f uep-probe.elf || refuse file-type\n'
        + 'test "$(stat -c %F:%u:%a:%h:%s:%Y uep-probe.elf)" = '
        + quote('regular file:901:700:1:5196:' + MTIME) + ' || refuse file-metadata\n'
        + 'test "$(sha256sum uep-probe.elf)" = ' + quote(p.NATIVE_SHA + '  uep-probe.elf') + ' || refuse hash\n'
        + 'test ! -L ' + quote(PATH) + ' || refuse redirected-before-unlink\n'
        + 'test "$(stat -c %d:%i:%u:%a ' + quote(PATH) + ')" = "$identity" || refuse identity\n'
        + 'unlink -- uep-probe.elf\ncd /\nrmdir -- ' + quote(PATH)
        + '\ntest ! -e ' + quote(PATH) + ' || refuse remains\ntest ! -L ' + quote(PATH)
        + ' || refuse link-remains\necho TASK46_REMOVED_PROVISIONAL\n')


def absence_command():
    return ('set -eu\ntest "$(id -u)" = 901\n'
            + 'test "$(cat /proc/sys/kernel/random/boot_id)" = ' + quote(p.CERTIFY_BOOT)
            + '\ncd -P ' + quote(p.ROOT) + '\ntest "$PWD" = ' + quote(p.CANON)
            + '\ntest ! -e ' + quote(PATH) + '\ntest ! -L ' + quote(PATH)
            + '\necho TASK46_ABSENT_FRESH_SESSION\n')


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
            out = await capture(sdk, 'task46-unlink-rmdir', command())
            p.require(out.strip() == 'TASK46_REMOVED_PROVISIONAL', 'task46 provisional receipt missing')
        finally:
            await sdk.disconnect()
        fresh = BridgeSDK(save)
        try:
            await fresh.connect()
            out = await capture(fresh, 'task46-fresh-absence', absence_command())
            p.require(out.strip() == 'TASK46_ABSENT_FRESH_SESSION', 'task46 fresh absence missing; STOP')
        finally:
            await fresh.disconnect()
        succeed(STAGE, STATUS, 'tidy', path=PATH, fresh_session_absence=True)
        (p.HERE / 'SPENT').write_text('r16 certified and optional task46 tidy completed; never replay.\n')
    except BaseException as error:
        record_failure(STAGE, STATUS, 'tidy', type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
