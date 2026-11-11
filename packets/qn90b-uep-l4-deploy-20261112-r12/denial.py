"""One-execution unsigned denial control, driver-side over the SDK shell (uid 901).

This is the L1 packet's proven context and recipe: a fresh owned staging
directory, an exclusive hash-pinned write of the 5196-byte ELF, an exact
metadata check, one bounded execution under the enforcer, then cleanup. The
only accepted result is `native_exit=126` with "Permission denied" and NO
success marker.
"""
import base64
import hashlib
import re
import secrets
from shlex import quote

import packet as p
from stage_lib import capture, log

MARKER = 'QN90B_UEP_NATIVE_PROBE_OK'


def bounded(arguments, seconds):
    """Wait for our child and watchdog; signal only a child still owned by this shell."""
    p.require(seconds in (5,), 'unapproved denial deadline')
    command = ' '.join(map(quote, arguments))
    return """(
set +e
ulimit -c 0
read -r owner unused < /proc/self/stat || exit 70
case "$owner" in ''|*[!0-9]*) exit 70;; esac
owned_child() {
    test -r /proc/$child/status || return 1
    while read -r field value rest; do
        if test "$field" = PPid:; then test "$value" = "$owner"; return $?; fi
    done < /proc/$child/status
    return 1
}
""" + command + """ &
child=$!
(
    /bin/sleep """ + str(seconds) + """
    if owned_child; then
        kill -TERM "$child"
        /bin/sleep 1
        if owned_child; then kill -KILL "$child"; fi
    fi
) </dev/null &
watchdog=$!
wait "$child"
status=$?
wait "$watchdog"
exit "$status"
)
"""


def stage_guard(stage, canonical, receipt):
    p.require(re.fullmatch(r'/home/owner/share/tmp/sdk_tools/denial-[a-f0-9]{16}', stage),
              'unsafe denial stage path')
    p.require(canonical == p.CANON + '/' + stage.rsplit('/', 1)[1], 'canonical stage mismatch')
    p.require(re.fullmatch(r'[0-9]+:[1-9][0-9]*', receipt), 'invalid creation receipt')
    return ('test ! -L ' + quote(stage) + '\ncd -P ' + quote(stage)
            + '\ntest "$PWD" = ' + quote(canonical)
            + '\ntest "$(stat -c %d:%i:%u:%a .)" = ' + quote(receipt + ':901:700'))


def process_guard(stage):
    pattern = r'^' + re.escape(stage) + r'/uep-probe[.]elf( |$)'
    return 'set +e\npgrep -f ' + quote(pattern) + '\nr=$?\nset -e\ntest "$r" = 1'


async def run(sdk, save):
    """Stage, execute once, verify the permission denial, clean up."""
    p.require(p.digest(p.NATIVE) == p.NATIVE_SHA, 'native control hash changed')
    name = 'denial-' + secrets.token_hex(8)
    stage = p.ROOT + '/' + name
    canonical = p.CANON + '/' + name
    command = ('set -eu\ncd -P ' + quote(p.ROOT) + '\ntest "$PWD" = ' + quote(p.CANON)
               + '\ntest ! -e ' + quote(stage) + '\ntest ! -L ' + quote(stage)
               + '\numask 077\nmkdir -- ' + quote(stage) + '\nstat -c %d:%i ' + quote(stage))
    receipt = (await capture(sdk, 'denial-stage-create', command)).strip()
    stage_guard(stage, canonical, receipt)
    save('denial-stage-created', path=stage, receipt=receipt)

    data = p.NATIVE.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    encoded = base64.b64encode(data).decode('ascii')
    upload = ('set -eu -o pipefail\n' + stage_guard(stage, canonical, receipt)
              + '\numask 077\nprintf %s ' + quote(encoded)
              + ' | base64 -d | /usr/bin/dd of=uep-probe.elf conv=excl oflag=nofollow'
              + ' status=noxfer 2>/dev/null\ntest ! -L uep-probe.elf && test -f uep-probe.elf'
              + '\nsha256sum uep-probe.elf')
    out = (await capture(sdk, 'denial-upload', upload)).strip()
    p.require(out == digest + '  uep-probe.elf', 'denial upload digest mismatch')
    save('denial-uploaded', sha256=digest, size=len(data))

    native = stage + '/uep-probe.elf'
    execute = ('set -eu\n' + stage_guard(stage, canonical, receipt)
               + '\nulimit -c 0\nchmod 700 -- uep-probe.elf'
               + '\ntest "$(stat -c %F:%u:%a:%h uep-probe.elf)" = "regular file:901:700:1"'
               + '\ntest "$(sha256sum uep-probe.elf)" = ' + quote(digest + '  uep-probe.elf')
               + '\nset +e\n' + bounded([native], 5) + ' 2>&1\nr=$?'
               + '\nprintf "native_exit=%s\\n" "$r"\nexit 0')
    output = await capture(sdk, 'denial-execute', execute)
    save('denial-output', output=output)
    p.require(MARKER not in output, 'unsigned probe executed; STOP for review')
    p.require(output.splitlines()[-1:] == ['native_exit=126'] and 'Permission denied' in output,
              'unsigned execution was not the expected permission denial')

    listing = (await capture(sdk, 'denial-cleanup-inspection',
                             'set -eu\n' + stage_guard(stage, canonical, receipt) + '\n'
                             + process_guard(stage)
                             + "\nfind . -mindepth 1 -maxdepth 1 -printf '%f\\n' | sort")).splitlines()
    p.require(listing == ['uep-probe.elf'], 'unexpected denial stage contents; preserve for inspection')
    cleanup = ('set -eu\n' + stage_guard(stage, canonical, receipt) + '\n' + process_guard(stage)
               + '\ntest ! -L uep-probe.elf\ntest "$(stat -c %F:%u:%h uep-probe.elf)" = "regular file:901:1"'
               + '\ntest "$(sha256sum uep-probe.elf)" = ' + quote(digest + '  uep-probe.elf')
               + '\nrm -- uep-probe.elf\ncd /\nrmdir -- ' + quote(stage)
               + '\ntest ! -e ' + quote(stage) + '\ntest ! -L ' + quote(stage) + '\necho staging-clean')
    p.require((await capture(sdk, 'denial-cleanup', cleanup)).strip() == 'staging-clean',
              'denial staging removal unverified')
    save('denial-passed', exit=126, marker_absent=True, staging_cleaned=True)
    log('denial-control-passed')
