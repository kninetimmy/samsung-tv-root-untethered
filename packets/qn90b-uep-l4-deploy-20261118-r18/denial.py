"""One-execution unsigned denial control, driver-side over the SDK shell (uid 901).

Kernel evidence for this exact canonical path in a retained attempt window
is authoritative. A direct managed Process.Start distinguishes execve refusal
(EPERM/EACCES, native_exit=null) from ANY started child. No shell text/$? pin.
"""
import base64
import binascii
import gzip
import hashlib
import io
import json
import math
import re
import secrets
from shlex import quote

import packet as p
from stage_lib import capture, log

MARKER = 'QN90B_UEP_NATIVE_PROBE_OK'
KERNEL_COMMAND = "set -eu -o pipefail\ndmesg | gzip -c | base64 | tr -d '\\012'"


async def kernel_log(sdk, label, save):
    # The SDK receipt cap is 128KiB; carry the full log compressed, never tail
    # away the endpoints needed for retention accounting. Save before inspecting.
    encoded = await capture(sdk, label, KERNEL_COMMAND)
    save(label + '-transport', encoded=encoded)
    try:
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(1048577)
        save(label, output=raw.decode('utf-8', 'replace'), bytes=len(raw),
             lines=len(raw.splitlines()))
        p.require(len(raw) <= 1048576, 'kernel log exceeds decoded bound; STOP')
        return raw.decode('utf-8', 'strict')
    except (binascii.Error, OSError, EOFError, UnicodeDecodeError) as error:
        raise p.Stop('kernel log transport/decode failed; STOP: ' + type(error).__name__) from error


def bounded(arguments, seconds):
    """Managed direct exec owns its child and bounds wait/output, not bash wait.

    An execve refusal returns protocol exit 77 with native_exit=null. The SDK
    trailer propagates 77 unchanged; it is never called a native child exit.
    """
    p.require(seconds in (5,), 'unapproved denial deadline')
    p.require(len(arguments) == 1, 'one denial executable required')
    native = arguments[0]
    p.require(re.fullmatch(re.escape(p.ROOT) + r'/denial-[a-f0-9]{16}/uep-probe\.elf', native),
              'unsafe native path')
    runner = native.rsplit('/', 1)[0] + '/DenialRunner.dll'
    return 'exec /usr/bin/dotnet ' + quote(runner) + ' ' + quote(native) + '\n'


def assess_exec(code, output):
    p.require(MARKER not in output, 'unsigned probe executed; STOP for review')
    try:
        result = json.loads(output)
    except json.JSONDecodeError as error:
        raise p.Stop('direct exec accounting is not one JSON result; STOP') from error
    p.require(set(result) == {'exec_started', 'errno', 'native_exit', 'timed_out', 'stdout', 'stderr'},
              'direct exec accounting keys changed; STOP')
    p.require(result['exec_started'] is False and result['native_exit'] is None,
              'native process started or refusal masked as child exit; STOP')
    p.require(type(result['errno']) is int and result['errno'] in (1, 13),
              'exec refusal is not EPERM or EACCES; STOP')
    p.require(result['timed_out'] is False and result['stdout'] == '' and result['stderr'] == '',
              'refused-before-exec output or timeout shape changed; STOP')
    p.require(code == 77, 'direct exec refusal trailer was masked; STOP')
    return result


def assess_kernel(after, canonical, start, end, save=None):
    """One read: require both window endpoints, not a preserved older prefix."""
    p.require(len(after.encode('utf-8')) <= 1048576, 'kernel log exceeds bound; STOP')
    p.require(math.isfinite(start) and math.isfinite(end) and 0 <= start <= end,
              'kernel attempt uptime window malformed; STOP')
    lines = after.splitlines()
    oldest = re.match(r'\[\s*([0-9]+\.[0-9]+)\] ', lines[0]) if lines else None
    newest = re.match(r'\[\s*([0-9]+\.[0-9]+)\] ', lines[-1]) if lines else None
    p.require(oldest is not None and newest is not None,
              'kernel retention endpoints missing timestamps; STOP')
    t_oldest, t_newest = float(oldest[1]), float(newest[1])
    p.require(math.isfinite(t_oldest) and math.isfinite(t_newest) and t_oldest <= t_newest,
              'kernel retention endpoints malformed; STOP')
    details = dict(observed_retention_span=t_newest - t_oldest, required_span=end - start,
                   t_oldest=t_oldest, t_newest=t_newest, start=start, end=end,
                   bytes=len(after.encode('utf-8')), lines=len(lines))
    if save is not None:
        save('denial-kernel-retention', **details)
    for retained, outcome in ((t_oldest <= start, 'kernel-window-not-retained'),
                              (t_newest >= end, 'kernel-window-end-not-retained')):
        if not retained:
            if save is not None:
                save(outcome, **details)
            raise p.Stop(outcome + ': ' + json.dumps(details, sort_keys=True))
    message = ('[Verification fail] file ' + canonical + '/uep-probe.elf'
               + ' is not signed. Sign it.(fsname:vdfs, mnt_flags:1020)')
    hits = []
    for line in lines:
        match = re.fullmatch(r'\[\s*([0-9]+\.[0-9]+)\] ' + re.escape(message), line)
        if match:
            p.require(start <= float(match[1]) <= end, 'kernel denial outside attempt uptime; STOP')
            hits.append(line)
    p.require(len(hits) == 1, 'missing or duplicate exact-path kernel signature denial; STOP')
    return hits[0]


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
    save('denial-attempt-context', packet='r18', predecessor='r17',
         predecessor_attempt_spent=True, additional_attempt=True)
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

    assets = {'uep-probe.elf': p.NATIVE, 'DenialRunner.dll': p.DENIAL_RUNNER,
              'DenialRunner.runtimeconfig.json': p.DENIAL_RC}
    hashes = {}
    for filename, path in assets.items():
        data = path.read_bytes()
        digest = hashes[filename] = hashlib.sha256(data).hexdigest()
        encoded = base64.b64encode(data).decode('ascii')
        upload = ('set -eu -o pipefail\n' + stage_guard(stage, canonical, receipt)
                  + '\numask 077\nprintf %s ' + quote(encoded)
                  + ' | base64 -d | /usr/bin/dd of=' + quote(filename) + ' conv=excl oflag=nofollow'
                  + ' status=noxfer 2>/dev/null\ntest ! -L ' + quote(filename)
                  + '\ntest -f ' + quote(filename) + '\nsha256sum ' + quote(filename))
        out = (await capture(sdk, 'denial-upload-' + filename, upload)).strip()
        p.require(out == digest + '  ' + filename, 'denial upload digest mismatch: ' + filename)
        save('denial-uploaded', filename=filename, sha256=digest, size=len(data))

    native = stage + '/uep-probe.elf'
    start = float((await capture(sdk, 'denial-window-start', 'cat /proc/uptime')).split()[0])
    digest = hashes['uep-probe.elf']
    execute = ('set -eu\n' + stage_guard(stage, canonical, receipt)
               + '\nulimit -c 0\nchmod 700 -- uep-probe.elf'
               + '\ntest "$(stat -c %F:%u:%a:%h uep-probe.elf)" = "regular file:901:700:1"'
               + '\ntest "$(sha256sum uep-probe.elf)" = ' + quote(digest + '  uep-probe.elf')
               + '\n' + ''.join('test ! -L ' + quote(n) + '\n'
                    + 'test "$(sha256sum ' + quote(n) + ')" = ' + quote(h + '  ' + n) + '\n'
                    for n, h in hashes.items())
               + bounded([native], 5))
    save('sdk-request', name='denial-execute', command=execute)
    code, output = await sdk.capture(execute)
    save('denial-output', wrapper_exit=code, output=output)
    end = float((await capture(sdk, 'denial-window-end', 'cat /proc/uptime')).split()[0])
    after = await kernel_log(sdk, 'denial-kernel-after', save)
    save('denial-attempt-window', start=start, end=end, path=canonical)
    result = assess_exec(code, output)
    line = assess_kernel(after, canonical, start, end, save)

    listing = (await capture(sdk, 'denial-cleanup-inspection',
                             'set -eu\n' + stage_guard(stage, canonical, receipt) + '\n'
                             + process_guard(stage)
                             + "\nfind . -mindepth 1 -maxdepth 1 -printf '%f\\n' | sort")).splitlines()
    p.require(listing == sorted(assets), 'unexpected denial stage contents; preserve for inspection')
    cleanup = ('set -eu\n' + stage_guard(stage, canonical, receipt) + '\n' + process_guard(stage)
               + '\ntest ! -L uep-probe.elf\ntest -f uep-probe.elf\ntest "$(stat -c %u:%h uep-probe.elf)" = "901:1"'
               + '\ntest "$(sha256sum uep-probe.elf)" = ' + quote(digest + '  uep-probe.elf')
               + '\n' + ''.join('test ! -L ' + quote(n) + '\n'
                    + 'test -f ' + quote(n) + '\n'
                    + 'test "$(stat -c %u:%h ' + quote(n) + ')" = 901:1\n'
                    + 'test "$(sha256sum ' + quote(n) + ')" = ' + quote(h + '  ' + n) + '\n'
                    for n, h in hashes.items())
               + 'unlink -- uep-probe.elf\nunlink -- DenialRunner.dll\n'
               + 'unlink -- DenialRunner.runtimeconfig.json\ncd /\nrmdir -- ' + quote(stage)
               + '\ntest ! -e ' + quote(stage) + '\ntest ! -L ' + quote(stage) + '\necho staging-clean')
    p.require((await capture(sdk, 'denial-cleanup', cleanup)).strip() == 'staging-clean',
              'denial staging removal unverified')
    save('denial-passed', native_exit=None, errno=result['errno'], exec_started=False,
         authoritative_line=line, marker_absent=True, staging_cleaned=True)
    log('denial-control-passed')
