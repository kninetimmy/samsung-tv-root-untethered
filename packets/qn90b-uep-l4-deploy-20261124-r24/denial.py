"""One-execution unsigned denial control, driver-side over the SDK shell (uid 901).

Kernel evidence is a complete committed-record bracket on one persistent fd.
A direct managed Process.Start distinguishes execve refusal
(EPERM/EACCES, native_exit=null) from ANY started child. No shell text/$? pin.
"""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r24-pycache-')

import base64
import binascii
import gzip
import hashlib
import io
import json
import re
import secrets
from shlex import quote

import packet as p
from stage_lib import capture, log

MARKER = 'QN90B_UEP_NATIVE_PROBE_OK'
EXPECTED_CAP_EFF = '0000000000200040'
EXPECTED_SMACK = 'User'


def kernel_log(encoded, save):
    """Hash the saved encoded string's exact UTF-8 bytes, then the raw envelope."""
    save('denial-evidence-transport', encoded=encoded,
         sha256=hashlib.sha256(encoded.encode('utf-8')).hexdigest())
    try:
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            # JSON contains base64 framing, not just raw records. This structural
            # budget is separate from the 1MiB combined raw-record bound below.
            raw = stream.read(2097153)
        save('denial-kernel-after', raw_b64=base64.b64encode(raw).decode('ascii'),
             bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        p.require(len(raw) <= 2097152, 'kernel-envelope-framing-bound')
        return json.loads(raw.decode('utf-8', 'strict'))
    except (binascii.Error, OSError, EOFError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise p.Stop('kernel-capture-transport-decode-incomplete: ' + type(error).__name__) from error


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
    return ("refuse_kmsg() { echo \"KERNEL_ACCESS_REFUSAL: $*\" >&2; exit 69; }\n"
            + 'kmsg_restrict=$(cat /proc/sys/kernel/dmesg_restrict) || refuse_kmsg dmesg-restrict-read-failed\n'
            + 'test "$kmsg_restrict" = 0 || refuse_kmsg dmesg-restrict-drift\n'
            + 'kmsg_meta=$(stat -c %F:%u:%g:%a:%U:%G /dev/kmsg) || refuse_kmsg node-metadata-read-failed\n'
            + 'test "$kmsg_meta" = '
            + quote('character special file:0:1901:660:root:log') + ' || refuse_kmsg node-metadata-drift\n'
            + 'kmsg_groups=$(id -G) || refuse_kmsg owning-group-read-failed\n'
            + 'case " $kmsg_groups " in *" 1901 "*) ;; *) refuse_kmsg owning-group-drift;; esac\n'
            + 'kmsg_label=$(chsmack /dev/kmsg) || refuse_kmsg node-smack-read-failed\n'
            + 'test "$kmsg_label" = ' + quote('/dev/kmsg access="*"')
            + ' || refuse_kmsg node-smack-drift\n'
            + 'exec /usr/bin/dotnet ' + quote(runner) + ' ' + quote(native) + '\n')


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


def assess_kernel(after, canonical, start, end, save=None, rotation_observed=None):
    """Uptime strings are diagnostic, never the causal membership test."""
    if isinstance(after, str):
        details = dict(capacity_state='unknown', rotation_observed=rotation_observed,
                       bytes=len(after.encode()), diagnostic_uptime=[start, end])
        if save is not None:
            save('kernel-capture-completeness-unproved', **details)
        raise p.Stop('kernel-capture-completeness-unproved: ' + json.dumps(details, sort_keys=True))
    p.require(isinstance(after, dict) and set(after) == {'version', 'exec', 'kernel_capture'}
              and type(after['version']) is int and after['version'] == 1, 'kernel-envelope-version-or-shape')
    cap = after['kernel_capture']
    p.require(isinstance(cap, dict), 'kernel-capture-shape')
    provenance = cap.get('failure_operation')
    if cap.get('errno') == 32:
        p.require(isinstance(provenance, dict) and provenance.get('syscall') == 'read'
                  and type(provenance.get('raw_return')) is int and provenance['raw_return'] == -1
                  and provenance.get('phase') in ('pre-fence', 'post-fence')
                  and type(provenance.get('execution_invoked')) is bool
                  and provenance['execution_invoked'] == cap.get('execution_invoked')
                  and provenance['execution_invoked'] == (provenance['phase'] == 'post-fence'),
                  'kernel-EPIPE-provenance-invalid')
        expected = ('kernel-pre-acquisition-EPIPE' if provenance['phase'] == 'pre-fence'
                    else 'kernel-mid-bracket-overrun-EPIPE')
        p.require(cap.get('failure') == expected and cap.get('capture_complete') is False,
                  'kernel-EPIPE-phase-name-mismatch')
    p.require(cap.get('errno') == 0, 'kernel-pre-acquisition-EPIPE' if cap.get('errno') == 32
              and provenance['phase'] == 'pre-fence' else 'kernel-mid-bracket-overrun-EPIPE'
              if cap.get('errno') == 32 else 'kernel-reader-errno')
    p.require(cap.get('capture_complete') is True and cap.get('failure') is None,
              'kernel-capture-incomplete: ' + str(cap.get('failure')))
    p.require(cap.get('pre_eagain') is True, 'kernel-pre-fence-missing')
    p.require(cap.get('post_eagain') is True, 'kernel-post-fence-missing')
    p.require(cap.get('same_fd') is True, 'kernel-cursor-continuity-unproved')
    p.require(cap.get('execution_invoked') is True and provenance is None,
              'kernel-execution-provenance-invalid')
    events = cap.get('resync_events')
    p.require(isinstance(events, list) and len(events) <= 1, 'kernel-resync-count-invalid')
    p.require(cap.get('resync_durable') is bool(events), 'kernel-resync-durability-unproved')
    if events:
        ev = events[0]
        p.require(isinstance(ev, dict) and set(ev) == {'syscall', 'raw_return', 'phase', 'execution_invoked',
                  'errno', 'fd', 'pre_records', 'pre_bytes', 'baseline_exists', 'fence_exists', 'elapsed_ms'}
                  and ev['syscall'] == 'read' and type(ev['raw_return']) is int and ev['raw_return'] == -1
                  and type(ev['errno']) is int and ev['errno'] == 32 and ev['phase'] == 'pre-fence'
                  and ev['execution_invoked'] is False and ev['baseline_exists'] is False
                  and ev['fence_exists'] is False and type(ev['pre_records']) is int and ev['pre_records'] == 0
                  and type(ev['pre_bytes']) is int and ev['pre_bytes'] == 0
                  and type(ev['fd']) is int and ev['fd'] >= 0
                  and type(ev['elapsed_ms']) is int and 0 <= ev['elapsed_ms'] < 2000,
                  'kernel-resync-gates-invalid')
    profile = cap.get('profile', {})
    p.require(isinstance(profile, dict), 'kernel-profile-shape')
    p.require(profile.get('boot') == p.CERTIFY_BOOT, 'kernel-boot-drift')
    p.require(profile.get('dmesg_restrict') == '0', 'kernel-access-dmesg-restrict-drift')
    p.require(profile.get('smack') == EXPECTED_SMACK, 'kernel-access-smack-drift')
    p.require(profile.get('CapEff') == EXPECTED_CAP_EFF
              and re.fullmatch(r'901\s+901\s+901\s+901', profile.get('Uid', ''))
              and re.fullmatch(r'901\s+901\s+901\s+901', profile.get('Gid', '')),
              'kernel-access-helper-identity-drift')
    p.require('1901' in profile.get('Groups', '').split(), 'kernel-access-owning-group-drift')
    p.require(cap.get('post_profile') == profile, 'kernel-access-profile-drift')
    p.require(cap.get('capacity_state') == 'unknown', 'kernel-capacity-unmeasured')
    records = cap.get('records')
    p.require(isinstance(records, list) and len(records) <= 16384, 'kernel-record-count-bound')
    def record(encoded):
        try:
            raw = base64.b64decode(encoded, validate=True)
            text = raw.decode('utf-8', 'strict')
        except (ValueError, TypeError, UnicodeError) as error:
            raise p.Stop('kernel-record-decode-incomplete') from error
        p.require(0 < len(raw) < 8192, 'kernel-record-oversize-or-empty')
        match = re.fullmatch(r'([0-9]{1,3}),([0-9]{1,20}),([0-9]{1,20}),-;([^\r\n\x00]*)\n', text)
        p.require(match is not None, 'kernel-record-malformed-or-unsupported')
        priority, sequence, timestamp = map(int, match.group(1, 2, 3))
        p.require(priority <= 191 and sequence <= 2**64-1 and timestamp <= 2**64-1,
                  'kernel-record-header-range')
        return priority, sequence, timestamp, match[4], raw
    baseline = record(cap.get('baseline'))
    previous = baseline
    pre_bytes, post_bytes, pre_records = (cap.get(key) for key in ('pre_bytes', 'post_bytes', 'pre_records'))
    p.require(type(pre_bytes) is int and type(post_bytes) is int and type(pre_records) is int
              and 1 <= pre_records <= 16384 and pre_bytes >= len(baseline[4]) and post_bytes >= 0,
              'kernel-capture-counters-invalid')
    total = 0
    message = ('[Verification fail] file ' + canonical + '/uep-probe.elf'
               + ' is not signed. Sign it.(fsname:vdfs, mnt_flags:1020)')
    hits = []
    for index, encoded in enumerate(records):
        current = record(encoded)
        total += len(current[4])
        if index == 0:
            p.require(current[1] == baseline[1] + 1,
                      f'kernel-sequence-gap: expected={baseline[1]+1} observed={current[1]}')
        else:
            p.require(current[1] == previous[1] + 1,
                      f'kernel-sequence-gap: expected={previous[1]+1} observed={current[1]}')
        p.require(current[2] >= previous[2], 'kernel-timestamp-reversal')
        p.require(not re.search(r'callbacks? suppressed|messages? suppressed|messages? dropped|dropped [0-9]+|[0-9]+ messages? lost|printk.*(?:suppress|drop|lost)|ratelimit',
                                current[3], re.I), 'kernel-emission-suppressed')
        if re.fullmatch(re.escape(message), current[3]):
            p.require(current[0] // 8 == 0, 'kernel-witness-not-kernel-origin')
            hits.append(current[4].decode())
        previous = current
    p.require(pre_bytes + total <= 1048576, 'kernel-capture-raw-bound')
    p.require(total == post_bytes, 'kernel-post-byte-count-mismatch')
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
    save('denial-attempt-context', packet='r24', predecessor='r23',
          earlier_attempt_packet='r17', earlier_attempt_spent=True, additional_attempt=True)
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
    start = (await capture(sdk, 'denial-window-start', 'cat /proc/uptime')).split()[0]
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
    code, output = await sdk.capture(execute, evidence_label='denial-evidence')
    save('denial-output', wrapper_exit=code, output=output)
    p.require(code != 69, output.strip())  # named shell access refusal, already durably saved
    after = kernel_log(output.strip(), save)
    end = (await capture(sdk, 'denial-window-end', 'cat /proc/uptime')).split()[0]
    save('denial-attempt-window', start=start, end=end, path=canonical)
    line = assess_kernel(after, canonical, start, end, save)
    result = assess_exec(code, json.dumps(after['exec']))

    if after['kernel_capture']['resync_events']:
        # The journal is created only by the helper, not uploaded or overwritten.
        # Pin its exact persisted bytes independently before any cleanup/pass.
        journal = json.dumps(after['kernel_capture']['resync_events'][0], separators=(',', ':')) + '\n'
        name = 'DenialRunner.resync.json'
        hashes[name] = hashlib.sha256(journal.encode('utf-8')).hexdigest()
        assets[name] = None
        check = ('set -eu\n' + stage_guard(stage, canonical, receipt)
                 + '\ntest ! -L ' + quote(name) + '\ntest -f ' + quote(name)
                 + '\ntest "$(stat -c %u:%h ' + quote(name) + ')" = 901:1\n'
                 + 'sha256sum ' + quote(name))
        observed = (await capture(sdk, 'denial-resync-journal', check)).strip()
        p.require(observed == hashes[name] + '  ' + name, 'kernel-resync-journal-mismatch')
        save('denial-resync-journal-verified', sha256=hashes[name], raw_b64=base64.b64encode(journal.encode()).decode())

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
               + ''.join('unlink -- ' + quote(n) + '\n' for n in hashes)
               + 'cd /\nrmdir -- ' + quote(stage)
               + '\ntest ! -e ' + quote(stage) + '\ntest ! -L ' + quote(stage) + '\necho staging-clean')
    p.require((await capture(sdk, 'denial-cleanup', cleanup)).strip() == 'staging-clean',
              'denial staging removal unverified')
    save('denial-passed', native_exit=None, errno=result['errno'], exec_started=False,
         authoritative_line=line, marker_absent=True, staging_cleaned=True)
    log('denial-control-passed')
