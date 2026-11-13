"""Offline r16/r17 cases plus r18 retention/tidy. No real SDK/TV/marker/attempt.

The host user can read fixture children: an explicit shim denies uid901 child
reads/listing, while real Bash runs the production metadata-only command. This
models the DAC boundary, not live TV validation.
"""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r22-pycache-')

import asyncio
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
from shlex import quote
from unittest.mock import patch

import packet as p
import certify
import denial
import driver_shim as ds
import relay_checks as rc
import stage_common as sc
import stage_lib as sl
import tidy


def stop(fn, message):
    try:
        fn()
    except p.Stop:
        return
    raise AssertionError(message)


def exec_result(**changes):
    result = dict(exec_started=False, errno=1, native_exit=None, timed_out=False, stdout='', stderr='')
    result.update(changes)
    return json.dumps(result)


CANON = p.CANON + '/denial-0123456789abcdef'
MESSAGE = ('[Verification fail] file ' + CANON
        + '/uep-probe.elf is not signed. Sign it.(fsname:vdfs, mnt_flags:1020)')
LINE = '6,103,95750000,-;' + MESSAGE + '\n'
PROFILE = dict(Uid='901 901 901 901', Gid='901 901 901 901', Groups='901 1901',
               CapEff='0000000000200040', smack='User', boot=p.CERTIFY_BOOT, dmesg_restrict='0')


def raw_record(seq, timestamp, message='ordinary noise', priority=6):
    return f'{priority},{seq},{timestamp},-;{message}\n'.encode()


def encoded_record(seq, timestamp, message='ordinary noise', priority=6):
    return base64.b64encode(raw_record(seq, timestamp, message, priority)).decode()


def kernel_text(line=LINE):
    records = [encoded_record(101, 95250000), encoded_record(102, 95400000),
               base64.b64encode(line.encode()).decode() if line else encoded_record(103, 95750000),
               encoded_record(104, 97000000, 'right endpoint')]
    return dict(version=1, exec=json.loads(exec_result()), kernel_capture=dict(
        capture_complete=True, capacity_state='unknown', profile=dict(PROFILE), post_profile=dict(PROFILE), pre_eagain=True,
        post_eagain=True, same_fd=True, baseline=encoded_record(100, 94000000, 'left endpoint'),
        records=records, pre_records=1, pre_bytes=len(raw_record(100, 94000000, 'left endpoint')),
        post_bytes=sum(len(base64.b64decode(x)) for x in records), errno=0, failure=None))


def wire_envelope(envelope):
    return base64.b64encode(gzip.compress(json.dumps(envelope).encode())).decode()


def evaluate(envelope, events=None, start='95', end='96'):
    events = [] if events is None else events
    save = lambda event, **data: events.append((event, data))
    cap = envelope.get('kernel_capture') if isinstance(envelope, dict) else None
    if isinstance(cap, dict) and isinstance(cap.get('records'), list):
        cap['post_bytes'] = sum(len(base64.b64decode(x)) for x in cap['records'])
    decoded = denial.kernel_log(wire_envelope(envelope), save)
    return denial.assess_kernel(decoded, CANON, start, end, save)


def exact_stop(fn, expected):
    try:
        fn()
    except p.Stop as error:
        assert str(error) == expected, f'wrong kernel refusal: expected {expected!r}, got {str(error)!r}'
    except (AttributeError, TypeError, ValueError) as error:
        raise AssertionError(f'wrong kernel refusal type: expected {expected!r}, got {type(error).__name__}') from error
    else:
        raise AssertionError('expected exact refusal: ' + expected)


def denial_good():
    for errno in (1, 13):
        assert denial.assess_exec(77, exec_result(errno=errno))['errno'] == errno
    assert evaluate(kernel_text()) == LINE
    text = denial.bounded([p.ROOT + '/denial-0123456789abcdef/uep-probe.elf'], 5)
    assert '\nexec /usr/bin/dotnet ' in text and '$?' not in text and 'wait ' not in text


def denial_started():
    stop(lambda: denial.assess_exec(77, exec_result(exec_started=True)),
         'started child was accepted')


def denial_masked():
    stop(lambda: denial.assess_exec(77, exec_result(native_exit=0)), 'refusal masked as successful child exit')


def denial_wrong_errno():
    stop(lambda: denial.assess_exec(77, exec_result(errno=2)), 'wrong errno accepted')


def denial_masked_trailer():
    stop(lambda: denial.assess_exec(0, exec_result()), 'wrapper masked refusal trailer')


def denial_marker():
    stop(lambda: denial.assess_exec(77, exec_result(stdout=denial.MARKER)), 'native success marker accepted')


def exec_shape_case(kind):
    result = json.loads(exec_result())
    expected = 'refused-before-exec output or timeout shape changed; STOP'
    if kind == 'schema':
        result['unreviewed'] = True
        expected = 'direct exec accounting keys changed; STOP'
    if kind == 'timeout': result['timed_out'] = True
    if kind == 'timeout-type': result['timed_out'] = 0
    if kind == 'stdout': result['stdout'] = 'unexpected output'
    if kind == 'stderr': result['stderr'] = 'unexpected error'
    exact_stop(lambda: denial.assess_exec(77, json.dumps(result)), expected)


def kernel_missing():
    exact_stop(lambda: evaluate(kernel_text('')), 'missing or duplicate exact-path kernel signature denial; STOP')


def kernel_old():
    envelope = kernel_text('')
    envelope['kernel_capture']['baseline'] = encoded_record(100, 94000000, MESSAGE)
    envelope['kernel_capture']['pre_bytes'] = len(raw_record(100, 94000000, MESSAGE))
    exact_stop(lambda: evaluate(envelope), 'missing or duplicate exact-path kernel signature denial; STOP')


def kernel_wrong_path():
    exact_stop(lambda: evaluate(kernel_text(LINE.replace(CANON, CANON + '0'))),
               'missing or duplicate exact-path kernel signature denial; STOP')


def kernel_outside():
    # Rounded uptime is not authority: a valid causal bracket accepts without widening timestamps.
    assert evaluate(kernel_text(), start='95.76', end='95.77') == LINE
    kernel_old()  # a matching pre-fence record never grants membership


def kernel_rotated():
    envelope = kernel_text()
    envelope['kernel_capture']['records'].pop(0)
    exact_stop(lambda: evaluate(envelope), 'kernel-sequence-gap: expected=101 observed=102')


def kernel_end_missing():
    envelope = kernel_text()
    envelope['kernel_capture']['post_eagain'] = False
    exact_stop(lambda: evaluate(envelope), 'kernel-post-fence-missing')


def kernel_retention_diagnostics():
    events = []
    try:
        denial.assess_kernel('[ 94.0] left\n[ 95.75] ' + MESSAGE + '\n[ 97.0] right\n', CANON, 95, 96,
                             lambda event, **data: events.append((event, data)))
    except p.Stop as error:
        assert str(error).startswith('kernel-capture-completeness-unproved: ')
    else:
        raise AssertionError('unsequenced endpoints granted completeness')
    assert events[0][1]['capacity_state'] == 'unknown' and events[0][1]['rotation_observed'] is None


def kernel_size_is_diagnostic():
    # Historical rotated byte size is a named refusal, never a capacity threshold.
    events = []
    text = '[ 16755.608247] rotated\n' + 'x' * (505101 - len('[ 16755.608247] rotated\n'))
    assert len(text.encode()) == 505101
    try:
        denial.assess_kernel(text, CANON, 17486.10, 17487.04,
                             lambda event, **data: events.append((event, data)), rotation_observed=True)
    except p.Stop as error:
        assert str(error).startswith('kernel-capture-completeness-unproved: ')
    else:
        raise AssertionError('historical 505 KB rotated capture accepted')
    assert events[0][1]['capacity_state'] == 'unknown' and events[0][1]['rotation_observed'] is True
    envelope = kernel_text()
    cap = envelope['kernel_capture']
    cap['records'] = [encoded_record(101 + i, 95000000 + i, 'x' * 4000) for i in range(125)]
    cap['records'].append(encoded_record(226, 95750000, MESSAGE))
    padding = 505101 - cap['pre_bytes'] - sum(len(base64.b64decode(x)) for x in cap['records'])
    assert 0 < 4000 + padding < 8000
    cap['records'][0] = encoded_record(101, 95000000, 'x' * (4000 + padding))
    assert evaluate(envelope).endswith(MESSAGE + '\n')
    assert cap['pre_bytes'] + cap['post_bytes'] == 505101


def kernel_malformed():
    for raw in (b'', b'bad\n', raw_record(103, 95750000, MESSAGE).replace(b',-;', b',c;'),
                raw_record(103, 95750000, MESSAGE) + b' KEY=value\n'):
        envelope = kernel_text()
        envelope['kernel_capture']['records'][2] = base64.b64encode(raw).decode()
        stop(lambda: evaluate(envelope), 'malformed kernel record accepted')


def kernel_exact_signature():
    for old, new in (('fsname:vdfs', 'fsname:other'), ('mnt_flags:1020', 'mnt_flags:1021'),
                     ('Sign it.', 'Sign itX'), ('uep-probe.elf', 'uep-probeXelf')):
        stop(lambda: evaluate(kernel_text(LINE.replace(old, new))),
             'nonexact kernel signature accepted')


def kernel_duplicate():
    envelope = kernel_text()
    envelope['kernel_capture']['records'][0] = encoded_record(101, 95250000, MESSAGE)
    exact_stop(lambda: evaluate(envelope), 'missing or duplicate exact-path kernel signature denial; STOP')


def kernel_endpoint_preserving_loss():
    envelope = kernel_text()
    events = []
    assert evaluate(envelope) == LINE, 'unique complete control refused'
    cap = envelope['kernel_capture']
    cap['records'][0] = encoded_record(101, 95250000, MESSAGE)
    exact_stop(lambda: evaluate(envelope), 'missing or duplicate exact-path kernel signature denial; STOP')
    baseline, right, survivor = cap['baseline'], cap['records'][-1], cap['records'][2]
    cap['records'].pop(0)
    assert (cap['baseline'], cap['records'][-1], cap['records'][1]) == (baseline, right, survivor)
    assert sum(MESSAGE.encode() in base64.b64decode(x) for x in cap['records']) == 1
    exact_stop(lambda: evaluate(envelope, events), 'kernel-sequence-gap: expected=101 observed=102')
    assert events[1][0] == 'denial-kernel-after', 'incomplete raw bracket not saved before gap refusal'
    saved = json.loads(base64.b64decode(events[1][1]['raw_b64']))
    assert saved == envelope


def kernel_middle_gap():
    envelope = kernel_text()
    envelope['kernel_capture']['records'][1] = encoded_record(102, 95400000, MESSAGE)
    exact_stop(lambda: evaluate(envelope), 'missing or duplicate exact-path kernel signature denial; STOP')
    envelope['kernel_capture']['records'].pop(1)
    exact_stop(lambda: evaluate(envelope), 'kernel-sequence-gap: expected=102 observed=103')


def kernel_guard_case(kind):
    envelope = kernel_text()
    cap = envelope['kernel_capture']
    expected = {
        'version': 'kernel-envelope-version-or-shape', 'complete': 'kernel-capture-incomplete: None',
        'pre': 'kernel-pre-fence-missing', 'post': 'kernel-post-fence-missing',
        'cursor': 'kernel-cursor-continuity-unproved', 'epipe': 'kernel-overrun-EPIPE',
        'boot': 'kernel-boot-drift', 'restrict': 'kernel-access-dmesg-restrict-drift',
        'smack': 'kernel-access-smack-drift', 'identity': 'kernel-access-helper-identity-drift',
        'group': 'kernel-access-owning-group-drift', 'capacity': 'kernel-capacity-unmeasured',
        'post-profile': 'kernel-access-profile-drift', 'zero-cap': 'kernel-access-helper-identity-drift',
        'system-label': 'kernel-access-smack-drift', 'uid': 'kernel-access-helper-identity-drift',
        'gid': 'kernel-access-helper-identity-drift',
        'order': 'kernel-timestamp-reversal', 'suppression': 'kernel-emission-suppressed',
        'facility': 'kernel-witness-not-kernel-origin', 'oversize': 'kernel-record-oversize-or-empty',
        'duplicate-seq': 'kernel-sequence-gap: expected=102 observed=101',
        'reverse-seq': 'kernel-sequence-gap: expected=102 observed=100',
    }[kind]
    if kind == 'version': envelope['version'] = 2
    if kind == 'complete': cap['capture_complete'] = False
    if kind == 'pre': cap['pre_eagain'] = False
    if kind == 'post': cap['post_eagain'] = False
    if kind == 'cursor': cap['same_fd'] = False
    if kind == 'epipe': cap['errno'] = 32
    for key, field, value in [('boot', 'boot', 'wrong'), ('restrict', 'dmesg_restrict', '1'),
        ('smack', 'smack', '_'), ('identity', 'CapEff', '0000000000200000'), ('group', 'Groups', '901'),
        ('zero-cap', 'CapEff', '0000000000000000'), ('system-label', 'smack', 'System'),
        ('uid', 'Uid', '901 901 0 901'), ('gid', 'Gid', '901 901 901 0')]:
        if kind == key: cap['profile'][field] = value
    if kind == 'post-profile': cap['post_profile']['CapEff'] = '0000000000000000'
    if kind == 'capacity': cap['capacity_state'] = 'full'
    if kind == 'order': cap['records'][1] = encoded_record(102, 95000000)
    if kind == 'suppression': cap['records'][1] = encoded_record(102, 95400000, '2 callbacks suppressed')
    if kind == 'facility': cap['records'][2] = encoded_record(103, 95750000, MESSAGE, 14)
    if kind == 'oversize': cap['records'][1] = encoded_record(102, 95400000, 'x' * 8192)
    if kind == 'duplicate-seq': cap['records'][1] = encoded_record(101, 95400000)
    if kind == 'reverse-seq': cap['records'][1] = encoded_record(100, 95400000)
    exact_stop(lambda: evaluate(envelope), expected)


def kernel_structure_case(kind):
    envelope = kernel_text()
    cap = envelope['kernel_capture']
    expected = {
        'profile': 'kernel-profile-shape', 'counters': 'kernel-capture-counters-invalid',
        'raw-bound': 'kernel-capture-raw-bound', 'post-bytes': 'kernel-post-byte-count-mismatch',
        'record-count': 'kernel-record-count-bound', 'priority': 'kernel-record-header-range',
        'flags': 'kernel-record-malformed-or-unsupported', 'dictionary': 'kernel-record-malformed-or-unsupported',
        'record-decode': 'kernel-record-decode-incomplete', 'cap-shape': 'kernel-capture-shape',
    }[kind]
    if kind == 'profile': cap['profile'] = None
    if kind == 'cap-shape': envelope['kernel_capture'] = None
    if kind == 'counters': cap['pre_records'] = 0
    if kind == 'raw-bound': cap['pre_bytes'] = 1048576
    if kind == 'post-bytes': cap['post_bytes'] += 1
    if kind == 'record-count':
        cap['records'] = [encoded_record(101+i, 95000000) for i in range(16384)] + [encoded_record(16485, 95750000, MESSAGE)]
        cap['post_bytes'] = sum(len(base64.b64decode(x)) for x in cap['records'])
    if kind == 'priority': cap['records'][0] = encoded_record(101, 95250000, priority=192)
    if kind == 'flags': cap['records'][0] = base64.b64encode(raw_record(101, 95250000).replace(b',-;', b',c;')).decode()
    if kind == 'dictionary': cap['records'][0] = base64.b64encode(raw_record(101, 95250000) + b' KEY=value\n').decode()
    if kind == 'record-decode': cap['records'][0] = '!'
    if kind not in ('post-bytes', 'record-decode', 'cap-shape'):
        cap['post_bytes'] = sum(len(base64.b64decode(x)) for x in cap['records'])
    exact_stop(lambda: denial.assess_kernel(envelope, CANON, '95', '96'), expected)


def kernel_decode_case(kind):
    events = []
    raw = json.dumps(kernel_text()).encode()
    if kind == 'utf8':
        raw = raw.replace(b'"User"', b'"Us\xffer"', 1)
        assert b'\xff' in raw, 'UTF8 fixture failed to inject invalid JSON bytes'
    if kind == 'json': raw = b'{'
    if kind == 'framing-bound': raw = b'x' * 2097153
    encoded = base64.b64encode(gzip.compress(raw)).decode()
    if kind == 'base64': encoded = '!'
    if kind == 'gzip': encoded = base64.b64encode(b'not gzip').decode()
    if kind == 'gzip-eof': encoded = base64.b64encode(gzip.compress(raw)[:-5]).decode()
    expected = {'utf8': 'UnicodeDecodeError', 'json': 'JSONDecodeError', 'base64': 'Error',
                'gzip': 'BadGzipFile', 'gzip-eof': 'EOFError'}.get(kind)
    exact_stop(lambda: denial.kernel_log(encoded, lambda event, **data: events.append((event, data))),
               'kernel-envelope-framing-bound' if kind == 'framing-bound' else 'kernel-capture-transport-decode-incomplete: ' + expected)
    assert events[0] == ('denial-evidence-transport', {'encoded': encoded,
                         'sha256': hashlib.sha256(encoded.encode('utf-8')).hexdigest()})
    if kind in ('utf8', 'json', 'framing-bound'):
        assert events[1][0] == 'denial-kernel-after', 'decoded evidence not saved before decoder verdict'


def managed_case(kind):
    import subprocess
    sdk = Path('C:/Users/Kninetimmy/.dotnet-sdks/3.1.426')
    env = dict(os.environ, DOTNET_MULTILEVEL_LOOKUP='0', DOTNET_ROOT=str(sdk))
    with tempfile.TemporaryDirectory(prefix='r19-managed-mutant-', dir=ds.REHEARSAL_TEMP) as temp:
        for name in ('obj', 'build'):
            p.make_private_directory(Path(temp) / name)
        output = Path(temp) / 'build'
        command = [str(sdk / 'dotnet.exe'), 'build', str(p.HERE / 'DenialSelfTest.csproj'), '-c', 'Release',
                   '-p:BaseIntermediateOutputPath=' + str(Path(temp) / 'obj') + os.sep,
                   '-p:OutputPath=' + str(output) + os.sep]
        built = subprocess.run(command, capture_output=True, env=env, cwd=p.REPO)
        text = built.stdout.decode() + built.stderr.decode()
        p.require(built.returncode == 0 and '0 Warning(s)' in text, 'managed mutation build failed or warned: ' + text[-2000:])
        result = subprocess.run([str(sdk / 'dotnet.exe'), str(output / 'DenialSelfTest.dll'), kind],
                                capture_output=True, env=env, cwd=p.REPO)
        if result.returncode:
            diagnostic = result.stdout.decode() + result.stderr.decode()
            if 'managed capture check failed: ' + kind not in diagnostic:
                raise RuntimeError('managed case failed for an unintended reason: ' + diagnostic[-2000:])
            raise AssertionError('managed guard missing: ' + kind)


def typed_exception():
    import mutation_checks as m
    for kind in ('builtins.ResourceWarning', 'builtins.RuntimeError', 'builtins.ValueError'):
        assert not m.exception_matches(1, {'type': kind, 'message': 'wanted'}, 'wanted')
    # A real wrong exception with a trailing warning must not satisfy the matcher.
    out = m.run_with_exception('import atexit; atexit.register(lambda: print("ResourceWarning: wanted")); raise ValueError("wrong")')
    assert not m.exception_matches(out.returncode, out.exception, 'wanted'), 'trailing warning supplied mutant kill'
    out = m.run_with_exception('import atexit; atexit.register(lambda: print("ResourceWarning: wanted")); raise AssertionError("wrong")')
    assert not m.exception_matches(out.returncode, out.exception, 'wanted'), 'trailing warning supplied exception message'
    out = m.run_with_exception('raise AssertionError("wanted")')
    assert m.exception_matches(out.returncode, out.exception, 'wanted')


def duplicate_precheck():
    import active
    import disable
    for module in (active, disable):
        events = []
        class Attempt:
            def __init__(self, stage):
                pass
            def require_unused(self):
                raise p.Stop('duplicate fixture attempt')
        def forbidden(*a, **k):
            events.append('touch')
            raise p.Stop('touch after duplicate')
        with patch.object(module, 'OneAttempt', Attempt), patch.object(p, 'require_openssl', forbidden):
            stop(lambda: asyncio.run(module.prerequisites()), 'duplicate attempt not refused')
        assert not events, 'duplicate attempt touched prerequisites: ' + module.__name__


class CertificationSDK:
    def __init__(self, change=None):
        self.change = change or {}
        self.commands = []

    async def capture(self, command, *, preserve_output=False):
        self.commands.append(command)
        from session_checks import _state_capture
        if "printf 'uid='" in command:
            values = dict(boot=p.CERTIFY_BOOT, gate='absent', budget='present', module='present',
                backup='present', proof_hash=p.CERTIFY_PROOF + '  ' + p.EV + '/selfroot-proof.txt')
            values.update(self.change.get('state', {}))
            obj = _state_capture(**values)
            return 0, obj.output
        if "printf 'proof='" in command:
            text = (p.HERE / 'evidence/anchored-proof.txt').read_bytes()
            return 0, 'proof=' + base64.b64encode(text).decode() + '\n'
        if "printf 'meta='; stat -c %F:%u:%g:%h" in command:
            sha = p._content_hash('boot=' + p.STALE_BOOT + ' clear=1 restore=0')
            return 0, 'meta=regular file:0:0:1\nsha=' + self.change.get('budget_sha', sha) + '  ' + p.UEP_STATE
        if 'backup_directory_meta=' in command:
            return backup_directory_fixture(command, self.change.get('backup', 'good'))
        if command.startswith('/usr/bin/dotnet '):
            value = self.change.get('flag', p.FINGERPRINT)
            return 0, ('read_words physical=' + p.UEP_PAGE + ' page=0x208c2000 offset=0x6c0 words=4\nwords word=0 ' + value)
        raise AssertionError('unexpected certification command: ' + command[:100])


def certification(change=None):
    obj = CertificationSDK(change)
    async def noop(*a, **k):
        return None
    async def module(*a, **k):
        assert k['probes'] == 1, 'certification retries missing module shape'
        return (change or {}).get('module_lines', [p.RECEIPT_ABSENT_BOOT, 'uep gate module exit=0'])
    assert p.digest(p.HERE / 'evidence/anchored-proof.txt') == p.CERTIFY_PROOF
    with patch.object(sc, 'module_files', noop), patch.object(sc, 'manager_files', noop), \
         patch.object(certify, 'protected_hashes', noop), patch.object(sc, 'module_gate', module), \
         patch.object(sl, 'save', lambda *a, **k: None):
        asyncio.run(certify.read_only(obj))
    assert not any(x in '\n'.join(obj.commands) for x in ('unlink ', 'mkdir ', 'chmod ', 'gate-remove:', 'reboot'))


def certification_refusal(kind):
    changes = {
        'boot': {'state': {'boot': '0' * 36}},
        'gate': {'state': {'gate': 'present'}},
        'fresh-budget': {'budget_sha': p._content_hash('boot=' + p.CERTIFY_BOOT + ' clear=1 restore=0')},
        'cleared': {'flag': p.CLEARED},
        'missing-module': {'module_lines': []},
        'unexpected-module': {'module_lines': [p.RECEIPT_ABSENT_BOOT, p.RECEIPT_CLEARED_BOOT, 'uep gate module exit=0']},
        'backup': {'backup': 'missing'},
    }
    stop(lambda: certification(changes[kind]), 'certification accepted ' + kind)


def backup_directory_fixture(command, kind='good'):
    """Real type guards; modeled POSIX metadata/DAC, explicitly denied reads."""
    assert p.BACKUP_DIR + '/' not in command, 'certification names a backup child'
    assert not any(word in command for word in ('sha256sum', 'find ', 'ls ', 'cat ', 'chmod ', 'chown '))
    with rc.Fixture() as f:
        backup = f.sdkroot / 'selfroot-evidence/r9-manager-backup'
        backup.mkdir()
        child = backup / 'com.samsung.tv.ghservice.dll'
        child.write_bytes(b'host-readable fixture; uid901 must not read this')
        (backup / 'com.samsung.tv.ghservice.runtimeconfig.json').write_bytes(b'host-readable fixture')
        if kind in ('symlink', 'non-directory', 'missing'):
            backup.rename(f.root / 'outside-backup')
            if kind == 'symlink':
                os.symlink(f.root / 'outside-backup', backup, target_is_directory=True)
            if kind == 'non-directory':
                backup.write_bytes(b'not a directory')
        metadata = {
            'owner': 'directory:901:0:700:1', 'group': 'directory:0:901:700:1',
            'mode': 'directory:0:0:755:1', 'links': 'directory:0:0:700:2',
        }.get(kind, certify.BACKUP_META)
        trace = f.root / 'child-read-attempts'
        extra = ('backup=' + quote(ds.to_posix(backup)) + '\ntrace=' + quote(ds.to_posix(trace))
                 + '\nbackup_meta=' + quote(metadata) + '\nstat_failure='
                 + ('1' if kind == 'stat-failure' else '0') + '\n')
        extra += r'''
deny_child_read() {
    local arg
    for arg in "$@"; do
        case "$arg" in "$backup"/*)
            echo "$arg" >> "$trace"
            echo 'Permission denied: uid901 root-only backup child' >&2
            return 13;;
        esac
    done
}
stat() {
    deny_child_read "$@" || return 13
    test "$stat_failure" = 0 || return 1
    test "$#" = 4 && test "$1" = -c && test "$2" = '%F:%u:%g:%a:%h' && test "$3" = -- && test "$4" = "$backup" || return 2
    printf '%s\n' "$backup_meta"
}
sha256sum() { deny_child_read "$@" || return 13; command sha256sum "$@"; }
cat() { deny_child_read "$@" || return 13; command cat "$@"; }
ls() { deny_child_read "$@" "$backup/listing"; }
find() { deny_child_read "$@" "$backup/listing"; }
'''
        if kind == 'good':
            # Positive control: without the modeled boundary this host can read
            # the file. Every shimmed child read/list must actually be denied.
            assert child.read_bytes().startswith(b'host-readable fixture')
            for op, target in (('cat', child), ('stat', child), ('sha256sum', child),
                               ('ls', backup), ('find', backup)):
                denied = f.run(False, command=op + ' ' + quote(ds.to_posix(target)), extra_shim=extra)
                assert denied.returncode == 13 and 'Permission denied' in denied.stderr, op + ' denial not modeled'
            assert len(trace.read_text().splitlines()) == 5
            trace.unlink()
        out = f.run(False, command=command, extra_shim=extra)
        assert not trace.exists(), 'certification attempted a denied backup child read'
        if kind == 'good':
            assert out.returncode == 0 and out.stdout.strip() == 'backup_directory_meta=' + certify.BACKUP_META, out.stderr
        else:
            assert out.returncode == 69 and 'BACKUP_DIRECTORY_REFUSAL:' in out.stderr, 'unclear backup refusal: ' + kind
        return out.returncode, out.stdout + out.stderr


def backup_directory_case(kind):
    if kind == 'good':
        certification()
    else:
        stop(lambda: certification({'backup': kind}), 'certification accepted backup ' + kind)


def certification_evidence_fields():
    """Exercise status/log arguments through the real main; all live calls fake."""
    events = []
    class Attempt:
        def __init__(self, stage):
            assert stage == certify.STAGE
        def require_unused(self):
            pass
        def take(self):
            events.append('attempt')
    class SDK:
        def __init__(self, save):
            pass
        async def connect(self):
            pass
        async def disconnect(self):
            pass
    async def read_only(sdk):
        return p.CERTIFY_PROOF
    async def denied(*a):
        pass
    def succeeded(stage, status, kind, **data):
        assert data['backup_directory_meta'] == certify.BACKUP_META
        assert data['backup_pair_evidence'] == certify.BACKUP_PAIR_EVIDENCE
        assert data['backup_certification'] == certify.BACKUP_SCOPE
        events.append('status')
    def failed(stage, status, kind, reason):
        assert certify.BACKUP_PAIR_EVIDENCE in reason and certify.BACKUP_SCOPE in reason
        events.append('failure')
    def logged(event, **data):
        assert data['backup_pair_evidence'] == certify.BACKUP_PAIR_EVIDENCE
        assert data['backup_certification'] == certify.BACKUP_SCOPE
        events.append(event)
    def noop(*a):
        pass
    with patch.object(certify, 'OneAttempt', Attempt), patch.object(certify, 'BridgeSDK', SDK), \
         patch.object(certify, 'refuse_if_stopped', noop), patch.object(certify, 'marker_for', noop), \
         patch.object(certify, 'protect_seal', noop), patch.object(p, 'require_source_integrity', noop), \
         patch.object(certify, 'read_only', read_only), patch.object(denial, 'run', denied), \
         patch.object(certify, 'succeed', succeeded), patch.object(certify, 'log', logged), \
         patch.object(certify, 'record_failure', failed):
        asyncio.run(certify.main())
        asyncio.run(certify.main(readiness=True))
        async def refusal(sdk):
            raise p.Stop('modeled metadata refusal')
        with patch.object(certify, 'read_only', refusal):
            stop(lambda: asyncio.run(certify.main(readiness=True)), 'metadata failure not propagated')
    assert events == ['attempt', 'status', 'r22-readiness-passed', 'failure'], events


def certification_privacy_case(kind):
    events = []
    class Attempt:
        def __init__(self, stage): pass
        def require_unused(self): pass
        def take(self): events.append('attempt')
    def privacy(path):
        target = p.HERE if kind == 'root' else p.HERE / 'evidence'
        if path == target:
            raise p.Stop('modeled privacy refusal: ' + kind)
    def forbidden(*args, **kwargs):
        events.append('SDK')
        raise p.Stop('SDK constructed after failed privacy preflight')
    with patch.object(certify, 'OneAttempt', Attempt), patch.object(certify, 'BridgeSDK', forbidden), \
         patch.object(certify, 'refuse_if_stopped', lambda: None), patch.object(certify, 'protect_seal', lambda: None), \
         patch.object(certify, 'record_failure', lambda *args: None), patch.object(p, 'require_source_integrity', lambda: None), \
         patch.object(p, 'private_acl', privacy), patch.object(p, 'record_refusal', lambda *a: None):
        try:
            asyncio.run(certify.main(readiness=True))
        except p.Stop as error:
            assert str(error) == 'modeled privacy refusal: ' + kind, 'privacy guard missing: ' + kind
        else:
            raise AssertionError('privacy guard missing: ' + kind)
    assert not events, 'privacy refusal did not precede attempt/SDK construction: ' + kind


def tidy_privacy_case(kind):
    events = []
    class Attempt:
        def __init__(self, stage): pass
        def require_unused(self): pass
        def take(self): events.append('attempt')
    def privacy(path):
        if path == (p.HERE if kind == 'root' else p.HERE / 'evidence'):
            raise p.Stop('modeled tidy privacy refusal: ' + kind)
    def forbidden(*a, **k):
        events.append('SDK')
        raise p.Stop('SDK constructed after failed tidy privacy preflight')
    # A fake successful certification status, never a live receipt or file write.
    prior = json.dumps(dict(stage='certify', passed=True, boot=p.CERTIFY_BOOT, proof_sha256=p.CERTIFY_PROOF))
    with patch.object(tidy, 'OneAttempt', Attempt), patch.object(tidy, 'BridgeSDK', forbidden), \
         patch.object(tidy, 'refuse_if_stopped', lambda: None), patch.object(tidy, 'marker_for', lambda *a: None), \
         patch.object(tidy, 'protect_seal', lambda: None), patch.object(tidy, 'record_failure', lambda *a: None), \
         patch.object(Path, 'read_text', lambda *a, **k: prior), patch.object(p, 'private_acl', privacy), \
         patch.object(p, 'record_refusal', lambda *a: None):
        try:
            asyncio.run(tidy.main())
        except p.Stop as error:
            assert str(error) == 'modeled tidy privacy refusal: ' + kind, 'tidy privacy guard missing: ' + kind
        else:
            raise AssertionError('tidy privacy guard missing: ' + kind)
    assert not events, 'tidy privacy did not precede attempt/SDK construction: ' + kind


def authoring_pin_refusal():
    with patch.object(sl, 'repo_head', lambda: '0' * 40), \
         patch.object(p, 'require_source_integrity', lambda: None):
        exact_stop(sl.require_authoring_pin,
                   'authoring source HEAD differs from provenance COMMIT; refuse stale pin')


def source_digest_case(kind):
    with tempfile.TemporaryDirectory(prefix='r20-source-', dir=ds.REHEARSAL_TEMP) as temp:
        root = Path(temp)
        names = [name + '/source.txt' for name in p.SOURCE_ROOTS]
        for name in names:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'original source')
        def listed(*args, **kwargs):
            assert args[0] == ['git', 'ls-files', '-z', '--cached', '--others', '--exclude-standard', '--', *p.SOURCE_ROOTS]
            assert kwargs['cwd'] == root
            return ('\0'.join(names) + '\0').encode()
        with patch.object(p, 'REPO', root), patch.object(p.subprocess, 'check_output', listed):
            pin = p.source_digest()
            with patch.object(p, 'SOURCE_SHA', pin):
                p.require_source_integrity()
                if kind == 'unrelated':
                    (root / 'archive-notes.md').write_bytes(b'archive/doc/test change, not a dependency')
                    names.reverse()  # Git enumeration order is not authority.
                    p.require_source_integrity()
                    with patch.object(p, 'marker', lambda stage: True), patch.object(sl, 'refuse_if_stopped', lambda: None), \
                         patch.object(sl, 'repo_head', lambda: 'f' * 40):
                        sl.marker_for('LIVE_ARM_CERTIFY')
                    return
                if kind == 'add':
                    names.append('payloads/new-source.txt')
                    (root / names[-1]).write_bytes(b'new source')
                elif kind == 'remove':
                    names.remove('modules/source.txt')
                elif kind == 'redirect':
                    outside = root / 'outside.txt'
                    outside.write_bytes(b'original source')
                    path = root / names[0]
                    path.unlink()
                    path.symlink_to(outside)
                    exact_stop(p.require_source_integrity, 'source path redirected: ' + names[0])
                    return
                else:
                    (root / p.SOURCE_ROOTS[int(kind)] / 'source.txt').write_bytes(b'drifted source')
                if kind == 'remove':
                    exact_stop(p.require_source_integrity, 'source digest directory missing or empty')
                else:
                    exact_stop(p.require_source_integrity, 'source dependency digest changed; STOP')


def source_preflight_case(kind):
    events = []
    def forbidden(*a, **k):
        events.append('SDK')
        raise p.Stop('source gate missing: ' + kind)
    if kind == 'marker':
        with patch.object(p, 'marker', lambda stage: True), patch.object(p, 'source_digest', lambda: '0' * 64), \
             patch.object(sl, 'refuse_if_stopped', lambda: None):
            exact_stop(lambda: sl.marker_for('LIVE_ARM_CERTIFY'), 'source dependency digest changed; STOP')
        return
    class Attempt:
        def __init__(self, stage): pass
        def require_unused(self): pass
        def take(self): events.append('attempt')
    with patch.object(certify, 'OneAttempt', Attempt), patch.object(certify, 'BridgeSDK', forbidden), \
         patch.object(certify, 'refuse_if_stopped', lambda: None), patch.object(certify, 'protect_seal', lambda: None), \
         patch.object(p, 'private_acl', lambda *a: None), patch.object(p, 'source_digest', lambda: '0' * 64), \
         patch.object(certify, 'record_failure', lambda *a: None), patch.object(p, 'record_refusal', lambda *a: None):
        try:
            asyncio.run(certify.main(readiness=True))
        except p.Stop as error:
            assert str(error) == 'source dependency digest changed; STOP', 'source preflight missing: certify'
        else:
            raise AssertionError('source preflight missing: certify')
    assert not events, 'source drift passed attempt/SDK boundary'


def tidy_fixture(kind='good', target_index=0, child='uep-probe.elf'):
    with rc.Fixture() as f:
        for index, target in enumerate(tidy.TARGETS):
            folder = f.sdkroot / target['path'].rsplit('/', 1)[1]
            folder.mkdir()
            for name in target['assets']:
                predecessor = 'qn90b-uep-l4-deploy-20261118-r18' if index == 1 else 'qn90b-uep-l4-deploy-20261119-r19'
                asset = p.NATIVE if name == 'uep-probe.elf' else (p.HERE.parent / predecessor / 'build/DenialRunner.dll') if name.endswith('.dll') else p.DENIAL_RC
                (folder / name).write_bytes(asset.read_bytes())
                os.utime(folder / name, (int(tidy.MTIME), int(tidy.MTIME)))
        f.relay = f.sdkroot / tidy.TARGETS[target_index]['path'].rsplit('/', 1)[1]
        elf = f.relay / child
        uid, mode = '901', tidy.TARGETS[target_index]['assets'][child][1]
        if kind == 'hash': elf.write_bytes(b'x' * tidy.TARGETS[target_index]['assets'][child][2])
        if kind == 'extra': (f.relay / 'extra').write_bytes(b'x')
        if kind == 'extra-newline':
            # Windows paths cannot contain LF; create the native MSYS filename
            # with bash so the actual command-substitution edge is exercised.
            out = ds.bash('touch ' + __import__('shlex').quote(ds.to_posix(f.relay)) + "/$'\\n'")
            assert out.returncode == 0, out.stderr
        if kind == 'composite-lf':
            assert target_index == 1
            names = sorted(tidy.TARGETS[1]['assets'])
            script = 'cd ' + quote(ds.to_posix(f.relay)) + '\n'
            script += ''.join('command unlink -- ' + quote(name) + '\n' for name in names)
            script += 'printf composite > ' + quote('\n'.join(names)) + '\n'
            out = ds.bash(script)
            assert out.returncode == 0, out.stderr
        if kind == 'wrong-name':
            elf.rename(f.relay / 'wrong-name')
        if kind == 'hardlink': os.link(elf, f.root / 'external')
        if kind == 'owner': uid = '0'
        if kind == 'mode': mode = '644'
        if kind == 'size': elf.write_bytes(b'x')
        if kind == 'missing': elf.unlink()
        if kind == 'directory-symlink':
            f.relay.rename(f.root / 'outside')
            os.symlink(f.root / 'outside', f.relay, target_is_directory=True)
        if kind == 'mtime': os.utime(elf, (0, 0))
        if kind == 'symlink':
            elf.rename(f.root / 'outside')
            os.symlink(f.root / 'outside', elf)
        if kind in ('hash', 'size'):
            os.utime(elf, (int(tidy.MTIME), int(tidy.MTIME)))
        extra = ('eval "$(declare -f stat | sed \'1s/stat/tidy_stat/\')"\n'
                 + 'changed=' + quote(ds.to_posix(elf)) + '\n'
                 + 'stat() { local file=${3:-}; if test "$file" = .; then file=$PWD; fi; '
                 + 'case "$file" in /*) ;; *) file=$PWD/$file;; esac\n'
                 + 'if test "$1" = -c && test "$2" = %u:%a:%h:%s; then '
                 + 'if test "$file" = "$changed"; then printf "' + uid + ':' + mode + '"; '
                 + 'else case "$file" in */uep-probe.elf) printf "901:700";; *) printf "901:600";; esac; fi\n'
                 + 'printf ":%s:%s\\n" "$(command stat -c %h "$file")" "$(command stat -c %s "$file")"\n'
                 + 'elif test "$1" = -c && test "$2" = %F:%u:%a; then printf "%s:901:700\\n" "$(command stat -c %F "$file")"\n'
                  + 'elif test "$1" = -c && { test "$2" = %d:%i || test "$2" = %d:%i:%u:%a; }; then\n'
                  + 'local receipt; case "$file" in */denial-ec6cf65890501d00) receipt=45845:32788;; *) receipt=45845:25356;; esac\n'
                  + ('if test "$file" = ' + quote(ds.to_posix(f.relay)) + '; then receipt=45845:99999; fi\n' if kind == 'receipt' else '')
                  + 'if test "$2" = %d:%i; then echo "$receipt"; else echo "$receipt:901:700"; fi\n'
                 + 'else tidy_stat "$@"; fi; }\n')
        text = tidy.command().replace(p.CERTIFY_BOOT, rc.BOOT)
        trace = f.root / 'unlink-trace'
        extra += 'unlink() { echo unlink >> ' + quote(ds.to_posix(trace)) + '; command unlink "$@"; }\n'
        if kind in ('composite-lf', 'wrong-name'):
            target = tidy.TARGETS[1]
            # Exercise the actual production prefix, not a reimplemented predicate.
            prefix = tidy.inspect(target).split('test "$(stat -c %d:%i .)"')[0]
            prologue = 'set -eu -o pipefail\nrefuse() { echo "TIDY_REFUSAL: $*" >&2; exit 69; }\n'
            diagnostic = ('cd ' + quote(target['path'])
                + '\nprintf "COUNT=%s\\n" "$(find . -mindepth 1 -maxdepth 1 -printf x | wc -c)"\n'
                + 'inventory=$(find . -mindepth 1 -maxdepth 1 -printf \'%f\\n\' | sort)\n'
                + 'if test "$inventory" = ' + quote('\n'.join(sorted(target['assets'])))
                + '; then echo COMPARE=equal; else echo COMPARE=different; fi\n')
            observed = f.run(False, command=diagnostic, extra_shim=extra)
            assert observed.stdout.strip() == ('COUNT=1\nCOMPARE=equal' if kind == 'composite-lf' else 'COUNT=3\nCOMPARE=different'), observed.stdout
            expected = 'TIDY_REFUSAL: ' + ('inventory-count' if kind == 'composite-lf' else 'inventory')
            out = f.run(False, command=prologue + prefix, extra_shim=extra)
            assert out.returncode == 69 and out.stderr.strip() == expected, 'inventory prefix guard missing: ' + kind + ': ' + out.stderr
        before = {x.relative_to(f.sdkroot).as_posix(): x.read_bytes() for x in f.sdkroot.rglob('*') if x.is_file()}
        identities = {x.relative_to(f.sdkroot).as_posix(): (x.stat().st_dev, x.stat().st_ino) for x in f.sdkroot.rglob('*') if x.is_dir()}
        out = f.run(False, command=text, extra_shim=extra)
        if kind == 'good':
            assert out.returncode == 0, out.stderr
            assert out.stdout.strip() == f.translate(tidy.removal_receipt()), out.stdout
            for target in tidy.TARGETS:
                assert not (f.sdkroot / target['path'].rsplit('/', 1)[1]).exists(), 'tidy path not removed'
            out = f.run(False, command=tidy.absence_command().replace(p.CERTIFY_BOOT, rc.BOOT))
            assert out.returncode == 0 and 'DENIAL_STAGES_ABSENT_FRESH_SESSION' in out.stdout, out.stderr
        else:
            assert out.returncode != 0 and 'TIDY_REFUSAL' in out.stderr, 'tidy accepted ' + kind
            if kind in ('composite-lf', 'wrong-name'):
                assert out.returncode == 69 and out.stderr.strip() == expected, 'inventory full guard missing: ' + kind
            assert not trace.exists(), 'tidy refusal ran unlink: ' + kind
            assert before == {x.relative_to(f.sdkroot).as_posix(): x.read_bytes() for x in f.sdkroot.rglob('*') if x.is_file()}, 'tidy refusal changed file: ' + kind
            assert identities == {x.relative_to(f.sdkroot).as_posix(): (x.stat().st_dev, x.stat().st_ino) for x in f.sdkroot.rglob('*') if x.is_dir()}, 'tidy refusal changed directory identities: ' + kind


def certify_boot_refusal():
    certification_refusal('boot')


def certify_module_refusal():
    certification_refusal('missing-module')


def tidy_newline_refusal():
    tidy_fixture('extra-newline')


def tidy_composite_refusal():
    tidy_fixture('composite-lf', 1)


def tidy_comparison_refusal():
    tidy_fixture('wrong-name', 1)


def denial_flow(errno=1, missing_kernel=False, transport_failure=False):
    """Execute real creation/upload/metadata/cleanup commands on host files.

    Only POSIX identity/path/proc and the exec/kernel event are modeled. The
    production C# exec branch is separately exercised by DenialSelfTest.
    """
    with rc.Fixture() as f:
        f.relay = f.sdkroot / 'denial-0123456789abcdef'
        events = []
        class SDK:
            def __init__(self):
                self.uptime_reads = self.logs = self.execs = 0
            async def capture(self, command, *, preserve_output=False, evidence_label=None):
                if command == 'cat /proc/uptime':
                    self.uptime_reads += 1
                    return 0, ('95.0 0.0' if self.uptime_reads == 1 else '96.0 0.0')
                if 'exec /usr/bin/dotnet ' in command:
                    self.execs += 1
                    assert evidence_label == 'denial-evidence'
                    if transport_failure:
                        import sdk as transport
                        broken = object.__new__(transport.DirectSDK)
                        broken.log = save
                        async def fail(label, command, **kwargs):
                            evidence = kwargs['evidence']
                            evidence.update(accepted=True, observed=131073)
                            evidence['prefix'].extend(b'x' * 131072)
                            raise ValueError('kernel-capture-transport-bound')
                        broken._request = fail
                        return await broken.capture(command, evidence_label=evidence_label)
                    envelope = kernel_text('' if missing_kernel else LINE)
                    envelope['exec'] = json.loads(exec_result(errno=errno))
                    command = command.replace(denial.bounded([p.ROOT + '/denial-0123456789abcdef/uep-probe.elf'], 5),
                        'printf %s ' + quote(wire_envelope(envelope)) + '\nexit 77\n')
                extra = 'chmod() { command chmod "$@"; }\npgrep() { return 1; }\n'
                # Git/MSYS dd has conv=excl but no oflag=nofollow. Model only
                # that unsupported flag with a symlink guard; real exclusive
                # file creation, decoding, bytes and hashes still execute.
                command = command.replace('/usr/bin/dd ', 'fixture_dd ')
                extra += r'''
fixture_dd() {
    local args=() target= arg
    for arg in "$@"; do
        case "$arg" in
            oflag=nofollow) ;;
            of=*) target=${arg#of=}; args+=("$arg");;
            *) args+=("$arg");;
        esac
    done
    test ! -L "$target" || return 70
    command dd "${args[@]}"
}
'''
                extra += ds.seed(f.relay / 'uep-probe.elf', '901:901:700')
                out = f.run(False, command=command, extra_shim=extra)
                return out.returncode, out.stdout + out.stderr
        obj = SDK()
        def save(event, **data):
            events.append(event)
            if event == 'denial-kernel-after':
                assert data['bytes'] == len(base64.b64decode(data['raw_b64']))
        assess = denial.assess_kernel
        def assess_saved(*args):
            assert 'denial-kernel-after' in events, 'kernel evidence not saved before assertion'
            return assess(*args)
        with patch.object(denial.secrets, 'token_hex', lambda size: '0123456789abcdef'), \
             patch.object(denial, 'assess_kernel', assess_saved), \
             patch.object(sl, 'save', lambda *a, **k: None):
            if transport_failure:
                try:
                    asyncio.run(denial.run(obj, save))
                except ValueError as error:
                    assert str(error) == 'kernel-capture-transport-bound'
                    assert events.count('sdk-reply-incomplete') == 1, 'stage failure preceded partial evidence'
                else:
                    raise AssertionError('denial stage accepted partial transport')
                assert f.relay.is_dir() and len(list(f.relay.iterdir())) == 3, 'transport failure erased staged evidence'
                assert 'denial-passed' not in events and 'denial-kernel-after' not in events
            elif missing_kernel:
                stop(lambda: asyncio.run(denial.run(obj, save)), 'denial flow accepted missing kernel witness')
                assert f.relay.is_dir() and (f.relay / 'uep-probe.elf').is_file(), 'failed denial lost staging evidence'
            else:
                asyncio.run(denial.run(obj, save))
                assert not f.relay.exists(), 'denial flow failed to remove its three-file stage'
                assert events.count('denial-passed') == 1
        assert obj.execs == 1, 'denial flow retried native execution'
        assert obj.logs == 0 and obj.uptime_reads == (1 if transport_failure else 2), 'denial flow used a dmesg fallback'


def denial_saved_before_assertion():
    denial_flow(missing_kernel=True)


def transport_case(kind):
    """Real request/teardown state machine; fake streams/server/process only, no sockets or SDK constructor."""
    import hashlib
    import sdk as transport
    nonce = 'a' * 16
    trailer = f'\n[exit:{nonce}:77]\n'.encode()
    payload = b'complete' + trailer
    if kind == 'limit': payload = b'x' * (131072 - len(trailer)) + trailer
    if kind in ('overflow', 'ordinary-overflow'): payload = bytes(range(256)) * 512 + b'!'
    if kind in ('eof', 'oserror', 'timeout', 'cancel', 'storage'): payload = b'partial\x00\xff'
    if kind == 'utf8': payload = b'\xe2\x82' + trailer
    if kind == 'bad-trailer': payload = b'body' + f'\n[exit:{nonce}:999]\n'.encode()
    if kind == 'extra-data': payload = b'complete' + trailer
    events, writers, spawns = [], [], []
    state = {}
    observed = bytearray()
    command = 'printf reviewed-denial-envelope'
    class Reader:
        def __init__(self, body, rejected=False):
            self.body, self.rejected, self.offset, self.reads = body, rejected, 0, 0
        async def readline(self):
            return b'rejected-tag\n' if self.rejected else (transport.payload_tag(command, nonce) + '\n').encode()
        async def read(self, size):
            self.reads += 1
            if self.offset < len(self.body):
                # Nonuniform boundaries, including split UTF8 and trailer boundaries.
                take = min(size, (1, 4096, 17, 4095)[(self.reads - 1) % 4])
                chunk = self.body[self.offset:self.offset + take]
                self.offset += len(chunk)
                observed.extend(chunk)
                return chunk
            if kind in ('oserror', 'storage'): raise OSError('injected read failure')
            if kind == 'timeout': await asyncio.Future()
            if kind == 'cancel':
                state['outer'].cancel()
                await asyncio.Future()
            if kind == 'extra-data' and self.reads < 100:
                self.reads = 100
                observed.extend(b'extra')
                return b'extra'
            return b''
    class Writer:
        def __init__(self, peer): self.peer, self.writes, self.closed = peer, [], False; writers.append(self)
        def get_extra_info(self, key): return (self.peer, 12345)
        def write(self, data): self.writes.append(data)
        async def drain(self): pass
        def close(self): self.closed = True
    class Socket:
        def getsockname(self): return ('127.0.0.1', 12345)
    class Server:
        sockets = [Socket()]
        def close(self): pass
        async def wait_closed(self):
            if kind == 'close': raise OSError('injected listener close failure')
    class Empty:
        async def read(self, size): return b''
    class Process:
        pid, returncode = 12345, None
        stdout, stderr = Empty(), Empty()
        async def wait(self):
            self.returncode = 2 if kind == 'local-exit' else 0
            return self.returncode
        def kill(self): self.returncode = -9
    async def server(accept, *args, **kwargs):
        state['accept'] = accept
        return Server()
    async def spawn(argument):
        spawns.append(argument)
        if kind in ('rejected-peer', 'rejected-tag', 'peer-only', 'tag-only'):
            rejected = Reader(b'NEVER-SAVE-REJECTED-BODY', rejected=kind in ('rejected-tag', 'tag-only'))
            state['rejected'] = rejected
            state['accept'](rejected, Writer('192.0.2.1' if kind in ('rejected-peer', 'peer-only') else transport.sdk.TV))
        if kind not in ('peer-only', 'tag-only'):
            state['accept'](Reader(payload), Writer(transport.sdk.TV))
        return Process()
    def save(event, **data):
        if kind == 'storage' and event == 'sdk-reply-incomplete': raise OSError('injected receipt fsync failure')
        events.append((event, data))
    obj = object.__new__(transport.DirectSDK)
    obj.log, obj.spawn = save, spawn
    success = kind in ('complete', 'limit', 'rejected-peer', 'rejected-tag')
    async def exercise():
        state['outer'] = asyncio.current_task()
        try:
            result = await obj.capture(command, evidence_label=None if kind == 'ordinary-overflow' else 'denial-evidence')
        except BaseException as error:
            assert not success, 'complete transport control refused: ' + str(error)
            state['error'] = error
        else:
            assert success, 'incomplete transport returned output: ' + kind
            assert result == (77, payload[:-len(trailer)].decode())
    with patch.object(transport.asyncio, 'start_server', server), \
         patch.object(transport.secrets, 'token_hex', lambda size: nonce), patch.object(transport, 'DEADLINE', 0.05):
        asyncio.run(exercise())
    partials = [data for event, data in events if event == 'sdk-reply-incomplete']
    if success or kind in ('ordinary-overflow', 'peer-only', 'tag-only'):
        assert not partials, 'incomplete receipt escaped opt-in/failure boundary'
    elif kind == 'storage':
        error = state['error']
        assert isinstance(error, BaseExceptionGroup) and len(error.exceptions) == 2
        assert str(error.exceptions[0]) == 'injected read failure'
        assert str(error.exceptions[1]) == 'injected receipt fsync failure'
    else:
        assert len(partials) == 1, 'partial receipt missing or emitted more than once'
        receipt = partials[0]
        prefix = bytes(observed[:131072])
        assert base64.b64decode(receipt['raw_prefix_b64'], validate=True) == prefix, 'partial prefix not byte-exact or overlong'
        assert receipt['retained_bytes'] == len(prefix) <= 131072, 'partial prefix exceeds bound'
        assert receipt['prefix_sha256'] == hashlib.sha256(prefix).hexdigest(), 'partial prefix digest covers wrong bytes'
        assert receipt['observed_bytes_at_least'] == len(observed)
        assert receipt['truncated'] == (len(observed) > len(prefix))
        assert receipt['prefix_limit_bytes'] == 131072 and receipt['raw_prefix_encoding'] == 'base64'
        assert receipt['transport_complete'] is False and receipt['capture_complete'] is False
        assert receipt['usable_as_kernel_authority'] is False
        assert receipt['exit_trailer_seen'] == (kind in ('local-exit', 'close', 'bad-trailer', 'utf8', 'extra-data'))
        assert receipt['request'] == 'denial-evidence' and receipt['request_id'] == nonce
        if kind == 'overflow':
            assert type(state['error']) is ValueError and str(state['error']) == 'kernel-capture-transport-bound', 'overflow changed the terminal limit error'
            assert receipt['reason'] == 'reply-limit' and receipt['retained_bytes'] == 131072
    assert len(spawns) == 1 and sum(bool(w.writes) for w in writers) == (0 if kind in ('peer-only', 'tag-only') else 1), 'transport retried command release'
    assert all(w.closed for w in writers), 'transport failed to close a writer'
    assert not any(event == 'denial-passed' for event, _ in events), 'incomplete transport granted denial authority'
    if 'rejected' in state:
        assert state['rejected'].reads == 0, 'read rejected-peer body'
        assert 'NEVER-SAVE-REJECTED-BODY' not in json.dumps(events), 'saved rejected-peer body'


def transport_overflow():
    transport_case('overflow')


def transport_limit():
    transport_case('limit')


def evidence_scope_case(kind):
    import sdk as transport
    calls = []
    obj = object.__new__(transport.DirectSDK)
    async def forbidden(*args, **kwargs):
        calls.append('released')
        return 0, ''
    if kind == 'capture':
        obj.request = forbidden
        exact_stop(lambda: asyncio.run(obj.capture('reviewed', evidence_label='other')), 'unreviewed evidence label')
    else:
        obj._request = forbidden
        exact_stop(lambda: asyncio.run(obj.request('other', 'reviewed', partial_evidence=True)), 'unreviewed partial-evidence request')
    assert not calls, 'unreviewed evidence scope contacted transport'


def access_case(kind):
    with rc.Fixture() as f:
        restrict = '1' if kind == 'restrict' else '0'
        metadata = 'character special file:0:1901:660:root:log' if kind != 'node' else 'regular file:0:1901:660:root:log'
        groups = '901' if kind == 'group' else '901 1901'
        label = '/dev/kmsg access="_"' if kind == 'smack' else '/dev/kmsg access="*"'
        extra = ''.join(name + '() { printf "%s\\n" ' + quote(value) + '; return '
                        + ('1' if kind == fault + '-read' else '0') + '; }\n'
                        for name, value, fault in (('cat', restrict, 'restrict'), ('stat', metadata, 'node'),
                                                    ('id', groups, 'group'), ('chsmack', label, 'smack')))
        command = denial.bounded([p.ROOT + '/denial-0123456789abcdef/uep-probe.elf'], 5)
        prefix = command.split('\nexec /usr/bin/dotnet ')[0] + '\necho WOULD_EXEC\n'
        out = f.run(False, command='set -eu\n' + prefix, extra_shim=extra)
        if kind == 'good':
            assert out.returncode == 0 and out.stdout.strip() == 'WOULD_EXEC', 'access positive control refused'
        else:
            expected = {'restrict': 'dmesg-restrict-drift', 'node': 'node-metadata-drift',
                        'group': 'owning-group-drift', 'smack': 'node-smack-drift',
                        'restrict-read': 'dmesg-restrict-read-failed', 'node-read': 'node-metadata-read-failed',
                        'group-read': 'owning-group-read-failed', 'smack-read': 'node-smack-read-failed'}[kind]
            assert out.returncode == 69 and out.stderr.strip() == 'KERNEL_ACCESS_REFUSAL: ' + expected, 'access guard missing: ' + kind
            assert 'WOULD_EXEC' not in out.stdout, 'access refusal executed native attempt'


def run():
    names = []
    def check(name, fn):
        fn()
        names.append(name)
    with patch.object(sl, 'save', lambda *a, **k: None):
        for fn in (denial_good, denial_started, denial_masked, denial_wrong_errno, denial_masked_trailer,
                   denial_marker, kernel_missing, kernel_old, kernel_wrong_path, kernel_outside,
                   kernel_rotated, kernel_duplicate, kernel_end_missing, kernel_retention_diagnostics,
                   kernel_size_is_diagnostic, kernel_malformed, kernel_exact_signature,
                   kernel_endpoint_preserving_loss, kernel_middle_gap,
                   typed_exception, duplicate_precheck, certification):
             check(fn.__name__, fn)
        for kind in ('version', 'complete', 'pre', 'post', 'cursor', 'epipe', 'boot', 'restrict', 'smack',
                     'identity', 'group', 'capacity', 'order', 'suppression', 'facility', 'oversize', 'duplicate-seq', 'reverse-seq',
                     'post-profile', 'zero-cap', 'system-label', 'uid', 'gid'):
            check('kernel-guard-' + kind, lambda kind=kind: kernel_guard_case(kind))
        for kind in ('schema', 'timeout', 'timeout-type', 'stdout', 'stderr'):
            check('exec-shape-' + kind, lambda kind=kind: exec_shape_case(kind))
        check('authoring-stale-pin', authoring_pin_refusal)
        for kind in ('0', '1', '2', 'add', 'remove', 'redirect', 'unrelated'):
            check('source-digest-' + kind, lambda kind=kind: source_digest_case(kind))
        for kind in ('marker', 'certify'):
            check('source-preflight-' + kind, lambda kind=kind: source_preflight_case(kind))
        for kind in ('profile', 'counters', 'raw-bound', 'post-bytes', 'record-count', 'priority',
                     'flags', 'dictionary', 'record-decode', 'cap-shape'):
            check('kernel-structure-' + kind, lambda kind=kind: kernel_structure_case(kind))
        for kind in ('utf8', 'json', 'framing-bound', 'base64', 'gzip', 'gzip-eof'):
            check('kernel-decode-' + kind, lambda kind=kind: kernel_decode_case(kind))
        check('tidy-composite-lf', tidy_composite_refusal)
        check('tidy-wrong-name', tidy_comparison_refusal)
        for kind in ('good', 'restrict', 'node', 'group', 'smack', 'restrict-read', 'node-read', 'group-read', 'smack-read'):
            check('kernel-access-' + kind, lambda kind=kind: access_case(kind))
        for kind in ('complete', 'limit', 'overflow', 'eof', 'utf8', 'bad-trailer', 'oserror', 'timeout', 'cancel',
                     'local-exit', 'close', 'extra-data', 'rejected-peer', 'rejected-tag', 'ordinary-overflow', 'storage', 'peer-only', 'tag-only'):
            check('transport-' + kind, lambda kind=kind: transport_case(kind))
        for kind in ('capture', 'request'):
            check('evidence-scope-' + kind, lambda kind=kind: evidence_scope_case(kind))
        for kind in ('boot', 'gate', 'fresh-budget', 'cleared', 'missing-module', 'unexpected-module', 'backup'):
            check('certification-' + kind, lambda kind=kind: certification_refusal(kind))
        for kind in ('good', 'symlink', 'non-directory', 'missing', 'owner', 'group', 'mode', 'links', 'stat-failure'):
            check('r17-backup-directory-' + kind, lambda kind=kind: backup_directory_case(kind))
        check('r17-certification-evidence-fields', certification_evidence_fields)
        for kind in ('root', 'evidence'):
            check('r19-privacy-' + kind, lambda kind=kind: certification_privacy_case(kind))
            check('r20-tidy-privacy-' + kind, lambda kind=kind: tidy_privacy_case(kind))
        for kind in ('good', 'hash', 'extra', 'extra-newline', 'hardlink', 'owner', 'mode', 'size', 'mtime', 'symlink'):
            check('task46-' + kind, lambda kind=kind: tidy_fixture(kind))
        for kind in ('hash', 'extra', 'extra-newline', 'hardlink', 'owner', 'mode', 'size', 'symlink', 'missing', 'receipt', 'directory-symlink'):
            check('r17-tidy-' + kind, lambda kind=kind: tidy_fixture(kind, 1))
        for child in ('DenialRunner.dll', 'DenialRunner.runtimeconfig.json'):
            for kind in ('hash', 'hardlink', 'owner', 'mode', 'size', 'symlink', 'missing'):
                check('r17-tidy-' + child + '-' + kind, lambda kind=kind, child=child: tidy_fixture(kind, 1, child))
        for kind in ('hash', 'extra', 'extra-newline', 'hardlink', 'owner', 'mode', 'size', 'symlink', 'missing', 'receipt', 'directory-symlink'):
            check('r19-tidy-' + kind, lambda kind=kind: tidy_fixture(kind, 2))
        for child in ('DenialRunner.dll', 'DenialRunner.runtimeconfig.json'):
            for kind in ('hash', 'hardlink', 'owner', 'mode', 'size', 'symlink', 'missing'):
                check('r19-tidy-' + child + '-' + kind, lambda kind=kind, child=child: tidy_fixture(kind, 2, child))
        check('denial-flow-EPERM', denial_flow)
        check('denial-flow-EACCES', lambda: denial_flow(13))
        check('denial-flow-missing-kernel', lambda: denial_flow(missing_kernel=True))
        check('denial-flow-transport-failure', lambda: denial_flow(transport_failure=True))
    result = {'runner': 'r16_checks.py', 'passed': len(names), 'failed': 0, 'skipped': 0,
              'TV_operations': 0, 'cases': names,
              'r17_fixture_boundary': 'uid901 DAC denial and POSIX metadata modeled explicitly; real Bash guards; no live TV validation'}
    (p.HERE / 'r16-results.json').write_text(json.dumps(result, indent=2) + '\n', newline='\n')
    print(json.dumps(result))


if __name__ == '__main__':
    run()
