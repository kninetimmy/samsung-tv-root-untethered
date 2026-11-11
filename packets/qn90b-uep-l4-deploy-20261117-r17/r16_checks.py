"""Offline r16 cases plus r17 DAC regressions. No real SDK/TV/marker/attempt.

The host user can read fixture children: an explicit shim denies uid901 child
reads/listing, while real Bash runs the production metadata-only command. This
models the DAC boundary, not live TV validation.
"""
import asyncio
import base64
import gzip
import json
import os
import tempfile
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
LINE = ('[   95.244381] [Verification fail] file ' + CANON
        + '/uep-probe.elf is not signed. Sign it.(fsname:vdfs, mnt_flags:1020)')


def denial_good():
    for errno in (1, 13):
        assert denial.assess_exec(77, exec_result(errno=errno))['errno'] == errno
    assert denial.assess_kernel('[ 1.000000] old\n', '[ 1.000000] old\n' + LINE + '\n', CANON, 95, 96) == LINE
    text = denial.bounded([p.ROOT + '/denial-0123456789abcdef/uep-probe.elf'], 5)
    assert text.startswith('exec /usr/bin/dotnet ') and '$?' not in text and 'wait ' not in text


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


def kernel_missing():
    stop(lambda: denial.assess_kernel('', '', CANON, 95, 96), 'missing kernel denial accepted')


def kernel_old():
    stop(lambda: denial.assess_kernel(LINE, LINE, CANON, 95, 96), 'old kernel denial accepted')


def kernel_wrong_path():
    stop(lambda: denial.assess_kernel('', LINE.replace(CANON, CANON + '0'), CANON, 95, 96),
         'wrong kernel path accepted')


def kernel_outside():
    stop(lambda: denial.assess_kernel('', LINE, CANON, 96, 97), 'out-of-window kernel denial accepted')


def kernel_rotated():
    stop(lambda: denial.assess_kernel('old\n', 'different\n' + LINE, CANON, 95, 96), 'rotated kernel window accepted')


def kernel_duplicate():
    stop(lambda: denial.assess_kernel('', LINE + '\n' + LINE, CANON, 95, 96), 'duplicate kernel denial accepted')


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
         patch.object(certify, 'protect_seal', noop), patch.object(certify, 'repo_head', lambda: p.COMMIT), \
         patch.object(certify, 'read_only', read_only), patch.object(denial, 'run', denied), \
         patch.object(certify, 'succeed', succeeded), patch.object(certify, 'log', logged), \
         patch.object(certify, 'record_failure', failed):
        asyncio.run(certify.main())
        asyncio.run(certify.main(readiness=True))
        async def refusal(sdk):
            raise p.Stop('modeled metadata refusal')
        with patch.object(certify, 'read_only', refusal):
            stop(lambda: asyncio.run(certify.main(readiness=True)), 'metadata failure not propagated')
    assert events == ['attempt', 'status', 'r17-readiness-passed', 'failure'], events


def tidy_fixture(kind='good'):
    with rc.Fixture() as f:
        f.relay = f.sdkroot / 'denial-fd9fa25930776ce9'
        f.relay.mkdir()
        elf = f.relay / 'uep-probe.elf'
        elf.write_bytes(p.NATIVE.read_bytes())
        os.utime(elf, (int(tidy.MTIME), int(tidy.MTIME)))
        uid, mode = '901', '700'
        if kind == 'hash': elf.write_bytes(b'x' * 5196)
        if kind == 'extra': (f.relay / 'extra').write_bytes(b'x')
        if kind == 'extra-newline':
            # Windows paths cannot contain LF; create the native MSYS filename
            # with bash so the actual command-substitution edge is exercised.
            out = ds.bash('touch ' + __import__('shlex').quote(ds.to_posix(f.relay)) + "/$'\\n'")
            assert out.returncode == 0, out.stderr
        if kind == 'hardlink': os.link(elf, f.root / 'external')
        if kind == 'owner': uid = '0'
        if kind == 'mode': mode = '600'
        if kind == 'size': elf.write_bytes(b'x')
        if kind == 'mtime': os.utime(elf, (0, 0))
        if kind == 'symlink':
            elf.rename(f.root / 'outside')
            os.symlink(f.root / 'outside', elf)
        if kind in ('hash', 'size'):
            os.utime(elf, (int(tidy.MTIME), int(tidy.MTIME)))
        extra = ('eval "$(declare -f stat | sed \'1s/stat/tidy_stat/\')"\n'
                 'stat() { if test "$1" = -c && test "$2" = %F:%u:%a:%h:%s:%Y; then '
                 'printf "%s:' + uid + ':' + mode + ':%s:%s:%s\\n" '
                 '"$(command stat -c %F "$3")" "$(command stat -c %h "$3")" '
                 '"$(command stat -c %s "$3")" "$(command stat -c %Y "$3")"; else tidy_stat "$@"; fi; }\n')
        text = tidy.command().replace(p.CERTIFY_BOOT, rc.BOOT)
        before = elf.read_bytes()
        out = f.run(False, command=text, extra_shim=extra)
        if kind == 'good':
            assert out.returncode == 0, out.stderr
            assert not f.relay.exists(), 'task46 path not removed'
            out = f.run(False, command=tidy.absence_command().replace(p.CERTIFY_BOOT, rc.BOOT))
            assert out.returncode == 0 and 'TASK46_ABSENT_FRESH_SESSION' in out.stdout, out.stderr
        else:
            assert out.returncode != 0 and 'TIDY_REFUSAL' in out.stderr, 'tidy accepted ' + kind
            assert elf.exists() and elf.read_bytes() == before, 'tidy refusal changed file: ' + kind


def certify_boot_refusal():
    certification_refusal('boot')


def certify_module_refusal():
    certification_refusal('missing-module')


def tidy_newline_refusal():
    tidy_fixture('extra-newline')


def denial_flow(errno=1, missing_kernel=False):
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
            async def capture(self, command, *, preserve_output=False):
                if command == 'cat /proc/uptime':
                    self.uptime_reads += 1
                    return 0, ('95.0 0.0' if self.uptime_reads == 1 else '96.0 0.0')
                if command == denial.KERNEL_COMMAND:
                    self.logs += 1
                    text = '[ 1.000000] old\n' + ((LINE + '\n') if self.logs == 2 and not missing_kernel else '')
                    return 0, base64.b64encode(gzip.compress(text.encode())).decode()
                if 'exec /usr/bin/dotnet ' in command:
                    self.execs += 1
                    command = command.replace(denial.bounded([p.ROOT + '/denial-0123456789abcdef/uep-probe.elf'], 5),
                        'printf %s ' + __import__('shlex').quote(exec_result(errno=errno)) + '\nexit 77\n')
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
        with patch.object(denial.secrets, 'token_hex', lambda size: '0123456789abcdef'), \
             patch.object(sl, 'save', lambda *a, **k: None):
            if missing_kernel:
                stop(lambda: asyncio.run(denial.run(obj, save)), 'denial flow accepted missing kernel witness')
                assert f.relay.is_dir() and (f.relay / 'uep-probe.elf').is_file(), 'failed denial lost staging evidence'
            else:
                asyncio.run(denial.run(obj, save))
                assert not f.relay.exists(), 'denial flow failed to remove its three-file stage'
                assert events.count('denial-passed') == 1
        assert obj.execs == 1, 'denial flow retried native execution'


def run():
    names = []
    def check(name, fn):
        fn()
        names.append(name)
    with patch.object(sl, 'save', lambda *a, **k: None):
        for fn in (denial_good, denial_started, denial_masked, denial_wrong_errno, denial_masked_trailer,
                   denial_marker, kernel_missing, kernel_old, kernel_wrong_path, kernel_outside,
                   kernel_rotated, kernel_duplicate, typed_exception, duplicate_precheck, certification):
            check(fn.__name__, fn)
        for kind in ('boot', 'gate', 'fresh-budget', 'cleared', 'missing-module', 'unexpected-module', 'backup'):
            check('certification-' + kind, lambda kind=kind: certification_refusal(kind))
        for kind in ('good', 'symlink', 'non-directory', 'missing', 'owner', 'group', 'mode', 'links', 'stat-failure'):
            check('r17-backup-directory-' + kind, lambda kind=kind: backup_directory_case(kind))
        check('r17-certification-evidence-fields', certification_evidence_fields)
        for kind in ('good', 'hash', 'extra', 'extra-newline', 'hardlink', 'owner', 'mode', 'size', 'mtime', 'symlink'):
            check('task46-' + kind, lambda kind=kind: tidy_fixture(kind))
        check('denial-flow-EPERM', denial_flow)
        check('denial-flow-EACCES', lambda: denial_flow(13))
        check('denial-flow-missing-kernel', lambda: denial_flow(missing_kernel=True))
    result = {'runner': 'r16_checks.py', 'passed': len(names), 'failed': 0, 'skipped': 0,
              'TV_operations': 0, 'cases': names,
              'r17_fixture_boundary': 'uid901 DAC denial and POSIX metadata modeled explicitly; real Bash guards; no live TV validation'}
    (p.HERE / 'r16-results.json').write_text(json.dumps(result, indent=2) + '\n', newline='\n')
    print(json.dumps(result))


if __name__ == '__main__':
    run()
