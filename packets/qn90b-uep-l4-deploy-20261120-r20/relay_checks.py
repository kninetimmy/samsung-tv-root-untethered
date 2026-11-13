"""Host-only r15 cases: execute reconciliation's REAL generated shell bytes.

Paths, /proc and Windows' unavailable POSIX ownership are mapped to fixtures.
Hashes, links, inventory, unlink/rmdir, Bash refusal semantics and exit codes
are real. Fixture relay pins replace the unavailable TV DLL, not its guards.
No marker/attempt file is created, and no real SDK is ever constructed.
"""
import asyncio
import hashlib
import json
import os
import subprocess
from shlex import quote
import tempfile
from functools import partial
from pathlib import Path
from unittest.mock import patch

import packet as p
import recovery
import driver_shim as ds

BOOT = 'dc1477b5-295d-452b-90c4-ce10aec2f3c8'
PROOF = '38bcea864cd701b5826bd5a744a43f01b95922234cb2ac9cda6a45567b526f91'
PID = '8998'


class Fixture:
    def __enter__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='r16-relay-', dir=ds.REHEARSAL_TEMP)
        self.root = Path(self.temp.name)
        self.sdkroot = self.root / 'sdk_tools'
        self.sdkroot.mkdir()
        self.relay = self.sdkroot / recovery.NAME
        self.proc = self.root / 'proc'
        (self.proc / 'net').mkdir(parents=True)
        (self.proc / 'sys/kernel/random').mkdir(parents=True)
        (self.proc / 'sys/kernel/random/boot_id').write_text(BOOT + '\n')
        for name in ('tcp', 'tcp6'):
            (self.proc / 'net' / name).write_text('header\n')
        self.dll = self.root / 'source.dll'
        self.rc = self.root / 'source.runtimeconfig.json'
        self.dll.write_bytes(b'known-relay-fixture')
        self.rc.write_bytes(b'known-runtimeconfig-fixture')
        self.proof = self.sdkroot / 'selfroot-evidence/selfroot-proof.txt'
        self.proof.parent.mkdir()
        self.proof.write_bytes(b'known-proof-fixture')
        self.dll_hash = hashlib.sha256(self.dll.read_bytes()).hexdigest()
        self.rc_hash = hashlib.sha256(self.rc.read_bytes()).hexdigest()
        self.proof_hash = hashlib.sha256(self.proof.read_bytes()).hexdigest()
        self.meta = {}
        self.listener = None
        self.uid = '901'
        return self

    def __exit__(self, *args):
        self.temp.cleanup()

    def stale(self):
        self.relay.mkdir()
        (self.relay / 'recovery.dll').write_bytes(self.dll.read_bytes())
        (self.relay / 'recovery.runtimeconfig.json').write_bytes(self.rc.read_bytes())
        (self.relay / 'pid').write_bytes(b'8998 12218909\n')

    def command(self, remove):
        return self.translate(recovery.reconciliation_command(BOOT, PROOF, remove=remove))

    def translate(self, text):
        mapping = {p.RELAY: ds.to_posix(self.dll), recovery.RUNTIME: ds.to_posix(self.rc),
                   p.CANON: ds.to_posix(self.sdkroot), p.ROOT: ds.to_posix(self.sdkroot),
                   '/proc/': ds.to_posix(self.proc) + '/', p.RELAY_SHA: self.dll_hash,
                   p.EXPECTED[recovery.RUNTIME]: self.rc_hash, PROOF: self.proof_hash}
        for old in sorted(mapping, key=len, reverse=True):
            text = text.replace(old, mapping[old])
        return text

    def run(self, remove, command=None, extra_shim=''):
        shim = ds.shim_text()
        # Extend the inherited metadata shim; real filesystem supplies type/links.
        shim += r'''
eval "$(declare -f stat | sed '1s/stat/original_stat/')"
stat() {
    if test "$1" = -c && { test "$2" = '%F:%u:%a' || test "$2" = '%F:%u:%a:%h' || test "$2" = '%u:%a:%h'; }; then
        local target=${3} meta
        if test "$target" = .; then target=$PWD; fi
        case "$target" in /*) ;; *) target=$PWD/$target;; esac
        meta=${_META[$target]:-901:901:600}
        local uid=${meta%%:*} mode=${meta##*:}
        if test "$2" != '%u:%a:%h'; then printf '%s:' "$(command stat -c %F "$target")"; fi
        printf '%s:%s' "$uid" "$mode"
        if test "$2" != '%F:%u:%a'; then printf ':%s' "$(command stat -c %h "$target")"; fi
        printf '\n'
    else
        original_stat "$@"
    fi
}
'''
        shim += 'export REHEARSAL_UID=' + self.uid + '\n'
        shim += ds.seed(self.relay, self.meta.get('.', '901:901:700'))
        if self.relay.exists():
            shim += ds.seed(self.relay.resolve(), self.meta.get('.', '901:901:700'))
        if self.relay.is_symlink() and self.relay.is_dir():
            # MSYS can render a native Windows symlink target via its /tmp mount.
            canonical = ds.bash('cd -P ' + quote(ds.to_posix(self.relay)) + '; pwd -P')
            assert canonical.returncode == 0, canonical.stderr
            shim += '_META[' + canonical.stdout.strip() + ']=' + self.meta.get('.', '901:901:700') + '\n'
        shim += ds.seed(self.proc / PID, '901:901:700')
        for name in ('pid', 'recovery.dll', 'recovery.runtimeconfig.json'):
            shim += ds.seed(self.relay / name, self.meta.get(name, '901:901:600'))
        shim += r'''
eval "$(declare -f stat | sed '1s/stat/previous_stat/')"
stat() {
    if test "$1" = -c && test "$2" = '%u:%h'; then
        printf '901:%s\n' "$(command stat -c %h "$3")"
    else
        previous_stat "$@"
    fi
}
'''
        shim += extra_shim
        text = self.command(remove) if command is None else self.translate(command)
        # Use stdin like the live SDK, not Windows' size-limited -c argv.
        return subprocess.run([ds.BASH, '--noprofile', '--norc'],
                              input=shim + '\n' + text, text=True,
                              capture_output=True, timeout=30)


def absent():
    with Fixture() as f:
        result = f.run(True)
        assert result.returncode == 0 and result.stdout.strip() == 'RELAY_ABSENT', result.stderr
        assert not f.relay.exists()


def stale_removed():
    with Fixture() as f:
        f.stale()
        result = f.run(True)
        assert result.returncode == 0 and result.stdout.strip() == 'RELAY_REMOVED_PROVISIONAL', result.stderr
        assert not f.relay.exists(), 'stale relay was not actually removed'
        assert f.dll.read_bytes() == b'known-relay-fixture', 'source relay changed'
        assert f.run(False).returncode == 0


def refusal(kind):
    with Fixture() as f:
        f.stale()
        if kind == 'directory-mode':
            f.meta['.'] = '901:901:755'
        elif kind == 'directory-owner':
            f.meta['.'] = '0:0:700'
        elif kind == 'file-mode':
            f.meta['recovery.dll'] = '901:901:644'
        elif kind == 'file-owner':
            f.meta['recovery.dll'] = '0:0:600'
        elif kind == 'dll-hash':
            (f.relay / 'recovery.dll').write_bytes(b'wrong')
        elif kind == 'runtime-hash':
            (f.relay / 'recovery.runtimeconfig.json').write_bytes(b'wrong')
        elif kind in ('empty-dll', 'empty-runtimeconfig', 'empty-pid'):
            child = {'empty-dll': 'recovery.dll', 'empty-runtimeconfig': 'recovery.runtimeconfig.json',
                     'empty-pid': 'pid'}[kind]
            (f.relay / child).write_bytes(b'')
        elif kind == 'source-hash':
            f.dll.write_bytes(b'wrong')
        elif kind == 'extra':
            (f.relay / 'unexpected').touch()
        elif kind == 'missing':
            (f.relay / 'recovery.dll').unlink()
        elif kind == 'hardlink':
            os.link(f.relay / 'recovery.dll', f.root / 'external-link')
        elif kind == 'child-symlink':
            (f.relay / 'recovery.dll').unlink()
            os.symlink(f.dll, f.relay / 'recovery.dll')
        elif kind == 'directory-symlink':
            f.relay.rename(f.root / 'outside')
            os.symlink(f.root / 'outside', f.relay, target_is_directory=True)
        elif kind == 'not-directory':
            # Use a second path; the first three-file tree stays untouched.
            f.relay.rename(f.root / 'outside')
            f.relay.write_bytes(b'not-directory')
        elif kind == 'live-pid':
            (f.proc / PID).mkdir()
        elif kind in ('listener', 'listener6'):
            table = 'tcp' if kind == 'listener' else 'tcp6'
            (f.proc / 'net' / table).write_text('0: 00000000:65F9 00000000:0000 0A\n')
        elif kind == 'unreadable-table':
            (f.proc / 'net/tcp').unlink()
        elif kind == 'boot':
            (f.proc / 'sys/kernel/random/boot_id').write_text('other-boot\n')
        elif kind == 'proof':
            f.proof.write_bytes(b'wrong-proof')
        elif kind == 'uid':
            f.uid = '0'
        elif kind in ('pid-malformed', 'pid-nul', 'pid-newline'):
            data = {'pid-malformed': b'../1 22\n', 'pid-nul': b'8998 12218909\n\0',
                    'pid-newline': b'8998 12218909\n\n'}[kind]
            (f.relay / 'pid').write_bytes(data)
        else:
            raise AssertionError('unknown case: ' + kind)
        before = {x.name: x.read_bytes() for x in f.relay.iterdir() if x.is_file()} if f.relay.is_dir() else None
        result = f.run(True)
        assert result.returncode != 0, 'relay refusal missing: ' + kind
        if before is not None:
            after = {x.name: x.read_bytes() for x in f.relay.iterdir() if x.is_file()}
            assert before == after, 'relay refusal wrote files: ' + kind
        assert 'RELAY_REFUSAL' in result.stderr, 'unclear relay refusal: ' + kind + result.stderr
        if kind.startswith('empty-'):
            expected = {'empty-dll': 'stale relay dll hash changed',
                        'empty-runtimeconfig': 'stale runtimeconfig hash changed',
                        'empty-pid': 'pid file malformed'}[kind]
            assert expected in result.stderr, 'empty child failed before hash/PID refusal: ' + kind + result.stderr


class SDK:
    def __init__(self, fixture, events, number, resurrect=False):
        self.fixture, self.events, self.number, self.resurrect = fixture, events, number, resurrect

    async def connect(self):
        self.events.append(('connect', self.number))

    async def disconnect(self):
        self.events.append(('disconnect', self.number))

    async def capture(self, command):
        remove = 'RELAY_REMOVED_PROVISIONAL' in command
        if self.resurrect and self.number == 2 and not self.fixture.relay.exists():
            self.fixture.stale()  # independent view: remover saw absent, next session does not
        result = self.fixture.run(remove, command=command)
        return result.returncode, (result.stdout + result.stderr).strip()


def fresh_session(resurrect=False):
    with Fixture() as f:
        f.stale()
        events, created = [], []
        def factory():
            obj = SDK(f, events, len(created) + 1, resurrect)
            created.append(obj)
            return obj
        try:
            asyncio.run(recovery.reconcile(factory, lambda *a, **k: None, BOOT, PROOF))
        except p.Stop:
            assert resurrect, 'valid fresh-session reconciliation refused'
        else:
            assert not resurrect, 'fresh-session reappearance was trusted'
        assert len(created) == 2 and created[0] is not created[1], 'fresh SDK session not constructed'
        assert events == [('connect', 1), ('disconnect', 1), ('connect', 2), ('disconnect', 2)], 'fresh SDK lifecycle wrong'


def cleanup_reappearance():
    import deploy
    from trial import Trial
    with Fixture() as f:
        f.stale()
        events, created = [], []
        def factory(*a):
            obj = SDK(f, events, len(created) + 1)
            created.append(obj)
            return obj
        async def noop(*a):
            pass
        obj = deploy.Deployment(None, lambda *a, **k: None, BOOT, PROOF)
        obj.recovery_attempted = True
        obj.recovery_receipt = {'directory': '45845:100001:901:700', 'pid': PID, 'birth': '12218909'}
        # False-success remover: same defect class as r14's receipt/view mismatch.
        with patch.object(Trial, 'finish', noop), patch.object(obj, 'baseline', noop), \
             patch.object(recovery, 'stop', noop), patch.object(deploy, 'BridgeSDK', factory):
            asyncio.run(obj.finish())
        assert 'recovery-relay' in obj.close_errors, 'cleanup trusted removal without a fresh-session check'
        assert obj.recovery_receipt is not None and recovery.PATH in obj.cleanup_pending, 'failed cleanup lost ownership evidence'


def before_attempt():
    import active
    import disable
    class End(Exception):
        pass
    for module in (active, disable):
        events = []
        async def reconcile(*a):
            events.append('reconcile')
            raise p.Stop('fixture precondition refusal')
        class Attempt:
            def __init__(self, *a):
                pass
            def take(self):
                events.append('attempt')
                raise End()
            def require_unused(self):
                pass
        def anchor():
            module.BOOT, module.PROOF_SHA = BOOT, PROOF
        with patch.object(module, 'marker_for', lambda *a: None), \
             patch.object(module, 'protect_seal', lambda: None), \
             patch.object(module, 'anchor_from_prior', anchor), \
             patch.object(module, 'log', lambda *a, **k: None), \
             patch.object(module, 'OneAttempt', Attempt), \
             patch.object(module, 'BridgeSDK', lambda *a: (_ for _ in ()).throw(AssertionError('real SDK construction'))), \
             patch.object(p, 'require_openssl', lambda: 'fixture'), \
             patch.object(recovery, 'reconcile', reconcile):
            try:
                asyncio.run(module.main())
            except (p.Stop, End):
                pass
        assert events == ['reconcile'], 'relay prerequisites must refuse before attempt: ' + module.__name__


def anchor_digest():
    import active
    with patch.object(p, 'digest', lambda path: '0' * 64), patch.object(active, 'log', lambda *a, **k: None):
        try:
            active.anchor_from_prior()
        except p.Stop:
            return
    raise AssertionError('inherited install digest refusal missing')


def install_replay():
    import install
    with patch.object(install, 'log', lambda *a, **k: None):
        try:
            install.prerequisites()
        except p.Stop as error:
            assert 'never replay' in str(error)
            return
    raise AssertionError('inherited install replay was not refused')


def stop_absence_guard():
    """A directory reappears after successful rmdir, in the SAME command view.

    The old AND-list absence guard printed success anyway. Execute the actual
    stop bytes, modeling only TERM/process exit and deliberate reappearance.
    """
    with Fixture() as f:
        f.stale()
        proc = f.proc / PID
        proc.mkdir()
        (proc / 'stat').write_text(' '.join(['0'] * 21 + ['12218909']) + '\n')
        (proc / 'cmdline').write_text(f.translate(recovery.ARGS))
        extra = ('kill() { test "$1" = -TERM; test "$2" = 8998; '
                 'command unlink ' + quote(ds.to_posix(proc / 'stat')) + '; '
                 'command unlink ' + quote(ds.to_posix(proc / 'cmdline')) + '; '
                 'command rmdir ' + quote(ds.to_posix(proc)) + '; }\n'
                 'rmdir() { command rmdir "$@"; command mkdir ' + quote(ds.to_posix(f.relay)) + '; }\n')
        class StopSDK:
            async def capture(self, command):
                result = f.run(False, command=command, extra_shim=extra)
                return result.returncode, (result.stdout + result.stderr).strip()
        try:
            asyncio.run(recovery.stop(StopSDK(), lambda *a, **k: None,
                        {'directory': '45845:100001:901:700', 'pid': PID, 'birth': '12218909'}))
        except p.Stop:
            assert f.relay.is_dir(), 'reappearance fixture did not execute'
            return
    raise AssertionError('stop trusted non-aborting absence guard')


def path_identity_refusal():
    with Fixture() as f:
        f.stale()
        before = {x.name: x.read_bytes() for x in f.relay.iterdir()}
        extra = ('eval "$(declare -f stat | sed \'1s/stat/identity_stat/\')"\n'
                 'stat() { if test "$1" = -c && test "$2" = \'%d:%i:%u:%a\' && test "$3" = '
                 + quote(ds.to_posix(f.relay)) + '; then echo 45845:200002:901:700; '
                 'else identity_stat "$@"; fi; }\n')
        result = f.run(True, extra_shim=extra)
        assert result.returncode != 0, 'relay path identity refusal missing'
        assert 'RELAY_REFUSAL' in result.stderr
        assert before == {x.name: x.read_bytes() for x in f.relay.iterdir()}, 'changed path caused unlink'


REFUSALS = ('directory-mode', 'directory-owner', 'file-mode', 'file-owner',
            'dll-hash', 'runtime-hash', 'source-hash', 'extra', 'missing', 'hardlink',
            'child-symlink', 'directory-symlink', 'not-directory', 'live-pid',
            'listener', 'listener6', 'unreadable-table', 'boot', 'proof', 'uid',
            'pid-malformed', 'pid-nul', 'pid-newline', 'empty-dll', 'empty-runtimeconfig', 'empty-pid')
for _kind in REFUSALS:
    globals()['refuses_' + _kind.replace('-', '_')] = partial(refusal, _kind)


def fresh_reappearance():
    fresh_session(True)


def run(case):
    case('relay-absent', absent)
    case('relay-stale-removed', stale_removed)
    for kind in REFUSALS:
        case('relay-refuses-' + kind, lambda kind=kind: refusal(kind))
    case('relay-fresh-session', fresh_session)
    case('relay-fresh-reappearance', lambda: fresh_session(True))
    case('relay-cleanup-reappearance', cleanup_reappearance)
    case('relay-before-attempt', before_attempt)
    case('relay-inherited-anchor', anchor_digest)
    case('relay-install-replay', install_replay)
    case('relay-stop-absence-guard', stop_absence_guard)
    case('relay-path-identity', path_identity_refusal)


if __name__ == '__main__':
    names = []
    def check(name, fn):
        fn()
        names.append(name)
    run(check)
    print(json.dumps({'passed': len(names), 'TV_operations': 0}))
