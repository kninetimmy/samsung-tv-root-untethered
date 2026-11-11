"""Host-only coverage for the session/staging layer (r13).

Every case is aimed at a defect that previously survived. The cases execute the
generated capture text wherever that is possible, use the real protected register
at seal time, and keep the negative fixture that a mutant would need to pass:

  1  upload-contract         every staged name is whitelisted AND the real
                             sdk.prepare_upload accepts the real files
  2  stage-files             the real stage_files() pushes the manifest and
                             stage.sh, creates the transport dir before the
                             first push, and cleans it afterwards
  3  module-files            the generated module capture is executed against
                             real files; a wrong byte, mode, dir or unkeyed
                             line must STOP
  4  protected-set           the real EXPECTED set (not a fallback), its 24
                             paths, and every hash sourced from the fresh
                             register
  5  protected-closeout      drift, an extra line, a swapped order and a short
                             response must all STOP
  6  stage-sh                publish, clean-EOF, unlisted, absent-with-row and
                             unterminated-wrong-row
  7  state-capture           every capture key is in the generated command; a
                             missing state_tmp key, a present temp path and a
                             malformed value must STOP
  8  module-gate             a valid boot log passes; an empty first log or a
                             partially written first line is polled until the
                             exit line arrives; a persistent missing exit, a
                             duplicate or nonzero exit, an unexpected line, a
                             stale log, a missing summary and a missing detail
                             must STOP

No TV contact: the remote side is a temp directory, the SDK is a stub, and the
shell shim only maps production paths to temp files.
"""
import asyncio
import hashlib
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
import sdk
import stage_common
import stage_lib
import stage_transport
import driver_shim
import prepare

RESULTS = []
TEMP_DIRS = []


def case(name, fn):
    try:
        fn()
    except Exception as error:
        RESULTS.append({'case': name, 'verdict': 'FAILED',
                        'detail': type(error).__name__ + ': ' + str(error)[:300]})
        raise
    RESULTS.append({'case': name, 'verdict': 'passed'})


def tmpdir(prefix):
    path = Path(tempfile.mkdtemp(prefix='r12-session-' + prefix + '-',
                                 dir=driver_shim.REHEARSAL_TEMP))
    TEMP_DIRS.append(path)
    return path


def expect_stop(fn, label):
    try:
        fn()
    except p.Stop:
        return
    raise AssertionError('expected STOP: ' + label)


def install_assets():
    return {'manager.dll': p.NEW, 'manager.runtimeconfig.json': p.NEW_RC,
            'UepGateHost.dll': p.HOST,
            'UepGateHost.runtimeconfig.json': p.HOST_RC,
            'boot.sh': p.MODULE_BOOT, 'module.json': p.MODULE_JSON}


def session_assets(extra):
    """Exactly what GateSession stages: chain + extras + materials + manifest."""
    agent = p.HERE / 'build/SamsungTvRootAgent.dll'
    if not agent.is_file():
        candidate = tmpdir('agent') / 'SamsungTvRootAgent.dll'
        candidate.write_bytes(b'agent-placeholder')
        agent = candidate
    assets = {'stage.sh': p.HERE / 'stage.sh',
              'SamsungTvArchiveRoot.dll': p.LAUNCHER,
              'SamsungTvRootAgent.dll': agent}
    assets.update(extra)
    materials = tmpdir('materials')
    for name in sorted(p.MATERIALS - {'private.pem', 'files.sha256'}):
        path = materials / name
        path.write_bytes(('material:' + name).encode('ascii'))
        assets[name] = path
    manifest = tmpdir('manifest') / 'files.sha256'
    manifest.write_text(''.join(p.digest(path) + '  ' + name + '\n'
                                for name, path in assets.items()),
                        encoding='ascii', newline='\n')
    assets['files.sha256'] = manifest
    return assets


# 1 --------------------------------------------------------------------------
def upload_contract():
    assets = session_assets(install_assets())
    unknown = sorted(set(assets) - sdk.UPLOAD_NAMES)
    p.require(not unknown, 'gate-session assets outside the upload whitelist: ' + str(unknown))
    p.require('arbitrary.dll' not in sdk.UPLOAD_NAMES, 'whitelist widened too far')

    exercised = 0
    for name, source in sorted(assets.items()):
        p.require(source.is_file(), 'staged asset missing from disk: ' + name)
        if source.stat().st_size > sdk.MAX_UPLOAD:
            continue
        command, expected = sdk.prepare_upload(source, p.STAGE + '/' + name,
                                               '45845:100001')
        p.require(expected == p.digest(source) + '  ' + name,
                  'prepare_upload receipt mismatch: ' + name)
        p.require('sha256sum' in command and name in command,
                  'prepare_upload command lost its receipt for ' + name)
        exercised += 1
    p.require(exercised >= 10,
              'prepare_upload was not exercised across the real asset set: ' + str(exercised))

    # The target must stay inside the owned stage and on the reviewed list.
    expect_stop(lambda: sdk.prepare_upload(
        p.HERE / 'stage.sh', p.STAGE + '/../boot.sh', '45845:100001'),
        'target outside the owned stage')
    expect_stop(lambda: sdk.prepare_upload(
        p.HERE / 'stage.sh', p.STAGE + '/arbitrary.dll', '45845:100001'),
        'unlisted upload name')


# 2 --------------------------------------------------------------------------
class FakeRemote:
    """Minimal stand-in for the TV-side staging directory."""

    def __init__(self, root):
        self.root = Path(root)
        self.claimed = False

    def path_of(self, target):
        return self.root / Path(target).name

    async def read(self, label, command):
        if label == 'sdk-root':
            return p.CANON
        if label == 'on-demand':
            return p.CANON + '/on-demand'
        if label == 'exclusive-claim':
            self.root.mkdir(parents=True)
            return '45845:100001'
        if label.startswith('upload-hash'):
            target = command.split()[-1]
            data = self.path_of(target).read_bytes()
            return hashlib.sha256(data).hexdigest() + '  ' + target
        raise AssertionError('unexpected remote read: ' + label)

    async def control(self, action):
        self.claimed = action == 'publish'


class FakeTrial:
    def __init__(self, remote_root):
        self.remote = FakeRemote(remote_root)
        self.sdk = self
        self.pushed = []
        self.publish_after_pushes = None
        self.gz_dir_seen = False
        self.stage_id = None

    async def push(self, source, target, stage_id=None):
        if not self.gz_dir_seen:
            self.gz_dir_seen = stage_transport.GZ_HOST_DIR.exists()
        self.pushed.append(Path(target).name)
        shutil.copyfile(source, self.remote.path_of(target))

    async def read(self, label, command):
        return await self.remote.read(label, command)

    async def control(self, action):
        if action == 'publish':
            self.publish_after_pushes = len(self.pushed)
        return await self.remote.control(action)

    async def metadata(self, path):
        candidate = self.remote.path_of(path)
        return None if not candidate.exists() else {'path': str(candidate)}

    async def check_stage(self):
        return True

    def save(self, event, **data):
        pass


def stage_files_all_small():
    stage_transport.GZ_HOST_DIR.exists() and shutil.rmtree(
        stage_transport.GZ_HOST_DIR, ignore_errors=True)
    tmp = tmpdir('transport')
    try:
        assets = session_assets(install_assets())
        trial = FakeTrial(tmp / 'remote' / p.PKG)
        asyncio.run(stage_transport.stage_files(trial, assets))
        p.require(trial.remote.claimed, 'publish control never reached')
        p.require('files.sha256' in trial.pushed,
                  'the manifest was not staged')
        p.require('stage.sh' in trial.pushed,
                  'stage.sh was not staged')
        p.require(trial.gz_dir_seen,
                  'the transport staging directory was not created before the first push')
        p.require(trial.publish_after_pushes == len(trial.pushed),
                  'publish was sent before every asset was pushed')
        p.require(not stage_transport.GZ_HOST_DIR.exists(),
                  'host transport staging directory was not cleaned up')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        shutil.rmtree(stage_transport.GZ_HOST_DIR, ignore_errors=True)


# 3 --------------------------------------------------------------------------
class MappedCapture:
    """Execute the generated module capture against real, mapped files."""

    def __init__(self, entries, dir_real, dir_meta, extra='', override_modes=None):
        self.entries = dict(entries)
        if override_modes:
            for name, mode in override_modes.items():
                real = self.entries[name][0]
                self.entries[name] = (real, mode)
        self.dir_real = Path(dir_real)
        self.dir_meta = dir_meta
        self.extra = extra
        self.commands = []

    def shim(self):
        lines = ['declare -A _REAL _MODE',
                 "_DIR_REAL='" + driver_shim.to_posix(self.dir_real) + "'",
                 "_DIR_META='" + self.dir_meta + "'"]
        for name, (real, mode) in self.entries.items():
            lines.append("_REAL['" + name + "']='" + driver_shim.to_posix(real) + "'")
            lines.append("_MODE['" + name + "']='" + mode + "'")
        lines.append(r'''sha256sum() {
    local target=$1 real=${_REAL[$1]:-}
    if test -z "$real" || test ! -f "$real"; then
        echo "unexpected sha path: $1" >&2
        return 1
    fi
    local line
    line=$(command sha256sum -- "$real") || return 1
    printf '%s  %s\n' "${line%% *}" "$target"
}
stat() {
    local fmt= target=
    while test $# -gt 0; do
        case "$1" in
            -c) fmt=$2; shift 2;;
            --) shift;;
            *) target=$1; shift;;
        esac
    done
    case "$fmt" in
        '%u:%a')
            if test -z "${_REAL[$target]:-}" || test ! -f "${_REAL[$target]}"; then
                echo "unexpected stat path: $target" >&2
                return 1
            fi
            echo "${_MODE[$target]}"
            ;;
        '%F:%u:%g:%a')
            if test -z "${_DIR_REAL:-}" || test ! -d "$_DIR_REAL"; then
                echo "missing module directory: $target" >&2
                return 1
            fi
            echo "$_DIR_META"
            ;;
        *)
            echo "unmodelled format: $fmt" >&2
            return 1
            ;;
    esac
}''')
        return '\n'.join(lines)

    async def capture(self, command):
        self.commands.append(command)
        result = driver_shim.bash(self.shim() + '\n' + command + self.extra + '\n')
        return result.returncode, result.stdout


def _module_fixture(flip=None):
    root = tmpdir('module')
    files = {
        p.MODULE_BOOT_PATH: (root / 'boot.sh', '0:755', p.MODULE_BOOT),
        p.MODULE_JSON_PATH: (root / 'module.json', '0:644', p.MODULE_JSON),
        p.MODULE_HOST: (root / 'UepGateHost.dll', '0:644', p.HOST),
        p.MODULE_HOST_RC: (root / 'UepGateHost.runtimeconfig.json', '0:644', p.HOST_RC),
    }
    entries = {}
    for name, (real, mode, source) in files.items():
        real.write_bytes(source.read_bytes())
        if flip == name:
            data = bytearray(real.read_bytes())
            data[0] ^= 0xff
            real.write_bytes(bytes(data))
        entries[name] = (real, mode)
    module_dir = root / 'uep-gate'
    module_dir.mkdir()
    return entries, module_dir


def module_files_parse():
    entries, module_dir = _module_fixture()
    stub = MappedCapture(entries, module_dir, p.MODULE_DIR_META)
    asyncio.run(stage_common.module_files(stub, 'session-check-module'))
    command = stub.commands[-1]
    for fragment in ('boot_mode=', 'json_mode=', 'host_mode=', 'rc_mode=', 'dir_meta='):
        p.require(fragment in command, 'module capture lost ' + fragment)
    p.require("stat -c '%u:%a' \" + ' '.join(paths)" not in command,
              'module capture still uses the unparseable multi-line modes form')


def module_files_rejects_content():
    entries, module_dir = _module_fixture(flip=p.MODULE_HOST)
    stub = MappedCapture(entries, module_dir, p.MODULE_DIR_META)
    expect_stop(lambda: asyncio.run(
        stage_common.module_files(stub, 'session-check-module-content')),
        'module file content drift')


def module_files_rejects_mode():
    entries, module_dir = _module_fixture()
    stub = MappedCapture(entries, module_dir, p.MODULE_DIR_META,
                         override_modes={p.MODULE_HOST: '0:600'})
    expect_stop(lambda: asyncio.run(
        stage_common.module_files(stub, 'session-check-module-mode')),
        'module file mode drift')


def module_files_rejects_unkeyed():
    entries, module_dir = _module_fixture()
    stub = MappedCapture(entries, module_dir, p.MODULE_DIR_META,
                         extra='\necho "unkeyed stat output"\n')
    expect_stop(lambda: asyncio.run(
        stage_common.module_files(stub, 'session-check-module-unkeyed')),
        'unkeyed output line')


def module_files_rejects_missing_dir():
    entries, module_dir = _module_fixture()
    missing = module_dir.parent / 'not-the-module-dir'
    stub = MappedCapture(entries, missing, p.MODULE_DIR_META)
    expect_stop(lambda: asyncio.run(
        stage_common.module_files(stub, 'session-check-module-dir')),
        'missing module directory')


# 4 --------------------------------------------------------------------------
def protected_set():
    p.require(p.EXPECTED is not None,
              'the fresh protected register must exist at seal time; no fallback')
    expected = p.expected_set()
    register = json.loads((p.HERE / 'protected-register.json').read_text(encoding='utf-8'))['files']
    p.require(len(register) == 26, 'the inspection register must hold 26 files')
    p.require(p.TARGET in register and p.TARGET_RC in register,
              'the inspection must capture both manager files')
    independent = set(p.inspection_targets()) - {p.TARGET_RC}
    p.require(set(expected) == independent,
              'post-install protected set is not the inspected set minus the replaced runtimeconfig')
    p.require(p.TARGET not in expected and p.TARGET_RC not in expected,
              'the post-install set still pins a file the install replaces')
    p.require(len(expected) == 24, 'post-install protected set must have 24 entries')
    for path, digest in expected.items():
        p.require(register.get(path) == digest,
                  'expected hash is not sourced from the fresh register: ' + path)
    p.require(p.TARGET_RC in p.inspection_targets(),
              'the inspection must still capture the runtimeconfig baseline')
    p.require(p.PREV_MANAGER_RC_SHA != p.NEW_MANAGER_RC_SHA,
              'the two manager runtimeconfig baselines must differ')


# 5 --------------------------------------------------------------------------
class FakeHashCapture:
    def __init__(self, hashes, order='normal', extra=None, drop=False, duplicate=False):
        self.hashes = hashes
        self.order = order
        self.extra = extra
        self.drop = drop
        self.duplicate = duplicate

    async def capture(self, command):
        paths = command.split()[1:]
        lines = [self.hashes.get(path, '0' * 64) + '  ' + path for path in paths]
        if self.order == 'reverse':
            lines.reverse()
        if self.drop:
            lines = lines[:-1]
        if self.duplicate:
            lines.append(lines[0])
        if self.extra:
            lines.append(self.extra)
        return 0, '\n'.join(lines) + '\n'


def _closeout_accepts():
    from stage_lib import protected_hashes
    expected = p.expected_set()
    asyncio.run(protected_hashes(FakeHashCapture(dict(expected)), expected))


def _closeout_rejects(**kwargs):
    from stage_lib import protected_hashes
    expected = p.expected_set()
    expect_stop(lambda: asyncio.run(
        protected_hashes(FakeHashCapture(dict(expected), **kwargs), expected)),
        'protected closeout ' + str(sorted(kwargs)))


def protected_closeout_accepts():
    _closeout_accepts()


def protected_closeout_rejects_drift():
    from stage_lib import protected_hashes
    expected = p.expected_set()
    victim = sorted(expected)[0]
    drifted = dict(expected)
    drifted[victim] = '0' * 64
    expect_stop(lambda: asyncio.run(
        protected_hashes(FakeHashCapture(drifted), expected)),
        'protected file drift')


def protected_closeout_rejects_extra():
    _closeout_rejects(extra='0' * 64 + '  ' + p.TARGET_RC)


def protected_closeout_rejects_order():
    _closeout_rejects(order='reverse')


def protected_closeout_rejects_order_synthetic():
    """Two paths with the same digest: only the order guard can catch this."""
    from stage_lib import protected_hashes
    expected = {'/a': '0' * 64, '/b': '0' * 64}

    class Swapped:
        async def capture(self, command):
            paths = command.split()[1:]
            lines = ['0' * 64 + '  ' + path for path in reversed(paths)]
            return 0, '\n'.join(lines) + '\n'

    expect_stop(lambda: asyncio.run(protected_hashes(Swapped(), expected)),
                'hash output did not follow the requested path order')


def protected_closeout_rejects_short():
    _closeout_rejects(drop=True)


def protected_closeout_rejects_duplicate():
    _closeout_rejects(duplicate=True)


# 6 --------------------------------------------------------------------------
def stage_sh_case(extra_file=False, missing_file=False,
                  no_final_newline=False, wrong_last=False):
    lay = driver_shim.new_layout()
    try:
        stage_dir = lay['stage_win'].parent / p.PKG
        stage_dir.mkdir()
        on_demand = stage_dir.parent / 'on-demand'
        on_demand.mkdir()
        names = {
            'stage.sh': p.HERE / 'stage.sh',
            'archive-root-a553e5ee83632f83.tar.gz': None,
            'archive-root-a553e5ee83632f83.tar.gz.signature': None,
            'manager.dll': p.NEW,
            'manager.runtimeconfig.json': p.NEW_RC,
            'UepGateHost.dll': p.HOST,
            'UepGateHost.runtimeconfig.json': p.HOST_RC,
            'boot.sh': p.MODULE_BOOT,
            'module.json': p.MODULE_JSON,
        }
        lines = []
        seeds = [driver_shim.seed(stage_dir, '901:901:700')]
        for linked in ('archive-root-a553e5ee83632f83.tar.gz',
                       'archive-root-a553e5ee83632f83.tar.gz.signature'):
            seeds.append(driver_shim.seed(on_demand / linked, '901:901:700'))
        for name, source in names.items():
            target = stage_dir / name
            absent = missing_file and name == 'module.json'
            if absent:
                # The manifest row stays; only the file is missing. Dropping
                # the row too would re-test "unlisted file", not "absent file".
                digest = p.MODULE_JSON_SHA
            else:
                if source is None:
                    target.write_bytes(b'fixture-' + name.encode('ascii'))
                else:
                    shutil.copyfile(source, target)
                seeds.append(driver_shim.seed(target, '901:901:700'))
                digest = hashlib.sha256(target.read_bytes()).hexdigest()
            lines.append(digest + '  ' + name)
        if extra_file:
            extra = stage_dir / 'unlisted.bin'
            extra.write_bytes(b'x')
            seeds.append(driver_shim.seed(extra, '901:901:700'))
        manifest = stage_dir / 'files.sha256'
        if wrong_last:
            lines[-1] = '0' * 64 + '  ' + lines[-1].split('  ', 1)[1]
        content = '\n'.join(lines) + ('' if no_final_newline else '\n')
        manifest.write_text(content, encoding='ascii', newline='\n')
        seeds.append(driver_shim.seed(manifest, '901:901:700'))
        manifest_hash = hashlib.sha256(manifest.read_bytes()).hexdigest()
        script = (p.HERE / 'stage.sh').read_text(encoding='ascii')
        script = script.replace('base=/home/owner/share/tmp/sdk_tools',
                                'base=' + driver_shim.to_posix(stage_dir.parent))
        script = script.replace('canon=/opt/usr/home/owner/share/tmp/sdk_tools',
                                'canon=' + driver_shim.to_posix(stage_dir.parent))
        script_path = lay['tmp'] / 'stage-copy.sh'
        script_path.write_text(script, encoding='ascii', newline='\n')
        runner = ('declare -A _META\ndeclare -A _SMACK\n'
                  + ''.join(seeds)
                  + 'export REHEARSAL_UID=901\n'
                  + driver_shim.shim_text()
                  + '\n'
                  + '( . ' + driver_shim.to_posix(script_path) + ' publish 45845:100001 '
                  + manifest_hash + ' 0 0 )\n'
                  + "printf 'rc=%s\\n' \"$?\"\n"
                  + '( . ' + driver_shim.to_posix(script_path) + ' clean 45845:100001 '
                  + manifest_hash + ' 0 0 )\n'
                  + "printf 'clean_rc=%s\\n' \"$?\"\n")
        result = driver_shim.bash(runner + '\n')
        result.manifest_text = content
        return result
    finally:
        shutil.rmtree(lay['tmp'], ignore_errors=True)


def stage_sh_publish():
    result = stage_sh_case()
    p.require('rc=0' in result.stdout.splitlines(),
              'stage.sh publish refused: ' + (result.stdout + result.stderr)[-400:])
    p.require('clean_rc=0' in result.stdout.splitlines(),
              'stage.sh clean refused: ' + (result.stdout + result.stderr)[-400:])


def stage_sh_clean_eof():
    # A valid final row without a trailing newline must be read and verified,
    # and accepted. (The wrong-hash case proves the other half: it must fail.)
    result = stage_sh_case(no_final_newline=True)
    p.require('rc=0' in result.stdout.splitlines(),
              'stage.sh rejected a clean EOF manifest: '
              + (result.stdout + result.stderr)[-400:])
    p.require('clean_rc=0' in result.stdout.splitlines(),
              'stage.sh clean rejected a clean EOF manifest: '
              + (result.stdout + result.stderr)[-400:])


def stage_sh_rejects_unlisted():
    result = stage_sh_case(extra_file=True)
    p.require('rc=0' not in result.stdout.splitlines(), 'stage.sh accepted an unlisted file')


def stage_sh_rejects_missing():
    result = stage_sh_case(missing_file=True)
    p.require('rc=0' not in result.stdout.splitlines(),
              'stage.sh accepted a manifest entry that is absent')
    p.require('  module.json' in result.manifest_text,
              'the absent-file case dropped its manifest row')


def stage_sh_rejects_unterminated():
    result = stage_sh_case(no_final_newline=True, wrong_last=True)
    p.require('rc=0' not in result.stdout.splitlines(),
              'stage.sh accepted an unverified final row without a trailing newline')


# 7 --------------------------------------------------------------------------
class FakeCapture:
    def __init__(self, output):
        self.output = output
        self.commands = []

    async def capture(self, command):
        self.commands.append(command)
        return 0, self.output


STATE_BASE = {
    'uid': '901', 'boot': 'a' * 36, 'service': 'active',
    'manager_hash': None,  # filled below
    'manager_rc_hash': None,
    'gate': 'absent', 'budget': 'absent', 'module': 'absent', 'backup': 'absent',
    'proof_hash': 'x', 'log_size': '0', 'manager_pids': '', 'port_config': 'absent',
    'state_tmp': 'absent',
}


def _state_capture(**overrides):
    values = dict(STATE_BASE)
    values['manager_hash'] = p.NEW_MANAGER_SHA + '  ' + p.TARGET
    values['manager_rc_hash'] = p.NEW_MANAGER_RC_SHA + '  ' + p.TARGET_RC
    values.update(overrides)
    return FakeCapture('\n'.join(key + '=' + value for key, value in values.items()))


def state_capture_contract():
    capture = _state_capture()
    asyncio.run(stage_common.state(capture, p.NEW_MANAGER_SHA, 'session-check-state'))
    command = capture.commands[-1]
    for key in STATE_BASE:
        p.require("printf '" + key + "='" in command,
                  'state capture lost the ' + key + ' key')


def state_missing_temp_key():
    values = dict(STATE_BASE)
    values['manager_hash'] = p.NEW_MANAGER_SHA + '  ' + p.TARGET
    values['manager_rc_hash'] = p.NEW_MANAGER_RC_SHA + '  ' + p.TARGET_RC
    values.pop('state_tmp')
    capture = FakeCapture('\n'.join(key + '=' + value for key, value in values.items()))
    expect_stop(lambda: asyncio.run(
        stage_common.state(capture, p.NEW_MANAGER_SHA, 'session-check-state-missing')),
        'missing state_tmp key')


def state_present_temp():
    expect_stop(lambda: asyncio.run(stage_common.state(
        _state_capture(state_tmp='present'), p.NEW_MANAGER_SHA,
        'session-check-state-present')), 'present budget temp path')


def state_malformed_temp():
    expect_stop(lambda: asyncio.run(stage_common.state(
        _state_capture(state_tmp='maybe'), p.NEW_MANAGER_SHA,
        'session-check-state-malformed')), 'malformed budget temp value')


# 8 --------------------------------------------------------------------------
class ScriptedSDK:
    def __init__(self, log, mtime=950, size=200, epoch=1000, uptime='100.0 0.0'):
        self.log = log
        self.mtime = mtime
        self.size = size
        self.epoch = epoch
        self.uptime = uptime

    async def capture(self, command):
        if 'epoch=' in command:
            return 0, 'epoch=' + str(self.epoch) + '\nuptime=' + self.uptime + '\n'
        if 'mtime=' in command:
            return 0, 'mtime=' + str(self.mtime) + '\nsize=' + str(self.size) + '\n'
        if 'cat -- ' in command:
            return 0, self.log
        return 1, 'unexpected command'


class ScriptedSequenceSDK(ScriptedSDK):
    """Returns a bounded sequence of module logs, repeating the last."""

    def __init__(self, logs, **kwargs):
        super().__init__(logs[0], **kwargs)
        self.logs = list(logs)

    async def capture(self, command):
        if 'cat -- ' in command:
            log = self.logs[0] if len(self.logs) == 1 else self.logs.pop(0)
            self.log = log
            return 0, log
        return await super().capture(command)


def _module_log(summary, detail=None, exit_line='uep gate module exit=0', extra=None):
    lines = [summary]
    if detail is not None:
        lines.append(detail)
    if exit_line is not None:
        lines.append(exit_line)
    if extra:
        lines.append(extra)
    return '\n'.join(lines) + '\n'


def _module_gate(sdk_obj, stage='install', probes=1):
    asyncio.run(stage_common.module_gate(sdk_obj, stage, 'session-check-gate',
                                         probes=probes))


def module_gate_accepts_valid():
    valid = {
        'install': _module_log(p.RECEIPT_READONLY_BOOT,
                               p.LOG_READONLY.format('boot', p.FINGERPRINT)),
        'active': _module_log(p.RECEIPT_CLEARED_BOOT, p.LOG_CLEARED),
        'disable': _module_log(p.RECEIPT_ABSENT_BOOT),
    }
    for stage, log in valid.items():
        _module_gate(ScriptedSDK(log), stage)


def module_gate_rejects_missing_exit():
    log = _module_log(p.RECEIPT_READONLY_BOOT,
                      p.LOG_READONLY.format('boot', p.FINGERPRINT), exit_line=None)
    expect_stop(lambda: _module_gate(ScriptedSDK(log)), 'missing module exit line')


def module_gate_rejects_duplicate_exit():
    log = _module_log(p.RECEIPT_READONLY_BOOT,
                      p.LOG_READONLY.format('boot', p.FINGERPRINT),
                      extra='uep gate module exit=0')
    expect_stop(lambda: _module_gate(ScriptedSDK(log)), 'duplicate module exit line')


def module_gate_rejects_nonzero_exit():
    log = _module_log(p.RECEIPT_READONLY_BOOT,
                      p.LOG_READONLY.format('boot', p.FINGERPRINT),
                      exit_line='uep gate module exit=1')
    expect_stop(lambda: _module_gate(ScriptedSDK(log)), 'nonzero module exit')


def module_gate_rejects_unexpected():
    log = _module_log(p.RECEIPT_READONLY_BOOT,
                      p.LOG_READONLY.format('boot', p.FINGERPRINT),
                      extra='uep gate: unexpected detail')
    expect_stop(lambda: _module_gate(ScriptedSDK(log)), 'unexpected gate event')


def module_gate_rejects_stale_log():
    log = _module_log(p.RECEIPT_READONLY_BOOT,
                      p.LOG_READONLY.format('boot', p.FINGERPRINT))
    expect_stop(lambda: _module_gate(ScriptedSDK(log, mtime=100)),
                'pre-boot module log')


def module_gate_waits_for_exit():
    # A fresh log can be empty while the module is still running. The first
    # partial read must not STOP; the bounded poll must reach the completed log.
    old = stage_common.POLL_SECONDS
    stage_common.POLL_SECONDS = 0
    try:
        valid = _module_log(p.RECEIPT_READONLY_BOOT,
                            p.LOG_READONLY.format('boot', p.FINGERPRINT))
        sdk_obj = ScriptedSequenceSDK(['', valid])
        asyncio.run(stage_common.module_gate(
            sdk_obj, 'install', 'session-check-race', probes=2))
    finally:
        stage_common.POLL_SECONDS = old


def module_gate_waits_for_partial_line():
    # A partially written last line is not a terminal unexpected event; the
    # completed log on a later poll must be accepted.
    old = stage_common.POLL_SECONDS
    stage_common.POLL_SECONDS = 0
    try:
        partial = 'uep gate (boot) uid=0: read-only: enforc'
        valid = _module_log(p.RECEIPT_READONLY_BOOT,
                            p.LOG_READONLY.format('boot', p.FINGERPRINT))
        sdk_obj = ScriptedSequenceSDK([partial, valid])
        asyncio.run(stage_common.module_gate(
            sdk_obj, 'install', 'session-check-partial', probes=2))
    finally:
        stage_common.POLL_SECONDS = old


def module_gate_rejects_persistent_missing_exit():
    old = stage_common.POLL_SECONDS
    stage_common.POLL_SECONDS = 0
    try:
        no_exit = _module_log(p.RECEIPT_READONLY_BOOT,
                              p.LOG_READONLY.format('boot', p.FINGERPRINT),
                              exit_line=None)
        sdk_obj = ScriptedSequenceSDK([no_exit, no_exit])
        expect_stop(lambda: asyncio.run(stage_common.module_gate(
            sdk_obj, 'install', 'session-check-persistent', probes=2)),
            'missing exit after the bounded poll')
    finally:
        stage_common.POLL_SECONDS = old


def module_gate_rejects_missing_detail():
    log = _module_log(p.RECEIPT_READONLY_BOOT, detail=None)
    expect_stop(lambda: _module_gate(ScriptedSDK(log)), 'missing required detail shape')


def module_gate_rejects_missing_summary():
    log = '\n'.join([p.LOG_READONLY.format('boot', p.FINGERPRINT),
                     'uep gate module exit=0']) + '\n'
    expect_stop(lambda: _module_gate(ScriptedSDK(log)), 'missing required summary shape')


def run():
    # The real receipts.jsonl is device evidence; host-only checks must not
    # pollute it.
    stage_lib.save = lambda event, **data: None
    try:
        case('upload-contract', upload_contract)
        case('stage-files-all-small', stage_files_all_small)
        case('module-files-parse', module_files_parse)
        case('module-files-rejects-content', module_files_rejects_content)
        case('module-files-rejects-mode', module_files_rejects_mode)
        case('module-files-rejects-unkeyed', module_files_rejects_unkeyed)
        case('module-files-rejects-missing-dir', module_files_rejects_missing_dir)
        case('protected-set', protected_set)
        case('protected-closeout-accepts', protected_closeout_accepts)
        case('protected-closeout-rejects-drift', protected_closeout_rejects_drift)
        case('protected-closeout-rejects-extra', protected_closeout_rejects_extra)
        case('protected-closeout-rejects-order', protected_closeout_rejects_order)
        case('protected-closeout-rejects-order-synthetic',
             protected_closeout_rejects_order_synthetic)
        case('protected-closeout-rejects-short', protected_closeout_rejects_short)
        case('protected-closeout-rejects-duplicate', protected_closeout_rejects_duplicate)
        case('stage-sh-publish', stage_sh_publish)
        case('stage-sh-clean-eof', stage_sh_clean_eof)
        case('stage-sh-rejects-unlisted', stage_sh_rejects_unlisted)
        case('stage-sh-rejects-missing', stage_sh_rejects_missing)
        case('stage-sh-rejects-unterminated', stage_sh_rejects_unterminated)
        case('state-capture-contract', state_capture_contract)
        case('state-missing-temp-key', state_missing_temp_key)
        case('state-present-temp', state_present_temp)
        case('state-malformed-temp', state_malformed_temp)
        case('module-gate-accepts-valid', module_gate_accepts_valid)
        case('module-gate-waits-for-exit', module_gate_waits_for_exit)
        case('module-gate-waits-for-partial-line', module_gate_waits_for_partial_line)
        case('module-gate-rejects-persistent-missing-exit',
             module_gate_rejects_persistent_missing_exit)
        case('module-gate-rejects-missing-exit', module_gate_rejects_missing_exit)
        case('module-gate-rejects-duplicate-exit', module_gate_rejects_duplicate_exit)
        case('module-gate-rejects-nonzero-exit', module_gate_rejects_nonzero_exit)
        case('module-gate-rejects-unexpected', module_gate_rejects_unexpected)
        case('module-gate-rejects-stale-log', module_gate_rejects_stale_log)
        case('module-gate-rejects-missing-detail', module_gate_rejects_missing_detail)
        case('module-gate-rejects-missing-summary', module_gate_rejects_missing_summary)
        record = {'runner': 'session_checks.py', 'tv_operations': 0,
                  'passed': len(RESULTS), 'failures': [], 'verdict': 'PASSED',
                  'cases': RESULTS}
        (p.HERE / 'session-results.json').write_text(
            json.dumps(record, indent=2) + '\n', encoding='utf-8', newline='\n')
        print(json.dumps({k: v for k, v in record.items() if k != 'cases'}))
    finally:
        for path in TEMP_DIRS:
            shutil.rmtree(path, ignore_errors=True)
        shutil.rmtree(stage_transport.GZ_HOST_DIR, ignore_errors=True)


if __name__ == '__main__':
    run()
