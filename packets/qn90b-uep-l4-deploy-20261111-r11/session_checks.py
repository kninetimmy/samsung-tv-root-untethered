"""Host-only coverage for the session/staging layer the r9 rehearsal never ran.

r9's rehearsal executed the three transition scripts and nothing else, so five
live blockers (B1-B5) passed a green 14/14. Each case here fails on the r9 code
and passes on r10:

  1 upload-contract   every asset the gate sessions stage is in the reviewed
                      upload whitelist (r9 rejected five of them)
  2 stage-files       the real stage_files() runs an all-small asset set end to
                      end against a fake remote, including its host cleanup
                      (r9 deleted a gzip directory that was never created)
  3 module-files      parse of the real module_files() capture (r9's capture
                      produced one keyed line plus three bare lines)
  4 protected-set     the post-install baseline excludes both manager files and
                      pins the runtimeconfig by baseline instead (r9 required
                      the pre-install runtimeconfig after replacing it)
  5 stage-sh          the sealed stage.sh publishes and cleans a manifest that
                      carries the module assets, and rejects an unlisted file

No TV contact: the remote side is a temp directory and the SDK is a stub.
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
import sdk
import stage_common
import stage_transport
import driver_shim
import prepare

RESULTS = []


def case(name, fn):
    try:
        fn()
    except Exception as error:
        RESULTS.append({'case': name, 'verdict': 'FAILED',
                        'detail': type(error).__name__ + ': ' + str(error)[:300]})
        raise
    RESULTS.append({'case': name, 'verdict': 'passed'})


def asset_map(extra):
    """Exactly what GateSession stages: base chain + gate assets + materials."""
    agent = p.HERE / 'build/SamsungTvRootAgent.dll'
    if not agent.is_file():
        # The upload contract is name-based; the seal-time build produces the
        # real bytes, so this suite does not depend on a prior build.
        agent = Path(tempfile.mkdtemp(prefix='r10-session-agent-')) / 'SamsungTvRootAgent.dll'
        agent.write_bytes(b'placeholder')
    assets = {'stage.sh': p.HERE / 'stage.sh',
              'SamsungTvArchiveRoot.dll': p.LAUNCHER,
              'SamsungTvRootAgent.dll': agent}
    assets.update(extra)
    for name in sorted(p.MATERIALS - {'private.pem', 'files.sha256'}):
        assets[name] = Path('execution/gate-materials') / name
    return assets


def install_assets():
    return {'manager.dll': p.NEW, 'manager.runtimeconfig.json': p.NEW_RC,
            'UepGateHost.dll': p.HOST,
            'UepGateHost.runtimeconfig.json': p.HOST_RC,
            'boot.sh': p.MODULE_BOOT, 'module.json': p.MODULE_JSON}


# 1 --------------------------------------------------------------------------
def upload_contract():
    names = asset_map(install_assets())
    unknown = sorted(set(names) - sdk.UPLOAD_NAMES)
    p.require(not unknown, 'gate-session assets outside the upload whitelist: ' + str(unknown))
    # the whitelist must still refuse an unreviewed name
    p.require('manager.runtimeconfig.json' in sdk.UPLOAD_NAMES, 'runtimeconfig not whitelisted')
    p.require('arbitrary.dll' not in sdk.UPLOAD_NAMES, 'whitelist widened too far')


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
            import hashlib
            return hashlib.sha256(data).hexdigest() + '  ' + target
        raise AssertionError('unexpected remote read: ' + label)

    async def control(self, action):
        self.claimed = action == 'publish'


class FakeTrial:
    def __init__(self, remote_root):
        self.remote = FakeRemote(remote_root)
        self.sdk = self
        self.saved = []
        self.stage_id = None
        self.claim_attempted = False
        self.control_hash = None
        self.manifest_hash = None

    async def push(self, source, target, stage_id=None):
        shutil.copyfile(source, self.remote.path_of(target))

    async def read(self, label, command):
        return await self.remote.read(label, command)

    async def control(self, action):
        return await self.remote.control(action)

    async def metadata(self, path):
        candidate = self.remote.path_of(path)
        return None if not candidate.exists() else {'path': str(candidate)}

    async def check_stage(self):
        return True

    def save(self, event, **data):
        self.saved.append((event, data))


def stage_files_all_small():
    tmp = Path(tempfile.mkdtemp(prefix='r10-session-checks-', dir=driver_shim.REHEARSAL_TEMP))
    try:
        # An absence check first: the r9 defect was that the cleanup target did
        # not exist for an all-small asset set.
        p.require(not stage_transport.GZ_HOST_DIR.exists()
                  or not any(stage_transport.GZ_HOST_DIR.iterdir()),
                  'transport staging directory must start empty')
        assets = {'stage.sh': p.HERE / 'stage.sh',
                  'manager.dll': p.NEW,
                  'manager.runtimeconfig.json': p.NEW_RC}
        manifest = tmp / 'files.sha256'
        manifest.write_text(''.join(p.digest(v) + '  ' + k + '\n' for k, v in assets.items()),
                            encoding='ascii', newline='\n')
        assets['files.sha256'] = manifest
        trial = FakeTrial(tmp / 'remote' / p.PKG)
        import asyncio
        asyncio.run(stage_transport.stage_files(trial, assets))
        p.require(trial.remote.claimed, 'publish control never reached')
        p.require(not stage_transport.GZ_HOST_DIR.exists(),
                  'host transport staging directory was not cleaned up')
        p.require(len(trial.saved) > 0, 'no transport receipts were saved')
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# 3 --------------------------------------------------------------------------
class FakeCapture:
    def __init__(self, output):
        self.output = output
        self.commands = []

    async def capture(self, command):
        self.commands.append(command)
        return 0, self.output


class ShimCapture:
    """Runs the generated capture in Git-Bash with stat/sha256sum shimmed.

    This executes the real command text, so any extra unkeyed output the
    command grows (r9's three bare stat lines) breaks fields() instead of
    being invisible behind a canned fixture.
    """

    def __init__(self, extra=''):
        self.extra = extra
        self.commands = []

    async def capture(self, command):
        self.commands.append(command)
        script = _module_shim() + '\n' + command + self.extra
        result = driver_shim.bash(script)
        return result.returncode, result.stdout


def _module_shim():
    files = {
        p.MODULE_BOOT_PATH: (p.MODULE_BOOT_SHA, '0:755'),
        p.MODULE_JSON_PATH: (p.MODULE_JSON_SHA, '0:644'),
        p.MODULE_HOST: (p.HOST_SHA, '0:644'),
        p.MODULE_HOST_RC: (p.HOST_RC_SHA, '0:644'),
    }
    hash_cases = '\n'.join(
        '        ' + path + ') echo "' + digest + '  ' + path + '";;'
        for path, (digest, mode) in files.items())
    mode_cases = '\n'.join(
        '            ' + path + ') echo "' + mode + '";;'
        for path, (digest, mode) in files.items())
    return (
        'sha256sum() {\n'
        '    case "$1" in\n'
        + hash_cases + '\n'
        '        *) echo "unexpected path: $1" >&2; return 1;;\n'
        '    esac\n'
        '}\n'
        'stat() {\n'
        '    local fmt= target=\n'
        '    while test $# -gt 0; do\n'
        '        case "$1" in\n'
        '            -c) fmt=$2; shift 2;;\n'
        '            --) shift;;\n'
        '            *) target=$1; shift;;\n'
        '        esac\n'
        '    done\n'
        '    case "$fmt" in\n'
        "        '%u:%a') case \"$target\" in\n"
        + mode_cases + '\n'
        '            *) echo "unknown target: $target" >&2; return 1;;\n'
        '        esac;;\n'
        "        '%F:%u:%g:%a') echo '" + p.MODULE_DIR_META + "';;\n"
        '        *) echo "unmodelled format: $fmt" >&2; return 1;;\n'
        '    esac\n'
        '}\n')


def module_files_parse():
    import asyncio
    stub = ShimCapture()
    asyncio.run(stage_common.module_files(stub, 'session-check-module'))
    command = stub.commands[-1]
    for fragment in ('boot_mode=', 'json_mode=', 'host_mode=', 'rc_mode=', 'dir_meta='):
        p.require(fragment in command, 'module capture lost ' + fragment)
    p.require("stat -c '%u:%a' \" + ' '.join(paths)" not in command,
              'module capture still uses the unparseable multi-line modes form')

    # The r9 shape (one keyed line followed by bare stat lines) must fail when
    # the same command text grows that extra output.
    broken = ShimCapture(extra="\nstat -c '%u:%a' -- " + p.MODULE_JSON_PATH + '\n')
    rejected = False
    try:
        asyncio.run(stage_common.module_files(broken, 'session-check-r9-shape'))
    except p.Stop:
        rejected = True
    p.require(rejected, 'an unkeyed stat line was accepted by the capture parser')


# 4 --------------------------------------------------------------------------
def protected_set():
    # At seal time the fresh register exists and the REAL EXPECTED set is the
    # thing to test. r10's case only inspected INHERITED and popped the rc
    # itself, so restoring the old runtimeconfig stayed green (review M1).
    if p.EXPECTED is not None:
        expected = p.expected_set()
        p.require(p.TARGET not in expected, 'manager dll must not be in the post-install set')
        p.require(p.TARGET_RC not in expected,
                  'manager runtimeconfig must not be in the post-install set')
        p.require(len(expected) == 24, 'post-install protected set must have 24 entries')
    else:
        base = dict(p.INHERITED)
        p.require(p.TARGET not in base, 'manager dll must not be in the post-install set')
        base.pop(p.TARGET_RC, None)
        p.require(len(base) == 24, 'post-install protected set must have 24 entries')
    p.require(p.TARGET_RC in p.inspection_targets(),
              'the inspection must still capture the runtimeconfig baseline')
    p.require(p.PREV_MANAGER_RC_SHA != p.NEW_MANAGER_RC_SHA,
              'the two manager runtimeconfig baselines must differ')


class FakeHashCapture:
    def __init__(self, hashes):
        self.hashes = hashes

    async def capture(self, command):
        paths = command.split()[1:]
        lines = [self.hashes.get(path, '0' * 64) + '  ' + path for path in paths]
        return 0, '\n'.join(lines) + '\n'


def _post_install_set():
    """The 24-entry post-install set: the real one at seal time, else derived."""
    if p.EXPECTED is not None:
        return dict(p.expected_set())
    base = dict(p.INHERITED)
    base.pop(p.TARGET_RC, None)
    return base


def protected_closeout():
    """Closeout must reject the pre-install runtimeconfig after v5.19."""
    import asyncio
    from stage_lib import protected_hashes
    expected = _post_install_set()
    good = {path: digest for path, digest in expected.items()}
    asyncio.run(protected_hashes(FakeHashCapture(good), expected))
    victim = sorted(good)[0]
    drifted = dict(good)
    drifted[victim] = '0' * 64
    rejected = False
    try:
        asyncio.run(protected_hashes(FakeHashCapture(drifted), expected))
    except p.Stop:
        rejected = True
    p.require(rejected, 'closeout accepted a drifted protected file')

    # A path outside the expected set must also stop closeout.
    class ExtraHashCapture(FakeHashCapture):
        async def capture(self, command):
            code, output = await super().capture(command)
            return code, output + ('0' * 64) + '  ' + p.TARGET_RC + '\n'

    rejected = False
    try:
        asyncio.run(protected_hashes(ExtraHashCapture(good), expected))
    except p.Stop:
        rejected = True
    p.require(rejected, 'closeout accepted a path outside the expected set')


# 5 --------------------------------------------------------------------------
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
        # publish hard-links the archive pair into on-demand; the shim models
        # the link target's metadata ahead of the ln.
        for linked in ('archive-root-a553e5ee83632f83.tar.gz',
                       'archive-root-a553e5ee83632f83.tar.gz.signature'):
            seeds.append(driver_shim.seed(on_demand / linked, '901:901:700'))
        for name, source in names.items():
            target = stage_dir / name
            absent = missing_file and name == 'module.json'
            if absent:
                # The manifest row stays; only the file is missing. r10 dropped
                # the row too, so the case re-tested "unlisted file" (review M1).
                digest = p.MODULE_JSON_SHA
            else:
                if source is None:
                    target.write_bytes(b'fixture-' + name.encode('ascii'))
                else:
                    shutil.copyfile(source, target)
                seeds.append(driver_shim.seed(target, '901:901:700'))
                import hashlib
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
        import hashlib
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
        return result
    finally:
        shutil.rmtree(lay['tmp'], ignore_errors=True)


def stage_sh_publish():
    result = stage_sh_case()
    p.require('rc=0' in result.stdout.splitlines(), 'stage.sh publish refused: ' + (result.stdout + result.stderr)[-400:])
    p.require('clean_rc=0' in result.stdout.splitlines(),
              'stage.sh clean refused: ' + (result.stdout + result.stderr)[-400:])


def stage_sh_rejects_unlisted():
    result = stage_sh_case(extra_file=True)
    p.require('rc=0' not in result.stdout.splitlines(), 'stage.sh accepted an unlisted file')


def stage_sh_rejects_missing():
    result = stage_sh_case(missing_file=True)
    p.require('rc=0' not in result.stdout.splitlines(), 'stage.sh accepted a manifest entry that is absent')


def stage_sh_rejects_unterminated():
    # r11 M2: a final row without a newline must still be verified.
    result = stage_sh_case(no_final_newline=True, wrong_last=True)
    p.require('rc=0' not in result.stdout.splitlines(),
              'stage.sh accepted an unverified final row without a trailing newline')


def state_temp_refusal():
    """r11 B1: the budget temp path must stop every stage."""
    import asyncio
    base = {
        'uid': '901', 'boot': 'a' * 36, 'service': 'active',
        'manager_hash': p.NEW_MANAGER_SHA + '  ' + p.TARGET,
        'manager_rc_hash': p.NEW_MANAGER_RC_SHA + '  ' + p.TARGET_RC,
        'gate': 'absent', 'budget': 'absent', 'module': 'absent', 'backup': 'absent',
        'proof_hash': 'x', 'log_size': '0', 'manager_pids': '', 'port_config': 'absent',
        'state_tmp': 'absent',
    }
    asyncio.run(stage_common.state(
        FakeCapture('\n'.join(k + '=' + v for k, v in base.items())),
        p.NEW_MANAGER_SHA, 'session-check-state'))
    bad = dict(base, state_tmp='present')
    rejected = False
    try:
        asyncio.run(stage_common.state(
            FakeCapture('\n'.join(k + '=' + v for k, v in bad.items())),
            p.NEW_MANAGER_SHA, 'session-check-state-bad'))
    except p.Stop:
        rejected = True
    p.require(rejected, 'a present budget temp path was accepted by state()')


def run():
    # The real receipts.jsonl is device-evidence from the inspection and the
    # live stages; host-only checks must not pollute it.
    import stage_lib
    stage_lib.save = lambda event, **data: None
    case('upload-contract', upload_contract)
    case('stage-files-all-small', stage_files_all_small)
    case('module-files-parse', module_files_parse)
    case('protected-set', protected_set)
    case('protected-closeout', protected_closeout)
    case('stage-sh-publish', stage_sh_publish)
    case('stage-sh-rejects-unlisted', stage_sh_rejects_unlisted)
    case('stage-sh-rejects-missing', stage_sh_rejects_missing)
    case('stage-sh-rejects-unterminated', stage_sh_rejects_unterminated)
    case('state-temp-refusal', state_temp_refusal)
    record = {'runner': 'session_checks.py', 'tv_operations': 0,
              'passed': len(RESULTS), 'failures': [], 'verdict': 'PASSED',
              'cases': RESULTS}
    (p.HERE / 'session-results.json').write_text(
        json.dumps(record, indent=2) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'cases'}))


if __name__ == '__main__':
    run()
