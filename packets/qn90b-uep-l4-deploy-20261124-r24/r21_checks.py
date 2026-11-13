"""Offline real-entrypoint imports and modeled stage preflights; never device contact."""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r24-pycache-')

import ast
import asyncio
import base64
import hashlib
import importlib.util
import json
import marshal
import os
import re
import shutil
import struct
import subprocess
from contextlib import ExitStack, contextmanager
from datetime import datetime
from pathlib import Path
from unittest.mock import patch

import packet as p

HOST_TEMP = Path(tempfile.gettempdir()).resolve(strict=True)
IMPORT_ENTRIES = ('certify', 'tidy', 'inspect_tv', 'bootstrap_sdk', 'stage_session',
                  'install', 'active', 'disable')
PROLOGUE = """import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r24-pycache-')
"""


def real_caches_absent():
    assert not [str(x) for root in p.SOURCE_ROOTS for x in (p.REPO / root).rglob('*')
                if x.name == '__pycache__' or x.suffix == '.pyc'], 'real SOURCE_ROOTS cache was repopulated'


@contextmanager
def sandbox():
    """All poison and credentials stay in a private host copy, removed on exit."""
    real_caches_absent()
    with tempfile.TemporaryDirectory(prefix='r21-fixture-', dir=HOST_TEMP) as temp:
        root = Path(temp) / 'repo'
        p.make_private_directory(root)
        pack = root / '.memhub/prep' / p.HERE.name
        pack.parent.mkdir(parents=True)
        p.make_private_directory(pack)
        for name in p.SEAL_ENTRIES:
            source = p.HERE / name
            if source.is_file() and source.suffix in ('.py', '.json'):
                target = pack / name
                if not target.parent.exists():
                    p.make_private_directory(target.parent)
                shutil.copyfile(source, target)
        controller = root / '.memhub/prep/qn90b-evidence-reboot-20261101-r1/controller'
        controller.mkdir(parents=True)
        for name in ('packet.py', 'baseline.json'):
            shutil.copyfile(p.TOOLS_DIR / name, controller / name)
        local = root / '.memhub/local'
        p.make_private_directory(local)
        shutil.copyfile(p.REPO / '.memhub/local/tv.env', local / 'tv.env')
        for name in p.SOURCE_ROOTS:
            (root / name).mkdir(parents=True, exist_ok=True)
        for source in (p.REPO / 'src/samsung_tv_root').rglob('*.py'):
            target = root / source.relative_to(p.REPO)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        try:
            yield root, pack
        finally:
            real_caches_absent()
    assert not Path(temp).exists(), 'isolated poison fixture survived cleanup'
    real_caches_absent()


def child(pack, code):
    # Run the actual entrypoint module bodies. A guard is installed before them;
    # only the established PowerShell ACL helper may launch a host subprocess.
    hook = '''import sys, pathlib, os, subprocess
acl_shell = pathlib.Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
def no_device(event, args):
    if event in ('socket.connect', 'socket.bind', 'socket.getaddrinfo'):
        raise AssertionError('offline fixture attempted network access')
    if event == 'subprocess.Popen':
        executable, command = args[:2]
        allowed = (pathlib.Path(executable) == acl_shell if executable is not None else
                   isinstance(command, str) and command.startswith(subprocess.list2cmdline([str(acl_shell)]) + ' '))
        if not allowed:
            raise AssertionError('offline fixture attempted non-ACL process')
sys.addaudithook(no_device)
sys.path.insert(0, str(pathlib.Path.cwd()))
'''
    env = dict(os.environ)
    env.pop('PYTHONPYCACHEPREFIX', None)
    result = subprocess.run([sys.executable, '-B', '-u', '-c', hook + code],
                            cwd=pack, env=env, capture_output=True, text=True)
    return result


def poison(root):
    source = root / 'src/samsung_tv_root/sdb.py'
    raw = source.read_bytes()
    code = compile(raw + b'\ndef build_shell_injection(command, gate_token=None):\n    return "R21_POISON_EXECUTED"\n', str(source), 'exec')
    stat = source.stat()
    header = importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(stat.st_mtime) & 0xffffffff, stat.st_size)
    cache = source.parent / '__pycache__' / ('sdb.' + sys.implementation.cache_tag + '.pyc')
    cache.parent.mkdir()
    cache.write_bytes(header + marshal.dumps(code))
    assert cache.read_bytes()[:16] == header and len(header) == 16
    return cache


def bytecode_case(kind):
    with sandbox() as (root, pack):
        cache = poison(root)
        original_poison = cache.read_bytes()
        packet = pack / 'packet.py'
        source = packet.read_text(encoding='utf-8')
        if kind == 'prefix':
            # Remove ONLY the preflight call: the private prefix must stand alone.
            call = '    require_empty_source_caches()\n'
            assert source.count(call) == 1, 'cache preflight call is not unique'
            packet.write_text(source.replace(call, '    pass  # isolated prefix-only fixture\n'), encoding='utf-8')
        for entry in IMPORT_ENTRIES:
            code = ('import runpy\nrunpy.run_module(' + repr(entry) + ', run_name="r21_import_fixture")\n'
                    'import samsung_tv_root.sdb as sdb\n'
                    'print(sdb.build_shell_injection("printf reviewed", "0123456789abcdef"))\n')
            out = child(pack, code)
            if kind == 'prefix':
                script = '/bin/mkdir /tmp/s-0123456789abcdef 2>/dev/null&&{ printf reviewed;}'
                expected = 'new2.tpk`printf${IFS}%s${IFS}' + base64.b64encode(script.encode()).decode() + '|base64${IFS}-d|bash`.tpk'
                assert out.returncode == 0 and out.stdout.strip() == expected, 'private prefix did not isolate poisoned source cache: ' + entry + ': ' + out.stderr[-800:]
            else:
                assert out.returncode != 0 and 'source-cache-populated: ' + str(cache.parent) in out.stderr, 'populated-cache preflight missing: ' + entry
                assert 'R21_POISON_EXECUTED' not in out.stdout
                stream = pack / 'refusals.jsonl'
                assert stream.is_file(), 'import preflight refusal was not recorded'
                rows = [json.loads(line) for line in stream.read_text().splitlines()]
                assert len(rows) == IMPORT_ENTRIES.index(entry) + 1 and rows[-1]['consumed'] is False
                assert_no_consumption(pack)
            assert cache.read_bytes() == original_poison, 'preflight erased or altered poison evidence'
        if kind == 'prefix':
            # Positive control: exactly the same header-valid poison is load-bearing
            # when both defenses are absent. No source or entrypoint toy substitute.
            text = packet.read_text(encoding='utf-8')
            packet.write_text(text.replace('    sys.pycache_prefix = str(prefix)', '    sys.pycache_prefix = None'), encoding='utf-8')
            out = child(pack, 'import certify\nimport samsung_tv_root.sdb as sdb\nprint(sdb.build_shell_injection("x"))\n')
            assert out.returncode == 0 and out.stdout.strip() == 'R21_POISON_EXECUTED', 'poison positive control was not load-bearing'


def cache_policy():
    """Fresh prefix, real ACL, write suppression even without interpreter -B."""
    with sandbox() as (root, pack):
        code = ('import hashlib, importlib.util, ipaddress, json, os, re, shutil, sqlite3, subprocess, sys, tempfile\n'
                'from contextlib import contextmanager\nfrom datetime import datetime, timezone\n'
                'sys.dont_write_bytecode = False\n' + PROLOGUE + 'original_prefix = sys.pycache_prefix\n'
                'import packet, json, sys\n'
                'packet.private_acl(pathlib.Path(sys.pycache_prefix))\n'
                'assert sys.pycache_prefix == original_prefix, "packet replaced bootstrap prefix"\n'
                'print(json.dumps([sys.pycache_prefix, sys.dont_write_bytecode]))\n')
        prefixes = []
        for _ in range(2):
            out = child(pack, code)
            assert out.returncode == 0, out.stderr
            prefix, disabled = json.loads(out.stdout)
            assert disabled is True, 'packet bytecode writes were not disabled'
            assert not Path(prefix).is_relative_to(root) and not Path(prefix).is_relative_to(p.REPO)
            assert Path(prefix).is_dir() and not list(Path(prefix).iterdir())
            prefixes.append(prefix)
        assert prefixes[0] != prefixes[1], 'private cache prefix reused between runs'
        assert not list((root / 'src').rglob('__pycache__'))


def packet_bytecode_case():
    """Header-valid adjacent packet.pyc: uncached entry script must select sealed source."""
    with sandbox() as (_, pack):
        source = pack / 'packet.py'
        original = source.read_bytes()
        stat = source.stat()
        header = importlib.util.MAGIC_NUMBER + struct.pack('<III', 0, int(stat.st_mtime) & 0xffffffff, stat.st_size)
        cache = pack / '__pycache__' / ('packet.' + sys.implementation.cache_tag + '.pyc')
        cache.parent.mkdir()
        forged = compile('print("FORGED_CACHE")\nraise SystemExit(0)\n', str(source), 'exec')
        cache.write_bytes(header + marshal.dumps(forged))
        planted = cache.read_bytes()
        for entry in IMPORT_ENTRIES:
            code = ('import runpy\nrunpy.run_path(' + repr(entry + '.py') + ', run_name="r24_import_fixture")\n'
                    'import packet, json\n'
                    'print(json.dumps([packet.SOURCE_SHA, sys.pycache_prefix]))\n')
            out = child(pack, code)
            assert out.returncode == 0 and 'FORGED_CACHE' not in out.stdout, 'forged packet cache executed: ' + entry + ': ' + out.stderr[-800:]
            sha, prefix = json.loads(out.stdout)
            assert sha == p.SOURCE_SHA and prefix is not None, 'real packet source or bootstrap prefix missing: ' + entry
            assert not (pack / 'refusals.jsonl').exists() and not (Path(prefix) / 'refusals.jsonl').exists(), 'clean packet cache case refused'
            assert source.read_bytes() == original and cache.read_bytes() == planted, 'packet cache fixture changed sealed source or poison'
            assert_no_consumption(pack)
        # Positive control changes only certify's prologue, not packet.py or its cache.
        entry = pack / 'certify.py'
        text = entry.read_text(encoding='utf-8')
        assert text.count(PROLOGUE) == 1, 'packet cache positive-control prologue missing'
        entry.write_text(text.replace(PROLOGUE, ''), encoding='utf-8')
        out = child(pack, 'import runpy\nrunpy.run_path("certify.py", run_name="r24_import_fixture")\n')
        assert out.returncode == 0 and out.stdout.strip() == 'FORGED_CACHE', 'forged packet cache positive control was not load-bearing'
        assert cache.read_bytes() == planted and source.read_bytes() == original
        assert not (pack / 'refusals.jsonl').exists()


def import_graph():
    """Exhaust all sealed Python imports; every path to repo source passes packet."""
    modules = {Path(name).stem: ast.parse((p.HERE / name).read_text(encoding='utf-8'))
               for name in p.SEAL_ENTRIES if name.endswith('.py')}
    expected = [ast.dump(node) for node in ast.parse(PROLOGUE).body]
    for name, module in modules.items():
        if name in ('packet', 'port_from_r15'):
            continue  # packet is the guarded import; the port tool executes only pinned controller source.
        body = module.body
        if isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
            body = body[1:]
        assert [ast.dump(node) for node in body[:3]] == expected, 'cache prologue missing or reordered: ' + name
        for node in ast.walk(module):
            if ((isinstance(node, ast.Import) and any(alias.name == 'packet' for alias in node.names))
                    or (isinstance(node, ast.ImportFrom) and node.module == 'packet')):
                assert node.lineno > body[2].end_lineno, 'packet import precedes cache prologue: ' + name
    direct = set()
    def walk(name, guarded, visiting):
        if name in visiting:
            return guarded
        if name == 'packet':
            assert not any(isinstance(n, ast.ImportFrom) and (n.module or '').startswith('samsung_tv_root')
                           for n in ast.walk(modules[name]))
            return True
        for node in modules[name].body:
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module] if isinstance(node, ast.ImportFrom) else []
            for imported in names:
                if imported.startswith('samsung_tv_root'):
                    direct.add(name)
                    assert guarded, 'source import precedes packet guard: ' + name
                elif imported in modules:
                    guarded = walk(imported, guarded, visiting | {name})
        return guarded
    for name in modules:
        walk(name, False, set())
    assert direct == {'bootstrap_sdk', 'inspect_tv', 'stage_session'}, 'source-importing surface changed'
    controller = ast.parse((p.TOOLS_DIR / 'packet.py').read_text())
    imports = {n.module if isinstance(n, ast.ImportFrom) else a.name
               for n in ast.walk(controller) if isinstance(n, (ast.Import, ast.ImportFrom))
               for a in n.names}
    assert imports == {'hashlib', 'json', 'os', 're', 'sqlite3', 'subprocess', 'pathlib'}
    labels = {node.value for node in ast.walk(modules['certify'])
              if isinstance(node, ast.Constant) and isinstance(node.value, str)
              and re.fullmatch(r'r\d+-[a-z-]+', node.value)}
    assert labels == {'r24-certification', 'r24-certification-end', 'r24-stale-budget',
                      'r24-module-files', 'r24-manager-files', 'r24-backup-evidence',
                      'r24-backup-directory', 'r24-module-log', 'r24-enforcing-read',
                      'r24-read-only-certified', 'r24-readiness-passed'}, 'current receipt event labels drifted'


def packet_attribution_case():
    """Literal emission sites across the seal catalog, not a per-file label allowlist."""
    import port_from_r15 as port
    current = re.search(r'-(r\d+)$', p.HERE.name).group(1)
    predecessor = re.search(r'-(r\d+)$', port.PRIOR.name).group(1)
    modules = {name: ast.parse((p.HERE / name).read_text(encoding='utf-8'))
               for name in p.SEAL_ENTRIES if name.endswith('.py')}
    # Discover positional label/event slots from sealed declarations. Match by
    # callee basename; no module inventory or per-packet label list to extend.
    slots = {}
    for module in modules.values():
        for node in ast.walk(module):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for index, argument in enumerate(node.args.posonlyargs + node.args.args):
                    if argument.arg in ('label', 'event'):
                        slots.setdefault(node.name, set()).add(index)
    labels = texts = attributions = 0
    for name, module in modules.items():
        for call in ast.walk(module):
            if not isinstance(call, ast.Call):
                continue
            callee = call.func.id if isinstance(call.func, ast.Name) else call.func.attr if isinstance(call.func, ast.Attribute) else ''
            values = [call.args[index] for index in slots.get(callee, ()) if index < len(call.args)]
            values += [item.value for item in call.keywords if item.arg in ('label', 'event', 'evidence_label')]
            output = callee in ('write_text', 'write_bytes')
            if output:
                values += call.args[:1] + [item.value for item in call.keywords if item.arg == 'data']
            for value in values:
                if isinstance(value, ast.Constant) and isinstance(value.value, (str, bytes)):
                    text = value.value.decode('utf-8', 'strict') if isinstance(value.value, bytes) else value.value
                    match = re.match(r'(r\d+)(?:-|(?=\s))', text)
                    if match:
                        assert match[1] == current, 'packet label is stale: ' + name + ':' + str(call.lineno)
                        labels += 1
                        texts += output
            attribution = {item.arg: item.value for item in call.keywords if item.arg in ('packet', 'predecessor')}
            # Directory-valued ledger metadata is not a literal revision pair.
            if 'packet' in attribution or any(isinstance(value, ast.Constant)
                    and isinstance(value.value, str) and re.fullmatch(r'r\d+', value.value)
                    for value in attribution.values()):
                assert (set(attribution) == {'packet', 'predecessor'}
                        and all(isinstance(attribution[key], ast.Constant) and attribution[key].value == expected
                                for key, expected in (('packet', current), ('predecessor', predecessor)))), 'packet attribution is stale: ' + name + ':' + str(call.lineno)
                attributions += 1
    assert labels and texts and attributions, 'packet attribution category missing from sealed emission sites'


def assert_no_consumption(root):
    assert not (root / 'STOP').exists() and not (root / 'SPENT').exists(), 'refusal consumed packet'
    assert not (root / 'execution').exists(), 'refusal wrote attempt tree'
    assert not list(root.glob('LIVE_ARM_*')), 'refusal wrote arming marker'


def refusal_case(kind):
    import certify
    import tidy
    import stage_lib as sl
    module = tidy if kind == 'tidy' else certify
    with tempfile.TemporaryDirectory(prefix='r21-refusal-', dir=HOST_TEMP) as temp:
        root = Path(temp) / 'packet'
        p.make_private_directory(root)
        prior = dict(stage='certify', passed=True, boot=p.CERTIFY_BOOT, proof_sha256=p.CERTIFY_PROOF)
        status = root / certify.STATUS
        status.write_text(json.dumps(prior))
        before = status.read_bytes()
        events = []
        class SDK:
            def __init__(self, save): events.append('sdk')
            async def connect(self): pass
            async def disconnect(self): pass
        async def readonly(sdk): return p.CERTIFY_PROOF
        async def denied(*a): pass
        async def captured(sdk, label, command):
            return tidy.removal_receipt() if label == 'denial-stages-unlink-rmdir' else 'DENIAL_STAGES_ABSENT_FRESH_SESSION'
        def refusal(): raise p.Stop('modeled fatal preflight refusal')
        def invoke():
            return asyncio.run(module.main(**({'readiness': kind == 'readiness'} if module is certify else {})))
        with ExitStack() as stack:
            for obj, name, value in (
                (p, 'HERE', root), (p, 'private_acl', lambda *a: None),
                (p, 'require_source_integrity', lambda: None), (p, 'clear_marker', lambda *a: None),
                (module, 'marker_for', lambda *a: None), (module, 'BridgeSDK', SDK),
                (module, 'protect_seal', refusal), (certify, 'read_only', readonly),
                (certify.denial, 'run', denied), (tidy, 'capture', captured), (sl, 'save', lambda *a, **k: None)):
                stack.enter_context(patch.object(obj, name, value))
            try:
                invoke()
            except p.Stop as error:
                assert str(error) == 'modeled fatal preflight refusal'
            else:
                raise AssertionError('modeled preflight did not refuse')
            assert not events, 'refusal constructed SDK'
            assert_no_consumption(root)
            assert status.read_bytes() == before and not (root / tidy.STATUS).exists(), 'refusal touched stage status'
            stream = root / 'refusals.jsonl'
            rows = [json.loads(line) for line in stream.read_text().splitlines()] if stream.exists() else []
            assert len(rows) == 1, 'fatal preflight did not persist exactly one refusal: ' + kind
            row = rows[0]
            assert set(row) == {'stage', 'kind', 'reason', 'utc', 'consumed'} and row['consumed'] is False, 'refusal outcome schema drift'
            assert row['stage'] == module.STAGE and row['kind'] == kind
            assert row['reason'] == 'Stop: modeled fatal preflight refusal'
            assert datetime.fromisoformat(row['utc']).utcoffset().total_seconds() == 0
            saved = stream.read_bytes()
            with patch.object(module, 'protect_seal', lambda: None):
                invoke()  # Same packet: real unused/stopped gates, attempt and status writer.
            assert stream.read_bytes() == saved, 'successful run altered refusal stream'
            assert events, 'post-refusal successful run never reached modeled SDK'
            if kind == 'readiness':
                assert_no_consumption(root)
                assert status.read_bytes() == before
            else:
                assert (root / 'execution/attempts' / (module.STAGE + '.attempt')).is_file()
                assert json.loads((root / module.STATUS).read_text())['passed'] is True


def refusal_storage(kind):
    with tempfile.TemporaryDirectory(prefix='r21-storage-', dir=HOST_TEMP) as temp:
        root = Path(temp) / 'packet'
        p.make_private_directory(root)
        synced = []
        def fsync(fd):
            synced.append(fd)
            if kind == 'failure': raise OSError('modeled refusal fsync failure')
        original = p.Stop('modeled refusal')
        with patch.object(p, 'HERE', root), patch.object(p.os, 'fsync', fsync):
            try:
                with p.preflight('fixture', 'storage'):
                    raise original
            except BaseExceptionGroup as error:
                assert kind == 'failure' and error.exceptions[0] is original
                assert isinstance(error.exceptions[1], OSError) and str(error.exceptions[1]) == 'modeled refusal fsync failure'
            except p.Stop:
                assert kind == 'success', 'refusal persistence failure was hidden'
            else:
                raise AssertionError('preflight swallowed fatal exception')
        assert len(synced) == 1, 'refusal row was not fsynced exactly once'
        assert_no_consumption(root)
        if kind == 'success':
            first = (root / 'refusals.jsonl').read_bytes()
            with patch.object(p, 'HERE', root):
                p.record_refusal('fixture', 'second', p.Stop('second refusal'))
            raw = (root / 'refusals.jsonl').read_bytes()
            assert raw.startswith(first) and len(raw.splitlines()) == 2, 'refusal stream is not append-only'


def refusal_acl_case():
    """Real Windows ACL rejection must leave that directory untouched and name durable fallback."""
    with tempfile.TemporaryDirectory(prefix='r24-acl-refusal-', dir=HOST_TEMP) as temp:
        root = Path(temp) / 'rejected'
        root.mkdir()  # Inherits host TEMP ACLs, including Administrators; deliberately not private.
        try:
            p.private_acl(root)
        except p.Stop as error:
            assert str(error) == 'private ACL/owner verification failed', 'fixture did not reach ACL rejection'
        else:
            raise AssertionError('refusal ACL fixture unexpectedly private')
        fallback = Path(temp) / 'private-prefix'
        p.make_private_directory(fallback)
        synced = []
        real_fsync = p.os.fsync
        def fsync(fd):
            real_fsync(fd)
            synced.append(fd)
        with patch.object(p, 'HERE', root), patch.object(sys, 'pycache_prefix', str(fallback)), patch.object(p.os, 'fsync', fsync):
            try:
                with p.preflight('fixture', 'acl'):
                    p.private_acl(root)
            except p.Stop as error:
                assert str(error) == 'private ACL/owner verification failed'
                notes = getattr(error, '__notes__', [])
            except BaseExceptionGroup as error:
                raise AssertionError('private refusal fallback persistence failed') from error
            else:
                raise AssertionError('ACL preflight did not refuse')
        assert not list(root.iterdir()), 'refusal wrote into ACL-rejected directory'
        stream = fallback / 'refusals.jsonl'
        assert stream.is_file(), 'private refusal fallback row missing'
        assert notes == ['refusal recorded at: ' + str(stream)], 'private refusal fallback path not named in raised error'
        rows = [json.loads(line) for line in stream.read_text().splitlines()]
        assert len(rows) == 1 and rows[0]['reason'] == 'Stop: private ACL/owner verification failed'
        assert rows[0]['consumed'] is False and len(synced) == 1, 'private refusal fallback was not durably fsynced'
        p.private_acl(fallback)
        assert_no_consumption(root)
        assert_no_consumption(fallback)


def retired_case(entry):
    with sandbox() as (_, pack):
        out = child(pack, 'import runpy\nrunpy.run_module(' + repr(entry) + ', run_name="__main__")\n')
        assert out.returncode != 0, 'retired entrypoint ran'
        stream = pack / 'refusals.jsonl'
        rows = [json.loads(line) for line in stream.read_text().splitlines()] if stream.exists() else []
        assert len(rows) == 1 and rows[0]['consumed'] is False, 'retired entrypoint refusal missing: ' + entry
        assert_no_consumption(pack)


def encoded_hash():
    import denial
    events = []
    encoded = 'invalid envelope \u00e9\n'
    try:
        denial.kernel_log(encoded, lambda event, **data: events.append((event, data)))
    except (p.Stop, ValueError):
        pass
    assert events and events[0] == ('denial-evidence-transport', dict(encoded=encoded,
        sha256=hashlib.sha256(encoded.encode('utf-8')).hexdigest())), 'encoded transport digest missing or covers different bytes'


def case_registration():
    """Strict inventory: every *_case needs a direct run() callback, not a helper edge."""
    module = ast.parse(Path(__file__).read_text(encoding='utf-8'))
    required = {node.name for node in ast.walk(module)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name.endswith('_case')} | {'case_registration'}
    runner = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == 'run')
    registered = set()
    def scan(body):
        for node in body:
            if isinstance(node, ast.For):
                assert isinstance(node.iter, ast.Tuple) and node.iter.elts and not node.orelse, 'unsupported case dispatch loop'
                assert all(isinstance(item, ast.Constant) for item in node.iter.elts), 'case dispatch loop is not literal'
                scan(node.body)
            elif (isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                  and isinstance(node.value.func, ast.Name) and node.value.func.id == 'check'):
                call = node.value
                assert len(call.args) == 2 and not call.keywords, 'unsupported case registration'
                callback = call.args[1]
                if isinstance(callback, ast.Lambda):
                    assert isinstance(callback.body, ast.Call), 'case callback is not a direct call'
                    callback = callback.body.func
                assert isinstance(callback, ast.Name), 'case callback is not a named function'
                registered.add(callback.id)
    scan(runner.body)
    missing = sorted(required - registered)
    assert not missing, 'case missing direct run registration: ' + ', '.join(missing)


def run():
    cases = []
    def check(name, fn):
        fn()
        cases.append(name)
    check('case-registration', case_registration)
    check('import-graph', import_graph)
    check('packet-attribution', packet_attribution_case)
    check('cache-policy', cache_policy)
    for kind in ('prefix', 'preflight'):
        check('bytecode-' + kind, lambda kind=kind: bytecode_case(kind))
    check('packet-bytecode', packet_bytecode_case)
    for kind in ('readiness', 'certify', 'tidy'):
        check('refusal-resume-' + kind, lambda kind=kind: refusal_case(kind))
    for kind in ('success', 'failure'):
        check('refusal-storage-' + kind, lambda kind=kind: refusal_storage(kind))
    check('refusal-acl', refusal_acl_case)
    for entry in ('install', 'active', 'disable', 'inspect_tv', 'prepare'):
        check('retired-' + entry, lambda entry=entry: retired_case(entry))
    check('encoded-hash', encoded_hash)
    real_caches_absent()
    return cases


if __name__ == '__main__':
    rounds = [run(), run()]
    result = dict(runner='r21_checks.py', passed=sum(map(len, rounds)), failed=0, skipped=0,
                  TV_operations=0, rounds=rounds, real_source_caches_absent=True)
    (p.HERE / 'r21-results.json').write_text(json.dumps(result, indent=2) + '\n', newline='\n')
    print(json.dumps(result))
