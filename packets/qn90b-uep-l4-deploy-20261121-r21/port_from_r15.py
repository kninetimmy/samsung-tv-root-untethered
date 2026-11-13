"""Exhaustive offline r20 -> r21 derivation and ledger; r16-r20 are immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261120-r20'
PRIOR_SEAL_SHA = 'a6988f7bcc6d23e27181a958971b1c5c6041d8ce77a5b1a2ec69b1faac9e9367'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited host gate-script rehearsals again; never live authority',
    'session-results.json': 'Execute the entire inherited session catalog again',
    'mutation-results.json': 'Execute full catalog including r21 guard removals; distinct transformations separate from executions',
    'r16-results.json': 'Execute all inherited regression cases with encoded-transport digest and isolated refusal records',
    'r21-results.json': 'Execute isolated real-entrypoint bytecode and durable non-consuming refusal regressions twice',
    'offline-results.json': 'Record r21 suites, pinned zero-warning builds and zero-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Rebuild unchanged regression-only agent with SDK 3.1.426',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited regression agent runtimeconfig',
    'build/DenialRunner.dll': 'Rebuild unchanged denial helper with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Regenerate denial helper netcoreapp3.1 runtimeconfig',
    'port-from-r15.json': 'Regenerate exhaustive r20 -> r21 ledger; digest lives in seal.json',
    'seal.json': 'Generate exact r21 manifest; report external SHA-256 (no self-hash)',
}
for project in ('SamsungTvRootAgent', 'DenialRunner'):
    for suffix in ('deps.json', 'runtimeconfig.dev.json'):
        GENERATED['build/' + project + '.' + suffix] = 'Unsealed compiler auxiliary; never a live input'
REASONS = {
    'PLAN.md': 'Close exactly the three r20 findings; state cache lifecycle, preconditions, refusal semantics and hash representation',
    'packet.py': 'Private per-process cache prefix and fail-closed source-cache preflight before source imports; durable refusal primitive; r21 seal set',
    'stage_lib.py': 'Document the distinction between consuming stage failures and packet-local non-consuming refusals',
    'certify.py': 'Record non-consuming host preflight refusals separately from stage failures',
    'tidy.py': 'Record non-consuming host preflight refusals separately from stage failures',
    'active.py': 'Record retired CLI and initial host preflight refusals; leave regression-only relay operations unchanged',
    'disable.py': 'Record retired CLI and initial host preflight refusals; leave regression-only relay operations unchanged',
    'install.py': 'Record retired CLI and initial host preflight refusals; leave regression-only driver unchanged',
    'inspect_tv.py': 'Record retired historical inspection entrypoint refusal without stage consumption',
    'prepare.py': 'Record retired historical preparation entrypoint refusal without stage consumption',
    'denial.py': 'Save SHA-256 of exact UTF-8 encoded transport string in the existing first evidence event',
    'r16_checks.py': 'Assert encoded hash without moving raw evidence ordering; isolate new refusal writes in inherited negative fixtures',
    'r21_checks.py': 'Subprocess poison tests on real entrypoint imports in isolated copies and modeled refusal/resumption tests',
    'driver_checks.py': 'Match the existing py312 isolated Ruff target for the refusal persistence ExceptionGroup',
    'mutation_checks.py': 'Kill private-prefix, cache-preflight, refusal persistence, stage coverage and transport-hash removals',
    'offline_checks.py': 'Run r21 suite twice, seal its results and verify immutable r16-r20 trees',
    'port_from_r15.py': 'Manifest-driven r20 -> r21 derivation plus exhaustive delta ledger and immutable predecessor verification',
    'evidence/r20-evidence-digests.json': 'Fresh complete r20 immutable whole-tree snapshot and seal digest',
}
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(tree):
    return dict(predecessor_seal_sha256=digest(tree / 'seal.json'),
                files={x.relative_to(tree).as_posix(): digest(x) for x in tree.rglob('*') if x.is_file()},
                directories=sorted(x.relative_to(tree).as_posix() for x in tree.rglob('*') if x.is_dir()))


def verify_predecessors():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r20 seal changed'
    for rev in (16, 17, 18, 19, 20):
        tree = HERE.parent / ('qn90b-uep-l4-deploy-202611' + str(rev) + '-r' + str(rev))
        saved = json.loads((HERE / ('evidence/r' + str(rev) + '-evidence-digests.json')).read_text())
        assert digest(tree / 'seal.json') == saved['predecessor_seal_sha256'], 'predecessor seal changed: ' + str(rev)
        for name, sha in json.loads((tree / 'seal.json').read_text()).items():
            rel = Path(name)
            assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
            assert digest(tree / name) == sha, 'predecessor sealed member changed: ' + str(rev) + '/' + name
        current = snapshot(tree)
        assert current['files'] == saved['files'], 'predecessor bytes or file set changed: ' + str(rev)
        assert current['directories'] == saved['directories'], 'predecessor directory set changed: ' + str(rev)


def derive():
    """Carry only seal-listed inputs, never runtime or generated results/builds."""
    assert {x.name for x in HERE.iterdir()} == {'port_from_r15.py', 'evidence'}, 'derivation requires a fresh directory'
    assert not list((HERE / 'evidence').iterdir()), 'derivation evidence directory is not empty'
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r20 seal changed'
    manifest = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in manifest.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r20 sealed member changed: ' + name
    controller = HERE.parent / 'qn90b-evidence-reboot-20261101-r1/controller/packet.py'
    raw = controller.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '757282b0430cdc7df414bdfe0b037d0fee347a141777010df5f14d8e5c4bb5db'
    tools = {'__file__': str(controller), '__name__': 'r21_derivation_controller'}
    exec(compile(raw, str(controller), 'exec'), tools)
    tools['private_acl'](HERE)
    tools['private_acl'](HERE / 'evidence')
    for name in sorted(manifest):
        if name in GENERATED or name == 'port_from_r15.py':
            continue
        target = HERE / name
        if not target.parent.exists():
            tools['make_private_directory'](target.parent)
        with target.open('xb') as stream:
            stream.write((PRIOR / name).read_bytes())
    tools['make_private_directory'](HERE / 'build')
    saved = snapshot(PRIOR)
    (HERE / 'evidence/r20-evidence-digests.json').write_text(json.dumps(saved, indent=2, sort_keys=True) + '\n', newline='\n')
    verify_predecessors()
    print('Derived seal-listed r20 inputs; generated files withheld; r16-r20 immutable snapshots verified')


def record():
    verify_predecessors()
    saved = json.loads((HERE / 'evidence/r20-evidence-digests.json').read_text())
    assert saved['predecessor_seal_sha256'] == PRIOR_SEAL_SHA
    prior_files = saved['files']
    current = {x.relative_to(HERE).as_posix(): digest(x) for x in HERE.rglob('*') if x.is_file()}
    directories = sorted(x.relative_to(HERE).as_posix() for x in HERE.rglob('*') if x.is_dir())
    assert 'execution' not in directories and '__pycache__' not in directories, 'runtime directory remains'
    for name in current:
        rel = Path(name)
        assert not any(part in ('execution', '__pycache__') for part in rel.parts), 'runtime artifact: ' + name
        assert not rel.name.startswith('LIVE_ARM_') and name not in ('STOP', 'SPENT', 'receipts.jsonl', 'refusals.jsonl', 'stage-status-certify.json'), 'runtime artifact: ' + name
    rows = {}
    for name in sorted(set(prior_files) | set(current)):
        if name in METADATA:
            continue
        new, prior = current.get(name), prior_files.get(name)
        state = 'removed' if new is None else 'added' if prior is None else 'carried' if prior == new else 'delta'
        row = dict(status=state, r20=prior, r21=new)
        if state != 'carried' or name in GENERATED:
            assert name in REASONS or name in GENERATED, 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                generated_metadata={name: dict(status='regenerated', r20=prior_files[name], reason=GENERATED[name],
                    r21_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                directories=dict(r20=saved['directories'], r21=directories,
                    removed=sorted(set(saved['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r21 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['derive'], ['ledger'], ['verify']), 'usage: port_from_r15.py derive|ledger|verify'
    {'derive': derive, 'ledger': ledger, 'verify': verify}[sys.argv[1]]()
