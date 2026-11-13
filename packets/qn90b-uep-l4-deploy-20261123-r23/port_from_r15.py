"""Exhaustive offline r22 -> r23 derivation and ledger; r16-r22 are immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261122-r22'
PRIOR_SEAL_SHA = '109664aa9e2890a0d185b449fc40a3c793caad24202e592a3fa2f9fcdc4f49aa'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited host gate-script rehearsals again; never live authority',
    'session-results.json': 'Execute the entire inherited session catalog again',
    'mutation-results.json': 'Execute full catalog plus stale label, packet, predecessor, SPENT and attribution-registration mutants; count distinct transformations separately',
    'r16-results.json': 'Execute all inherited regressions with r23 receipt labels',
    'r21-results.json': 'Execute 19 directly registered cases twice, including seal-wide literal emission and packet/predecessor attribution guard',
    'offline-results.json': 'Record r23 suites, pinned zero-warning builds and zero-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Rebuild unchanged regression-only agent with SDK 3.1.426',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited regression agent runtimeconfig',
    'build/DenialRunner.dll': 'Rebuild unchanged denial helper with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Regenerate denial helper netcoreapp3.1 runtimeconfig',
    'port-from-r15.json': 'Regenerate exhaustive r22 -> r23 ledger; digest lives in seal.json',
    'seal.json': 'Generate exact 89-member r23 manifest; report external SHA-256 (no self-hash)',
}
for project in ('SamsungTvRootAgent', 'DenialRunner'):
    for suffix in ('deps.json', 'runtimeconfig.dev.json'):
        GENERATED['build/' + project + '.' + suffix] = 'Unsealed compiler auxiliary; never a live input'
REASONS = {
    'PLAN.md': 'Describe r22 -> r23 attribution closures, 89-member seal, structural guard limits and unchanged inherited r21 readiness; preserve contract, pins and residuals verbatim',
    'packet.py': 'Rename current packet/bootstrap identity to r23 and add the r22 whole-tree snapshot to the explicit seal catalog',
    'certify.py': 'Rename bootstrap prefix and all 11 current capture/event labels to r23; leave device pins unchanged',
    'denial.py': 'Rename bootstrap prefix to r23; attribute attempt context to packet r23 and actual predecessor r22',
    'tidy.py': 'Rename bootstrap prefix to r23; name r23 in successful tidy SPENT text',
    'r16_checks.py': 'Rename bootstrap prefix and current readiness event expectation to r23; preserve inherited regressions',
    'r21_checks.py': 'Rename current labels/prefixes to r23; directly register structural seal-wide literal label/output and packet/predecessor checks without a per-module emission list',
    'mutation_checks.py': 'Rename current bootstrap/label expectations to r23; add five intended-reason mutants for other-module labels, each attribution field, SPENT and guard registration',
    'offline_checks.py': 'Rename current packet/bootstrap identity to r23; require 19 cases twice including attribution guard and verify immutable r16-r22 trees before sealing',
    'port_from_r15.py': 'Manifest-driven r22 -> r23 derivation and exhaustive delta ledger; carry r21 readiness unchanged and verify predecessors through r22',
    'evidence/r22-evidence-digests.json': 'Add complete immutable r22 whole-tree snapshot and seal digest; no readiness run or new device evidence',
}
for name in ('active', 'authoring_checks', 'bootstrap_sdk', 'deploy', 'disable',
             'driver_checks', 'driver_shim', 'flow_cases', 'inspect_tv', 'install', 'prepare',
             'recovery', 'relay_checks', 'sdk', 'session_checks', 'stage_common', 'stage_lib',
             'stage_session', 'stage_transport', 'trial'):
    REASONS[name + '.py'] = 'Rename only the current packet bootstrap cache prefix from r22 to r23'
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(tree):
    return dict(predecessor_seal_sha256=digest(tree / 'seal.json'),
                files={x.relative_to(tree).as_posix(): digest(x) for x in tree.rglob('*') if x.is_file()},
                directories=sorted(x.relative_to(tree).as_posix() for x in tree.rglob('*') if x.is_dir()))


def verify_predecessors():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r22 seal changed'
    for rev in (16, 17, 18, 19, 20, 21, 22):
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
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r22 seal changed'
    manifest = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in manifest.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r22 sealed member changed: ' + name
    controller = HERE.parent / 'qn90b-evidence-reboot-20261101-r1/controller/packet.py'
    raw = controller.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '757282b0430cdc7df414bdfe0b037d0fee347a141777010df5f14d8e5c4bb5db'
    tools = {'__file__': str(controller), '__name__': 'r23_derivation_controller'}
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
    (HERE / 'evidence/r22-evidence-digests.json').write_text(json.dumps(saved, indent=2, sort_keys=True) + '\n', newline='\n')
    assert digest(HERE / 'evidence/r21-readiness.json') == digest(PRIOR / 'evidence/r21-readiness.json'), 'inherited r21 readiness changed'
    evidence = json.loads((HERE / 'evidence/r21-readiness.json').read_text())
    events = ('r16-certification', 'r16-certification-end', 'proof-captured', 'protected-hashes-verified',
              'r20-read-only-certified', 'r20-readiness-passed')
    assert all(sum(row['receipt']['event'] == event for row in evidence['rows']) == 1 for event in events), 'readiness event set changed'
    verify_predecessors()
    print('Derived seal-listed r22 inputs with unchanged r21 readiness; r16-r22 immutable snapshots verified')


def record():
    verify_predecessors()
    saved = json.loads((HERE / 'evidence/r22-evidence-digests.json').read_text())
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
        row = dict(status=state, r22=prior, r23=new)
        if state != 'carried' or name in GENERATED:
            assert name in REASONS or name in GENERATED, 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                 generated_metadata={name: dict(status='regenerated', r22=prior_files[name], reason=GENERATED[name],
                    r23_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                 directories=dict(r22=saved['directories'], r23=directories,
                    removed=sorted(set(saved['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r23 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['derive'], ['ledger'], ['verify']), 'usage: port_from_r15.py derive|ledger|verify'
    {'derive': derive, 'ledger': ledger, 'verify': verify}[sys.argv[1]]()
