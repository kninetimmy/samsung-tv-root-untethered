"""Exhaustive offline r21 -> r22 derivation and ledger; r16-r21 are immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261121-r21'
PRIOR_SEAL_SHA = '07c92d93ebeb60c491107f991df7017fbd51d3c42836a752c445c31bcc449f89'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited host gate-script rehearsals again; never live authority',
    'session-results.json': 'Execute the entire inherited session catalog again',
    'mutation-results.json': 'Execute full catalog including bootstrap and refusal-route mutants; count distinct transformations separately',
    'r16-results.json': 'Execute all inherited regressions with r22 receipt labels',
    'r21-results.json': 'Execute 18 declared cases twice, including packet.pyc controls, ACL refusal routing and strict case registration',
    'offline-results.json': 'Record r22 suites, pinned zero-warning builds and zero-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Rebuild unchanged regression-only agent with SDK 3.1.426',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited regression agent runtimeconfig',
    'build/DenialRunner.dll': 'Rebuild unchanged denial helper with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Regenerate denial helper netcoreapp3.1 runtimeconfig',
    'port-from-r15.json': 'Regenerate exhaustive r21 -> r22 ledger; digest lives in seal.json',
    'seal.json': 'Generate exact r22 manifest; report external SHA-256 (no self-hash)',
}
for project in ('SamsungTvRootAgent', 'DenialRunner'):
    for suffix in ('deps.json', 'runtimeconfig.dev.json'):
        GENERATED['build/' + project + '.' + suffix] = 'Unsealed compiler auxiliary; never a live input'
REASONS = {
    'PLAN.md': 'Describe r21 M1/m1 closures, inherited readiness evidence, exact bootstrap and refusal boundaries',
    'packet.py': 'Adopt and harden bootstrap prefix; verify privacy before refusal writes and name private fallback; extend seal set',
    'certify.py': 'Pre-import bootstrap plus current r22 event names, without changing device pins',
    'r16_checks.py': 'Pre-import bootstrap and current r22 event expectations; preserve inherited regression guards',
    'r21_checks.py': 'Structural prologue order; explicitly register packet.pyc and ACL cases; require direct registration of every *_case',
    'mutation_checks.py': 'Pre-import bootstrap; kill bootstrap, packet-cache, refusal-route and missing-case-registration defects for intended reasons',
    'offline_checks.py': 'Pre-import bootstrap; verify extended regressions and immutable r16-r21 trees before sealing',
    'port_from_r15.py': 'Manifest-driven r21 -> r22 derivation, inherited readiness extraction and exhaustive delta ledger',
    'evidence/r21-evidence-digests.json': 'Fresh complete r21 immutable whole-tree snapshot including unsealed readiness receipts',
    'evidence/r21-readiness.json': 'Exact selected inherited device receipt rows with line citations and whole-stream digest; not a new probe',
    'receipts.jsonl': 'Do not inherit runtime stream; bind and extract the predecessor readiness evidence instead',
}
for name in ('active', 'authoring_checks', 'bootstrap_sdk', 'denial', 'deploy', 'disable',
             'driver_checks', 'driver_shim', 'flow_cases', 'inspect_tv', 'install', 'prepare',
             'recovery', 'relay_checks', 'sdk', 'session_checks', 'stage_common', 'stage_lib',
             'stage_session', 'stage_transport', 'tidy', 'trial'):
    REASONS[name + '.py'] = 'Stdlib-only fresh cache prefix before the first local import; reuse once packet is loaded'
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(tree):
    return dict(predecessor_seal_sha256=digest(tree / 'seal.json'),
                files={x.relative_to(tree).as_posix(): digest(x) for x in tree.rglob('*') if x.is_file()},
                directories=sorted(x.relative_to(tree).as_posix() for x in tree.rglob('*') if x.is_dir()))


def verify_predecessors():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r21 seal changed'
    for rev in (16, 17, 18, 19, 20, 21):
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
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r21 seal changed'
    manifest = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in manifest.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r21 sealed member changed: ' + name
    controller = HERE.parent / 'qn90b-evidence-reboot-20261101-r1/controller/packet.py'
    raw = controller.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '757282b0430cdc7df414bdfe0b037d0fee347a141777010df5f14d8e5c4bb5db'
    tools = {'__file__': str(controller), '__name__': 'r22_derivation_controller'}
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
    (HERE / 'evidence/r21-evidence-digests.json').write_text(json.dumps(saved, indent=2, sort_keys=True) + '\n', newline='\n')
    events = ('r16-certification', 'r16-certification-end', 'proof-captured', 'protected-hashes-verified',
              'r20-read-only-certified', 'r20-readiness-passed')
    rows = [dict(line=i, receipt=json.loads(line)) for i, line in
            enumerate((PRIOR / 'receipts.jsonl').read_text(encoding='utf-8').splitlines(), 1)]
    selected = [row for row in rows if row['receipt']['event'] in events]
    assert all(sum(row['receipt']['event'] == event for row in selected) == 1 for event in events), 'readiness event set changed'
    evidence = dict(source_packet=PRIOR.name, source_seal_sha256=PRIOR_SEAL_SHA,
                    source='receipts.jsonl', source_sealed=False, source_sha256=saved['files']['receipts.jsonl'],
                    inherited=True, new_device_contact=False, rows=selected,
                    absent_runtime_paths=[name for name in ('STOP', 'SPENT', 'refusals.jsonl', 'execution')
                                          if not (PRIOR / name).exists()])
    (HERE / 'evidence/r21-readiness.json').write_text(json.dumps(evidence, indent=2) + '\n', newline='\n')
    verify_predecessors()
    print('Derived seal-listed r21 inputs and inherited readiness evidence; r16-r21 immutable snapshots verified')


def record():
    verify_predecessors()
    saved = json.loads((HERE / 'evidence/r21-evidence-digests.json').read_text())
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
        row = dict(status=state, r21=prior, r22=new)
        if state != 'carried' or name in GENERATED:
            assert name in REASONS or name in GENERATED, 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                generated_metadata={name: dict(status='regenerated', r21=prior_files[name], reason=GENERATED[name],
                    r22_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                directories=dict(r21=saved['directories'], r22=directories,
                    removed=sorted(set(saved['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r22 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['derive'], ['ledger'], ['verify']), 'usage: port_from_r15.py derive|ledger|verify'
    {'derive': derive, 'ledger': ledger, 'verify': verify}[sys.argv[1]]()
