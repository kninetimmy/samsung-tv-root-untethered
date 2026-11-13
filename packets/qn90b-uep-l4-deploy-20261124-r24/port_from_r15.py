"""Exhaustive offline r23 -> r24 derivation and ledger; r16-r23 are immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261123-r23'
PRIOR_SEAL_SHA = 'c4db777e5ab97ff69e0c02552b7e493f50c8145ae5eff042f5f43511ea595804'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited host gate-script rehearsals again; never live authority',
    'session-results.json': 'Execute the entire inherited session catalog again',
    'mutation-results.json': 'Execute inherited catalog plus one-shot resync, provenance, phase naming, final-read bounds and journal mutants; count distinct transformations separately',
    'r16-results.json': 'Execute inherited and r24 host/journal/phase regressions with r24 labels',
    'r21-results.json': 'Execute 19 directly registered cases twice, including seal-wide literal emission and packet/predecessor attribution guard',
    'offline-results.json': 'Record r24 suites, pinned zero-warning builds and zero-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Rebuild unchanged regression-only agent with SDK 3.1.426',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited regression agent runtimeconfig',
    'build/DenialRunner.dll': 'Rebuild decision-50 one-shot resync helper with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Regenerate denial helper netcoreapp3.1 runtimeconfig',
    'port-from-r15.json': 'Regenerate exhaustive r23 -> r24 ledger; digest lives in seal.json',
    'seal.json': 'Generate exact 91-member r24 manifest; report external SHA-256 (no self-hash)',
}
for project in ('SamsungTvRootAgent', 'DenialRunner'):
    for suffix in ('deps.json', 'runtimeconfig.dev.json'):
        GENERATED['build/' + project + '.' + suffix] = 'Unsealed compiler auxiliary; never a live input'
REASONS = {
    'PLAN.md': 'Preserve original accepted clause verbatim and explicitly amend under decision 50; document journal, evidence limits, unchanged bounds and named fourth-stage residual',
    'packet.py': 'Rename packet/bootstrap identity to r24; seal r23 whole-tree snapshot and relocate historical install receipt out of stage-status namespace',
    'certify.py': 'Rename bootstrap and 11 current labels to r24; cite relocated historical install receipt without changing its hash',
    'denial.py': 'Rename bootstrap/attempt attribution to r24/r23; independently validate resync gates, durability and phase refusals; verify optional journal before guarded cleanup',
    'DenialRunner.cs': 'Implement gated once-only durable pre-baseline resync, raw syscall provenance, phase EPIPE names, truthful same_fd, final-call bounds and pre-open buffer',
    'DenialSelfTest.cs': 'Exercise all resync gates, fatal later failures, persistence ordering/failure, provenance and final-call time limits',
    'tidy.py': 'Rename bootstrap and SPENT attribution to r24 only; deliberately retain the exact three-directory scope',
    'r16_checks.py': 'Rename bootstrap/readiness expectation; add exact host phase/resync refusals, journal flow and durable-evidence assertions',
    'r21_checks.py': 'Rename only current receipt/bootstrap/import-fixture/ACL-fixture identity to r24; preserve historical suite and evidence names',
    'mutation_checks.py': 'Update current attribution and changed predicate anchors; add intended-reason resync, provenance, final-bound and journal mutants',
    'offline_checks.py': 'Require expanded r24 named test catalogs, relocated install bytes, exact amended contract gates and immutable r16-r23 snapshots before sealing',
    'port_from_r15.py': 'Manifest-driven r23 -> r24 derivation and exhaustive delta ledger; snapshot every r23 runtime byte without carrying runtime files',
    'evidence/r23-evidence-digests.json': 'Bind complete immutable r23 whole tree including unsealed STOP, marker, receipts, status and attempt; no device contact',
    'evidence/inherited-install.json': 'Carry exact historical stage-status-install bytes under evidence-only name and unchanged digest',
    'NuGet.Config': 'Clear package sources explicitly so pinned SDK builds cannot query network feeds',
}
for name in ('active', 'authoring_checks', 'bootstrap_sdk', 'deploy', 'disable',
             'driver_checks', 'driver_shim', 'flow_cases', 'inspect_tv', 'install', 'prepare',
             'recovery', 'relay_checks', 'sdk', 'session_checks', 'stage_common', 'stage_lib',
             'stage_session', 'stage_transport', 'trial'):
    REASONS[name + '.py'] = 'Rename only the current packet bootstrap cache prefix from r23 to r24'
REASONS['active.py'] = 'Rename bootstrap to r24 and use relocated historical install evidence in regression-only predecessor guard'
REASONS['authoring_checks.py'] = 'Rename bootstrap to r24; build/test actual new helper before host flows and disable NuGet network feeds'
for name in ('LIVE_ARM_CERTIFY', 'STOP', 'receipts.jsonl', 'stage-status-certify.json',
             'stage-status-install.json', 'execution/attempts/LIVE_ARM_CERTIFY.attempt'):
    REASONS[name] = 'Do not carry predecessor runtime artifacts; bind their unchanged bytes in evidence/r23-evidence-digests.json'
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def snapshot(tree):
    return dict(predecessor_seal_sha256=digest(tree / 'seal.json'),
                files={x.relative_to(tree).as_posix(): digest(x) for x in tree.rglob('*') if x.is_file()},
                directories=sorted(x.relative_to(tree).as_posix() for x in tree.rglob('*') if x.is_dir()))


def verify_predecessors():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r23 seal changed'
    for rev in (16, 17, 18, 19, 20, 21, 22, 23):
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
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r23 seal changed'
    manifest = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in manifest.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r23 sealed member changed: ' + name
    controller = HERE.parent / 'qn90b-evidence-reboot-20261101-r1/controller/packet.py'
    raw = controller.read_bytes()
    assert hashlib.sha256(raw).hexdigest() == '757282b0430cdc7df414bdfe0b037d0fee347a141777010df5f14d8e5c4bb5db'
    tools = {'__file__': str(controller), '__name__': 'r24_derivation_controller'}
    exec(compile(raw, str(controller), 'exec'), tools)
    tools['private_acl'](HERE)
    tools['private_acl'](HERE / 'evidence')
    for name in sorted(manifest):
        if name in GENERATED or name == 'port_from_r15.py' or name.startswith('stage-status-'):
            continue
        target = HERE / name
        if not target.parent.exists():
            tools['make_private_directory'](target.parent)
        with target.open('xb') as stream:
            stream.write((PRIOR / name).read_bytes())
    tools['make_private_directory'](HERE / 'build')
    saved = snapshot(PRIOR)
    (HERE / 'evidence/r23-evidence-digests.json').write_text(json.dumps(saved, indent=2, sort_keys=True) + '\n', newline='\n')
    (HERE / 'evidence/inherited-install.json').write_bytes((PRIOR / 'stage-status-install.json').read_bytes())
    assert digest(HERE / 'evidence/r21-readiness.json') == digest(PRIOR / 'evidence/r21-readiness.json'), 'inherited r21 readiness changed'
    evidence = json.loads((HERE / 'evidence/r21-readiness.json').read_text())
    events = ('r16-certification', 'r16-certification-end', 'proof-captured', 'protected-hashes-verified',
              'r20-read-only-certified', 'r20-readiness-passed')
    assert all(sum(row['receipt']['event'] == event for row in evidence['rows']) == 1 for event in events), 'readiness event set changed'
    verify_predecessors()
    print('Derived seal-listed r23 inputs with unchanged r21 readiness; r16-r23 immutable snapshots verified')


def record():
    verify_predecessors()
    saved = json.loads((HERE / 'evidence/r23-evidence-digests.json').read_text())
    assert saved['predecessor_seal_sha256'] == PRIOR_SEAL_SHA
    prior_files = saved['files']
    current = {x.relative_to(HERE).as_posix(): digest(x) for x in HERE.rglob('*') if x.is_file()}
    directories = sorted(x.relative_to(HERE).as_posix() for x in HERE.rglob('*') if x.is_dir())
    assert 'execution' not in directories and '__pycache__' not in directories, 'runtime directory remains'
    for name in current:
        rel = Path(name)
        assert not any(part in ('execution', '__pycache__') for part in rel.parts), 'runtime artifact: ' + name
        assert not rel.name.startswith(('LIVE_ARM_', 'stage-status-')) and name not in ('STOP', 'SPENT', 'receipts.jsonl', 'refusals.jsonl'), 'runtime artifact: ' + name
    rows = {}
    for name in sorted(set(prior_files) | set(current)):
        if name in METADATA:
            continue
        new, prior = current.get(name), prior_files.get(name)
        state = 'removed' if new is None else 'added' if prior is None else 'carried' if prior == new else 'delta'
        row = dict(status=state, r23=prior, r24=new)
        if state != 'carried' or name in GENERATED:
            assert name in REASONS or name in GENERATED, 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                  generated_metadata={name: dict(status='regenerated', r23=prior_files[name], reason=GENERATED[name],
                     r24_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                  directories=dict(r23=saved['directories'], r24=directories,
                    removed=sorted(set(saved['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r24 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['derive'], ['ledger'], ['verify']), 'usage: port_from_r15.py derive|ledger|verify'
    {'derive': derive, 'ledger': ledger, 'verify': verify}[sys.argv[1]]()
