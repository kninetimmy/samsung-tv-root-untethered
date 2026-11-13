"""Exhaustive offline r19 -> r20 ledger; every r16-r19 predecessor is immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261119-r19'
PRIOR_SEAL_SHA = '18d47bdd6a344fa24a0ef4311fbdf1aaf322b2606fe7f0edf47e4de08cfff509'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited host gate-script rehearsals again; never live authority',
    'session-results.json': 'Execute the entire inherited session catalog again',
    'mutation-results.json': 'Execute the full mutant catalog; count distinct transformations separately from fixtures',
    'r16-results.json': 'Execute inherited and r20 identity/diagnostic/privacy/source/exec/tidy cases again',
    'offline-results.json': 'Record r20 suites, pinned zero-warning builds and zero-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Rebuild inherited regression-only agent with SDK 3.1.426',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited regression agent runtimeconfig',
    'build/DenialRunner.dll': 'Build exact measured identity gates and retained failure observations with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Generate denial helper netcoreapp3.1 runtimeconfig',
    'port-from-r15.json': 'Regenerate exhaustive r19 -> r20 ledger; digest lives in seal.json',
    'seal.json': 'Generate exact r20 manifest; report external SHA-256 (no self-hash)',
}
for project in ('SamsungTvRootAgent', 'DenialRunner'):
    for suffix in ('deps.json', 'runtimeconfig.dev.json'):
        GENERATED['build/' + project + '.' + suffix] = 'Unsealed compiler auxiliary; never a live input'
REASONS = {
    'PLAN.md': 'Record owner-accepted measured helper residual, correct decision47 citation, diagnostic precedence, source pins and three-target tidy',
    'packet.py': 'Identify r20; current authoring COMMIT, canonical dependency digest and new sealed evidence',
    'stage_lib.py': 'Refuse stale authoring HEAD pins; live marker gates depend on canonical source digest, not HEAD',
    'certify.py': 'Identify r20 and replace the live HEAD equality with dependency digest preflight',
    'denial.py': 'Assert exact measured CapEff/SMACK constants and independently compare observed post-profile',
    'DenialRunner.cs': 'Exact measured identity constants, bounded offending read diagnostic before guards, retained post-profile before validation',
    'DenialSelfTest.cs': 'Exercise identity drift, pre-drain parse failures and exact failed-read/post-profile retention',
    'tidy.py': 'Privacy preflight before attempt/SDK and receipt-pinned third directory; retain split inventory/metadata/hash guards',
    'r16_checks.py': 'Malformed exec fixtures, source-pin boundaries, exact identities, tidy ACL and third-directory real-Bash cases',
    'mutation_checks.py': 'Kill schema/output, identity, diagnostic, tidy ACL and pin regressions; exact distinct-source accounting',
    'authoring_checks.py': 'Refuse stale authoring pin before builds; private build directories before compiler writes',
    'offline_checks.py': 'Re-run complete r20 catalog, private builds, provenance guard and all four immutable predecessor snapshots',
    'port_from_r15.py': 'Retarget exhaustive ledger to sibling r19 -> r20 and verify every r16-r19 sealed member and whole-tree snapshot',
    'evidence/r19-incident.json': 'Historical r19 refusal/creation/upload extracts bound to immutable snapshot; not new device validation',
    'evidence/source-digests.json': 'Canonical working-byte dependency manifest and authoring HEAD provenance',
    'STOP': 'Never inherit predecessor permanent STOP; r19 original remains unchanged',
    'stage-status-certify.json': 'Never inherit predecessor failed runtime certification status as a live input',
    'receipts.jsonl': 'Never inherit predecessor runtime conversations as live input',
}
for rev in (16, 17, 18, 19):
    REASONS['evidence/r' + str(rev) + '-evidence-digests.json'] = 'Fresh complete r' + str(rev) + ' immutable whole-tree snapshot and seal digest'
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r19 seal changed'
    for rev in (16, 17, 18, 19):
        tree = HERE.parent / ('qn90b-uep-l4-deploy-202611' + str(rev) + '-r' + str(rev))
        saved = json.loads((HERE / ('evidence/r' + str(rev) + '-evidence-digests.json')).read_text())
        assert digest(tree / 'seal.json') == saved['predecessor_seal_sha256'], 'predecessor seal changed: ' + str(rev)
        for name, sha in json.loads((tree / 'seal.json').read_text()).items():
            rel = Path(name)
            assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
            assert digest(tree / name) == sha, 'predecessor sealed member changed: ' + str(rev) + '/' + name
        assert {x.relative_to(tree).as_posix(): digest(x) for x in tree.rglob('*') if x.is_file()} == saved['files'], 'predecessor bytes or file set changed: ' + str(rev)
        assert sorted(x.relative_to(tree).as_posix() for x in tree.rglob('*') if x.is_dir()) == saved['directories'], 'predecessor directory set changed: ' + str(rev)
    snapshot = json.loads((HERE / 'evidence/r19-evidence-digests.json').read_text())
    assert snapshot['predecessor_seal_sha256'] == PRIOR_SEAL_SHA
    prior_files = snapshot['files']
    current = {x.relative_to(HERE).as_posix(): digest(x) for x in HERE.rglob('*') if x.is_file()}
    directories = sorted(x.relative_to(HERE).as_posix() for x in HERE.rglob('*') if x.is_dir())
    assert 'execution' not in directories and '__pycache__' not in directories, 'runtime directory remains'
    for name in current:
        rel = Path(name)
        assert not any(part in ('execution', '__pycache__') for part in rel.parts), 'runtime artifact: ' + name
        assert not rel.name.startswith('LIVE_ARM_') and name not in ('STOP', 'SPENT', 'receipts.jsonl', 'stage-status-certify.json'), 'runtime artifact: ' + name
    rows = {}
    for name in sorted(set(prior_files) | set(current)):
        if name in METADATA:
            continue
        new, prior = current.get(name), prior_files.get(name)
        state = 'removed' if new is None else 'added' if prior is None else 'carried' if prior == new else 'delta'
        row = dict(status=state, r19=prior, r20=new)
        if state != 'carried' or name in GENERATED:
            runtime = Path(name).parts[0] in ('execution', '__pycache__') or Path(name).name.startswith('LIVE_ARM_')
            assert name in REASONS or name in GENERATED or (state == 'removed' and runtime), 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name,
                'Never inherit predecessor runtime/cache/arming bytes; snapshot pins original'))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                generated_metadata={name: dict(status='regenerated', r19=prior_files[name], reason=GENERATED[name],
                    r20_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                directories=dict(r19=snapshot['directories'], r20=directories,
                    removed=sorted(set(snapshot['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r20 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['ledger'], ['verify']), 'usage: port_from_r15.py ledger|verify'
    {'ledger': ledger, 'verify': verify}[sys.argv[1]]()
