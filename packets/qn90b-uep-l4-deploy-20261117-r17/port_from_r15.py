"""Exhaustive offline r16 -> r17 ledger; inherited filename, immutable source."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261116-r16'
PRIOR_SEAL_SHA = 'c41976bc39e5c429caf576565f298a531bee368262f92f3ef252c93dbf905f1a'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited gate-script host rehearsals again; not live authority',
    'session-results.json': 'Execute all inherited session and relay cases again',
    'mutation-results.json': 'Execute unchanged inherited mutants with typed exception accounting',
    'r16-results.json': 'Execute inherited cases plus r17 DAC and evidence-field regressions',
    'offline-results.json': 'Record all r17 offline suites, builds and no-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Build inherited agent with SDK 3.1.426 for regression verification only',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited agent runtimeconfig',
    'build/DenialRunner.dll': 'Build direct managed exec refusal accountant with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Generate netcoreapp3.1 runtimeconfig for denial accountant',
    'build/SamsungTvRootAgent.deps.json': 'Unsealed compiler byproduct; not a live input',
    'build/SamsungTvRootAgent.runtimeconfig.dev.json': 'Unsealed compiler byproduct; not a live input',
    'build/DenialRunner.deps.json': 'Unsealed compiler byproduct; not a live input',
    'build/DenialRunner.runtimeconfig.dev.json': 'Unsealed compiler byproduct; not a live input',
    'port-from-r15.json': 'Regenerate this exhaustive r16 -> r17 ledger; digest is in seal.json',
    'seal.json': 'Regenerate exact r17 manifest; verify its digest externally (no self-hash)',
}
REASONS = {
    'PLAN.md': 'Document r16 incident, design A, receipt authority, DAC fixture boundary and unchanged live contract',
    'packet.py': 'Identify r17 and add the immutable r16 evidence snapshot to the seal; no live contract/pin change',
    'certify.py': 'Replace uid901 backup child hashes with explicit fatal directory metadata guards and receipt evidence fields',
    'r16_checks.py': 'Add DAC-denied-child acceptance, directory shape STOPs and evidence status/log cases; retain inherited dispatch',
    'offline_checks.py': 'Run all suites freshly and emit/verify the complete r16 -> r17 ledger before sealing',
    'port_from_r15.py': 'Retarget inherited ledger tool to immutable r16, including runtime exclusions and exact regenerated digests',
    'evidence/r16-evidence-digests.json': 'Pin every r16 file and directory, including STOP, failed status, receipts and seal, without carrying runtime bytes',
    'STOP': 'Never carry predecessor permanent STOP into a new packet; original remains untouched',
    'stage-status-certify.json': 'Never carry failed predecessor runtime certification status',
    'receipts.jsonl': 'Never carry predecessor runtime conversations into a new packet',
}
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r16 seal changed'
    old = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in old.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r16 sealed file changed: ' + name
    snapshot = json.loads((HERE / 'evidence/r16-evidence-digests.json').read_text())
    assert snapshot['predecessor_seal_sha256'] == PRIOR_SEAL_SHA
    prior_files = {x.relative_to(PRIOR).as_posix(): digest(x) for x in PRIOR.rglob('*') if x.is_file()}
    assert prior_files == snapshot['files'], 'r16 evidence content or file set changed'
    assert sorted(x.relative_to(PRIOR).as_posix() for x in PRIOR.rglob('*') if x.is_dir()) == snapshot['directories'], 'r16 directory set changed'
    current = {x.relative_to(HERE).as_posix(): digest(x) for x in HERE.rglob('*') if x.is_file()}
    directories = sorted(x.relative_to(HERE).as_posix() for x in HERE.rglob('*') if x.is_dir())
    assert 'execution' not in directories and '__pycache__' not in directories, 'runtime directory remains'
    for name in current:
        rel = Path(name)
        assert not any(part in ('execution', '__pycache__') for part in rel.parts), 'runtime artifact: ' + name
        assert not rel.name.startswith('LIVE_ARM_') and name not in ('STOP', 'SPENT', 'receipts.jsonl', 'stage-status-certify.json'), 'runtime artifact: ' + name
    names = set(prior_files) | set(current)
    rows = {}
    for name in sorted(names):
        if name in METADATA:
            continue
        new = current.get(name)
        prior = prior_files.get(name)
        state = 'removed' if new is None else 'added' if prior is None else 'carried' if prior == new else 'delta'
        row = dict(status=state, r16=prior, r17=new)
        if state != 'carried' or name in GENERATED:
            assert name in REASONS or name in GENERATED, 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                generated_metadata={name: dict(status='regenerated', r16=prior_files[name],
                    reason=GENERATED[name], r17_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                directories=dict(r16=snapshot['directories'],
                    r17=directories, removed=sorted(set(snapshot['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r17 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['ledger'], ['verify']), 'usage: port_from_r15.py ledger|verify'
    {'ledger': ledger, 'verify': verify}[sys.argv[1]]()
