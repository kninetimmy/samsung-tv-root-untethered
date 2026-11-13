"""Exhaustive offline r17 -> r18 ledger; both predecessors remain immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261117-r17'
PRIOR_SEAL_SHA = '0170d27c141ce5332206ae07bdca530e7ee3bf9defdd07ea29737b5e409f1508'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited gate-script host rehearsals again; not live authority',
    'session-results.json': 'Execute all inherited session and relay cases again',
    'mutation-results.json': 'Execute inherited and new mutants; count distinct sources separately from cases',
    'r16-results.json': 'Execute inherited cases plus r18 retention, save ordering and two-directory tidy regressions',
    'offline-results.json': 'Record all r18 offline suites, builds and no-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Build inherited agent with SDK 3.1.426 for regression verification only',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited agent runtimeconfig',
    'build/DenialRunner.dll': 'Build direct managed exec refusal accountant with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Generate netcoreapp3.1 runtimeconfig for denial accountant',
    'build/SamsungTvRootAgent.deps.json': 'Unsealed compiler byproduct; not a live input',
    'build/SamsungTvRootAgent.runtimeconfig.dev.json': 'Unsealed compiler byproduct; not a live input',
    'build/DenialRunner.deps.json': 'Unsealed compiler byproduct; not a live input',
    'build/DenialRunner.runtimeconfig.dev.json': 'Unsealed compiler byproduct; not a live input',
    'port-from-r15.json': 'Regenerate this exhaustive r17 -> r18 ledger; digest is in seal.json',
    'seal.json': 'Regenerate exact r18 manifest; verify its digest externally (no self-hash)',
}
REASONS = {
    'PLAN.md': 'Record approved retention decision, actual r17 incident/spent attempt, corrected r16 history and two-directory tidy',
    'packet.py': 'Identify r18 and seal immutable r17 snapshot and receipt extracts; no shipped pin change',
    'certify.py': 'Identify the additional r18 denial after spent r17; use single-read retained-window status wording',
    'denial.py': 'Single post-attempt dmesg read, save before assertions, endpoint retention diagnostics; no byte saturation policy',
    'tidy.py': 'Validate both exact directories and all receipt-pinned assets before unlink; verify fresh-session absence',
    'relay_checks.py': 'Empty dll/runtimeconfig/PID cases must reach hash/PID refusal',
    'mutation_checks.py': 'Separate distinct source mutation counts and add retention/save/empty-child regressions. The inventory count guard and exact-set comparison are one unit under test; the count guard is a fail-fast optimization inside it, not an independently observable defense. One distinct transformation removes both guards; tidy.py is unchanged by this recast.',
    'r16_checks.py': 'Exercise retention diagnostics, size neutrality, single-read saving and both exact tidy inventories',
    'offline_checks.py': 'Run all suites freshly and verify the r17 -> r18 ledger and both immutable predecessors',
    'port_from_r15.py': 'Retarget inherited ledger to immutable r17 and verify r16 remains unchanged too',
    'evidence/r17-evidence-digests.json': 'Pin every r17 file/directory, including STOP, spent attempt, marker, receipts and seal, without carrying runtime bytes',
    'evidence/r17-incident.json': 'Historical receipt extracts and retention diagnostics, never runtime authority or a new attempt',
    'flow_cases.py': 'Retarget only r18 host fixture paths to verified r8 v5.18 bytes after predecessor working-tree pruning',
    'artifacts/v518-manager.dll': 'Host-only v5.18 fixture copied from pruned ZIP; verified against r8 seal and archive commit',
    'artifacts/v518-manager.runtimeconfig.json': 'Host-only v5.18 runtimeconfig copied from pruned ZIP; verified against r8 seal and archive commit',
    'evidence/r8-fixture-receipts.json': 'Authoring receipts record ZIP members, archive commit, verified seal/asset digests and non-shipping provenance',
    'STOP': 'Never carry predecessor permanent STOP into a new packet; original remains untouched',
    'stage-status-certify.json': 'Never carry failed predecessor runtime certification status',
    'receipts.jsonl': 'Never carry predecessor runtime conversations into a new packet',
}
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r17 seal changed'
    old = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in old.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r17 sealed file changed: ' + name
    snapshot = json.loads((HERE / 'evidence/r17-evidence-digests.json').read_text())
    assert snapshot['predecessor_seal_sha256'] == PRIOR_SEAL_SHA
    prior_files = {x.relative_to(PRIOR).as_posix(): digest(x) for x in PRIOR.rglob('*') if x.is_file()}
    assert prior_files == snapshot['files'], 'r17 evidence content or file set changed'
    assert sorted(x.relative_to(PRIOR).as_posix() for x in PRIOR.rglob('*') if x.is_dir()) == snapshot['directories'], 'r17 directory set changed'
    r16 = HERE.parent / 'qn90b-uep-l4-deploy-20261116-r16'
    r16_snapshot = json.loads((HERE / 'evidence/r16-evidence-digests.json').read_text())
    assert {x.relative_to(r16).as_posix(): digest(x) for x in r16.rglob('*') if x.is_file()} == r16_snapshot['files'], 'r16 file set or bytes changed'
    assert sorted(x.relative_to(r16).as_posix() for x in r16.rglob('*') if x.is_dir()) == r16_snapshot['directories'], 'r16 directory set changed'
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
        row = dict(status=state, r17=prior, r18=new)
        if state != 'carried' or name in GENERATED:
            runtime = (Path(name).parts[0] in ('execution', '__pycache__')
                       or Path(name).name.startswith('LIVE_ARM_'))
            assert name in REASONS or name in GENERATED or (state == 'removed' and runtime), 'undocumented delta: ' + name
            row['reason'] = REASONS.get(name, GENERATED.get(name,
                'Never carry predecessor runtime/cache/arming bytes; immutable snapshot pins original'))
        if name in GENERATED:
            row['regenerated'] = True
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED,
                generated_metadata={name: dict(status='regenerated', r17=prior_files[name],
                    reason=GENERATED[name], r18_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                directories=dict(r17=snapshot['directories'],
                    r18=directories, removed=sorted(set(snapshot['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r18 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['ledger'], ['verify']), 'usage: port_from_r15.py ledger|verify'
    {'ledger': ledger, 'verify': verify}[sys.argv[1]]()
