"""Exhaustive offline r18 -> r19 ledger; r16/r17/r18 remain immutable."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261118-r18'
PRIOR_SEAL_SHA = '7edfc1af5f4a91c51c6aa106dc68430a1b857ab8bb8270aaaf841a71b20eca4d'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited gate-script host rehearsals again; not live authority',
    'session-results.json': 'Execute all inherited session and relay cases again',
    'mutation-results.json': 'Execute inherited and new mutants; count distinct sources separately from cases',
    'r16-results.json': 'Execute inherited and r19 sequence/transport/inventory/privacy cases; no inherited green results',
    'offline-results.json': 'Record all r19 offline suites, builds and no-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Build inherited agent with SDK 3.1.426 for regression verification only',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited agent runtimeconfig',
    'build/DenialRunner.dll': 'Build direct managed exec refusal accountant with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Generate netcoreapp3.1 runtimeconfig for denial accountant',
    'build/SamsungTvRootAgent.deps.json': 'Unsealed compiler byproduct; not a live input',
    'build/SamsungTvRootAgent.runtimeconfig.dev.json': 'Unsealed compiler byproduct; not a live input',
    'build/DenialRunner.deps.json': 'Unsealed compiler byproduct; not a live input',
    'build/DenialRunner.runtimeconfig.dev.json': 'Unsealed compiler byproduct; not a live input',
    'port-from-r15.json': 'Regenerate this exhaustive r18 -> r19 ledger; digest is in seal.json',
    'seal.json': 'Regenerate exact r19 manifest; verify its digest externally (no self-hash)',
}
REASONS = {
    'tidy.py': 'Identify r19 spent receipt; both production inventory predicates and receipt-pinned deletion guards unchanged',
    'relay_checks.py': 'Empty dll/runtimeconfig/PID cases must reach hash/PID refusal',
    'mutation_checks.py': 'Independent sequence/fence/reader/transport guards and split count-only/comparison-only inventory mutants; report every distinct transformed source and survivor',
    'evidence/r17-incident.json': 'Historical receipt extracts and retention diagnostics, never runtime authority or a new attempt',
    'flow_cases.py': 'Retarget only r18 host fixture paths to verified r8 v5.18 bytes after predecessor working-tree pruning',
    'artifacts/v518-manager.dll': 'Host-only v5.18 fixture copied from pruned ZIP; verified against r8 seal and archive commit',
    'artifacts/v518-manager.runtimeconfig.json': 'Host-only v5.18 runtimeconfig copied from pruned ZIP; verified against r8 seal and archive commit',
    'evidence/r8-fixture-receipts.json': 'Authoring receipts record ZIP members, archive commit, verified seal/asset digests and non-shipping provenance',
    'STOP': 'Never carry predecessor permanent STOP into a new packet; original remains untouched',
    'stage-status-certify.json': 'Never carry failed predecessor runtime certification status',
    'receipts.jsonl': 'Never carry predecessor runtime conversations into a new packet',
}
REASONS.update({
    'PLAN.md': 'Quote owner-accepted task52 replacement; document committed-record authority, independent raw/wire bounds and device-unproven ABI',
    'packet.py': 'Identify r19 and seal probe/design and all three predecessor snapshots; shipped pins unchanged',
    'DenialRunner.cs': 'One persistent nonblocking libc cursor, profile preflight, bounded EAGAIN fences and one direct Attempt',
    'DenialSelfTest.cs': 'Injected open/read/errno/clock transcripts plus real inherited exec/child/timeout tests',
    'denial.py': 'Persist the versioned envelope before independent raw framing, sequence, profile, counters and semantic checks; no dmesg authority',
    'sdk.py': 'Denial-only byte-exact bounded incomplete prefix after accepted tag, exactly once after teardown and before propagating failure',
    'certify.py': 'Describe complete committed-record bracket and verify this packet/evidence ACLs before attempt or SDK construction',
    'r16_checks.py': 'Sequenced controls/gaps/order, split real-Bash inventory, fake-stream partial transport and save-before-failure cases',
    'authoring_checks.py': 'Set isolated Ruff target to py312, matching project requires-python >=3.12, without changing repository configuration',
    'offline_checks.py': 'Run named complete suites with zero warnings, no mutation minima, and verify all three immutable predecessors',
    'port_from_r15.py': 'Retarget exhaustive ledger to r18 -> r19 and verify r16/r17/r18 seals and whole-tree snapshots',
    'evidence/r16-evidence-digests.json': 'Fresh complete immutable r16 file/directory snapshot with recorded seal digest',
    'evidence/r17-evidence-digests.json': 'Fresh complete immutable r17 file/directory snapshot with recorded seal digest',
    'evidence/r18-evidence-digests.json': 'Complete immutable r18 file/directory snapshot including its recorded 77-member seal',
    'evidence/r19-probe.json': 'Copy completed read-only probe evidence; no new device operation',
    'evidence/r19-proposal.md': 'Carry design of record; its future gates are historical, owner decisions are recorded in PLAN',
})
METADATA = ('port-from-r15.json', 'offline-results.json', 'seal.json')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r18 seal changed'
    old = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in old.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r18 sealed file changed: ' + name
    snapshot = json.loads((HERE / 'evidence/r18-evidence-digests.json').read_text())
    assert snapshot['predecessor_seal_sha256'] == PRIOR_SEAL_SHA
    prior_files = {x.relative_to(PRIOR).as_posix(): digest(x) for x in PRIOR.rglob('*') if x.is_file()}
    assert prior_files == snapshot['files'], 'r18 evidence content or file set changed'
    assert sorted(x.relative_to(PRIOR).as_posix() for x in PRIOR.rglob('*') if x.is_dir()) == snapshot['directories'], 'r18 directory set changed'
    for rev, date in ((16, '20261116'), (17, '20261117')):
        tree = HERE.parent / ('qn90b-uep-l4-deploy-' + date + '-r' + str(rev))
        saved = json.loads((HERE / ('evidence/r' + str(rev) + '-evidence-digests.json')).read_text())
        assert digest(tree / 'seal.json') == saved['predecessor_seal_sha256'], 'predecessor seal changed: ' + str(rev)
        for name, sha in json.loads((tree / 'seal.json').read_text()).items():
            assert digest(tree / name) == sha, 'predecessor sealed member changed: ' + str(rev) + '/' + name
        assert {x.relative_to(tree).as_posix(): digest(x) for x in tree.rglob('*') if x.is_file()} == saved['files'], 'predecessor file set or bytes changed: ' + str(rev)
        assert sorted(x.relative_to(tree).as_posix() for x in tree.rglob('*') if x.is_dir()) == saved['directories'], 'predecessor directory set changed: ' + str(rev)
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
        row = dict(status=state, r18=prior, r19=new)
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
                generated_metadata={name: dict(status='regenerated', r18=prior_files[name],
                    reason=GENERATED[name], r19_digest_source='seal.json entry' if name != 'seal.json' else 'external seal digest') for name in METADATA},
                directories=dict(r18=snapshot['directories'],
                    r19=directories, removed=sorted(set(snapshot['directories']) - set(directories))),
                counts={state: sum(x['status'] == state for x in rows.values())
                        for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r19 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['ledger'], ['verify']), 'usage: port_from_r15.py ledger|verify'
    {'ledger': ledger, 'verify': verify}[sys.argv[1]]()
