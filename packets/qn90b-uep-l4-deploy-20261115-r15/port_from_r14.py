"""Digest-verified r14 carry and exhaustive successor delta ledger; host only."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261114-r14'
PRIOR_SEAL_SHA = 'cf2fb939533e4215def484158c5c59c9e34731040d4a917a63bb802eb9dc4a4c'
INSTALL_SHA = 'be77d4940030944e8939ca223f66d253864c980de919e0ad6d5a2b8d35794042'
GENERATED = {
    'rehearsal-results.json': 'Re-run real gate-script rehearsals for r15',
    'session-results.json': 'Re-run inherited and relay session cases for r15',
    'mutation-results.json': 'Re-run inherited and relay mutation kills for r15',
    'offline-results.json': 'Record r15 checks, pinned build and inherited stage anchor',
    'build/SamsungTvRootAgent.dll': 'Rebuild the unchanged packet agent with SDK 3.1.426',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate the packet agent runtimeconfig with SDK 3.1.426',
}
REASONS = {
    'port_from_r13.py': 'Replace predecessor authoring tool with r15 digest-verified r14 port',
    'port-from-r13.json': 'Replace predecessor ledger with r15 r14 carry/delta ledger',
    'port_from_r14.py': 'Verify the pinned r14 seal, carry allowlisted bytes and audit every r15 delta',
    'packet.py': 'Declare r15 seal and digest-pinned inherited stage-1 status; v5.19 pins unchanged',
    'active.py': 'Verify inherited stage-1 evidence and reconcile relay in async prerequisites before the attempt',
    'disable.py': 'Reconcile the relay again before stage 3 consumes an attempt',
    'install.py': 'Refuse replay of the completed inherited install stage before any attempt or SDK construction',
    'recovery.py': 'Strict stale-relay validation/removal and fresh-session absence checks before attempts and after cleanup',
    'deploy.py': 'Require a new ordinary SDK session to verify relay cleanup rather than trust its removal receipt',
    'session_checks.py': 'Run the new relay real-shell and prerequisite-order cases alongside all inherited cases',
    'relay_checks.py': 'Execute production relay command bytes against a host-only filesystem/process shim and falsify guards',
    'mutation_checks.py': 'Mutation-test relay refusals, fresh-session verification, inherited anchor and attempt ordering',
    'offline_checks.py': 'Gate the r15 seal on all inherited/new suites, authoring checks, full provenance and anchor',
    'authoring_checks.py': 'Verify and retain byte-identical production scripts without executing prepare.py',
    'PLAN.md': 'Document the r14 incident, r15 delta, removal strategy, refusal paths, inherited boot and residual risks',
    'stage-status-install.json': 'Inherit only the digest-pinned successful r14 install evidence; never copy markers or attempts',
    'evidence/r14-evidence-digests.json': 'Snapshot non-secret r14 evidence digests to check predecessor immutability',
    'evidence/FORENSIC.md': 'Saved-evidence incident findings and exact receipt citations; no live-device claims',
}
SKIP_TOP = {'execution', '__pycache__', '.pytest_cache'}
BUILD_AUX = {'build/SamsungTvRootAgent.deps.json', 'build/SamsungTvRootAgent.runtimeconfig.dev.json'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prior_seal():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r14 seal changed'
    seal = json.loads((PRIOR / 'seal.json').read_text(encoding='utf-8'))
    for name, want in seal.items():
        path = Path(name)
        assert not path.is_absolute() and '..' not in path.parts, 'unsafe seal path'
        assert digest(PRIOR / name) == want, 'r14 sealed entry drift: ' + name
    assert digest(PRIOR / 'stage-status-install.json') == INSTALL_SHA, 'r14 install evidence changed'
    return seal


def carry():
    seal = prior_seal()
    copied = 0
    for name, want in sorted(dict(seal, **{'stage-status-install.json': INSTALL_SHA}).items()):
        if name in GENERATED or name in ('port_from_r13.py', 'port-from-r13.json'):
            continue
        target = HERE / name
        assert not target.exists(), 'refuse overwrite: ' + name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(PRIOR / name, target)
        assert digest(target) == want, 'carry mismatch: ' + name
        copied += 1
    print(json.dumps({'carried': copied, 'TV_operations': 0}))


def record():
    seal = prior_seal()
    entries = {}
    names = set(seal)
    for path in HERE.rglob('*'):
        rel = path.relative_to(HERE)
        if path.is_file() and not any(part in SKIP_TOP for part in rel.parts):
            names.add(rel.as_posix())
    for name in sorted(names):
        if name in GENERATED or name in BUILD_AUX or name in ('port-from-r14.json', 'seal.json', 'receipts.jsonl'):
            continue
        path = HERE / name
        old = seal.get(name)
        new = digest(path) if path.is_file() else None
        status = 'removed' if new is None else 'added' if old is None else 'carried' if old == new else 'delta'
        entry = {'status': status, 'r14': old, 'r15': new}
        if status != 'carried':
            assert name in REASONS, 'undocumented r15 delta: ' + name
            entry['reason'] = REASONS[name]
        entries[name] = entry
    assert digest(HERE / 'stage-status-install.json') == INSTALL_SHA, 'inherited install drift'
    snapshot = json.loads((HERE / 'evidence/r14-evidence-digests.json').read_text())
    for name, want in snapshot.items():
        assert digest(PRIOR / name) == want, 'immutable r14 evidence changed: ' + name
    return {'successor_of': PRIOR.name, 'r14_seal_sha256': PRIOR_SEAL_SHA,
            'inherited_install_sha256': INSTALL_SHA, 'entries': entries,
            'regenerated': GENERATED,
            'counts': {s: sum(e['status'] == s for e in entries.values()) for s in ('carried', 'delta', 'added', 'removed')}}


def ledger():
    data = record()
    (HERE / 'port-from-r14.json').write_text(json.dumps(data, indent=2, sort_keys=True) + '\n', encoding='utf-8', newline='\n')
    print(json.dumps(data['counts']))


def verify():
    saved = json.loads((HERE / 'port-from-r14.json').read_text(encoding='utf-8'))
    assert saved == record(), 'r15 tree differs from its exhaustive port ledger'


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('carry', 'ledger', 'verify'):
        raise SystemExit('usage: port_from_r14.py carry|ledger|verify')
    {'carry': carry, 'ledger': ledger, 'verify': verify}[sys.argv[1]]()
