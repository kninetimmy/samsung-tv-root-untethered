"""Exhaustive offline r15 -> r16 digest ledger and predecessor immutability."""
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PRIOR = HERE.parent / 'qn90b-uep-l4-deploy-20261115-r15'
PRIOR_SEAL_SHA = '18d14375d0576fc52e0ba15647c2aebf2f8de1c6e13788d8b11c3d19f89c7e2e'
GENERATED = {
    'rehearsal-results.json': 'Execute inherited gate-script host rehearsals again; not live authority',
    'session-results.json': 'Execute all inherited session and relay cases again',
    'mutation-results.json': 'Execute inherited and new mutants with typed exception accounting',
    'r16-results.json': 'Execute certification, denial evidence/accounting and task46 refusal cases',
    'offline-results.json': 'Record all r16 offline suites, builds and no-TV boundary',
    'build/SamsungTvRootAgent.dll': 'Build inherited agent with SDK 3.1.426 for regression verification only',
    'build/SamsungTvRootAgent.runtimeconfig.json': 'Regenerate inherited agent runtimeconfig',
    'build/DenialRunner.dll': 'Build direct managed exec refusal accountant with SDK 3.1.426',
    'build/DenialRunner.runtimeconfig.json': 'Generate netcoreapp3.1 runtimeconfig for denial accountant',
}
REASONS = {
    'PLAN.md': 'Replace obsolete gate/reboot plan with enforcing-only A-G certification and separate optional tidy',
    'packet.py': 'Restrict markers to certify/tidy; pin current and stale boots/proof and new seal entries',
    'active.py': 'Refuse CLI; retain regression code and precheck duplicate attempt before prerequisites',
    'disable.py': 'Refuse CLI; retain regression code, duplicate precheck and honest runtime-anchor documentation',
    'inspect_tv.py': 'Refuse historical inspection CLI; shared transport/save retained',
    'prepare.py': 'Refuse historical preparation CLI; pure bake helpers retained for all regressions',
    'stage_lib.py': 'Share attempt-existence guard, including symlink, before any prerequisite can touch TV',
    'stage_common.py': 'Strip captured proof base64 newlines with literal octal 012 and pipefail',
    'denial.py': 'Replace shell/126 assertion and misleading exit accounting with direct errno and exact fresh kernel evidence',
    'recovery.py': 'Check regular type separately so empty regular children fail on meaningful content/pid checks',
    'relay_checks.py': 'Use resolved rehearsal TEMP and cover retained shared attempt/stat interfaces',
    'mutation_checks.py': 'Record actual terminal exception type/message; add r16 safety mutants; update cosmetic guard anchors',
    'offline_checks.py': 'Run full inherited/new suites, helper self-tests and pinned builds before exact r16 seal',
    'authoring_checks.py': 'Retain all inherited authoring checks and report exact passed/failed/skipped group counts',
    'certify.py': 'Implement single-pass read-only anchored certification and single denial; no gate/reboot path',
    'tidy.py': 'Separate optional final exact-path task46 unlink/rmdir/fresh-session absence step',
    'r16_checks.py': 'Execute new certification/denial/exception/duplicate/tidy acceptance and refusal cases offline',
    'DenialRunner.cs': 'Account for refused-before-exec with errno and null native_exit; own bounded child if started',
    'DenialRunner.csproj': 'Build packet-only netcoreapp3.1 managed helper; no new dependency',
    'DenialSelfTest.cs': 'Exercise real accountant refusal and real started-child code paths on host',
    'DenialSelfTest.csproj': 'Compile host self-test with exact production accountant source',
    'port_from_r14.py': 'Supersede predecessor port tool; original remains immutable in r15',
    'port-from-r14.json': 'Supersede predecessor ledger with r15 -> r16 exhaustive ledger',
    'port_from_r15.py': 'Verify pinned predecessor seal, evidence immutability and every r16 delta',
    'evidence/r15-evidence-digests.json': 'Preserve pinned predecessor sealed entries, STOP, receipts and runtime statuses',
    'evidence/measurement.json': 'Carry authoritative errno measurement byte-identically, including its raw trailing-pipe caveat',
    'evidence/dmesg_grep.txt': 'Carry authoritative kernel signature-denial measurement byte-identically',
    'evidence/R15-INCIDENT.md': 'Record receipt citations, measurement caveat and unresolved EACCES-vs-EPERM observation',
    'evidence/R15-PLAN.md': 'Retain original r15 plan under an explicitly historical non-authoritative heading',
    'evidence/anchored-proof.txt': 'Extract byte-exact proof matching sealed CERTIFY_PROOF from historical r15 receipt6452 for real-hash host tests',
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record():
    assert digest(PRIOR / 'seal.json') == PRIOR_SEAL_SHA, 'r15 seal changed'
    old = json.loads((PRIOR / 'seal.json').read_text())
    for name, sha in old.items():
        rel = Path(name)
        assert not rel.is_absolute() and '..' not in rel.parts, 'unsafe predecessor manifest path'
        assert digest(PRIOR / name) == sha, 'r15 sealed file changed: ' + name
    snapshot = json.loads((HERE / 'evidence/r15-evidence-digests.json').read_text())
    for name, sha in snapshot.items():
        assert digest(PRIOR / name) == sha, 'r15 evidence changed: ' + name
    names = set(old)
    names.update(x.relative_to(HERE).as_posix() for x in HERE.rglob('*') if x.is_file()
                 and not any(part in ('execution', '__pycache__') for part in x.relative_to(HERE).parts))
    rows = {}
    for name in sorted(names):
        if name in GENERATED or name in ('seal.json', 'port-from-r15.json'):
            continue
        if name.startswith('build/'):
            assert name in ('build/SamsungTvRootAgent.deps.json', 'build/SamsungTvRootAgent.runtimeconfig.dev.json',
                            'build/DenialRunner.deps.json', 'build/DenialRunner.runtimeconfig.dev.json'), 'unexpected build auxiliary: ' + name
            continue
        new = digest(HERE / name) if (HERE / name).is_file() else None
        prior = old.get(name)
        state = 'removed' if new is None else 'added' if prior is None else 'carried' if prior == new else 'delta'
        row = dict(status=state, r15=prior, r16=new)
        if state != 'carried':
            assert name in REASONS, 'undocumented delta: ' + name
            row['reason'] = REASONS[name]
        rows[name] = row
    return dict(predecessor=PRIOR.name, predecessor_seal_sha256=PRIOR_SEAL_SHA, entries=rows,
                regenerated=GENERATED, counts={state: sum(x['status'] == state for x in rows.values())
                for state in ('carried', 'delta', 'added', 'removed')})


def ledger():
    result = record()
    (HERE / 'port-from-r15.json').write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', newline='\n')
    print(json.dumps(result['counts']))


def verify():
    assert json.loads((HERE / 'port-from-r15.json').read_text()) == record(), 'r16 exhaustive port ledger drift'


if __name__ == '__main__':
    assert sys.argv[1:] in (['ledger'], ['verify']), 'usage: port_from_r15.py ledger|verify'
    {'ledger': ledger, 'verify': verify}[sys.argv[1]]()
