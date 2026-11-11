"""Port the sealed r12 packet into r13 and maintain its carry/delta ledger.

  python -B port_from_r12.py carry
      Copy every file listed in r12's seal.json into r13, verifying each copy
      against the sealed digest. Files in REGENERATED are authored fresh.

  python -B port_from_r12.py ledger
      Compare the current r13 tree against r12's seal.json and write
      port-from-r12.json. Every difference needs a reason in REASONS.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
R12 = HERE.parent / 'qn90b-uep-l4-deploy-20261112-r12'

REGENERATED = {
    'rehearsal-results.json', 'session-results.json', 'mutation-results.json',
    'offline-results.json', 'seal.json', 'receipts.jsonl', 'STOP',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'build/SamsungTvRootAgent.deps.json', 'build/SamsungTvRootAgent.runtimeconfig.dev.json',
    'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh',
    'port_from_r11.py', 'port-from-r11.json',
}

REASONS = {
    'port_from_r12.py': 'r13 provenance tool: digest-verified carry from the sealed r12 plus the delta ledger the seal re-checks',
    'packet.py': 'r13 docstring and SEAL_ENTRIES: the r12 provenance files are replaced by the r13 ones',
    'prepare.py': 'r13 minor: the removal receipt is compared by SHA-256 against the exact current-boot one-line bytes, so a NUL or an extra byte cannot pass; the wc/cat substitution is gone',
    'flow_cases.py': 'r13 minor: receipt cases include appended and embedded NUL bytes, which the old cat/wc check accepted',
    'stage_common.py': 'r13 major: a fresh partial module log is polled, not STOPped; a missing exit or missing required shape fails only when the bounded poll is exhausted, while a duplicate or nonzero exit still stops immediately',
    'session_checks.py': 'r13 majors: a startup-race case (empty first log, valid second log), proper missing-shape cases, and a synthetic order case that isolates the order guard',
    'mutation_checks.py': 'r13 majors: every mutant must fail with the intended assertion, not an unrelated crash; new mutants cover the immediate-STOP race, the required-shape guard and the NUL receipt',
    'offline_checks.py': 'guards for the r13 fixes (hash-exact receipt, pending module exit, proper shape cases, expected-message mutation kills) and the r12 port ledger',
    'PLAN.md': 'r13 plan: the fourth-review fixes, the corrected module-gate wait, and the byte-exact removal receipt',
}

SKIP_DIRS = {'__pycache__', 'execution', '.pytest_cache'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def r12_seal():
    return json.loads((R12 / 'seal.json').read_text(encoding='utf-8'))


def carry():
    seal = r12_seal()
    copied = 0
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        source = R12 / name
        target = HERE / name
        if not source.is_file():
            raise SystemExit('r12 sealed file missing: ' + name)
        if target.exists() and digest(target) != seal[name]:
            raise SystemExit('r13 target already diverged; refusing to overwrite: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != seal[name]:
            raise SystemExit('carry digest mismatch: ' + name)
        copied += 1
    print(json.dumps({'mode': 'carry', 'copied': copied,
                      'regenerated': sorted(REGENERATED)}))


def ledger():
    seal = r12_seal()
    entries = {}
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        path = HERE / name
        if not path.is_file():
            entries[name] = {'status': 'removed', 'r12': seal[name],
                             'reason': REASONS.get(name, '')}
            continue
        got = digest(path)
        if got == seal[name]:
            entries[name] = {'status': 'carried', 'sha256': got}
        else:
            entries[name] = {'status': 'delta', 'r12': seal[name], 'r13': got,
                             'reason': REASONS.get(name, '')}
    known = set(seal) | REGENERATED
    for path in sorted(HERE.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(HERE).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(HERE).parts):
            continue
        if name in known or name == 'port-from-r12.json':
            continue
        entries[name] = {'status': 'added', 'sha256': digest(path),
                         'reason': REASONS.get(name, '')}
    undocumented = [n for n, e in entries.items()
                    if e['status'] in ('delta', 'removed', 'added') and not e.get('reason')]
    if undocumented:
        raise SystemExit('undocumented r13 differences: ' + ', '.join(undocumented))
    record = {
        'successor_of': R12.name,
        'r12_seal_sha256': digest(R12 / 'seal.json'),
        'carried': sum(1 for e in entries.values() if e['status'] == 'carried'),
        'delta': sum(1 for e in entries.values() if e['status'] == 'delta'),
        'removed': sum(1 for e in entries.values() if e['status'] == 'removed'),
        'added': sum(1 for e in entries.values() if e['status'] == 'added'),
        'entries': entries,
    }
    (HERE / 'port-from-r12.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n',
        encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'entries'}))


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('carry', 'ledger'):
        raise SystemExit('usage: port_from_r12.py carry|ledger')
    {'carry': carry, 'ledger': ledger}[sys.argv[1]]()
