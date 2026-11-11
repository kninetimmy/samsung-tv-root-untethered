"""Port the sealed r11 packet into r12 and maintain its carry/delta ledger.

  python -B port_from_r11.py carry
      Copy every file listed in r11's seal.json into r12, verifying each copy
      against the sealed digest. Files in REGENERATED are authored fresh.

  python -B port_from_r11.py ledger
      Compare the current r12 tree against r11's seal.json and write
      port-from-r11.json. Every difference needs a reason in REASONS.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
R11 = HERE.parent / 'qn90b-uep-l4-deploy-20261111-r11'

REGENERATED = {
    'inspection.json', 'protected-register.json', 'rehearsal-results.json',
    'session-results.json', 'mutation-results.json', 'offline-results.json',
    'seal.json', 'receipts.jsonl', 'STOP',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'build/SamsungTvRootAgent.deps.json', 'build/SamsungTvRootAgent.runtimeconfig.dev.json',
    'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh',
    'port_from_r10.py', 'port-from-r10.json',
    'port_from_r11.py', 'port-from-r11.json',
}

REASONS = {
    'port_from_r11.py': 'r12 provenance tool: digest-verified carry from the sealed r11 plus the delta ledger the seal re-checks',
    'packet.py': 'r12 constants/docstring; SEAL_ENTRIES gains mutation_checks.py and mutation-results.json, and the predecessor port files are replaced',
    'prepare.py': 'r12 B1/M1: removal guard drops the writer-impossible 0644 equality, binds the budget receipt to the current boot id, and requires exactly one line; the budget-temp comments now state the residual instead of claiming coverage',
    'flow_cases.py': 'r12 removal cases: the real writer metadata (0666), the current boot id, stale and multiline receipts, and the budget temp path on install/activation',
    'session_checks.py': 'r12 coverage: real files for module capture and prepare_upload, the real EXPECTED set, clean-EOF accept, absent-file manifest row, module-gate exit cases, and a missing state_tmp key',
    'stage_common.py': 'r12 m1: module_gate requires exactly one uep gate module exit=0 line; state() requires every captured key, so a missing state_tmp is a STOP, not a KeyError',
    'driver_shim.py': 'r12 B1: model the owner:group:link stat format the removal guard uses, without pinning a mode the writer does not promise',
    'mutation_checks.py': 'r12 mutation harness: each listed session/shell defect is applied in place, the mapped check must fail, and every file is restored and digest-verified',
    'offline_checks.py': 'guards for the r12 fixes (boot-bound single-line receipt, real writer metadata, module exit presence, state_tmp key, mutation harness) and the r11 port ledger',
    'driver_checks.py': 'r12 host runner: the static sweep names the new mutation_checks.py and the r12 source set',
    'PLAN.md': 'r12 plan: the third-review fixes, the budget-writer residual, the corrected modules.log/display claims, and the mutation evidence',
}

SKIP_DIRS = {'__pycache__', 'execution', '.pytest_cache'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def r11_seal():
    return json.loads((R11 / 'seal.json').read_text(encoding='utf-8'))


def carry():
    seal = r11_seal()
    copied = 0
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        source = R11 / name
        target = HERE / name
        if not source.is_file():
            raise SystemExit('r11 sealed file missing: ' + name)
        if target.exists() and digest(target) != seal[name]:
            raise SystemExit('r12 target already diverged; refusing to overwrite: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != seal[name]:
            raise SystemExit('carry digest mismatch: ' + name)
        copied += 1
    print(json.dumps({'mode': 'carry', 'copied': copied,
                      'regenerated': sorted(REGENERATED)}))


def ledger():
    seal = r11_seal()
    entries = {}
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        path = HERE / name
        if not path.is_file():
            entries[name] = {'status': 'removed', 'r11': seal[name],
                             'reason': REASONS.get(name, '')}
            continue
        got = digest(path)
        if got == seal[name]:
            entries[name] = {'status': 'carried', 'sha256': got}
        else:
            entries[name] = {'status': 'delta', 'r11': seal[name], 'r12': got,
                             'reason': REASONS.get(name, '')}
    known = set(seal) | REGENERATED
    for path in sorted(HERE.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(HERE).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(HERE).parts):
            continue
        if name in known or name == 'port-from-r11.json':
            continue
        entries[name] = {'status': 'added', 'sha256': digest(path),
                         'reason': REASONS.get(name, '')}
    undocumented = [n for n, e in entries.items()
                    if e['status'] in ('delta', 'removed', 'added') and not e.get('reason')]
    if undocumented:
        raise SystemExit('undocumented r12 differences: ' + ', '.join(undocumented))
    record = {
        'successor_of': R11.name,
        'r11_seal_sha256': digest(R11 / 'seal.json'),
        'carried': sum(1 for e in entries.values() if e['status'] == 'carried'),
        'delta': sum(1 for e in entries.values() if e['status'] == 'delta'),
        'removed': sum(1 for e in entries.values() if e['status'] == 'removed'),
        'added': sum(1 for e in entries.values() if e['status'] == 'added'),
        'entries': entries,
    }
    (HERE / 'port-from-r11.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n',
        encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'entries'}))


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('carry', 'ledger'):
        raise SystemExit('usage: port_from_r11.py carry|ledger')
    {'carry': carry, 'ledger': ledger}[sys.argv[1]]()
