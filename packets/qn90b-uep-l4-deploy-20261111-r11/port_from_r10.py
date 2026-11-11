"""Port the sealed r10 packet into r11 and maintain its carry/delta ledger.

  python -B port_from_r10.py carry
      Copy every file listed in r10's seal.json into r11, verifying each copy
      against the sealed digest. Files in REGENERATED are authored fresh.

  python -B port_from_r10.py ledger
      Compare the current r11 tree against r10's seal.json and write
      port-from-r10.json. Every difference needs a reason in REASONS.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
R10 = HERE.parent / 'qn90b-uep-l4-deploy-20261110-r10'

REGENERATED = {
    'inspection.json', 'protected-register.json', 'rehearsal-results.json',
    'session-results.json', 'offline-results.json', 'seal.json',
    'receipts.jsonl', 'STOP',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh',
    'port_from_r9.py', 'port-from-r9.json',
}

REASONS = {
    'port_from_r10.py': 'r11 provenance tool: digest-verified carry from the sealed r10 plus the delta ledger the seal re-checks',
    'packet.py': 'r11 constants (state temp path, module exit receipt) and the docstring/ledger references; SEAL_ENTRIES gains the new files',
    'prepare.py': 'B1: every baked script refuses a pre-existing or linked uep-state.conf.tmp before the host can write it; M3: gate-remove requires the present, well-shaped active-boot budget receipt',
    'stage_common.py': 'B1: state capture reports state_tmp and the stage refuses it; m1: module_gate requires module exit=0',
    'stage_lib.py': 'closeout: protected_hashes requires exactly one response line per requested path (an extra line was silently ignored by zip)',
    'stage.sh': 'M2: manifest loops process a final row that lacks a trailing newline, so publish and clean cannot disagree with the awk sweep',
    'flow_cases.py': 'M3: the removal happy path carries the active-boot budget receipt and a removal case proves an absent receipt is refused',
    'session_checks.py': 'M1: the suite now checks the real EXPECTED set at seal time, executes the generated module capture under the shim, keeps the manifest row for an absent file, and covers closeout',
    'offline_checks.py': 'guards for the r11 fixes (state temp refusal, manifest EOF idiom, removal receipt, module exit) and the strengthened session suite',
    'PLAN.md': 'r11 plan: budget-temp boundary, removal receipt, manifest EOF, module exit and the review-coverage corrections',
}

SKIP_DIRS = {'__pycache__', 'execution', '.pytest_cache'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def r10_seal():
    return json.loads((R10 / 'seal.json').read_text(encoding='utf-8'))


def carry():
    seal = r10_seal()
    copied = 0
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        source = R10 / name
        target = HERE / name
        if not source.is_file():
            raise SystemExit('r10 sealed file missing: ' + name)
        if target.exists() and digest(target) != seal[name]:
            raise SystemExit('r11 target already diverged; refusing to overwrite: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != seal[name]:
            raise SystemExit('carry digest mismatch: ' + name)
        copied += 1
    print(json.dumps({'mode': 'carry', 'copied': copied,
                      'regenerated': sorted(REGENERATED)}))


def ledger():
    seal = r10_seal()
    entries = {}
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        path = HERE / name
        if not path.is_file():
            entries[name] = {'status': 'removed', 'r10': seal[name],
                             'reason': REASONS.get(name, '')}
            continue
        got = digest(path)
        if got == seal[name]:
            entries[name] = {'status': 'carried', 'sha256': got}
        else:
            entries[name] = {'status': 'delta', 'r10': seal[name], 'r11': got,
                             'reason': REASONS.get(name, '')}
    known = set(seal) | REGENERATED
    for path in sorted(HERE.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(HERE).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(HERE).parts):
            continue
        if name in known or name == 'port-from-r10.json':
            continue
        entries[name] = {'status': 'added', 'sha256': digest(path),
                         'reason': REASONS.get(name, '')}
    undocumented = [n for n, e in entries.items()
                    if e['status'] in ('delta', 'removed', 'added') and not e['reason']]
    if undocumented:
        raise SystemExit('undocumented r11 differences: ' + ', '.join(undocumented))
    record = {
        'successor_of': R10.name,
        'r10_seal_sha256': digest(R10 / 'seal.json'),
        'carried': sum(1 for e in entries.values() if e['status'] == 'carried'),
        'delta': sum(1 for e in entries.values() if e['status'] == 'delta'),
        'removed': sum(1 for e in entries.values() if e['status'] == 'removed'),
        'added': sum(1 for e in entries.values() if e['status'] == 'added'),
        'entries': entries,
    }
    (HERE / 'port-from-r10.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n',
        encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'entries'}))


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('carry', 'ledger'):
        raise SystemExit('usage: port_from_r10.py carry|ledger')
    {'carry': carry, 'ledger': ledger}[sys.argv[1]]()
