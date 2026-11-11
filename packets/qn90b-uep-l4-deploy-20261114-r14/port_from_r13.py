"""Port the sealed r13 packet into r14 and maintain its carry/delta ledger.

  python -B port_from_r13.py carry
      Copy every file listed in r13's seal.json into r14, verifying each copy
      against the sealed digest. Files in REGENERATED are authored fresh.

  python -B port_from_r13.py ledger
      Compare the current r14 tree against r13's seal.json and write
      port-from-r13.json. Every difference needs a reason in REASONS.
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
R13 = HERE.parent / 'qn90b-uep-l4-deploy-20261113-r13'

REGENERATED = {
    'rehearsal-results.json', 'session-results.json', 'mutation-results.json',
    'offline-results.json', 'seal.json', 'receipts.jsonl', 'STOP',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'build/SamsungTvRootAgent.deps.json', 'build/SamsungTvRootAgent.runtimeconfig.dev.json',
    'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh',
    'port_from_r12.py', 'port-from-r12.json',
}

REASONS = {
    'port_from_r13.py': 'r14 provenance tool: digest-verified carry from the sealed r13 plus the delta ledger the seal re-checks',
    'packet.py': 'r14 docstring and SEAL_ENTRIES: the r13 provenance files are replaced by the r14 ones',
    'stage_lib.py': 'r14 major: capture() can preserve the raw log bytes so module_gate can tell a complete exit line from a partial one',
    'stage_common.py': 'r14 major/minor: a partial exit suffix stays pending until its newline arrives; the terminal exception fast-path matches the host\'s actual "uep gate (boot) EXCEPTION" format',
    'session_checks.py': 'r14 coverage: partial-exit wait, real-format exception fast-path, and fake capture signatures for the raw-log read',
    'mutation_checks.py': 'r14 minor: the expected message must appear on the terminal exception line, not anywhere in the traceback; a new mutant proves the partial-exit wait',
    'offline_checks.py': 'guards for the r14 fixes (partial exit pending, exception format, terminal-line mutation matching) and the r13 port ledger',
    'PLAN.md': 'r14 plan: the fifth-review fixes and the partial-exit/exception/mutation corrections',
}

SKIP_DIRS = {'__pycache__', 'execution', '.pytest_cache'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def r13_seal():
    return json.loads((R13 / 'seal.json').read_text(encoding='utf-8'))


def carry():
    seal = r13_seal()
    copied = 0
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        source = R13 / name
        target = HERE / name
        if not source.is_file():
            raise SystemExit('r13 sealed file missing: ' + name)
        if target.exists() and digest(target) != seal[name]:
            raise SystemExit('r14 target already diverged; refusing to overwrite: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != seal[name]:
            raise SystemExit('carry digest mismatch: ' + name)
        copied += 1
    print(json.dumps({'mode': 'carry', 'copied': copied,
                      'regenerated': sorted(REGENERATED)}))


def ledger():
    seal = r13_seal()
    entries = {}
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        path = HERE / name
        if not path.is_file():
            entries[name] = {'status': 'removed', 'r13': seal[name],
                             'reason': REASONS.get(name, '')}
            continue
        got = digest(path)
        if got == seal[name]:
            entries[name] = {'status': 'carried', 'sha256': got}
        else:
            entries[name] = {'status': 'delta', 'r13': seal[name], 'r14': got,
                             'reason': REASONS.get(name, '')}
    known = set(seal) | REGENERATED
    for path in sorted(HERE.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(HERE).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(HERE).parts):
            continue
        if name in known or name == 'port-from-r13.json':
            continue
        entries[name] = {'status': 'added', 'sha256': digest(path),
                         'reason': REASONS.get(name, '')}
    undocumented = [n for n, e in entries.items()
                    if e['status'] in ('delta', 'removed', 'added') and not e.get('reason')]
    if undocumented:
        raise SystemExit('undocumented r14 differences: ' + ', '.join(undocumented))
    record = {
        'successor_of': R13.name,
        'r13_seal_sha256': digest(R13 / 'seal.json'),
        'carried': sum(1 for e in entries.values() if e['status'] == 'carried'),
        'delta': sum(1 for e in entries.values() if e['status'] == 'delta'),
        'removed': sum(1 for e in entries.values() if e['status'] == 'removed'),
        'added': sum(1 for e in entries.values() if e['status'] == 'added'),
        'entries': entries,
    }
    (HERE / 'port-from-r13.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n',
        encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'entries'}))


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('carry', 'ledger'):
        raise SystemExit('usage: port_from_r13.py carry|ledger')
    {'carry': carry, 'ledger': ledger}[sys.argv[1]]()
