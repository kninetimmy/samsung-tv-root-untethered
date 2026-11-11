"""Port the sealed r9 packet into r10 and maintain its carry/delta ledger.

Two modes:

  python -B port_from_r9.py carry
      Copy every file listed in r9's seal.json into r10, verifying each copy
      against the sealed digest. Files named in REGENERATED are not copied:
      they are authored fresh in r10 (inspection output, bake, build, seal).

  python -B port_from_r9.py ledger
      Compare the current r10 tree against r9's seal.json and write
      port-from-r9.json. Every difference (delta, removal, addition) must have
      a documented reason in REASONS; an undocumented difference is a STOP.

The ledger is the r10 provenance record that replaces r9's hand-maintained
port_from_r8.py + port-from-r8.json (which had drifted).
"""
import hashlib
import json
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
R9 = HERE.parent / 'qn90b-uep-l4-deploy-20261109-r9'

# Authored fresh in r10: device inspection output, live bake, seal-time build,
# and the seal artefacts themselves. r9's copies are evidence, not inputs.
REGENERATED = {
    'inspection.json', 'protected-register.json', 'rehearsal-results.json',
    'offline-results.json', 'seal.json', 'receipts.jsonl', 'STOP',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh',
    'port_from_r8.py', 'port-from-r8.json',
}

# Every file whose bytes differ from r9 must be explained here.
REASONS = {
    'packet.py': 'B3: manager runtimeconfig removed from the protected set (install replaces it) and pinned separately; B1: module/manager asset names added to the upload contract; M4: seal contract (SEAL_ENTRIES) moved here as one source of truth',
    'sdk.py': 'B1: UPLOAD_NAMES gains the five v5.19 install assets (manager.runtimeconfig.json, UepGateHost.dll, UepGateHost.runtimeconfig.json, boot.sh, module.json)',
    'stage.sh': 'B1: publish contract derived from files.sha256 instead of a hardcoded list that still demanded FdetProbe/manager.dll and rejected the module assets',
    'stage_transport.py': 'B2: gzip staging directory created unconditionally (and execution/ parent) instead of only when an oversized asset exists',
    'stage_common.py': 'B4: module_files emits one keyed line per path so fields() can parse it; B5: module directory mode/owner captured and verified; M1: bounded gate-readiness wait helper',
    'stage_lib.py': 'M4: protect_seal requires the exact sealed entry set and a matching seal digest, not just whatever manifest is presented',
    'install.py': 'M1/closeout: module readiness and protected-set order corrected for the post-install state',
    'active.py': 'M1: budget/gate receipt polled with a bounded wait after the fresh boot instead of a single-shot read',
    'disable.py': 'M5: the active-boot budget receipt is required in preflight, not optional',
    'prepare.py': 'M2: every .r9-tmp collision refusal is checked before the first write; B5: module directory ownership/mode/label set and verified; receipt pins updated',
    'offline_checks.py': 'seal-time guards: denial pin check corrected, receipt/shape contract tied to ground truth, new session-layer coverage, ledger required',
    'authoring_checks.py': 'M3: add session/staging coverage and ground-truth receipt pins instead of packet-to-packet comparisons',
    'flow_cases.py': 'M3: rehearsal also executes the sealed scripts and covers staging/closeout, not only the transition scripts',
    'driver_shim.py': 'M3 support: shim models directories, relative stat targets, plain %u and the %d:%i:%u:%a / %F:%u:%g:%a formats, and REHEARSAL_UID so the sealed stage.sh runs at uid 901',
    'session_checks.py': 'new host suite for the staging/session/closeout layer r9 never exercised (B1-B5 regression coverage)',
    'session-results.json': 'generated evidence for session_checks.py, written before the seal and sealed with it',
    'port_from_r9.py': 'r10 provenance tool: digest-verified carry from the sealed r9 plus a delta ledger the seal re-checks',
    'PLAN.md': 'r10 plan: rewritten for the corrected staging, baseline, readiness and recovery contract',
    'protected-register-20261108.json': 'carried reference register; byte-identical copy of the earlier baseline, kept for provenance only',
}

SKIP_DIRS = {'__pycache__', 'execution', '.pytest_cache'}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def r9_seal():
    return json.loads((R9 / 'seal.json').read_text(encoding='utf-8'))


def carry():
    seal = r9_seal()
    copied = 0
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        source = R9 / name
        target = HERE / name
        if not source.is_file():
            raise SystemExit('r9 sealed file missing: ' + name)
        if target.exists() and digest(target) != seal[name]:
            raise SystemExit('r10 target already diverged; refusing to overwrite: ' + name)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        if digest(target) != seal[name]:
            raise SystemExit('carry digest mismatch: ' + name)
        copied += 1
    print(json.dumps({'mode': 'carry', 'copied': copied,
                      'regenerated': sorted(REGENERATED)}))


def ledger():
    seal = r9_seal()
    entries = {}
    changed = []
    for name in sorted(seal):
        if name in REGENERATED:
            continue
        path = HERE / name
        if not path.is_file():
            changed.append(name)
            entries[name] = {'status': 'removed', 'r9': seal[name],
                             'reason': REASONS.get(name, '')}
            continue
        got = digest(path)
        if got == seal[name]:
            entries[name] = {'status': 'carried', 'sha256': got}
        else:
            changed.append(name)
            entries[name] = {'status': 'delta', 'r9': seal[name], 'r10': got,
                             'reason': REASONS.get(name, '')}
    known = set(seal) | REGENERATED
    added = []
    for path in sorted(HERE.rglob('*')):
        if not path.is_file():
            continue
        name = path.relative_to(HERE).as_posix()
        if any(part in SKIP_DIRS for part in path.relative_to(HERE).parts):
            continue
        if name in known or name == 'port-from-r9.json':
            continue
        added.append(name)
        entries[name] = {'status': 'added', 'sha256': digest(path),
                         'reason': REASONS.get(name, '')}
    undocumented = [n for n, e in entries.items()
                    if e['status'] in ('delta', 'removed', 'added') and not e['reason']]
    if undocumented:
        raise SystemExit('undocumented r10 differences: ' + ', '.join(undocumented))
    record = {
        'successor_of': R9.name,
        'r9_seal_sha256': digest(R9 / 'seal.json'),
        'r9_stopped': (R9 / 'STOP').is_file(),
        'carried': sum(1 for e in entries.values() if e['status'] == 'carried'),
        'delta': sum(1 for e in entries.values() if e['status'] == 'delta'),
        'removed': sum(1 for e in entries.values() if e['status'] == 'removed'),
        'added': sum(1 for e in entries.values() if e['status'] == 'added'),
        'entries': entries,
    }
    (HERE / 'port-from-r9.json').write_text(
        json.dumps(record, indent=2, sort_keys=True) + '\n',
        encoding='utf-8', newline='\n')
    print(json.dumps({k: v for k, v in record.items() if k != 'entries'}))


if __name__ == '__main__':
    if len(sys.argv) != 2 or sys.argv[1] not in ('carry', 'ledger'):
        raise SystemExit('usage: port_from_r9.py carry|ledger')
    {'carry': carry, 'ledger': ledger}[sys.argv[1]]()
