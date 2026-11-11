"""Host-only verbatim port of r6's SEALED continuation packet into r7, digest-verified.

r6 carried stages 2-5 and was consumed by the first-ever live non-absent gate
run (the DIRREAD stage wrote the read-only config, then the owner's intentional
reopen ran v5.18's in-app dotnet payload check, which failed closed at
2026-11-09T03:47:22.9591640Z: dotnet missing in the manager app context).
r7 carries only the config-removal stage (LIVE_ARM_REMOVE) on top of that
installed/verified state. r6's SPENT/STOP receipts, seal and probe-less
post-mortem provenance remain untouched in its own directory.

Carried via r6's seal.json (digest-verified against r6 before any copy):
the deployment/base/transport/relay machinery (deploy.py, stage_lib.py,
trial.py, recovery.py, sdk.py, bootstrap_sdk.py, stage_transport.py,
stage.sh, snapshot.sh), the exact five artifact bytes, and r1's provenance
receipts (deployment-result.json, post-deploy-verification.json,
protected-register-20261108.json, inspection-r1-predeploy.json,
post-mortem-20261108.md).

Rewritten here (NOT carried): PLAN.md, packet.py, inspect_tv.py, prepare.py,
remove.py (the single stage driver), offline_checks.py, driver_checks.py,
driver_shim.py, flow_cases.py, BridgeRepairAgent.cs/.csproj, and the three
gate scripts — r7 bakes only gate-remove.sh.

Recorded without seal pinning (live receipts, taken as copied): r6's stage
status pair and its seal/port lineage receipts.

One-shot: the script refuses (nonzero exit, nothing written) when any
destination file it would produce already exists, so a re-run can never
overwrite the authored r7 packet with r6's originals.
"""
import hashlib
import json
import sys
from pathlib import Path
import shutil

SRC = Path('C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261109-r6')
DST = Path('C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261109-r7')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Everything named here must exist in r6's seal.json and match its digest.
CARRY_FROM_SEAL = [
    'deploy.py',
    'stage_lib.py',
    'trial.py',
    'recovery.py',
    'sdk.py',
    'bootstrap_sdk.py',
    'stage_transport.py',
    'stage.sh',
    'snapshot.sh',
    'inspection-r1-predeploy.json',
    'protected-register-20261108.json',
    'deployment-result.json',
    'post-deploy-verification.json',
    'post-mortem-20261108.md',
    'artifacts/manager.dll',
    'artifacts/manager.runtimeconfig.json',
    'artifacts/FdetProbe.dll',
    'artifacts/FdetProbe.runtimeconfig.json',
    'artifacts/uep-probe.elf',
]

# Renamed provenance copies of r6's live state; digests verified directly
# against the r6 directory (they are live receipts, not seal entries).
RENAMED = {
    'stage-status-watch.json': 'r6-stage-status-watch.json',
    'stage-status-dirread.json': 'r6-stage-status-dirread.json',
    'seal.json': 'r6-seal.json',
    'port-from-r5.json': 'r6-port-from-r5.json',
    'STOP': 'r6-STOP.txt',
}

# One-shot provenance guard: the destination already holds the authored r7
# packet (including the documented r7 delta in stage_lib.py). Re-running this
# port must never silently overwrite carried bytes with r6's originals.
for _name in list(CARRY_FROM_SEAL) + list(RENAMED.values()) + ['port-from-r6.json']:
    if (DST / _name).exists():
        sys.exit('refusing to overwrite existing ' + _name
                 + '; the r6 port is a one-shot provenance step')

# Bytes that intentionally diverge from the carried digest AFTER this port.
# Recorded so a naive "every carried digest still matches" audit does not
# report the documented r7 delta as drift.
PORT_DELTAS = {
    'stage_lib.py': "r7 delta applied after this port: GATE_EVENT_SHAPES gains "
                    "the 'remove' key (see PLAN.md); the carried digest above is "
                    "r6's bytes",
}

if not DST.exists():
    DST.mkdir(parents=True)

seal = json.loads((SRC / 'seal.json').read_text(encoding='utf-8'))
report = {}
for name in CARRY_FROM_SEAL:
    if name not in seal:
        sys.exit('r6 seal does not pin a carried name: ' + name)
    source = SRC / name
    if not source.is_file():
        sys.exit('missing source: ' + name)
    observed = sha256(source)
    if observed != seal[name]:
        sys.exit('r6 seal drift for ' + name + ': ' + observed)
    target = DST / name
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)
    report[name] = observed
for source_name, target_name in RENAMED.items():
    source = SRC / source_name
    if not source.is_file():
        sys.exit('missing renamed source: ' + source_name)
    observed = sha256(source)
    shutil.copy2(source, DST / target_name)
    report[target_name] = observed + ' (from r6/' + source_name + ')'
document = {'carried': report, 'post_port_deltas': PORT_DELTAS}
(DST / 'port-from-r6.json').write_text(json.dumps(document, indent=1))
print(json.dumps({'carried': len(report)}, indent=1))
