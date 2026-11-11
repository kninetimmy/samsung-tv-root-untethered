"""Host-only verbatim-port of r1's qualified artifacts into r3, hash-checked."""
import hashlib
import json
import shutil
import sys
from pathlib import Path

SRC = Path('C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261108-r1')
DST = Path('C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261109-r3')

# Pinned artifact bytes (identical values recorded across r1 offline-status.json,
# its seal, and post-deploy-verification.json for the pair now installed on TV).
MANIFEST = {
    'artifacts/manager.dll': 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a',
    'artifacts/manager.runtimeconfig.json': '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b',
    'artifacts/FdetProbe.dll': '2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb',
    'artifacts/FdetProbe.runtimeconfig.json': '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b',
    'artifacts/uep-probe.elf': 'd1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d',
    # Stage-1 receipts + inspections referenced by r2 drivers as prerequisites
    # (deploy closeout receipt, post-deploy verification, register snapshot).
    'deployment-result.json': None,
    'post-deploy-verification.json': None,
    'protected-register-20261108.json': None,
    'inspection-r1-predeploy.json': None,   # r1's PRE-deploy inspection, provenance only
    'post-mortem-20261108.md': None,        # provenance of the reconstructed deploy result
}

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

report = {}
for name, pinned in MANIFEST.items():
    source = SRC / name
    if not source.is_file() and name == 'inspection-r1-predeploy.json':
        source = SRC / 'inspection.json'
    if not source.is_file():
        sys.exit('missing source: ' + name)
    if pinned is not None:
        observed = sha256(source)
        if observed != pinned:
            sys.exit('hash drift for ' + name + ': ' + observed)
    report[name] = sha256(source)

for name in MANIFEST:
    target = DST / name
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        shutil.copy2(SRC / name, target)
print(json.dumps({'ported': sorted(report)}, indent=1))
