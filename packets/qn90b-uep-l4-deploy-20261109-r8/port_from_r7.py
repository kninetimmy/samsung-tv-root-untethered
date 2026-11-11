"""Host-only verbatim port of r7's SEALED removal packet into r8, digest-verified.

r7 was sealed (45 entries) and owner-armed, then failed HOST-SIDE before any
root session or TV write: remove.py's read-only preflight passed (boot
4b2c70c7-2d64-46df-b84e-02541ed33659, 25 protected files, gate config present
read-only), then samsung_tv_root.archive_root._prepare_artifacts raised
'OpenSSL was not found; install it on the host and put openssl on PATH' in
the harness shell. The stage attempt had already been taken, so the failure
handler wrote STOP: r7 is permanently consumed with the r6 read-only gate
config still on the TV (fail-closed). r8 carries the SAME removal stage and
the SAME double-reviewed code; the only behavioural delta is a host-tool
preflight that runs BEFORE the one attempt is taken, so a missing openssl
can never burn a packet again. r7's STOP, seal and port lineage remain
untouched in its own directory.

Carried via r7's seal.json (digest-verified against r7 before any copy):
the deployment/base/transport/relay machinery (deploy.py, stage_lib.py,
trial.py, recovery.py, sdk.py, bootstrap_sdk.py, stage_transport.py,
stage.sh, snapshot.sh), inspect_tv.py, prepare.py, driver/shape suites
(driver_checks.py, driver_shim.py, authoring_checks.py), the agent sources,
the exact five artifact bytes, and r1/r6 provenance receipts.

Carried with a documented delta applied AFTER this port (see PORT_DELTAS):
packet.py, remove.py, offline_checks.py, flow_cases.py.

Rewritten here (NOT carried): PLAN.md, the r8 inspection.json and
protected-register.json, gate-remove.sh (re-baked for the r8 boot), the
build/ output and the seal-flow results.

Recorded without seal pinning (live receipts, taken as copied): r7's STOP,
seal.json and port-from-r6.json lineage.

One-shot: the script refuses (nonzero exit, nothing written) when any
destination file it would produce already exists, so a re-run can never
overwrite the authored r8 packet with r7's originals.
"""
import hashlib
import json
import sys
from pathlib import Path
import shutil

SRC = Path('C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261109-r7')
DST = Path('C:/Users/Kninetimmy/samtv/.memhub/prep/qn90b-uep-l4-deploy-20261109-r8')


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


# Everything named here must exist in r7's seal.json and match its digest.
CARRY_FROM_SEAL = [
    'deploy.py',
    'stage_lib.py',
    'trial.py',
    'recovery.py',
    'sdk.py',
    'bootstrap_sdk.py',
    'stage_transport.py',
    'inspect_tv.py',
    'prepare.py',
    'driver_checks.py',
    'driver_shim.py',
    'authoring_checks.py',
    'inspection-r1-predeploy.json',
    'protected-register-20261108.json',
    'deployment-result.json',
    'post-deploy-verification.json',
    'post-mortem-20261108.md',
    'r6-stage-status-watch.json',
    'r6-stage-status-dirread.json',
    'r6-seal.json',
    'r6-port-from-r5.json',
    'r6-STOP.txt',
    'stage.sh',
    'snapshot.sh',
    'BridgeRepairAgent.cs',
    'BridgeRepairAgent.csproj',
    'artifacts/manager.dll',
    'artifacts/manager.runtimeconfig.json',
    'artifacts/FdetProbe.dll',
    'artifacts/FdetProbe.runtimeconfig.json',
    'artifacts/uep-probe.elf',
    # Delta-carry: copied byte-exact from r7, then edited; see PORT_DELTAS.
    'packet.py',
    'remove.py',
    'offline_checks.py',
    'flow_cases.py',
]

# Renamed provenance copies of r7's live state; digests verified directly
# against the r7 directory (they are live receipts, not seal entries).
RENAMED = {
    'STOP': 'r7-STOP.txt',
    'seal.json': 'r7-seal.json',
    'port-from-r6.json': 'r7-port-from-r6.json',
}

# One-shot provenance guard: the destination already holds the authored r8
# packet. Re-running this port must never silently overwrite carried bytes.
for _name in list(CARRY_FROM_SEAL) + list(RENAMED.values()) + ['port-from-r7.json']:
    if (DST / _name).exists():
        sys.exit('refusing to overwrite existing ' + _name
                 + '; the r7 port is a one-shot provenance step')

# Bytes that intentionally diverge from the carried digest AFTER this port.
# Recorded so a naive "every carried digest still matches" audit does not
# report the documented r8 deltas as drift.
PORT_DELTAS = {
    'packet.py': "r8 delta applied after this port: OPENSSL_CANDIDATES + "
                 "require_openssl() (resolve a working openssl via PATH or the "
                 "known Git locations, verify it runs, prepend its directory to "
                 "PATH so archive_root's bare 'openssl' calls resolve); header "
                 "notes the r7 host-env STOP. The carried digest above is r7's "
                 "byte-exact file.",
    'remove.py': "r8 delta applied after this port: prerequisites() calls "
                 "p.require_openssl() BEFORE OneAttempt.take(), so a missing "
                 "host tool refuses without consuming the packet's one attempt "
                 "and without any TV contact (the exact r7 failure).",
    'offline_checks.py': "r8 delta applied after this port: seal list re-pins "
                         "r8 lineage (port_from_r7.py, port-from-r7.json, "
                         "r7-STOP.txt, r7-seal.json, r7-port-from-r6.json), the "
                         "host-tool step seals openssl provenance, and messages "
                         "name this packet.",
    'flow_cases.py': "r8 delta applied after this port: adds the load-bearing "
                     "case proving a missing openssl refuses BEFORE the attempt "
                     "file is taken and writes no STOP.",
}

if not DST.exists():
    DST.mkdir(parents=True)

seal = json.loads((SRC / 'seal.json').read_text(encoding='utf-8'))
report = {}
for name in CARRY_FROM_SEAL:
    if name not in seal:
        sys.exit('r7 seal does not pin a carried name: ' + name)
    source = SRC / name
    if not source.is_file():
        sys.exit('missing source: ' + name)
    observed = sha256(source)
    if observed != seal[name]:
        sys.exit('r7 seal drift for ' + name + ': ' + observed)
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
    report[target_name] = observed + ' (from r7/' + source_name + ')'
document = {'carried': report, 'post_port_deltas': PORT_DELTAS}
(DST / 'port-from-r7.json').write_text(json.dumps(document, indent=1))
print(json.dumps({'carried': len(report)}, indent=1))
