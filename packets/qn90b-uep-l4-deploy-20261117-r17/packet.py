"""r17 enforcing-only certification, derived from permanently STOPPED r16.

Only certify/tidy markers are accepted. No gate operation or reboot is part of
r17. Historical inspection/bake/drivers and v5.19 artifacts remain for offline
regressions, never as current-state authority. Live certification uses the
separate immutable CERTIFY_BOOT/PROOF and exact STALE_BOOT receipt pins below.
"""
import hashlib
import importlib.util
import ipaddress
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PREP = HERE.parent

# The inherited controller is the executable authority for every stage, so its
# bytes are verified BEFORE the module is imported. r9 imported it from an
# unsealed sibling packet and only checked it indirectly at stage time (r10 M4).
TOOLS_DIR = PREP / 'qn90b-evidence-reboot-20261101-r1/controller'
TOOLS_SHA = '757282b0430cdc7df414bdfe0b037d0fee347a141777010df5f14d8e5c4bb5db'
BASELINE_SHA = '149f5ba674a934260777eeabd62eec451044ef802357ec92ffc7c2183fcae31a'
for _path, _want in ((TOOLS_DIR / 'packet.py', TOOLS_SHA),
                     (TOOLS_DIR / 'baseline.json', BASELINE_SHA)):
    if hashlib.sha256(_path.read_bytes()).hexdigest() != _want:
        raise RuntimeError('inherited controller drifted from its pin: ' + str(_path))
spec = importlib.util.spec_from_file_location('manager_tools', TOOLS_DIR / 'packet.py')
tools = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tools)
require, Stop = tools.require, tools.Stop
digest, private_acl, make_private_directory = tools.digest, tools.private_acl, tools.make_private_directory
BASE = tools.BASE
SDB, SSL, LAUNCHER = tools.SDB, tools.SSL, tools.LAUNCHER
env = {}
for line in (REPO / '.memhub/local/tv.env').read_text(encoding='utf-8-sig').splitlines():
    if line.strip() and not line.lstrip().startswith('#'):
        key, value = line.split('=', 1)
        require(key not in env, 'duplicate local pairing field')
        env[key] = value.strip().strip('"').strip("'")
TV, PC = str(ipaddress.IPv4Address(env['TVROOT_HOST'])), BASE['callback']
require(TV == BASE['target'] and env['TVROOT_BRIDGE_PORT'] == '26103', 'unexpected TV/port')
require(re.fullmatch('[a-f0-9]{32}', env['TVROOT_BRIDGE_TOKEN']), 'invalid saved credential')


def token():
    return env['TVROOT_BRIDGE_TOKEN']


ROOT = '/home/owner/share/tmp/sdk_tools'
CANON = '/opt/usr/home/owner/share/tmp/sdk_tools'
PKG = 'archive-root-a553e5ee83632f83'
STAGE = ROOT + '/' + PKG
DEMAND = ROOT + '/on-demand'
EV = ROOT + '/selfroot-evidence'
PROOF = '/tmp/selfroot-proof.txt'
MATERIALS = {'private.pem', 'public.pem', 'passwd', 'root-agent.token', PKG + '.tar.gz', PKG + '.tar.gz.signature', 'SamsungTvArchiveRoot.runtimeconfig.json', 'SamsungTvRootAgent.runtimeconfig.json', 'launcher.log', 'files.sha256'}

APP = '/opt/usr/apps/com.samsung.tv.ghservice'
TARGET = APP + '/bin/com.samsung.tv.ghservice.dll'
TARGET_RC = APP + '/bin/com.samsung.tv.ghservice.runtimeconfig.json'
# Installed package metadata/labels the fresh inspection must match exactly and
# the install must preserve on the temp file BEFORE the atomic rename. Owner
# 201 is the package's installed owner; root replaced it with root:root or the
# floor label and the app would no longer load its own assembly.
TARGET_OWNER = '201:0'
TARGET_MODE = '755'
TARGET_LABEL_VALUE = 'User::Pkg::com.samsung.tv.ghservice::RO'
TARGET_LABEL = TARGET + ' access="' + TARGET_LABEL_VALUE + '"'
TARGET_RC_OWNER = '201:0'
TARGET_RC_MODE = '755'
TARGET_RC_LABEL_VALUE = TARGET_LABEL_VALUE
TARGET_RC_LABEL = TARGET_RC + ' access="' + TARGET_RC_LABEL_VALUE + '"'
# Installed baseline (r8 SPENT): v5.18. The fresh inspection must agree with it;
# the v5.19 install is the only writer in this packet.
PREV_MANAGER_SHA = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'
PREV_MANAGER_RC_SHA = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
NEW_MANAGER_SHA = '449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c'
NEW_MANAGER_RC_SHA = 'ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38'
HOST_SHA = '3b1e3a80dcb4b6aab8ad4c97bea6bf24ae536fe3a90b633e9e6a3755cf217d1f'
HOST_RC_SHA = NEW_MANAGER_RC_SHA
MODULE_BOOT_SHA = '1afd5b7c8c4158714726e627f70ef72adcb394e0e3db3eb563609fd41d2456b0'
MODULE_JSON_SHA = '63b13c8439e4bcf94cd186406641a2a81368896cf43c8355b67352e6294177f5'

NEW = HERE / 'artifacts/manager.dll'
NEW_RC = HERE / 'artifacts/manager.runtimeconfig.json'
HOST = HERE / 'artifacts/UepGateHost.dll'
HOST_RC = HERE / 'artifacts/UepGateHost.runtimeconfig.json'
MODULE_BOOT = HERE / 'module/boot.sh'
MODULE_JSON = HERE / 'module/module.json'
MODULE_DIR = '/opt/usr/share/selfroot/modules/uep-gate'
MODULE_HOST = MODULE_DIR + '/UepGateHost.dll'
MODULE_HOST_RC = MODULE_DIR + '/UepGateHost.runtimeconfig.json'
MODULE_BOOT_PATH = MODULE_DIR + '/boot.sh'
MODULE_JSON_PATH = MODULE_DIR + '/module.json'
BACKUP_DIR = EV + '/r9-manager-backup'

FDET_PROBE = HERE / 'artifacts/FdetProbe.dll'
FDET_PROBE_SHA = '2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb'
FDET_RUNTIMECONFIG = HERE / 'artifacts/FdetProbe.runtimeconfig.json'
FDET_RUNTIMECONFIG_SHA = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
FDET_HOME = '/opt/usr/share/selfroot/fdetprobe'
UEP_CONFIG = '/opt/usr/share/selfroot/uep-off.conf'
UEP_STATE = '/opt/usr/share/selfroot/uep-state.conf'
NATIVE = HERE / 'artifacts/uep-probe.elf'
NATIVE_SHA = 'd1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d'
UEP_PAGE = '0x208c26c0'
FINGERPRINT = 'c07bd300 00000001 00000000 000004e2'
CLEARED = 'c07bd300 00000000 00000000 000004e2'
RELAY = '/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.dll'
RELAY_SHA = 'ef42c7590ecb5e67b794295939e2be9658520b1b3b1222095063f93a5049f541'
SOURCE_COMMIT = '8f92e54346a6d89ecda4ce540c341d855b8646a6'
COMMIT = SOURCE_COMMIT
INHERITED_INSTALL_SHA = 'be77d4940030944e8939ca223f66d253864c980de919e0ad6d5a2b8d35794042'
ARTIFACT_SHAS = {
    'artifacts/manager.dll': NEW_MANAGER_SHA,
    'artifacts/manager.runtimeconfig.json': NEW_MANAGER_RC_SHA,
    'artifacts/UepGateHost.dll': HOST_SHA,
    'artifacts/UepGateHost.runtimeconfig.json': HOST_RC_SHA,
    'artifacts/FdetProbe.dll': FDET_PROBE_SHA,
    'artifacts/FdetProbe.runtimeconfig.json': FDET_RUNTIMECONFIG_SHA,
    'artifacts/uep-probe.elf': NATIVE_SHA,
    'module/boot.sh': MODULE_BOOT_SHA,
    'module/module.json': MODULE_JSON_SHA,
}

# Gate config algebra. r6 proved the exact file shape live; r9 creates and
# replaces it only through the reviewed ops. Every decision below pins bytes,
# metadata and the labe, never just "a file exists".
UEP_READONLY_CONTENT = 'read-only'
UEP_ACTIVE_CONTENT = 'active'


def _content_hash(text):
    import hashlib
    return hashlib.sha256((text + '\n').encode('ascii')).hexdigest()


UEP_READONLY_SHA = _content_hash(UEP_READONLY_CONTENT)
UEP_ACTIVE_SHA = _content_hash(UEP_ACTIVE_CONTENT)
UEP_META = 'regular file:0:0:644:1'
UEP_LABEL_VALUE = '_'
UEP_LABEL = UEP_CONFIG + ' access="' + UEP_LABEL_VALUE + '"'

# r12 residual (owner-accepted at arming; task 40 tracks the code fix):
# UepGate.SaveBudget writes "$state.tmp" with File.WriteAllText, which follows
# symlinks and truncates an existing file before the rename. A script-level
# "temp path absent" check runs BEFORE the host and therefore cannot close the
# check-to-write window. The complete fix is an exclusive create in a v5.20
# build (new shipped bytes, new pins, PR + CI); r12 does not carry those bytes.
# Until that build lands, arming the active stage accepts this residual. The
# pre-write refusal stays because it still rejects a temp path planted before
# the stage starts; it is not represented as covering the host's own write.
BUDGET_WRITER_RESIDUAL = (
    'UepGate.SaveBudget still writes uep-state.conf.tmp with a following '
    'File.WriteAllText before the rename; the packet pre-write refusal cannot '
    'cover that check-to-write window. Exclusive-create hardening is task 40 '
    '(v5.20); r14 arms only with the owner-accepted residual.'
)

# v5.19 host receipts (exact lines the driver greps; see UepGateHost.cs).
# The host prints the SUMMARY receipt as `return "read-only: " + classification`
# (UepGate.cs) and the fingerprint only on the companion detail line
# (`uep gate: read-only <phase>: enforcing <fpr> (zero stores)`). The receipt
# therefore carries no fingerprint; LOG_READONLY carries it.
RECEIPT_ABSENT_BOOT = 'uep gate (boot) uid=0: config absent (enforcing; no action)'
RECEIPT_READONLY_BOOT = 'uep gate (boot) uid=0: read-only: enforcing'
RECEIPT_READONLY_MANUAL = 'uep gate (manual) uid=0: read-only: enforcing'
RECEIPT_CLEARED_BOOT = 'uep gate (boot) uid=0: cleared (boot)'
LOG_READONLY = 'uep gate: read-only {}: enforcing {} (zero stores)'
LOG_CLEARED = 'uep gate: cleared boot: ' + CLEARED + ' (one word, neighbourhood pinned)'

# Host tools the live stages cannot do without. A missing openssl must refuse
# BEFORE the one attempt is taken (the r7 burn); this guard is unchanged.
OPENSSL_CANDIDATES = (
    r'C:/Program Files/Git/usr/bin/openssl.exe',
    r'C:/Program Files/Git/mingw64/bin/openssl.exe',
)


def require_openssl():
    """Return the openssl this process will use, or refuse before any attempt."""
    found = shutil.which('openssl')
    if found is None:
        for candidate in OPENSSL_CANDIDATES:
            if Path(candidate).is_file():
                found = candidate
                os.environ['PATH'] = (str(Path(candidate).parent) + os.pathsep
                                      + os.environ.get('PATH', ''))
                break
    require(found is not None,
            'openssl is not on PATH and no known Git OpenSSL exists; the archive-root '
            'staging needs it (refusing before any attempt)')
    result = subprocess.run([found, 'version'], capture_output=True)
    require(result.returncode == 0, 'openssl is not runnable: ' + found)
    return found


MARKERS = ('LIVE_ARM_CERTIFY', 'LIVE_ARM_TIDY')
CERTIFY_BOOT = '299d6f3f-c014-43e5-a487-59c47c833f6f'
CERTIFY_PROOF = '90dd4328ec810b4646745d4940b39652dd4d519e9b247c59ea5f517372aefc29'
STALE_BOOT = 'edc9debc-8b83-4ecb-afab-27602cd084fd'
DENIAL_RUNNER = HERE / 'build/DenialRunner.dll'
DENIAL_RC = HERE / 'build/DenialRunner.runtimeconfig.json'

# r1's deploy receipt is the provenance that the v5.18 baseline was installed
# deliberately. Its boot is a historical receipt, never a stage anchor.
DEPLOY_RECEIPT_BOOT = '27959362-134c-4ba8-95f4-5c00dfb16eaf'
DEPLOY_RECEIPT_SHA = PREV_MANAGER_SHA


def inspection():
    path = HERE / 'inspection.json'
    require(path.is_file(), 'the r9 read-only inspection must run first')
    return json.loads(path.read_text(encoding='utf-8'))


BOOT = None
PROOF_SHA = None
if (HERE / 'inspection.json').is_file():
    initial = inspection()
    BOOT = initial['boot']
    PROOF_SHA = initial['proof_hash'].split('  ')[0]
    require(re.fullmatch('[0-9a-f-]{36}', BOOT), 'inspection boot is not a boot id')
    require(re.fullmatch('[0-9a-f]{64}', PROOF_SHA), 'inspection proof digest malformed')
    require(initial.get('hash', '').split('  ')[0] == PREV_MANAGER_SHA,
            'the inspected manager is not the pinned v5.18 baseline; STOP')
    require(initial.get('target_rc_hash', '').split('  ')[0] == PREV_MANAGER_RC_SHA,
            'the inspected manager runtimeconfig is not the v5.18 baseline; STOP')
    require(re.fullmatch(r'regular file:[0-9]+:[0-9]+:' + TARGET_OWNER + ':' + TARGET_MODE
                         + r':1:[0-9]+', initial.get('target_meta', '')) is not None,
            'installed manager metadata is not the package shape; STOP')
    require(re.fullmatch(r'regular file:[0-9]+:[0-9]+:' + TARGET_RC_OWNER + ':' + TARGET_RC_MODE
                         + r':1:[0-9]+', initial.get('target_rc_meta', '')) is not None,
            'installed manager runtimeconfig metadata is not the package shape; STOP')
    require(initial.get('label') == TARGET_LABEL, 'installed manager label changed; STOP')
    require(initial.get('target_rc_label') == TARGET_RC_LABEL,
            'installed manager runtimeconfig label changed; STOP')
    require(initial.get('fdet_home') == 'present', 'the installed fdet payload is missing; STOP')
    require(initial.get('gate_config', 'present') == 'absent',
            'the gate config must be absent before install (r8 baseline); STOP')
    require(initial.get('gate_state', 'present') == 'absent',
            'the budget state file must be absent before install; STOP')
    require(initial.get('module_dir', 'present') == 'absent',
            'the uep-gate module directory already exists; review before install; STOP')

INHERITED_REGISTER = json.loads((HERE / 'protected-register-20261108.json').read_text(encoding='utf-8'))

EXPECTED = None
if (HERE / 'protected-register.json').is_file():
    REGISTER = json.loads((HERE / 'protected-register.json').read_text(encoding='utf-8'))
    EXPECTED = dict(REGISTER['files'])
    EXPECTED.pop(TARGET, None)
    # The install replaces the manager runtimeconfig too (r9 B3: it stayed in
    # the protected set, so a SUCCESSFUL install failed its own closeout). The
    # file is pinned explicitly by stage_common.state() for the installed
    # baseline instead of being compared against the pre-install bytes.
    EXPECTED.pop(TARGET_RC, None)
    EXPECTED[RELAY] = RELAY_SHA
    EXPECTED[FDET_HOME + '/FdetProbe.dll'] = FDET_PROBE_SHA
    EXPECTED[FDET_HOME + '/FdetProbe.runtimeconfig.json'] = FDET_RUNTIMECONFIG_SHA
    require(len(EXPECTED) == 24, 'expected protected set must be the 24-file post-install baseline')

INHERITED = dict(INHERITED_REGISTER['files'])
INHERITED.pop(TARGET, None)
INHERITED[RELAY] = RELAY_SHA
INHERITED[FDET_HOME + '/FdetProbe.dll'] = FDET_PROBE_SHA
INHERITED[FDET_HOME + '/FdetProbe.runtimeconfig.json'] = FDET_RUNTIMECONFIG_SHA
require(len(INHERITED) == 25, 'inherited expected set must be the 25-file baseline')


def expected_set():
    require(EXPECTED is not None, 'the r10 protected register must exist; run the inspection at prep time')
    return EXPECTED


# Module directory metadata the install must establish (r9 B5: `mkdir` under
# `umask 077` left it root-owned 0700, which uid 901 cannot traverse).
MODULE_DIR_OWNER = '0:0'
MODULE_DIR_MODE = '755'
MODULE_DIR_META = 'directory:0:0:755'


# The sealed entry set, single source of truth (r10 M4): offline_checks seals
# exactly these, and stage_lib.protect_seal refuses any manifest that is not
# exactly this set.
SEAL_ENTRIES = [
    'PLAN.md', 'packet.py', 'deploy.py', 'stage_lib.py', 'stage_common.py',
    'stage_session.py', 'install.py', 'active.py', 'disable.py', 'denial.py',
    'trial.py', 'recovery.py', 'sdk.py', 'bootstrap_sdk.py', 'stage_transport.py',
    'inspect_tv.py', 'prepare.py', 'offline_checks.py', 'driver_checks.py',
    'driver_shim.py', 'flow_cases.py', 'session_checks.py', 'mutation_checks.py',
    'authoring_checks.py', 'port_from_r15.py', 'port-from-r15.json', 'relay_checks.py',
    'certify.py', 'tidy.py', 'r16_checks.py', 'r16-results.json',
    'DenialRunner.cs', 'DenialRunner.csproj', 'DenialSelfTest.cs', 'DenialSelfTest.csproj',
    'build/DenialRunner.dll', 'build/DenialRunner.runtimeconfig.json',
    'evidence/r15-evidence-digests.json', 'evidence/measurement.json', 'evidence/dmesg_grep.txt',
    'evidence/R15-INCIDENT.md', 'evidence/R15-PLAN.md',
    'evidence/anchored-proof.txt',
    'evidence/r16-evidence-digests.json',
    'stage-status-install.json', 'evidence/r14-evidence-digests.json', 'evidence/FORENSIC.md',
    'protected-register-20261108.json', 'inspection.json', 'protected-register.json',
    'stage.sh', 'snapshot.sh', 'gate-install.sh', 'gate-config-active.sh', 'gate-remove.sh',
    'UepGateAgent.cs', 'UepGateAgent.csproj',
    'artifacts/manager.dll', 'artifacts/manager.runtimeconfig.json',
    'artifacts/UepGateHost.dll', 'artifacts/UepGateHost.runtimeconfig.json',
    'artifacts/FdetProbe.dll', 'artifacts/FdetProbe.runtimeconfig.json',
    'artifacts/uep-probe.elf',
    'module/boot.sh', 'module/module.json',
    'build/SamsungTvRootAgent.dll', 'build/SamsungTvRootAgent.runtimeconfig.json',
    'rehearsal-results.json', 'session-results.json', 'mutation-results.json',
    'offline-results.json',
]


def inspection_targets():
    return sorted(dict(INHERITED))


def marker(stage):
    path = HERE / stage
    require(stage in MARKERS, 'unexpected marker file')
    if not path.is_file():
        return False
    lines = path.read_text(encoding='utf-8').splitlines()
    require(lines[0] == COMMIT if lines else False, 'marker must name this packet commit')
    return True


def read_marker(stage):
    path = HERE / stage
    require(stage in MARKERS, 'unexpected marker file')
    return path.read_text(encoding='utf-8')


def clear_marker(stage):
    path = HERE / stage
    require(stage in MARKERS, 'unexpected marker file')
    path.unlink()
