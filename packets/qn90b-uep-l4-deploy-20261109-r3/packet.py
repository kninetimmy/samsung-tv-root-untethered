"""QN90B UEP L4 continuation packet (r2) constants; inspection-sourced values lazy.

Successor to the spent qn90b-uep-l4-deploy-20261108-r1. Stage 1 (v5.18 manager
update + FdetProbe install) completed live there and is never replayed; this
packet carries only stages 2-5 on top of the already-installed verified state.
"""
import importlib.util
import ipaddress
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
PREP = HERE.parent
spec = importlib.util.spec_from_file_location('manager_tools', PREP / 'qn90b-evidence-reboot-20261101-r1/controller/packet.py')
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
NEW_SHA = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'   # installed v5.18 manager (never re-applied; pinned as installed state)
OLD_SHA = 'eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1'   # v5.17, preserved at the r1 backup path
KEEP_BACKUP = TARGET + '.before-quiet517-manager-20261102-r1'
DEPLOY_BACKUP = TARGET + '.before-l4-20261108-r1'                             # r1's stage-1 v5.17 backup, still on TV
NEW = HERE / 'artifacts/manager.dll'
FDET_PROBE = HERE / 'artifacts/FdetProbe.dll'
FDET_PROBE_SHA = '2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb'
FDET_RUNTIMECONFIG = HERE / 'artifacts/FdetProbe.runtimeconfig.json'
FDET_RUNTIMECONFIG_SHA = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
FDET_HOME = '/opt/usr/share/selfroot/fdetprobe'
UEP_CONFIG = '/opt/usr/share/selfroot/uep-off.conf'
NATIVE = HERE / 'artifacts/uep-probe.elf'
NATIVE_SHA = 'd1b87cbaf563e6a454fb85903727e497109ec219693e1ec0183cea817e5c266d'
UEP_PAGE = '0x208c26c0'
FINGERPRINT = 'c07bd300 00000001 00000000 000004e2'
CLEARED = 'c07bd300 00000000 00000000 000004e2'
RELAY = '/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.dll'
RELAY_SHA = 'ef42c7590ecb5e67b794295939e2be9658520b1b3b1222095063f93a5049f541'
SOURCE_COMMIT = '847443cfa62a6d160a712216c3835706b350752e'   # master head; unchanged since r1's stage 1
COMMIT = SOURCE_COMMIT
# Artifact bytes came from r1's sealed packet and were re-verified by
# port_from_r1.py; the r2 seal re-pins them independently.
ARTIFACT_SHAS = {
    'artifacts/manager.dll': NEW_SHA,
    'artifacts/manager.runtimeconfig.json': FDET_RUNTIMECONFIG_SHA,
    'artifacts/FdetProbe.dll': FDET_PROBE_SHA,
    'artifacts/FdetProbe.runtimeconfig.json': FDET_RUNTIMECONFIG_SHA,
    'artifacts/uep-probe.elf': NATIVE_SHA,
}

# Stage markers for r2. LIVE_ARM_DEPLOY does not exist here: stage 1 ran and
# closed in r1; this packet never touches the manager or fdet payloads.
MARKERS = ('LIVE_ARM_WATCH', 'LIVE_ARM_DIRREAD', 'LIVE_ARM_ACTIVE', 'LIVE_ARM_DISABLE')

# Only this exact boot identity line in r1's reused receipts is recognised.
DEPLOY_RECEIPT_BOOT = '27959362-134c-4ba8-95f4-5c00dfb16eaf'
DEPLOY_RECEIPT_SHA = NEW_SHA

# The approved boot/proof pins are host-file driven: absent until the r2
# read-only inspection (its own light approval at TV-contact time) lands in
# this packet directory, because the TV may have rebooted since r1's stage 1
# and no stale pin may silently bind those receipts to a different boot.
def inspection():
    path = HERE / 'inspection.json'
    require(path.is_file(), 'the r2 read-only inspection must run first')
    return json.loads(path.read_text(encoding='utf-8'))

BOOT = None
PROOF_SHA = None
if (HERE / 'inspection.json').is_file():
    initial = inspection()
    BOOT = initial['boot']
    PROOF_SHA = initial['proof_hash'].split('  ')[0]
    require(re.fullmatch('[0-9a-f-]{36}', BOOT), 'inspection boot is not a boot id')
    require(re.fullmatch('[0-9a-f]{64}', PROOF_SHA), 'inspection proof digest malformed')
    # The fdet pair and the v5.18 manager were already installed by r1; the
    # fresh inspection must agree with that recorded installed state.
    require(initial.get('fdet_home') != 'absent', 'inspection disagrees with the installed fdet payload; STOP')
    require(initial.get('uep_config', 'absent') == 'absent', 'gate config must be absent before any r2 stage; STOP')

# The protected register is re-pinned by the r2 inspection into
# protected-register.json (same shape as r1's protected-register-20261108.json,
# which is also present as inherited provenance and must agree path by path).
INHERITED_REGISTER = json.loads((HERE / 'protected-register-20261108.json').read_text(encoding='utf-8'))
TEMP_L4 = TARGET + '.prepared-l4-20261108-r1'
ROLLBACK_L4 = TARGET + '.rollback-l4-20261108-r1'

EXPECTED = None
if (HERE / 'protected-register.json').is_file():
    REGISTER = json.loads((HERE / 'protected-register.json').read_text(encoding='utf-8'))
    EXPECTED = dict(REGISTER['files'])
    EXPECTED.pop(TARGET, None)
    EXPECTED[RELAY] = RELAY_SHA
    EXPECTED[FDET_HOME + '/FdetProbe.dll'] = FDET_PROBE_SHA
    EXPECTED[FDET_HOME + '/FdetProbe.runtimeconfig.json'] = FDET_RUNTIMECONFIG_SHA
    require(len(EXPECTED) == 25, 'expected protected set must be the 25-file post-install state')

INHERITED = dict(INHERITED_REGISTER['files'])
INHERITED.pop(TARGET, None)
INHERITED[RELAY] = RELAY_SHA
INHERITED[FDET_HOME + '/FdetProbe.dll'] = FDET_PROBE_SHA
INHERITED[FDET_HOME + '/FdetProbe.runtimeconfig.json'] = FDET_RUNTIMECONFIG_SHA
require(len(INHERITED) == 25, 'inherited expected set must be the 25-file post-install state')


def expected_set():
    require(EXPECTED is not None, 'the r2 protected register must exist; run the inspection at prep time')
    return EXPECTED


def inspection_targets():
    """Protected path set for the r2 inspection, constant plus inherited register paths."""
    targets = dict(INHERITED)
    return sorted(targets)


def marker(stage):
    """One-time stage approval: true only while its marker file matches."""
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
    """Consume the one-time marker after its stage receipts terminal state."""
    path = HERE / stage
    require(stage in MARKERS, 'unexpected marker file')
    path.unlink()
