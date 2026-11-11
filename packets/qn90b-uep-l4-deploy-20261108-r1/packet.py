"""QN90B UEP L4 combined deploy packet (r1) constants; inspection-sourced values lazy."""
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
OLD_SHA = 'eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1'   # installed v5.17 manager
KEEP_BACKUP = TARGET + '.before-quiet517-manager-20261102-r1'                 # v5.16 diagnostic backup retained on TV
BACKUP = TARGET + '.before-l4-20261108-r1'                                    # this packet's v5.17 backup
TEMP = TARGET + '.prepared-l4-20261108-r1'
ROLLBACK_TEMP = TARGET + '.rollback-l4-20261108-r1'
NEW = HERE / 'artifacts/manager.dll'
NEW_SHA = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'
BEFORE = PREP / 'qn90b-manager-quiet-517-20261102-r1/manager31/com.samsung.tv.ghservice.dll'
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
# Protected register: today's live capture (see protected-register-20261108.json).
# The 2026-11-01 anchor baseline.json predates three legitimate root-stack
# changes: the deployed v5.17 manager (popped here, verified via OLD_SHA), the
# bridge relay (RELAY_SHA, pins exactly today's bytes), and the bridge boot
# script; their today-values are in the register. All 24 path hashes passed
# identical across the three L-series captures of 2026-11-08 (same boot).
REGISTER = json.loads((HERE / 'protected-register-20261108.json').read_text(encoding='utf-8'))
EXPECTED = dict(REGISTER['files'])
EXPECTED.pop(TARGET, None)   # the manager DLL itself is verified by its own hash-bearing stage script
EXPECTED[RELAY] = RELAY_SHA
# FdetProbe staging expectations join the protected set only after the
# fdet-install root op receipts its terminal state (deploy.py merges this).
FDET_EXPECT = {
    FDET_HOME + '/FdetProbe.dll': FDET_PROBE_SHA,
    FDET_HOME + '/FdetProbe.runtimeconfig.json': FDET_RUNTIMECONFIG_SHA,
}
MARKERS = ('LIVE_ARM_DEPLOY', 'LIVE_ARM_WATCH', 'LIVE_ARM_DIRREAD', 'LIVE_ARM_ACTIVE', 'LIVE_ARM_DISABLE')
SOURCE_COMMIT = '847443cfa62a6d160a712216c3835706b350752e'   # master merge of PR23
COMMIT = SOURCE_COMMIT

# Inspection-sourced constants stay absent until the read-only inspection has
# run (host-only imports succeed either way; deploy paths require them real).
def inspection():
    path = HERE / 'inspection.json'
    require(path.is_file(), 'read-only inspection must run first')
    return json.loads(path.read_text(encoding='utf-8'))

# Approved boot baseline: the same boot recorded live in both spent L-series
# sessions earlier 2026-11-08 (qn90b-uep-l1-20261108-r1/final-identity.json and
# qn90b-uep-l2-20261108-r1/identity.json; TV continuously up 3+ days). A
# mismatch at inspection means the TV rebooted since the packet's evidence was
# taken; STOP and re-evaluate. Stage 4/5 reboots are the only sanctioned ones.
BOOT = '27959362-134c-4ba8-95f4-5c00dfb16eaf'
# Approved proof digest for that same boot: matches the proof bytes captured
# live in qn90b-uep-l2-20261108-r1/identity.json and re-read live at inspection
# (sha256 agreement of two independent captures). The proof is rewritten per
# boot, so the stage 4/5 reboots produce fresh proofs validated through their
# own capture; this pin protects only this packet session.
PROOF_SHA = 'ad5bab649bc20d3ed31f901117d77347abdd5dc146c2e7f55caca1e4099eac9b'
if (HERE / 'inspection.json').is_file():
    initial = inspection()
    require(BOOT == initial['boot'], 'inspection boot left the approved baseline')
    require(PROOF_SHA == initial['proof_hash'].split('  ')[0], 'inspection proof left the approved baseline')


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
