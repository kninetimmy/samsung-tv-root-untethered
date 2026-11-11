"""Shared stage machinery for the L4 stage 2-5 drivers.

Every driver: verifies its marker and prerequisite stage status, keeps ALL
remote commands inside SDK-staging + root-agent guarded writes, receipts
every SDK conversation into the packet's receipts.jsonl, consumes its marker
only after a terminal success receipt, and writes a STOP file on any failure
(no retries, spent = spent). Importing this module performs no TV operations.
"""
import asyncio
import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path, PurePosixPath
from shlex import quote
from datetime import datetime, timezone

sys.dont_write_bytecode = True
import packet as p
import deploy
import trial
from inspect_tv import BridgeSDK, save

SUID = '901'
TARGET_HASH = p.NEW_SHA
PROTECTED = dict(p.EXPECTED)
PROTECTED.update(p.FDET_EXPECT)          # fdet payload joined the set at deploy
UEP_STATE = p.UEP_CONFIG.rsplit('/', 1)[0] + '/uep-state.conf'
LOG_MATCHES = {
    'absent': 'config absent (enforcing; no action)',
    'readonly_enforcing': 'read-only %ph%: enforcing ' + p.FINGERPRINT + ' (zero stores)',
    'cleared': 'cleared (%ph%): ' + p.CLEARED,
}


def log(event, **data):
    save(event, **data)


def prerequisite(stage_status_name, kind):
    path = p.HERE / stage_status_name
    p.require(path.is_file(), 'missing prerequisite: ' + stage_status_name)
    status = json.loads(path.read_text(encoding='utf-8'))
    p.require(status.get('stage') == kind, 'wrong prerequisite stage: ' + stage_status_name)
    p.require(status.get('passed') is True, 'prerequisite stage did not pass: ' + stage_status_name)
    return status


def protect_seal():
    deploy_seal = p.HERE / 'seal.json'
    p.require(deploy_seal.is_file(), 'seal.json missing; the sealed packet is not consumable')
    seal = json.loads(deploy_seal.read_text(encoding='utf-8'))
    for name, checksum in seal.items():
        p.require(p.digest(p.HERE / name) == checksum, 'sealed packet changed: ' + name)
    p.tools.local_checks()
    p.require((p.HERE / 'SPENT').is_file(), 'the deploy stage has not receipted its terminal state')


def marker_for(stage):
    p.require(p.marker(stage) is True,
              'explicit ' + stage + ' approval is not standing; refuse no touch')
    p.require(repo_head() == p.COMMIT, 'source head changed while the marker stood')


def repo_head():
    import subprocess
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p.REPO).decode().strip()


def fields(text):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        p.require(sep and key not in result, 'malformed capture: ' + key[:40])
        result[key] = value
    return result


async def sdk_state(sdk, label='state'):
    out = fields(await capture(sdk, 'state', (
        "printf 'uid='; id -u\n"
        "printf 'boot='; cat /proc/sys/kernel/random/boot_id\n"
        "printf 'service='; systemctl is-active tvroot-bridge.service\n"
        "printf 'target_hash='; sha256sum " + p.TARGET + "\n"
        "printf 'proof_hash='; sha256sum " + p.EV + "/selfroot-proof.txt\n"
        "printf 'log_size='; stat -c %s " + p.EV + "/agent.log\n"
        "printf 'manager_pids='; pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll' | tr '\\n' ','; echo\n"
        "printf 'gate_config='; if test -e " + p.UEP_CONFIG + " || test -L " + p.UEP_CONFIG + "; then echo present; else echo absent; fi\n"
        "printf 'gate_state='; if test -e " + UEP_STATE + " || test -L " + UEP_STATE + "; then echo present; else echo absent; fi\n"
        "printf 'port_config='; if test -e /opt/usr/share/selfroot/bridge-port.conf || test -L /opt/usr/share/selfroot/bridge-port.conf; then echo present; else echo absent; fi\n"
    )))
    p.require(out['uid'] == SUID, 'SDK identity mismatch')
    p.require(out['service'] == 'active', 'bridge inactive')
    p.require(out['target_hash'] == TARGET_HASH + '  ' + p.TARGET,
              'installed manager drifted from ' + 'v5.18; STOP')
    p.require(out['gate_config'] in ('absent', 'present'), 'malformed gate capture')
    p.require(out['gate_state'] in ('absent', 'present'), 'malformed gate-state capture')
    p.require(out['port_config'] == 'absent', 'management port configuration changed; STOP')
    log(label + '-state', **out)
    return out


async def protected_hashes(sdk):
    command = ('sha256sum ' + ' '.join(map(quote, PROTECTED)))
    out = await capture(sdk, 'protected-hashes', command)
    got = {}
    for line in out.splitlines():
        digest, sep, path = line.partition('  ')
        p.require(sep and re.fullmatch(r'[0-9a-f]{64}', digest), 'malformed hash line: ' + line[:60])
        got[path] = digest
    p.require(set(got) == set(PROTECTED), 'protected path set changed; STOP')
    drift = [path for path in PROTECTED if got[path] != PROTECTED[path]]
    p.require(not drift, 'protected file drift: ' + str(drift[:4]))
    log('protected-hashes-verified', count=len(PROTECTED))
    return got


async def capture(sdk, label, command):
    save('sdk-request', name=label, command=command)
    code, output = await sdk.capture(command)
    save('sdk', name=label, command=command, exit=code)
    p.require(code == 0, label + ' refused or failed: ' + output[:200])
    return output


async def agent_log_lines(sdk, count=80):
    out = await capture(sdk, 'agent-log-tail',
                        'tail -n ' + str(int(count)) + ' -- ' + p.EV + '/agent.log')
    for line in out.splitlines():
        p.require(len(line) <= 2000, 'agent log line exceeds receipt bound')
    return out.splitlines()


def gate_lines(lines, needle_text):
    found = [line for line in lines if 'uep gate ' in line and 'uep gate EXCEPTION' not in line]
    exact = [line for line in found if needle_text in line]
    details = [line for line in lines
               if needle_text in line and not line.startswith('[')]
    return found, exact, details


async def fail(stage, status_name, kind, reason):
    log('stage-failed', stage=stage, kind=kind, reason=reason)
    (p.HERE / status_name).write_text(json.dumps({
        'stage': kind, 'passed': False, 'reason': reason,
        'utc': datetime.now(timezone.utc).isoformat()}, indent=2) + chr(10), encoding='utf-8', newline=chr(10))
    (p.HERE / 'STOP').write_text('Stage ' + stage + ' failed; packet stops permanently (no replay).\n',
                                 encoding='ascii', newline=chr(10))
    raise RuntimeError('stage ' + stage + ' failed: ' + reason)


def succeed(stage, status_name, kind, **extra):
    result = dict({'stage': kind, 'passed': True,
                   'utc': datetime.now(timezone.utc).isoformat()}, **extra)
    (p.HERE / status_name).write_text(json.dumps(result, indent=2) + chr(10), encoding='utf-8', newline=chr(10))
    log('stage-passed', stage=stage, kind=kind)
    p.clear_marker(stage)
    return result
