"""Shared state captures, gate receipts and boot-wait logic for the three r9 stages.

Read-only over the SDK bridge plus two owned writes (the denial staging
directory and the stage evidence files). Nothing here decides a gate
transition: the scripts do, and these helpers only verify what the TV reports.
"""
import asyncio
import base64
import hashlib
import re
import time
from datetime import datetime, timezone

import packet as p
import stage_lib
from stage_lib import capture, fields, log

POLL_SECONDS = 15
AWAIT_BOOT_DEADLINE = 8 * 60 * 60
MODULE_LOG = p.EV + '/module-uep-gate.log'


async def read_proof(sdk, receipted_digest=None):
    """Consume the automatic proof as ONE normalized base64 line."""
    command = ("printf 'proof='; base64 < " + p.EV + "/selfroot-proof.txt | tr -d '\\n'; echo")
    out = fields(await capture(sdk, 'proof-capture', command))
    p.require(re.fullmatch(r'[A-Za-z0-9+/]{100,}={0,2}', out['proof']),
              'proof payload is not one unwrapped base64 line')
    data = base64.b64decode(out['proof'])
    digest = hashlib.sha256(data).hexdigest()
    log('proof-captured', sha256=digest, bytes=len(data))
    if receipted_digest is not None:
        p.require(digest == receipted_digest, 'automatic proof drifts from the receipted capture; STOP')
    return data.decode(), digest


def assert_proof(fresh_boot, proof_text):
    p.require('SELFROOT-PROOF uid=0 gid=0' in proof_text, 'automatic root header missing')
    p.require(re.findall(r'(?m)^BOOT_ID=([^\r\n]+)', proof_text) == [fresh_boot],
              'automatic proof does not match the new boot')
    for field in ('Uid', 'Gid'):
        p.require(re.findall(
            r'(?m)^' + field + r':[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]*\r?$', proof_text
        ) == [('0', '0', '0', '0')], 'automatic proof lacks the full zero identity after reboot')
    log('new-boot-proof-verified', boot=fresh_boot)


async def state(sdk, manager_sha, label='state'):
    """One SDK capture of everything a stage anchors on; no gate decision."""
    command = (
        "printf 'uid='; id -u\n"
        "printf 'boot='; cat /proc/sys/kernel/random/boot_id\n"
        "printf 'service='; systemctl is-active tvroot-bridge.service\n"
        "printf 'manager_hash='; sha256sum " + p.TARGET + "\n"
        "printf 'manager_rc_hash='; sha256sum " + p.TARGET_RC + "\n"
        "printf 'gate='; if test -L " + p.UEP_CONFIG + "; then echo symlink; "
        "elif test -e " + p.UEP_CONFIG + "; then echo present; else echo absent; fi\n"
        "printf 'budget='; if test -e " + p.UEP_STATE + " || test -L " + p.UEP_STATE
        + "; then echo present; else echo absent; fi\n"
        # r11 B1: the host's overwrite-before-rename temp path must be absent
        # whenever a stage inspects state; a leftover there is a root-write
        # hazard, not noise.
        "printf 'state_tmp='; if test -e " + p.UEP_STATE + ".tmp || test -L "
        + p.UEP_STATE + ".tmp; then echo present; else echo absent; fi\n"
        "printf 'module='; if test -L " + p.MODULE_DIR + "; then echo symlink; "
        "elif test -e " + p.MODULE_DIR + "; then echo present; else echo absent; fi\n"
        "printf 'backup='; if test -L " + p.BACKUP_DIR + "; then echo symlink; "
        "elif test -e " + p.BACKUP_DIR + "; then echo present; else echo absent; fi\n"
        "printf 'proof_hash='; sha256sum " + p.EV + "/selfroot-proof.txt\n"
        "printf 'log_size='; stat -c %s " + p.EV + "/agent.log\n"
        "printf 'manager_pids='; pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll' | tr '\\n' ','; echo\n"
        "printf 'port_config='; if test -e /opt/usr/share/selfroot/bridge-port.conf || "
        "test -L /opt/usr/share/selfroot/bridge-port.conf; then echo present; else echo absent; fi\n"
    )
    out = fields(await capture(sdk, label, command))
    p.require(out['uid'] == '901', 'SDK identity mismatch')
    p.require(out['service'] == 'active', 'bridge inactive')
    p.require(out['manager_hash'] == manager_sha + '  ' + p.TARGET, 'installed manager hash drift; STOP')
    # The runtimeconfig must match the SAME baseline as the manager DLL: after
    # the v5.19 install, accepting the v5.18 runtimeconfig again would mask a
    # half-applied install.
    expected_rc = p.NEW_MANAGER_RC_SHA if manager_sha == p.NEW_MANAGER_SHA else p.PREV_MANAGER_RC_SHA
    p.require(out['manager_rc_hash'] == expected_rc + '  ' + p.TARGET_RC,
              'manager runtimeconfig drift; STOP')
    for key in ('gate', 'budget', 'module', 'backup'):
        p.require(out[key] in ('absent', 'present'), 'malformed ' + key + ' capture')
    p.require(out['state_tmp'] == 'absent',
              'the budget temp path exists; a root write could be redirected; STOP')
    p.require(out['port_config'] == 'absent', 'management port configuration changed; STOP')
    log(label, **out)
    return out


async def gate_config(sdk, label):
    """Exact content + metadata + label of the gate config (must exist)."""
    out = fields(await capture(sdk, label, (
        "printf 'content='; cat -- " + p.UEP_CONFIG + "\n"
        "printf 'meta='; stat -c '%F:%u:%g:%a:%h' -- " + p.UEP_CONFIG + "\n"
        "printf 'label='; chsmack " + p.UEP_CONFIG + "\n"
        "printf 'hash='; sha256sum -- " + p.UEP_CONFIG + "\n")))
    p.require(out['content'] in (p.UEP_READONLY_CONTENT, p.UEP_ACTIVE_CONTENT),
              'gate config content is not a reviewed value; STOP')
    p.require(out['meta'] == p.UEP_META, 'gate config metadata changed; STOP: ' + out['meta'])
    p.require(out['label'] == p.UEP_LABEL, 'gate config label changed; STOP')
    return out


async def manager_files(sdk, label):
    """Installed manager metadata/labels the package must keep to load."""
    out = fields(await capture(sdk, label, (
        "printf 'meta='; stat -c '%F:%u:%g:%a:%h' -- " + p.TARGET + "\n"
        "printf 'label='; chsmack " + p.TARGET + "\n"
        "printf 'rc_meta='; stat -c '%F:%u:%g:%a:%h' -- " + p.TARGET_RC + "\n"
        "printf 'rc_label='; chsmack " + p.TARGET_RC + "\n")))
    p.require(out['meta'] == 'regular file:' + p.TARGET_OWNER + ':' + p.TARGET_MODE + ':1',
              'manager metadata drift: ' + out['meta'])
    p.require(out['label'] == p.TARGET_LABEL, 'manager label drift: ' + out['label'])
    p.require(out['rc_meta'] == 'regular file:' + p.TARGET_RC_OWNER + ':' + p.TARGET_RC_MODE + ':1',
              'manager runtimeconfig metadata drift: ' + out['rc_meta'])
    p.require(out['rc_label'] == p.TARGET_RC_LABEL, 'manager runtimeconfig label drift: ' + out['rc_label'])
    return out


async def module_files(sdk, label):
    """Pinned module hashes, file modes and directory metadata.

    r9 emitted `printf 'modes='; stat ... <four paths>`, which produces one
    keyed line and three bare lines; fields() rejects the bare lines, so this
    helper could never succeed (r9 B4). Every path now gets its own keyed line,
    and the directory itself is checked because uid 901 must be able to
    traverse it (r9 B5).
    """
    out = fields(await capture(sdk, label, (
        "printf 'boot='; sha256sum " + p.MODULE_BOOT_PATH + "\n"
        "printf 'json='; sha256sum " + p.MODULE_JSON_PATH + "\n"
        "printf 'host='; sha256sum " + p.MODULE_HOST + "\n"
        "printf 'rc='; sha256sum " + p.MODULE_HOST_RC + "\n"
        "printf 'boot_mode='; stat -c '%u:%a' -- " + p.MODULE_BOOT_PATH + "\n"
        "printf 'json_mode='; stat -c '%u:%a' -- " + p.MODULE_JSON_PATH + "\n"
        "printf 'host_mode='; stat -c '%u:%a' -- " + p.MODULE_HOST + "\n"
        "printf 'rc_mode='; stat -c '%u:%a' -- " + p.MODULE_HOST_RC + "\n"
        "printf 'dir_meta='; stat -c '%F:%u:%g:%a' -- " + p.MODULE_DIR + "\n")))
    expected = {
        'boot': p.MODULE_BOOT_SHA + '  ' + p.MODULE_BOOT_PATH,
        'json': p.MODULE_JSON_SHA + '  ' + p.MODULE_JSON_PATH,
        'host': p.HOST_SHA + '  ' + p.MODULE_HOST,
        'rc': p.HOST_RC_SHA + '  ' + p.MODULE_HOST_RC,
    }
    for key, line in expected.items():
        p.require(out[key] == line, 'module file drift: ' + key)
    p.require(out['boot_mode'] == '0:755', 'module boot mode changed: ' + out['boot_mode'])
    for key in ('json_mode', 'host_mode', 'rc_mode'):
        p.require(out[key] == '0:644', 'module file mode changed: ' + key + ' ' + out[key])
    p.require(out['dir_meta'] == p.MODULE_DIR_META,
              'module directory metadata changed: ' + out['dir_meta'])
    return out


async def module_gate(sdk, stage, label, probes=12):
    """Bounded wait for THIS boot's module-log receipt lines.

    The module runner truncates module-uep-gate.log when it starts the module,
    so the file is boot-scoped; its mtime must still be newer than the current
    boot clock before its lines may serve as evidence.
    """
    shapes = stage_lib.GATE_EVENT_SHAPES[stage]
    for attempt in range(1, probes + 1):
        boot_epoch, epoch = await stage_lib.boot_clock(sdk)
        meta = fields(await capture(sdk, 'module-log-meta-' + str(attempt), (
            "printf 'mtime='; stat -c %Y -- " + MODULE_LOG + " 2>/dev/null || echo 0\n"
            "printf 'size='; stat -c %s -- " + MODULE_LOG + " 2>/dev/null || echo 0\n")))
        p.require(int(meta['size']) <= 65536, 'module log exceeds the receipt bound')
        mtime = int(meta['mtime'])
        if mtime >= boot_epoch - 5:
            lines = (await capture(sdk, 'module-log-' + str(attempt),
                                   'cat -- ' + MODULE_LOG)).splitlines()
            p.require(len(lines) <= 200, 'module log exceeds the line bound')
            matched = [line for line in lines if any(shape.search(line) for shape in shapes)]
            unexpected = [line for line in lines
                          if ('uep gate' in line and not any(shape.search(line) for shape in stage_lib.KNOWN_SHAPES)
                              and 'uep gate module exit=' not in line)]
            p.require(not unexpected, 'unexpected gate event: ' + (unexpected[0][:160] if unexpected else ''))
            # r11 m1: the module's own exit status is evidence. r10 accepted a
            # nonzero exit line beside the required receipts.
            exits = [line for line in lines if 'uep gate module exit=' in line]
            bad_exit = [line for line in exits
                        if not re.search(r'uep gate module exit=0$', line)]
            p.require(not bad_exit, 'the gate module exited non-zero: '
                      + (bad_exit[0][:160] if bad_exit else ''))
            if all(any(shape.search(line) for line in matched) for shape in shapes):
                log('module-gate-observed', stage=stage, attempts=attempt, lines=len(matched))
                return lines
        log('module-gate-pending', stage=stage, attempts=attempt, mtime=mtime, boot_epoch=boot_epoch)
        if attempt < probes:
            await asyncio.sleep(POLL_SECONDS)
    raise p.Stop('the ' + stage + ' module-gate receipt is missing after '
                 + str(probes) + ' probes; STOP')


async def assert_flag_read(sdk, fingerprint, label='fdet-flag-read'):
    out = await capture(sdk, label,
                        '/usr/bin/dotnet ' + p.FDET_HOME + '/FdetProbe.dll rw ' + p.UEP_PAGE + ' 4')
    lines = out.splitlines()
    p.require(len(lines) == 2, 'stalled or malformed fdet read')
    p.require(lines[0] == 'read_words physical=' + p.UEP_PAGE + ' page=0x208c2000 offset=0x6c0 words=4',
              'unexpected fdet header')
    p.require(lines[1] == 'words word=0 ' + fingerprint, 'flag state mismatch; STOP: ' + lines[1][:60])


async def budget(sdk, label):
    """Exact budget file bytes (must exist)."""
    return (await capture(sdk, label, 'cat -- ' + p.UEP_STATE)).strip()


def parse_budget(text):
    match = re.fullmatch(r'boot=([0-9a-f-]{36}) clear=([12]) restore=([01])', text)
    p.require(match is not None, 'budget state does not match the documented shape; STOP')
    return match[1], int(match[2]), int(match[3])


async def await_new_boot(old_boot, sdk_factory):
    deadline = time.monotonic() + AWAIT_BOOT_DEADLINE
    attempts = 0
    while time.monotonic() < deadline - POLL_SECONDS:
        attempts += 1
        sdk = sdk_factory()
        try:
            await sdk.connect()
            out = fields(await capture(sdk, 'boot-poll-' + str(attempts),
                                       "printf 'boot='; cat /proc/sys/kernel/random/boot_id\n"
                                       "printf 'service='; systemctl is-active tvroot-bridge.service\n"))
        except Exception as attempt_error:
            log('await-boot-attempt', attempts=attempts, outcome=type(attempt_error).__name__)
            try:
                await sdk.disconnect()
            except Exception:
                pass
            await asyncio.sleep(POLL_SECONDS)
            continue
        try:
            await sdk.disconnect()
        except Exception:
            pass
        if out['boot'] != old_boot:
            if out['service'] != 'active':
                log('new-boot-bridge-warming', boot=out['boot'], attempts=attempts)
                await asyncio.sleep(POLL_SECONDS)
                continue
            log('new-boot-observed', boot=out['boot'], attempts=attempts)
            return out['boot']
        await asyncio.sleep(POLL_SECONDS)
    return None


def utc_now():
    return datetime.now(timezone.utc).isoformat()
