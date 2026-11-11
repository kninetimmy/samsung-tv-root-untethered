"""Stage 4a: ACTIVE + reboot observation.

One archive-root root session runs the single `gate-active` op (the manager
clears the enforcement word at the next boot while the config exists). The
driver then waits for a NEW boot id across bounded reconnect cycles — the
reboot itself is the stage-4 act, triggered either by user power-cycle at the
TV or by the established reboot-helper route run separately (that helper
needs its own agent build and is deliberately outside this packet). After
the new boot it verifies: fresh all-zero automatic proof, the boot gate's
`cleared (boot)` summary plus its fingerprint detail line, the budget state
file for the fresh boot, the staged hash-locked uep-probe admission
(QN90B_UEP_NATIVE_PROBE_OK + native_exit=42), an fdet read agreeing with the
cleared fingerprint, bridge alive, and the whole protected register
byte-identical.
"""
import asyncio
import base64
import hashlib
import json
import re
import secrets
import sys
import time
from pathlib import Path
from shlex import quote

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
from stage_lib import (agent_log_lines, capture, fail, fields, marker_for,
                       log, protect_seal, sdk_state, succeed, protected_hashes,
                       UEP_STATE)
import dirread as dirread_module
from dirread import DirRead

INITIAL = dirread_module.INITIAL
STAGE = 'LIVE_ARM_ACTIVE'
STATUS = 'stage-status-active.json'
KIND = 'active'
NATIVE = p.NATIVE
NATIVE_SHA = p.NATIVE_SHA
MARKER_OK = 'QN90B_UEP_NATIVE_PROBE_OK'
OK_EXIT = 'native_exit=42'
POLL_SECONDS = 15
AWAIT_BOOT_DEADLINE = 8 * 60 * 60


def prerequisites():
    receipt = json.loads((p.HERE / 'deployment-result.json').read_text(encoding='utf-8'))
    p.require(receipt.get('installed') is True and receipt.get('sha256') == p.NEW_SHA,
              'deploy receipt missing or wrong')
    dirread = json.loads((p.HERE / 'stage-status-dirread.json').read_text(encoding='utf-8'))
    p.require(dirread.get('passed') is True, 'the dirread stage did not pass')
    log('active-prerequisites-verified')


class ActiveSession(DirRead):
    MATERIALS = Path(p.HERE / 'execution/gate-materials-active')

    async def run_gate(self):
        result = await self.connection.execute('gate-active', 12)
        self.save('gate-active-receipt', exit=result.exit_code, timed_out=result.timed_out,
                  stdout=result.stdout, stderr=result.stderr)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr
                  and 'GATE_CONFIG_ACTIVE_COMPLETE\n' in result.stdout,
                  'gate-active did not complete; no retry')
        p.require(re.search(r'^GATE_METADATA 0:0:644:1$', result.stdout, re.M),
                  'gate metadata receipt missing')


async def arm_and_verify():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    session = ActiveSession(BridgeSDK(save), save)
    try:
        await session.run()
    finally:
        await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        state = await sdk_state(sdk, 'active-post-op')
        content = (await capture(sdk, 'gate-config-content', 'cat -- ' + p.UEP_CONFIG)).strip()
        p.require(content == 'active', 'gate config content mismatch; STOP')
        meta = fields(await capture(sdk, 'gate-config-meta', (
            "printf 'meta='; stat -c '%u:%g:%a:%h' -- " + p.UEP_CONFIG + "\n"
            "printf 'label='; chsmack " + p.UEP_CONFIG + "\n")))
        p.require(meta['meta'] == '0:0:644:1', 'gate config metadata changed; STOP')
        p.require(meta['label'] == p.UEP_CONFIG + ' access="_"', 'gate config label changed; STOP')
        p.require(state['gate_state'] == 'absent', 'budget state file before any boot; STOP')
        p.require(state['boot'] == p.BOOT, 'boot changed while arming; STOP')
        log('active-armed', boot=p.BOOT)
    finally:
        await sdk.disconnect()


async def await_new_boot(old_boot):
    deadline = time.monotonic() + AWAIT_BOOT_DEADLINE
    attempts = 0
    while time.monotonic() < deadline - POLL_SECONDS:
        attempts += 1
        sdk = BridgeSDK(save)
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


def assert_proof(fresh_boot, proof_text):
    p.require('SELFROOT-PROOF uid=0 gid=0' in proof_text, 'automatic root header missing')
    p.require(re.findall(r'(?m)^BOOT_ID=([^\r\n]+)', proof_text) == [fresh_boot],
              'automatic proof does not match the new boot')
    for field in ('Uid', 'Gid'):
        p.require(re.findall(
            r'(?m)^' + field + r':[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]*\r?$', proof_text
        ) == [('0', '0', '0', '0')], 'automatic proof lacks the full zero identity after reboot')
    log('new-boot-proof-verified', boot=fresh_boot)


async def assert_cleared_gate(sdk, fresh_boot):
    lines = await agent_log_lines(sdk, 120)
    p.require([line for line in lines if
               re.search(r'uep gate \((?:boot|reopen)\): cleared \(boot\)$', line)],
              'the boot gate did not receipt its clear; the active boot cannot continue')
    p.require([line for line in lines if
               re.search(r'uep gate: cleared boot: ' + re.escape(p.CLEARED) +
                         r' \(one word, neighbourhood pinned\)$', line)],
              'the clear detail line is missing; the active boot cannot continue')
    budget = (await capture(sdk, 'gate-state-content', 'cat -- ' + UEP_STATE)).strip()
    p.require(re.fullmatch('boot=' + re.escape(fresh_boot) + r' clear=[12] restore=[01]', budget),
              'budget state does not match the fresh boot: ' + budget[:80])
    log('cleared-gate-verified', boot=fresh_boot, budget=budget)


def probe_stage_guard(stage, receipt):
    p.require(re.fullmatch('/home/owner/share/tmp/sdk_tools/l4-[a-f0-9]{16}', stage),
              'unsafe probe stage path')
    return ('test ! -L ' + quote(stage) + '\ncd -P ' + quote(stage)
            + '\ntest "$PWD" = ' + quote(p.CANON + '/' + stage.rsplit('/', 1)[1])
            + '\ntest "$(stat -c %d:%i:%u:%a .)" = ' + quote(receipt + ':901:700'))


async def native_probe_admission(sdk, fresh_boot):
    """One bounded staging; the hash-locked uep-probe.elf runs exactly once.

    Any output other than the marker line + native_exit=42 stops the stage
    permanently (no retry; the flag state stays whatever it currently is and
    the packet closes with the evidence).
    """
    stage_dir = 'l4-' + secrets.token_hex(8)
    stage = p.ROOT + '/' + stage_dir
    data = NATIVE.read_bytes()
    p.require(hashlib.sha256(data).hexdigest() == NATIVE_SHA, 'probe artifact drift; STOP')
    encoded = base64.b64encode(data).decode('ascii')
    out = fields(await capture(sdk, 'probe-stage-create', (
        "printf 'receipt=%s\\n' \"$( cd -P " + p.ROOT + " && umask 077 && "
        "mkdir -m 700 -- '" + stage_dir + "' && stat -c '%d:%i' '" +
        quote(stage_dir) + "' )\"")))
    receipt = out['receipt']
    out = await capture(sdk, 'native-probe-admit', (
        "set -eu\n" + probe_stage_guard(stage, receipt)
        + "\numask 077\nprintf %s " + quote(encoded)
        + " | base64 -d | /usr/bin/dd of=uep-probe.elf conv=excl oflag=nofollow status=noxfer 2>/dev/null\n"
        + "test ! -L uep-probe.elf && test -f uep-probe.elf\n"
        + "test \"$(sha256sum uep-probe.elf)\" = " + quote(NATIVE_SHA + '  uep-probe.elf')
        + "\nchmod 700 -- uep-probe.elf\n"
        + "test \"$(stat -c '%F:%u:%a:%h' uep-probe.elf)\" = 'regular file:901:700:1'"
        + "\nset +e\n"
        + "out=$( { ulimit -c 0; " + quote(stage + '/uep-probe.elf') + "; } 2>&1 | head -c 4096 )\n"
        + "r=$?\nprintf '%s\\nnative_exit=%s\\n' \"$out\" \"$r\"\nexit 0"))
    lines = [line for line in out.splitlines() if line.strip()]
    p.require(lines, 'native admission produced no output')
    p.require(lines[0] == MARKER_OK, 'unsigned probe did not print the success marker; STOP')
    p.require(lines[-1] == OK_EXIT, 'unsigned probe exit differed; STOP')
    log('native-probe-passed', stage_dir=stage, boot=fresh_boot)
    cleanup = ('set -eu\n' + probe_stage_guard(stage, receipt)
               + "\ntest \"$(find . -mindepth 1 -maxdepth 1 -printf '%f\\n' | sort)\" = 'uep-probe.elf'"
               + "\ntest \"$(sha256sum uep-probe.elf)\" = " + quote(NATIVE_SHA + '  uep-probe.elf')
               + "\nrm -- uep-probe.elf\ncd /\nrmdir -- " + quote(stage_dir)
               + "\ntest ! -e " + quote(stage) + "\ntest ! -L " + quote(stage)
               + "\necho probe-stage-clean")
    p.require((await capture(sdk, 'probe-cleanup', cleanup)).strip() == 'probe-stage-clean',
              'probe staging cleanup unverified')


async def assert_flag_read(sdk, fingerprint):
    out = await capture(sdk, 'fdet-flag-read',
                        '/usr/bin/dotnet ' + p.FDET_HOME + '/FdetProbe.dll rw 0x208c26c0 4')
    lines = out.splitlines()
    p.require(len(lines) == 2, 'stalled or malformed fdet read')
    p.require(lines[0] == 'read_words physical=0x208c26c0 page=0x208c2000 offset=0x6c0 words=4',
              'unexpected fdet header')
    p.require(lines[1] == 'words word=0 ' + fingerprint, 'flag state mismatch; STOP: ' + lines[1][:60])


async def main():
    await arm_and_verify()
    fresh = await await_new_boot(p.BOOT)
    if fresh is None:
        await fail(STAGE, STATUS, KIND,
                   'no new boot within the awaiting bound; the config stays active and the packet stops')
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        post = await sdk_state(sdk, 'active-post-boot')
        p.require(post['boot'] == fresh, 'boot poll lost the fresh boot')
        await protected_hashes(sdk)
        out = fields(await capture(sdk, 'proof-capture',
                                   "printf 'proof='; base64 < " + p.EV + "/selfroot-proof.txt\n"))
        assert_proof(fresh, base64.b64decode(out['proof']).decode())
        await assert_cleared_gate(sdk, fresh)
        await assert_flag_read(sdk, p.CLEARED)
        await native_probe_admission(sdk, fresh)
        end = await sdk_state(sdk, 'active-final')
        await protected_hashes(sdk)
        p.require(post['boot'] == end['boot'] == fresh, 'boot changed inside the active stage')
        succeed(STAGE, STATUS, KIND, fresh_boot=fresh)
    finally:
        await sdk.disconnect()


if __name__ == '__main__':
    asyncio.run(main())
