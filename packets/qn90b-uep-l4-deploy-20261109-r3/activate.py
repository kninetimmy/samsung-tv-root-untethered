"""Stage 4: ACTIVE + reboot observation.

One archive-root root session runs the single `gate-active` op; the baked
script accepts the verified read-only-to-active transition (exact content,
owner 0:0, mode 0644, link count 1, smack label `_`) and publishes `active`
atomically. The driver then waits for a NEW boot id across bounded reconnect
cycles — the reboot itself is the stage-4 act, triggered by the owner
power-cycling at the TV (the packet never reboots on its own; the reboot
helper route stays outside this packet). After the new boot it verifies:
fresh all-zero automatic proof captured as ONE normalized base64 line whose
digest is receipted, the boot gate's `cleared (boot)` summary plus its
fingerprint detail line, the budget state file for the fresh boot, the staged
hash-locked uep-probe admission (exact marker + native_exit=42, with the
probe's own exit status preserved and owned cleanup from the sdk_tools root),
an fdet read agreeing with the cleared fingerprint, bridge alive, and the
whole protected register byte-identical.
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
from stage_lib import (agent_log_lines, capture, record_failure, fields, marker_for,
                       log, OneAttempt, protect_seal, refuse_if_stopped,
                       sdk_state, succeed, protected_hashes,
                       gate_event_assessment, boot_clock, UEP_STATE)
from dirread import DirRead

STAGE = 'LIVE_ARM_ACTIVE'
STATUS = 'stage-status-active.json'
KIND = 'active'
NATIVE_SHA = p.NATIVE_SHA
MARKER_OK = 'QN90B_UEP_NATIVE_PROBE_OK'
POLL_SECONDS = 15
AWAIT_BOOT_DEADLINE = 8 * 60 * 60


def prerequisites():
    refuse_if_stopped()
    dirread = json.loads((p.HERE / 'stage-status-dirread.json').read_text(encoding='utf-8'))
    p.require(dirread.get('stage') == 'dirread' and dirread.get('passed') is True,
              'the dirread stage did not pass')
    p.require(p.BOOT is not None and dirread.get('boot') == p.BOOT,
              'dirread receipt boot differs from the inspected boot; STOP')
    log('active-prerequisites-verified', inspection_boot=p.BOOT)


def probe_stage_guard(stage, receipt):
    """Identity checks of the dedicated probe staging directory.

    stage = the full absolute path; receipt = the device:inode pair captured
    at the exclusive mkdir so only THAT directory is accepted.
    """
    stage_dir_name = stage.rsplit('/', 1)[1]
    p.require(re.fullmatch('l[45]-[a-f0-9]{16}', stage_dir_name), 'unsafe probe stage name')
    p.require(stage.startswith(p.ROOT + '/'), 'probe stage outside the sdk_tools root')
    return ('test ! -L ' + quote(stage) + '\n'
            'test ! -e ' + quote(stage) + '.prepared\n'
            'cd -P ' + quote(p.CANON) + '\n'
            'test "$PWD" = ' + quote(p.CANON) + '\n'
            'cd -P ' + quote(stage) + '\n'
            'test "$PWD" = ' + quote(p.CANON + '/' + stage_dir_name) + '\n'
            'test "$(stat -c %d:%i:%u:%a .)" = ' + quote(receipt + ':901:700') + '\n')


async def stage_new_probe_directory(sdk, prefix):
    """Exclusive, owned staging directory for the exact uep-probe bytes."""
    data = p.NATIVE.read_bytes()
    p.require(hashlib.sha256(data).hexdigest() == NATIVE_SHA, 'probe artifact drift; STOP')
    encoded = base64.b64encode(data).decode('ascii')
    stage_dir = prefix + secrets.token_hex(8)
    stage = p.ROOT + '/' + stage_dir
    out = fields(await capture(sdk, 'probe-stage-create', (
        "printf 'receipt=%s\\n' \"$( cd -P " + p.CANON + " && umask 077 && "
        "mkdir -m 700 -- '" + stage_dir + "' && stat -c '%d:%i' '" +
        quote(stage_dir) + "' )\"")))
    receipt = out['receipt']
    p.require(re.fullmatch(r'\d+:\d+', receipt), 'unsafe probe stage receipt')
    return stage, receipt, encoded


PROBE_RUN_BODY = (
    "umask 077\n"
    "test ! -e uep-probe.elf\n"
    "test ! -L uep-probe.elf\n"
    "printf %s {ENCODED} | base64 -d | /usr/bin/dd of=uep-probe.elf conv=excl 2>/dev/null\n"
    "test ! -L uep-probe.elf\n"
    "test -f uep-probe.elf\n"
    "test \"$(sha256sum uep-probe.elf)\" = '{NAT}  uep-probe.elf'\n"
    "chmod 700 -- uep-probe.elf\n"
    "test \"$(stat -c '%F:%u:%a:%h' uep-probe.elf)\" = 'regular file:901:700:1'\n"
    "set +e\n"
    "{ ulimit -c 0; {STAGE}/uep-probe.elf; } >uep-probe.out 2>&1\n"
    "probe_exit=$?\n"
    "set -e\n"
    "head -c 4096 -- uep-probe.out\n"
    "printf '\\nnative_exit=%s\\n' \"$probe_exit\"\n"
    "rm -f -- uep-probe.out\n"
    "rm -- uep-probe.elf\n"
    "cd -P {CANON}\n"
    "rmdir -- {STAGE}\n"
    "test ! -e {STAGE}\n"
    "test ! -L {STAGE}\n"
    "printf 'probe-stage-clean\\n'\n"
)


async def staged_probe_run(sdk, boot_receipt, prefix, expect_exit, expect_marker):
    """One bounded staging; the hash-locked uep-probe.elf runs exactly once.

    expect_marker = the exact first output line required (MARKER_OK for the
    admission round, None for the denial round where ANY marker output stops
    the stage). Output other than the agreed shape stops the stage
    permanently (no retry). The staging identity is re-proved before the run
    and the directory is removed in the same command by its ABSOLUTE path
    from the verified canonical sdk_tools root (review finding 4c).
    """
    stage, receipt, encoded = await stage_new_probe_directory(sdk, prefix)
    body = (PROBE_RUN_BODY
            .replace('{ENCODED}', quote(encoded))
            .replace('{STAGE}', quote(stage))
            .replace('{CANON}', quote(p.CANON))
            .replace('{NAT}', NATIVE_SHA))
    command = ('set -eu\n' + probe_stage_guard(stage, receipt) + '\n' + body)
    out = await capture(sdk, 'probe-run', command)
    tail = [line for line in out.splitlines() if line.strip()]
    p.require(tail, 'probe run produced no output')
    p.require(tail[-1] == 'probe-stage-clean', 'probe staging did not clean up; no retry')
    p.require(tail[-2] == 'native_exit=' + str(expect_exit),
              'probe exit differed from the expected value; STOP')
    payload = tail[:-2]
    p.require(payload, 'probe produced no payload output')
    if expect_marker is not None:
        p.require(payload[0] == expect_marker, 'probe did not print the expected marker; STOP')
    else:
        for line in payload:
            p.require(MARKER_OK not in line, 'the denied probe still admitted; STOP')
    log('probe-round-verified', stage=stage, exit=expect_exit, marker=bool(expect_marker),
        boot=boot_receipt)
    return out


async def read_proof(sdk, receipted_digest=None):
    """Consume the automatic proof as ONE normalized base64 line.

    base64 default output wraps at 76 columns, which `fields()` rejects
    (review finding 4a); the `tr -d '\\n'` normalization matches the
    inspection's own proof capture exactly.
    """
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


async def assert_cleared_gate(sdk, fresh_boot):
    lines = await agent_log_lines(sdk, 120)
    boot_epoch, epoch = await boot_clock(sdk)
    gate = gate_event_assessment(lines, 'active', regime='legacy',
                                  boot_epoch=boot_epoch, epoch_at_fetch=epoch)
    p.require(gate, 'the boot gate did not receipt its clear; the active boot cannot continue')
    budget = (await capture(sdk, 'gate-state-content', 'cat -- ' + UEP_STATE)).strip()
    p.require(re.fullmatch('boot=' + re.escape(fresh_boot) + r' clear=[12] restore=[01]', budget),
              'budget state does not match the fresh boot: ' + budget[:80])
    log('cleared-gate-verified', boot=fresh_boot, budget=budget)


async def assert_flag_read(sdk, fingerprint):
    out = await capture(sdk, 'fdet-flag-read',
                        '/usr/bin/dotnet ' + p.FDET_HOME + '/FdetProbe.dll rw 0x208c26c0 4')
    lines = out.splitlines()
    p.require(len(lines) == 2, 'stalled or malformed fdet read')
    p.require(lines[0] == 'read_words physical=0x208c26c0 page=0x208c2000 offset=0x6c0 words=4',
              'unexpected fdet header')
    p.require(lines[1] == 'words word=0 ' + fingerprint, 'flag state mismatch; STOP: ' + lines[1][:60])


class ActiveSession(DirRead):
    GATE_OP = 'gate-active'
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


async def main():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        # Preflight: the read-only state left by stage 3 is the exact input.
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            state = await sdk_state(sdk, 'active-baseline-state')
            p.require(state['boot'] == p.BOOT,
                      'boot left the inspected boot; re-inspect before stage 4; STOP')
            content = await capture(sdk, 'gate-config-content', 'cat -- ' + p.UEP_CONFIG)
            p.require(content == 'read-only',
                      'the dirread state (read-only config) is required first; STOP')
            await protected_hashes(sdk)
        finally:
            await sdk.disconnect()
        session = ActiveSession(BridgeSDK(save), save, p.BOOT, p.PROOF_SHA)
        relay_note = 'pending'
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
        # Identity-checked relay teardown AFTER root shutdown and ordinary SDK
        # verification; the awaiting loop below reconnects on the ordinary port.
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            session.sdk = sdk
            await session.baseline()
            relay_note = 'removed'
            state = await sdk_state(sdk, 'active-post-op')
            p.require(state['boot'] == p.BOOT, 'boot changed while arming; STOP')
            content = await capture(sdk, 'gate-config-content', 'cat -- ' + p.UEP_CONFIG)
            p.require(content == 'active', 'gate config content mismatch; STOP')
            meta = fields(await capture(sdk, 'gate-config-meta', (
                "printf 'meta='; stat -c '%u:%g:%a:%h' -- " + p.UEP_CONFIG + "\n"
                "printf 'label='; chsmack " + p.UEP_CONFIG + "\n")))
            p.require(meta['meta'] == '0:0:644:1', 'gate config metadata changed; STOP')
            p.require(meta['label'] == p.UEP_CONFIG + ' access="_"', 'gate config label changed; STOP')
            p.require(state['gate_state'] == 'absent', 'budget state file before any boot; STOP')
        finally:
            await sdk.disconnect()
        fresh = await await_new_boot(p.BOOT)
        p.require(fresh is not None,
                  'no new boot within the awaiting bound; the config stays active; STOP')
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            post = await sdk_state(sdk, 'active-post-boot')
            p.require(post['boot'] == fresh, 'boot poll lost the fresh boot')
            await protected_hashes(sdk)
            proof_text, proof_digest = await read_proof(sdk)
            assert_proof(fresh, proof_text)
            await assert_cleared_gate(sdk, fresh)
            await assert_flag_read(sdk, p.CLEARED)
            await staged_probe_run(sdk, fresh, 'l4-', 42, MARKER_OK)
            end = await sdk_state(sdk, 'active-final')
            await protected_hashes(sdk)
            p.require(post['boot'] == end['boot'] == fresh, 'boot changed inside the active stage')
            succeed(STAGE, STATUS, KIND, fresh_boot=fresh, fresh_proof_sha256=proof_digest,
                    relay=relay_note, attempt_utc=attempt.path.read_text().strip())
        finally:
            await sdk.disconnect()
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
