"""Stage 1 (and only stage): REMOVE — delete the read-only gate config,
owner-approved reboot, verify the enforcing-only baseline restored.

The r6 DISREAD stage created /opt/usr/share/selfroot/uep-off.conf live
(content `read-only\\n`, 0:0:644, label `_`); the owner's reopen then proved
v5.18's in-app payload check can never pass in the manager app context, so
no ACTIVE receipt can ever exist and r6's disable stage is unreachable.
This packet's standalone removal (owner decision 2026-11-09, memhub
decision 26) anchors directly to the fresh r7 inspection instead:

- The removal runs on the inspection boot: the r7 root agent takes the
  expected boot through the authenticated op command (`gate-remove:<boot
  id>`) and asserts it inside the root shell; the baked script carries no
  boot pin and removes only the exact verified read-only content.
- After the removal the owner reboots once; the driver verifies a distinct
  boot: fresh automatic proof (one normalized line, content-locked to the
  new boot and the zero identity), the absent-config boot gate line, the
  budget state file absent on both boots (or stale, never claiming the
  fresh boot), the fdet fingerprint still ENFORCING (the payload never
  ran: no store, no clear), and the 25-file protected register
  byte-identical.

Out of scope by owner decision: the uep-probe admission/denial run (that
acceptance criterion belonged to the r2 disable stage's ACTIVE boot) and
any v5.19-class probe redesign. Scope failure writes STOP like every r6
stage: any exception outside success receipts failure status + STOP before
raising; one exclusive attempt; the packet never replays.
"""
import asyncio
import base64
import hashlib
import json
import re
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
from deploy import Deployment
import recovery
from stage_lib import (agent_log_lines, capture, record_failure, fields, marker_for,
                       log, OneAttempt, protect_seal, refuse_if_stopped,
                       sdk_state, succeed, protected_hashes,
                       gate_event_assessment, boot_clock, GATE_EVENT_SHAPES, UEP_STATE)
from samsung_tv_root.archive_root import _prepare_artifacts
from samsung_tv_root.root_agent import RootAgentServer, generate_secret

STAGE = 'LIVE_ARM_REMOVE'
STATUS = 'stage-status-remove.json'
KIND = 'remove'
POLL_SECONDS = 15
AWAIT_BOOT_DEADLINE = 8 * 60 * 60
# The manager app writes its boot gate line on its own startup schedule, which
# is independent of tvroot-bridge.service (the boot poll below only proves the
# BRIDGE is up). The required absent-config line is therefore waited for, with
# a bounded number of probes (~3 minutes at POLL_SECONDS); a single-shot read
# would race the manager's boot path and burn the packet.
BOOT_GATE_PROBES = 12


def prerequisites():
    refuse_if_stopped()
    receipt = json.loads((p.HERE / 'deployment-result.json').read_text(encoding='utf-8'))
    p.require(receipt.get('installed') is True and receipt.get('sha256') == p.DEPLOY_RECEIPT_SHA,
              'r1 deploy receipt missing or wrong; stage 1 provenance required')
    p.require(receipt.get('boot') == p.DEPLOY_RECEIPT_BOOT, 'r1 deploy receipt boot mismatch')
    p.require(p.BOOT is not None, 'the fresh r7 inspection must establish the current boot')
    dirread = json.loads((p.HERE / 'r6-stage-status-dirread.json').read_text(encoding='utf-8'))
    p.require(dirread.get('stage') == 'dirread',
              'r6 provenance unavailable: no dirread stage status; STOP')
    log('remove-prerequisites-verified', inspection_boot=p.BOOT)


async def read_proof(sdk, receipted_digest=None):
    """Consume the automatic proof as ONE normalized base64 line (r6 activate)."""
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


async def assert_flag_read(sdk, fingerprint):
    out = await capture(sdk, 'fdet-flag-read',
                        '/usr/bin/dotnet ' + p.FDET_HOME + '/FdetProbe.dll rw ' + p.UEP_PAGE + ' 4')
    lines = out.splitlines()
    p.require(len(lines) == 2, 'stalled or malformed fdet read')
    p.require(lines[0] == 'read_words physical=' + p.UEP_PAGE + ' page=0x208c2000 offset=0x6c0 words=4',
              'unexpected fdet header')
    p.require(lines[1] == 'words word=0 ' + fingerprint, 'flag state mismatch; STOP: ' + lines[1][:60])


async def await_boot_gate(sdk, fresh_boot):
    """Bounded wait for THIS boot's absent-config gate line, then assess it.

    tvroot-bridge.service and the manager app start independently: the boot
    poll proves only that the bridge accepts SDK work. The manager writes its
    gate line when its own boot path reaches RunUepGate, so a single-shot read
    races that startup. The required shape is polled for a bounded number of
    probes; gate exceptions, malformed timestamps and ANY unexpected current-
    boot gate line still stop the stage immediately for owner review.
    """
    for attempt in range(1, BOOT_GATE_PROBES + 1):
        lines = await agent_log_lines(sdk, 200)
        boot_epoch, epoch = await boot_clock(sdk)
        gate = gate_event_assessment(lines, 'remove', needle_required=False,
                                     regime='legacy', boot_epoch=boot_epoch,
                                     epoch_at_fetch=epoch)
        if all(any(shape.search(line) for line in gate)
               for shape in GATE_EVENT_SHAPES['remove']):
            log('absent-boot-gate-observed', boot=fresh_boot, attempts=attempt,
                gate_lines=len(gate))
            return gate
        log('absent-boot-gate-pending', boot=fresh_boot, attempts=attempt)
        if attempt < BOOT_GATE_PROBES:
            await asyncio.sleep(POLL_SECONDS)
    raise p.Stop('the absent-config boot gate line is missing after '
                 + str(BOOT_GATE_PROBES) + ' probes; the removal stage cannot continue')


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


class RemoveSession(Deployment):
    GATE_OP = 'gate-remove'
    MATERIALS = Path(p.HERE / 'execution/gate-materials-remove')

    async def run(self):
        # Verbatim r6 DirRead staging path (recovery relay, transport, root
        # agent session, phase1 snapshot); only the gate op differs.
        p.require(not await self.sdk.present(), 'SDK slot present')
        self.owned_sdk = True
        await self.sdk.connect()
        await self.baseline()
        await self.check_runtime()
        self.baseline_passed = True
        self.recovery_attempted = True
        self.recovery_receipt = await recovery.start(self.sdk, self.save)
        await recovery.validate(self.sdk, self.save, self.recovery_receipt)
        self.disconnected = True
        await self.sdk.disconnect()
        self.sdk = BridgeSDK(save, port=recovery.PORT)
        await self.sdk.connect()
        self.disconnected = False
        await self.baseline()
        self.save('recovery-sdk-verified', port=recovery.PORT)
        secret = generate_secret()
        self.server = RootAgentServer(p.PC, 0, p.TV, secret, require_root=True)
        await self.server.start()
        self.materials = self.MATERIALS
        p.make_private_directory(self.materials)
        _prepare_artifacts(self.materials, '3.1', p.PKG, p.PC,
                           self.server.listening_port, secret)
        (self.materials / 'launcher.log').touch(exist_ok=False)
        assets = {'stage.sh': p.HERE / 'stage.sh',
                  'manager.dll': p.HERE / 'artifacts/manager.dll',
                  'SamsungTvArchiveRoot.dll': p.LAUNCHER,
                  'SamsungTvRootAgent.dll': p.HERE / 'build/SamsungTvRootAgent.dll',
                  'FdetProbe.dll': p.FDET_PROBE,
                  'FdetProbe.runtimeconfig.json': p.FDET_RUNTIMECONFIG}
        for name in sorted(p.MATERIALS - {'private.pem', 'files.sha256'}):
            assets[name] = self.materials / name
        with (self.materials / 'files.sha256').open('x', encoding='ascii', newline='\n') as stream:
            for name, path in assets.items():
                stream.write(p.digest(path) + '  ' + name + '\n')
        import stage_transport
        await stage_transport.stage_files(self, {'files.sha256': self.materials / 'files.sha256', **assets})
        await self.current()
        await self.control('launch')
        self.connection = await self.server.accept(30)
        self.agent_pid = self.connection.identity.pid
        p.require(self.agent_pid > 1, 'invalid root PID')
        await self.root_snapshot(self.expected_boot)
        self.save('gate-config-intent', op='gate-remove:' + self.expected_boot, boot=self.expected_boot)
        await self.run_gate()

    async def root_snapshot(self, expected_boot):
        result = await self.connection.execute('phase1-snapshot', 12)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr,
                  'root snapshot failed')
        value = fields(result.stdout)
        p.require(value['agent'] == str(self.agent_pid) and value['boot'] == expected_boot,
                  'root identity/boot mismatch')
        p.require(value['uid'].split() == value['gid'].split() == ['0'] * 4,
                  'complete root identity missing')
        p.require(value['label'] == 'User' and value['Seccomp'] == value['NoNewPrivs'] == '0',
                  'root context changed')
        INITIAL = p.inspection()
        p.require(value['ip'] == INITIAL['ip'] and value['mode'] == INITIAL['mode'],
                  'root settings changed')
        for ns in ('pid', 'user'):
            p.require(value['caller_' + ns] == value['init_' + ns], 'root namespace changed')
        p.require(value['caller_mnt'] != value['init_mnt'], 'private root mount missing')
        for key, path in (('host_passwd', '/etc/passwd'), ('host_key', '/usr/share/sdbd/public.pem')):
            p.require(value[key] == p.BASE['files'][path] + '  /proc/1/root' + path,
                      'global system hash drift')
        self.save('root-context-verified', snapshot=result.stdout)

    async def run_gate(self):
        # The expected boot travels through the authenticated op command; the
        # r7 root agent asserts it inside the root shell before the removal.
        result = await self.connection.execute('gate-remove:' + self.expected_boot, 12)
        self.save('gate-remove-receipt', exit=result.exit_code, timed_out=result.timed_out,
                  stdout=result.stdout, stderr=result.stderr)
        p.require(result.exit_code == 0 and not result.timed_out and not result.stderr
                  and 'GATE_CONFIG_REMOVED_COMPLETE\n' in result.stdout,
                  'gate-remove did not complete; no retry')
        p.require(re.search(r'^GATE_ABSENT$', result.stdout, re.M), 'removal must end absence-verified')


async def main():
    marker_for(STAGE)
    protect_seal()
    prerequisites()
    attempt = OneAttempt(STAGE)
    attempt.take()
    try:
        # Preflight (SDK only): the r6-configured read-only state is the exact
        # and only input. Anything else refuses BEFORE the root session.
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            state = await sdk_state(sdk, 'remove-baseline-state')
            p.require(state['boot'] == p.BOOT,
                      'boot left the inspected boot; re-inspect before removal; STOP')
            p.require(state['gate_state'] == 'absent',
                      'the budget state file pre-exists; the r6 dirread state changed; STOP')
            await protected_hashes(sdk)
            content = await capture(sdk, 'gate-config-content', 'cat -- ' + p.UEP_CONFIG)
            p.require(content == p.UEP_READONLY_CONTENT,
                      'the gate config is not the verified read-only content; the removal stage refuses; STOP')
            meta = fields(await capture(sdk, 'gate-config-meta', (
                "printf 'meta='; stat -c '%u:%g:%a:%h' -- " + p.UEP_CONFIG + "\n"
                "printf 'label='; chsmack " + p.UEP_CONFIG + "\n")))
            p.require(meta['meta'] == '0:0:644:1', 'gate config metadata changed; STOP')
            p.require(meta['label'] == p.UEP_LABEL, 'gate config label changed; STOP')
            # Strict absence (no fallback echo): an unreadable pre-existing
            # state file must NOT be mistaken for absence. sdk_state.'s -e/-L
            # probe above already characterized presence; this is the receipt.
            stale_pre = (await capture(sdk, 'gate-state-pre',
                                       'test ! -e ' + UEP_STATE + ' && test ! -L ' + UEP_STATE
                                       + ' && echo plain-absent')).strip()
            p.require(stale_pre == 'plain-absent',
                      'the budget state file pre-exists or is alien-shaped; the r6 dirread state changed; STOP')
            await read_proof(sdk, p.PROOF_SHA)
        finally:
            await sdk.disconnect()
        session = RemoveSession(BridgeSDK(save), save, p.BOOT, p.PROOF_SHA)
        try:
            await session.run()
        finally:
            await session.finish()
        p.require(not session.cleanup_pending and not session.close_errors,
                  'gate closeout incomplete; retain evidence')
        prior_boot = p.BOOT
        # Relay teardown after root shutdown + ordinary verification.
        sdk = BridgeSDK(save)
        try:
            await sdk.connect()
            session.sdk = sdk
            await session.baseline()
            state = await sdk_state(sdk, 'remove-post-op')
            p.require(state['gate_config'] == 'absent', 'gate config present after removal; STOP')
            p.require(state['gate_state'] == 'absent', 'budget state file exists after removal; STOP')
            p.require(state['boot'] == prior_boot, 'boot identity changed during removal; STOP')
        finally:
            await sdk.disconnect()
        fresh = await await_new_boot(prior_boot)
        p.require(fresh is not None,
                  'no new boot within the awaiting bound; config is absent, current enforcement unverified; STOP')
        p.require(fresh != prior_boot, 'the removal must be observed on a distinct boot')
        sdk = BridgeSDK(save)
        terminal = False
        try:
            await sdk.connect()
            post = await sdk_state(sdk, 'remove-post-boot')
            p.require(post['boot'] == fresh, 'boot poll lost the fresh boot')
            p.require(post['gate_config'] == 'absent', 'gate config reappeared; STOP')
            await protected_hashes(sdk)
            proof_text, proof_digest = await read_proof(sdk)
            assert_proof(fresh, proof_text)
            # Bounded wait: the manager app writes its boot gate line on its own
            # startup schedule, independent of the bridge service the poll above
            # watched (see await_boot_gate).
            await await_boot_gate(sdk, fresh)
            # The budget state file: read it ONLY if it actually exists, with
            # no fallback echo — an unreadable state file stops the stage
            # (capture refuses non-zero exits), never masquerades as absence.
            if post['gate_state'] == 'present':
                stale = (await capture(sdk, 'gate-state-post', 'cat -- ' + UEP_STATE)).strip()
                stale_boot = re.fullmatch(r'boot=([0-9a-f-]{36}) clear=[12] restore=[01]', stale)
                p.require(stale_boot is not None,
                          'budget state does not match the documented shape; STOP: ' + stale[:80])
                p.require(stale_boot[1] != fresh,
                          'budget state claims the fresh boot; the absent-config path must not have touched it')
                log('remove-stale-budget-verified', claimed_boot=stale_boot[1])
            else:
                log('remove-budget-absent-verified')
            await assert_flag_read(sdk, p.FINGERPRINT)
            end = await sdk_state(sdk, 'remove-final')
            await protected_hashes(sdk)
            p.require(post['boot'] == end['boot'] == fresh, 'boot changed inside the removal stage')
            p.require(end['gate_config'] == 'absent' and end['gate_state'] == 'absent',
                      'final state drifted (config or budget state re-appeared); STOP')
            succeed(STAGE, STATUS, KIND, fresh_boot=fresh, fresh_proof_sha256=proof_digest,
                    attempt_utc=attempt.path.read_text().strip())
            # Terminal stage of the packet: write the one-use receipt.
            (p.HERE / 'SPENT').write_text('The gate config was removed and the enforcing-only '
                                          'baseline re-verified; the packet never replays.\n',
                                          encoding='ascii', newline='\n')
            terminal = True
            log('packet-spent', stage=KIND)
        finally:
            # A close failure AFTER the terminal receipt must never rewrite the
            # packet as failed (SPENT + STOP + passed:false); the passed status
            # and the consumed marker are already durable here. Before the
            # receipt, a close failure is a real stage failure and propagates.
            try:
                await sdk.disconnect()
            except Exception as close_error:
                if not terminal:
                    raise
                log('post-spent-sdk-close-failed', error=type(close_error).__name__,
                    reason=str(close_error)[:200])
    except BaseException as error:
        record_failure(STAGE, STATUS, KIND, type(error).__name__ + ': ' + str(error)[:400])
        raise


if __name__ == '__main__':
    asyncio.run(main())
