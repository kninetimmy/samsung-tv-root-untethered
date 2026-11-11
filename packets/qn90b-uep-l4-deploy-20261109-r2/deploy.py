"""Corrected Deployment/baseline library for r2's stages; contains NO TV-touching
entrypoint of its own (stage 1 closed in r1 and is never replayed).

Fixes carried from the 2026-11-08 review:
- baseline compares the ACTUAL requested protected set as a path->hash mapping
  (r1 compared an enlarged request against the original 23-file snapshot,
  which made the post-install closeout unpassable and burned r1);
- boot and proof expectations are stage parameters, never baked globals, so
  stages that legitimately run after a reboot bind to their own validated
  receipts instead of the original packet boot;
- the fdet pair is part of the baseline from the start (it is already
  installed; nothing in this module installs anything).
"""
import base64
import re
import sys
from shlex import quote

sys.dont_write_bytecode = True
import packet as p
from trial import Trial
from inspect_tv import BridgeSDK
import recovery

INSPECTION = None

def initial_inspection():
    """The r2 inspection snapshot (boot, developer settings, reference metadata)."""
    global INSPECTION
    if INSPECTION is None:
        INSPECTION = p.inspection()
    return INSPECTION


def fields(text):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        p.require(sep and key not in result, 'malformed snapshot')
        result[key] = value
    return result


def parse_hash_output(output):
    """sha256sum response -> ordered path->digest mapping (fix for the r1 bug)."""
    got = {}
    for line in output.splitlines():
        digest, sep, path = line.partition('  ')
        p.require(sep and re.fullmatch(r'[0-9a-f]{64}', digest), 'malformed hash line: ' + line[:80])
        p.require(path not in got, 'duplicate protected path in response: ' + path[:120])
        got[path] = digest
    return got


class Deployment(Trial):
    applied = True   # installed state, not an action: the v5.18 manager is live

    def __init__(self, sdk, save, expected_boot, expected_proof_hash):
        super().__init__(sdk, save)
        p.require(isinstance(expected_boot, str) and re.fullmatch(
            r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', expected_boot),
            'missing or malformed stage boot anchor')
        p.require(isinstance(expected_proof_hash, str) and re.fullmatch(
            r'[0-9a-f]{64}', expected_proof_hash), 'missing or malformed stage proof anchor')
        self.expected_boot = expected_boot
        self.expected_proof_hash = expected_proof_hash
        self.recovery_attempted = False
        self.recovery_receipt = None

    async def current(self):
        result = fields(await self.read('current-boot', "printf 'uid='; id -u; printf 'boot='; cat /proc/sys/kernel/random/boot_id; printf 'ip='; buxton2ctl get system db/sdk/develop/ip; printf 'mode='; buxton2ctl get system db/sdk/develop/mode"))
        p.require(result['uid'] == '901', 'SDK identity mismatch')
        p.require(result['boot'] == self.expected_boot, 'SDK identity or boot changed from the stage-anchored boot')
        initial = initial_inspection()
        p.require(result['ip'] == initial['ip'] and result['mode'] == initial['mode'], 'settings changed')

    async def baseline(self):
        """The same session anchors apply during preflight and inherited cleanup."""
        await self.current()
        initial = initial_inspection()
        expected = p.expected_set()
        response = await self.read('protected-hashes',
                                   'sha256sum ' + ' '.join(map(quote, sorted(expected))))
        got = parse_hash_output(response)
        p.require(set(got) == set(expected), 'protected path set changed; STOP')
        drift = [path for path in expected if got[path] != expected[path]]
        p.require(not drift, 'protected file drift: ' + str(drift[:4]))
        p.require(await self.read('manager-hash', 'sha256sum ' + quote(p.TARGET))
                  == p.NEW_SHA + '  ' + p.TARGET, 'installed manager hash drift; STOP')
        p.require(await self.read('bridge-active', 'systemctl is-active tvroot-bridge.service') == 'active',
                  'bridge inactive')
        p.require(await self.read('proof-hash', 'sha256sum ' + quote(p.EV + '/selfroot-proof.txt'))
                  == self.expected_proof_hash + '  ' + p.EV + '/selfroot-proof.txt',
                  'automatic proof changed from the stage-anchored capture; STOP')
        p.require(await self.read('pairing-hash', 'sha256sum ' + quote('/opt/usr/share/selfroot/bridge.conf'))
                  == initial['pairing_hash'], 'pairing hash changed')
        p.require(base64.b64decode(await self.read('service-unit',
                                                   "systemctl cat tvroot-bridge.service | base64 | tr -d '\\n'"))
                  == base64.b64decode(initial['unit']), 'service unit changed')
        p.require(await self.read('startup', p.tools.STARTUP) == initial['startup'], 'startup changed')
        p.require(await self.read('port-config', 'test ! -e /opt/usr/share/selfroot/bridge-port.conf && test ! -L /opt/usr/share/selfroot/bridge-port.conf && echo absent') == 'absent',
                  'port configuration changed')
        self.save('baseline-passed', boot=self.expected_boot, manager_sha=p.NEW_SHA,
                  protected_files=len(expected))

    async def finish(self):
        await super().finish()
        if not self.recovery_attempted:
            return
        sdk = None
        try:
            p.require(not self.close_errors and not self.cleanup_pending,
                      'root closeout incomplete; retain the independent recovery relay')
            p.require(self.recovery_receipt is not None,
                      'recovery relay ownership receipt missing; retain for reviewed cleanup')
            sdk = BridgeSDK(self.save)
            await sdk.connect()
            self.sdk = sdk
            await self.baseline()
            await recovery.stop(sdk, self.save, self.recovery_receipt)
            self.recovery_receipt = None
            await self.baseline()
            self.save('closeout', name='recovery-relay', verified=True)
        except Exception as error:
            self.close_errors.append('recovery-relay')
            if self.recovery_receipt is not None or sdk is None:
                self.cleanup_pending.append(recovery.PATH)
            self.save('closeout', name='recovery-relay', verified=False,
                      error=type(error).__name__, reason=str(error),
                      cleanup_pending=list(self.cleanup_pending))
        finally:
            if sdk is not None:
                try:
                    await sdk.disconnect()
                except Exception as error:
                    self.close_errors.append('ordinary-sdk-close-after-recovery')
                    self.save('closeout', name='ordinary-sdk-close-after-recovery',
                              verified=False, error=type(error).__name__)
