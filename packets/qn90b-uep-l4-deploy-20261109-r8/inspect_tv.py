import asyncio
import base64
import json
import os
import re
import sys
from datetime import datetime, timezone
from shlex import quote
sys.dont_write_bytecode = True
import packet as p
from sdk import DirectSDK
from samsung_tv_root.sdb import SdbBridgeProxy, SdbClient, route_callback_host


def save(event, **data):
    with (p.HERE / 'receipts.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps(dict(utc=datetime.now(timezone.utc).isoformat(), event=event, **data)) + '\n')
        stream.flush()
        os.fsync(stream.fileno())


class BridgeSDK(DirectSDK):
    def __init__(self, save, port=26103):
        self.bridge_port = port
        super().__init__(save)
        self.proxy = None
        self.open_proxy()

    def open_proxy(self):
        p.require(self.proxy is None, 'proxy already open')
        proxy = SdbBridgeProxy(p.TV, self.bridge_port, p.token())
        proxy.start()
        self.proxy = proxy
        class OwnedClient(SdbClient):
            @property
            def serial(self):
                return proxy.serial
        self.client = OwnedClient(p.SDB, p.TV, timeout=12)

    async def connect(self):
        if self.proxy is None:
            self.open_proxy()
        await super().connect()

    async def disconnect(self):
        if self.proxy is None:
            return
        try:
            await super().disconnect()
        finally:
            self.proxy.close()
            self.proxy = None


async def capture(sdk, command):
    code, output = await sdk.capture(command)
    p.require(code == 0, 'SDK read failed: ' + output[:200])
    return output


PROBE = r'''set -eu
printf 'uid='; id -u
printf 'boot='; cat /proc/sys/kernel/random/boot_id
printf 'uptime='; cat /proc/uptime
printf 'firmware='; cat /etc/os-release /etc/tizen-release | base64 | tr -d '\n'; echo
printf 'ip='; buxton2ctl get system db/sdk/develop/ip
printf 'mode='; buxton2ctl get system db/sdk/develop/mode
printf 'root='; readlink -f /home/owner/share/tmp/sdk_tools
printf 'app='; readlink -f /opt/usr/apps/com.samsung.tv.ghservice
printf 'target='; readlink -f /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
printf 'target_meta='; stat -c '%F:%d:%i:%u:%g:%a:%h:%s' /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
printf 'label='; chsmack /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
printf 'hash='; sha256sum /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
printf 'service='; systemctl is-active tvroot-bridge.service
printf 'proof='; base64 < /home/owner/share/tmp/sdk_tools/selfroot-evidence/selfroot-proof.txt | tr -d '\n'; echo
printf 'proof_mtime='; stat -c %Y /home/owner/share/tmp/sdk_tools/selfroot-evidence/selfroot-proof.txt
printf 'epoch='; date +%s
printf 'startup='; sqlite3 -readonly /opt/dbspace/.pkgmgr_parser.db "SELECT app_component,app_onboot,app_nodisplay FROM package_app_info WHERE app_id='com.samsung.tv.ghservice'"
printf 'runtime='; readlink -f /usr/share/dotnet.tizen/netcoreapp
printf 'caps='; getcap /usr/bin/dotnet /usr/sbin/sdbd-tarlauncher | base64 | tr -d '\n'; echo
printf 'proof_hash='; sha256sum /home/owner/share/tmp/sdk_tools/selfroot-evidence/selfroot-proof.txt
printf 'pairing_hash='; sha256sum /opt/usr/share/selfroot/bridge.conf
printf 'unit='; systemctl cat tvroot-bridge.service | base64 | tr -d '\n'; echo
printf 'port_config='; if test -e /opt/usr/share/selfroot/bridge-port.conf || test -L /opt/usr/share/selfroot/bridge-port.conf; then test ! -L /opt/usr/share/selfroot/bridge-port.conf; test -f /opt/usr/share/selfroot/bridge-port.conf; test "$(stat -c %s /opt/usr/share/selfroot/bridge-port.conf)" -le 64; base64 /opt/usr/share/selfroot/bridge-port.conf | tr -d '\n'; echo; else echo absent; fi
printf 'agent_log_size='; stat -c %s /home/owner/share/tmp/sdk_tools/selfroot-evidence/agent.log
printf 'manager_pids='; pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll' | tr '\n' ','; echo
printf 'selfroot_meta='; stat -c '%F:%d:%i:%u:%g:%a:%h:%s' /opt/usr/share/selfroot
printf 'selfroot_label='; chsmack /opt/usr/share/selfroot | sed -n 's/.*access="\(.*\)"/\1/p'
printf 'bridge_meta='; stat -c '%F:%d:%i:%u:%g:%a:%h:%s' /opt/usr/share/selfroot/bridge.conf
printf 'bridge_label='; chsmack /opt/usr/share/selfroot/bridge.conf | sed -n 's/.*access="\(.*\)"/\1/p'
printf 'gate_config=%s\n' "$(if test -L /opt/usr/share/selfroot/uep-off.conf; then echo symlink; elif test -e /opt/usr/share/selfroot/uep-off.conf; then echo present; else echo absent; fi)"
printf 'gate_hash=%s\n' "$(test -e /opt/usr/share/selfroot/uep-off.conf && test ! -L /opt/usr/share/selfroot/uep-off.conf && sha256sum /opt/usr/share/selfroot/uep-off.conf | base64 | tr -d '\n' || true)"
printf 'gate_meta=%s\n' "$(test -e /opt/usr/share/selfroot/uep-off.conf && test ! -L /opt/usr/share/selfroot/uep-off.conf && stat -c '%F:%u:%g:%a:%h' -- /opt/usr/share/selfroot/uep-off.conf || true)"
printf 'gate_label=%s\n' "$(test -e /opt/usr/share/selfroot/uep-off.conf && test ! -L /opt/usr/share/selfroot/uep-off.conf && chsmack /opt/usr/share/selfroot/uep-off.conf || true)"
printf 'gate_state=%s\n' "$(if test -e /opt/usr/share/selfroot/uep-state.conf || test -L /opt/usr/share/selfroot/uep-state.conf; then echo present; else echo absent; fi)"
printf 'fdet_home='; if test -e /opt/usr/share/selfroot/fdetprobe || test -L /opt/usr/share/selfroot/fdetprobe; then echo present; else echo absent; fi
'''


async def main():
    p.require(not (p.HERE / 'inspection.json').exists(), 'inspection already captured')
    for packet_marker in ('STOP', 'SPENT'):
        p.require(not (p.HERE / packet_marker).is_file(),
                  'the packet is stopped or spent; no TV contact is authorized: ' + packet_marker)
    p.require(route_callback_host(p.TV) == p.PC, 'callback route changed')
    p.private_acl(p.HERE)
    targets = p.inspection_targets()
    for path in targets:
        p.require(re.fullmatch(r'/[A-Za-z0-9_./+-]+', path), 'invalid protected path')
    probe = PROBE + "printf 'hashes='; sha256sum " + ' '.join(map(quote, targets)) + " | base64 | tr -d '\\n'; echo\n"
    sdk = BridgeSDK(save)
    try:
        p.require(not await sdk.present(), 'owned proxy SDK slot already present')
        await sdk.connect()
        fields = {}
        for line in (await capture(sdk, probe)).splitlines():
            key, sep, value = line.partition('=')
            p.require(sep and key not in fields, 'malformed probe response')
            fields[key] = value
        p.require(fields['uid'] == '901', 'SDK identity mismatch')
        p.require(base64.b64decode(fields['firmware']).decode().strip() == p.BASE['firmware'], 'firmware changed')
        p.require(fields['ip'] == '[system] db/sdk/develop/ip = String: 127.0.0.1' and fields['mode'] == '[system] db/sdk/develop/mode = Int32: 1', 'developer settings changed')
        p.require(fields['root'] == p.CANON and fields['app'] == p.APP and fields['target'] == p.TARGET, 'path redirected')
        p.require(fields['hash'] == p.NEW_SHA + '  ' + p.TARGET, 'installed manager differs from the r1-installed v5.18; STOP')
        p.require(fields['target_meta'].startswith('regular file:') and fields['target_meta'].split(':')[-2] == '1', 'target type/link mismatch')
        p.require(fields['label'] == p.TARGET + ' access="User::Pkg::com.samsung.tv.ghservice::RO"', 'relay label changed')
        p.require(fields['service'] == 'active' and fields['startup'] == 'uiapp|true|false', 'service/startup mismatch')
        p.require(fields['runtime'].endswith('/3.1.3'), 'runtime mismatch')
        p.require(fields['port_config'] == 'absent' or base64.b64decode(fields['port_config']).decode().strip() == '26103', 'configured port would change management endpoint; STOP')
        proof = base64.b64decode(fields['proof']).decode()
        p.require(re.findall(r'(?m)^BOOT_ID=([^\r\n]+)', proof) == [fields['boot']], 'automatic proof does not match current boot')
        p.require('SELFROOT-PROOF uid=0 gid=0' in proof, 'automatic root header missing')
        for field in ('Uid','Gid'):
            p.require(re.findall(r'(?m)^' + field + r':[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]+(\d+)[ \t]*\r?$', proof) == [('0','0','0','0')], 'automatic proof lacks full zero identity')
        p.require(int(fields['proof_mtime']) > int(fields['epoch']) - float(fields['uptime'].split()[0]) - 5, 'proof predates current boot')
        expected = '\n'.join(p.INHERITED[path] + '  ' + path for path in sorted(targets))
        p.require(base64.b64decode(fields['hashes']).decode().strip() == expected, 'protected file or fdet/relay hash drift; STOP')
        # r7 pins the captured boot/proof itself: the TV may have rebooted since
        # r6's consumption, and no stale pin may silently bind this inspection to
        # a provenance boot. The fresh capture becomes the packet identity.
        p.require(not fields['manager_pids'], 'manager is running; wait for natural exit')
        p.require(re.fullmatch(r'directory:(?:[0-9]+:){6}[0-9]+', fields['selfroot_meta']), 'unexpected selfroot reference metadata; STOP')
        p.require(re.fullmatch(r'[A-Za-z0-9:_-]{1,64}', fields['selfroot_label']), 'unexpected selfroot label; STOP')
        p.require(re.fullmatch(r'regular file:(?:[0-9]+:){6}[0-9]+', fields['bridge_meta']), 'unexpected bridge reference metadata; STOP')
        p.require(re.fullmatch(r'[A-Za-z0-9:_-]{1,64}', fields['bridge_label']), 'unexpected bridge label; STOP')
        # The r6 dirread stage left the read-only gate config behind; that exact
        # state (content, content hash, metadata, smack label) and an absent
        # budget state file are what this packet removes.
        p.require(fields['gate_config'] == 'present',
                  'the r6-created read-only gate config is not present (observed: '
                  + (fields['gate_config'] or 'empty') + '); the removal stage cannot anchor; STOP')
        gate_hash_line = base64.b64decode(fields['gate_hash']).decode().strip()
        p.require(gate_hash_line.partition('  ')[0] == p.UEP_READONLY_SHA, 'gate config content is not the verified read-only bytes; STOP')
        gate_first_hash = gate_hash_line.partition('  ')[0]
        p.require(fields['gate_meta'] == p.UEP_META, 'gate config metadata changed since the r6 dirread; STOP: ' + fields['gate_meta'])
        p.require(fields['gate_label'] == p.UEP_LABEL, 'gate config label changed since the r6 dirread; STOP')
        p.require(fields['gate_state'] == 'absent', 'the budget state file exists before removal; STOP')
        p.require(fields['fdet_home'] == 'present', 'fdet probe home missing; it was installed by r1 stage 1; STOP')
        for path in (p.KEEP_BACKUP, p.DEPLOY_BACKUP):
            p.require(await capture(sdk, 'test -e ' + quote(path) + ' && test ! -L ' + quote(path) + ' && echo present') == 'present', 'installed backup path changed: ' + path)
        p.require((await capture(sdk, "sha256sum " + quote(p.DEPLOY_BACKUP))).split()[0] == p.OLD_SHA, 'r1 stage-1 backup no longer holds the v5.17 bytes; STOP')
        p.require(await capture(sdk, 'test ! -e ' + quote(p.TEMP_L4) + ' && test ! -L ' + quote(p.TEMP_L4) + ' && echo absent') == 'absent', 'r1 staging temp still present; STOP')
        p.require(await capture(sdk, 'test ! -e ' + quote(p.ROLLBACK_L4) + ' && test ! -L ' + quote(p.ROLLBACK_L4) + ' && echo absent') == 'absent', 'r1 rollback temp still present; STOP')
        (p.HERE / 'inspection.json').write_text(json.dumps(fields, indent=2), encoding='utf-8')
        hashes = {}
        for line in base64.b64decode(fields['hashes']).decode().strip().splitlines():
            digest_value, sep, path = line.partition('  ')
            p.require(sep, 'malformed protected hash line')
            hashes[path] = digest_value
        register = {'files': dict(hashes), 'target': {p.TARGET: fields['hash'].split('  ')[0]}}
        register['files'][p.TARGET] = fields['hash'].split('  ')[0]
        register['captured'] = {'boot': fields['boot'], 'proof_hash': fields['proof_hash']}
        (p.HERE / 'protected-register.json').write_text(json.dumps(register, indent=2), encoding='utf-8')
        save('inspection-passed', boot=fields['boot'], metadata=fields['target_meta'], deployed_state_verified=True,
             protected_files=len(targets), proof_verified_before_host_root=True,
             gate_config='read-only', gate_hash=gate_first_hash,
             gate_state=fields['gate_state'])
        print(json.dumps({'inspection':'passed','boot':fields['boot'],'bridge':fields['service'],'manager_metadata':fields['target_meta'],'register':'fresh captured','port_config':fields['port_config'],'protected_files':len(targets),'gate':'read-only present'}), flush=True)
    finally:
        await sdk.disconnect()


if __name__ == '__main__':
    asyncio.run(main())
