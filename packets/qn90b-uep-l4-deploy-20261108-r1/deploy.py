import asyncio
import base64
import json
import os
import shutil
import subprocess
from pathlib import Path
import sys
sys.dont_writebytecode = True
import packet as p
from inspect_tv import BridgeSDK, save
from trial import Trial
from samsung_tv_root.archive_root import _prepare_artifacts
from samsung_tv_root.root_agent import RootAgentServer, generate_secret
import recovery

INITIAL = json.loads((p.HERE / 'inspection.json').read_text())
OP = json.loads((p.HERE / 'operation.json').read_text())

def fields(text):
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        p.require(sep and key not in result, 'malformed snapshot')
        result[key] = value
    return result

class Deployment(Trial):
    applied = False
    recovery_receipt = None

    async def current(self):
        result = fields(await self.read('current-boot', "printf 'uid='; id -u; printf 'boot='; cat /proc/sys/kernel/random/boot_id; printf 'ip='; buxton2ctl get system db/sdk/develop/ip; printf 'mode='; buxton2ctl get system db/sdk/develop/mode"))
        p.require(result['uid'] == '901' and result['boot'] == p.BOOT, 'SDK identity or boot changed')
        p.require(result['ip'] == INITIAL['ip'] and result['mode'] == INITIAL['mode'], 'settings changed')

    async def baseline(self):
        await self.current()
        expected = base64.b64decode(INITIAL['hashes']).decode().strip()
        p.require(await self.read('protected-hashes','sha256sum '+' '.join(p.EXPECTED)) == expected, 'protected file drift')
        manager = p.NEW_SHA if self.applied else p.OLD_SHA
        p.require(await self.read('manager-hash','sha256sum '+p.TARGET) == manager+'  '+p.TARGET,'manager hash drift')
        p.require(await self.read('bridge-active','systemctl is-active tvroot-bridge.service') == 'active','bridge inactive')
        p.require(await self.read('proof-hash','sha256sum '+p.EV+'/selfroot-proof.txt') == INITIAL['proof_hash'],'automatic proof changed')
        p.require(await self.read('pairing-hash','sha256sum /opt/usr/share/selfroot/bridge.conf') == INITIAL['pairing_hash'],'pairing hash changed')
        p.require(base64.b64decode(await self.read('service-unit',"systemctl cat tvroot-bridge.service | base64 | tr -d '\\n'")) == base64.b64decode(INITIAL['unit']),'service unit changed')
        p.require(await self.read('startup',p.tools.STARTUP) == INITIAL['startup'],'startup changed')
        p.require(await self.read('port-config','test ! -e /opt/usr/share/selfroot/bridge-port.conf && test ! -L /opt/usr/share/selfroot/bridge-port.conf && echo absent') == 'absent','port configuration changed')
        self.save('baseline-passed',boot=p.BOOT,manager_sha=manager)

    async def run(self):
        p.require(not await self.sdk.present(),'SDK slot present')
        self.owned_sdk = True
        await self.sdk.connect()
        await self.baseline()
        await self.check_runtime()
        self.baseline_passed = True
        self.recovery_receipt = await recovery.start(self.sdk,self.save)
        await recovery.validate(self.sdk,self.save,self.recovery_receipt)
        self.disconnected = True
        await self.sdk.disconnect()
        self.sdk = BridgeSDK(self.save,port=recovery.PORT)
        await self.sdk.connect()
        self.disconnected = False
        await self.baseline()
        self.save('recovery-sdk-verified',port=recovery.PORT)
        secret = generate_secret()
        self.server = RootAgentServer(p.PC,0,p.TV,secret,require_root=True)
        await self.server.start()
        self.materials = p.HERE/'execution/materials'
        p.make_private_directory(self.materials)
        _prepare_artifacts(self.materials,'3.1',p.PKG,p.PC,self.server.listening_port,secret)
        (self.materials/'launcher.log').touch(exist_ok=False)
        assets = {'stage.sh':p.HERE/'stage.sh','manager.dll':p.HERE/'manager.dll','SamsungTvArchiveRoot.dll':p.LAUNCHER,'SamsungTvRootAgent.dll':p.HERE/'build/SamsungTvRootAgent.dll'}
        assets['FdetProbe.dll'] = p.FDET_PROBE
        assets['FdetProbe.runtimeconfig.json'] = p.FDET_RUNTIMECONFIG
        for name in sorted(p.MATERIALS-{'private.pem','files.sha256'}):
            assets[name] = self.materials/name
        manifest = self.materials/'files.sha256'
        with manifest.open('x',encoding='ascii',newline='\n') as stream:
            for name,path in assets.items(): stream.write(p.digest(path)+'  '+name+'\n')
        import stage_transport
        await stage_transport.stage_files(self, {'files.sha256':manifest,**assets})
        await self.current()
        await self.control('launch')
        self.connection = await self.server.accept(30)
        self.agent_pid = self.connection.identity.pid
        p.require(self.agent_pid>1,'invalid root PID')
        result = await self.connection.execute('phase1-snapshot',12)
        p.require(result.exit_code==0 and not result.timed_out and not result.stderr,'root snapshot failed')
        value = fields(result.stdout)
        p.require(value['agent']==str(self.agent_pid) and value['boot']==p.BOOT,'root identity/boot mismatch')
        p.require(value['uid'].split()==value['gid'].split()==['0']*4,'complete root identity missing')
        p.require(value['label']=='User' and value['Seccomp']==value['NoNewPrivs']=='0','root context changed')
        p.require(value['ip']==INITIAL['ip'] and value['mode']==INITIAL['mode'],'root settings changed')
        for ns in ('pid','user'): p.require(value['caller_'+ns]==value['init_'+ns],'root namespace changed')
        p.require(value['caller_mnt']!=value['init_mnt'],'private root mount missing')
        for key,path in (('host_passwd','/etc/passwd'),('host_key','/usr/share/sdbd/public.pem')):
            p.require(value[key]==p.BASE['files'][path]+'  /proc/1/root'+path,'global system hash drift')
        self.save('root-context-verified',snapshot=result.stdout)
        self.save('manager-update-intent',**OP)
        try:
            result = await self.connection.execute('manager-apply',12)
            self.save('manager-update-receipt',exit=result.exit_code,timed_out=result.timed_out,stdout=result.stdout,stderr=result.stderr)
            p.require(result.exit_code==0 and not result.timed_out and not result.stderr and 'MANAGER_UPDATE_COMPLETE\n' in result.stdout,'manager update did not verify; no retry')
            self.applied = True
            fdet = await self.connection.execute('fdet-install',12)
            self.save('fdet-install-receipt',exit=fdet.exit_code,timed_out=fdet.timed_out,stdout=fdet.stdout,stderr=fdet.stderr)
            p.require(fdet.exit_code==0 and not fdet.timed_out and not fdet.stderr and 'FDET_INSTALL_COMPLETE\n' in fdet.stdout,'fdet payload deployment failed; no retry; rollback follows')
            p.EXPECTED.update(p.FDET_EXPECT)
            self.fdets = True
            self.save('sdk-verification-deferred-until-root-close')
        except Exception:
            status = await self.connection.execute('manager-status',12)
            self.save('manager-failure-status',exit=status.exit_code,timed_out=status.timed_out,stdout=status.stdout,stderr=status.stderr)
            if p.NEW_SHA in status.stdout:
                rollback = await self.connection.execute('manager-rollback',12)
                self.save('manager-rollback',exit=rollback.exit_code,timed_out=rollback.timed_out,stdout=rollback.stdout,stderr=rollback.stderr)
                p.require(rollback.exit_code==0 and not rollback.timed_out and not rollback.stderr and 'MANAGER_ROLLBACK_COMPLETE\n' in rollback.stdout,'rollback incomplete')
            raise
        print(json.dumps({'installed':True,'sha256':p.NEW_SHA,'boot':p.BOOT,'backup':p.BACKUP}),flush=True)

async def main():
    p.require((p.HERE/'LIVE_ARM_DEPLOY').is_file() and (p.HERE/'LIVE_ARM_DEPLOY').read_text()==p.COMMIT+'\n'+p.NEW_SHA+'\n','explicit live deploy approval has not been recorded for this artifact')
    p.require(not (p.HERE/'execution').exists() and not (p.HERE/'SPENT').exists(),'one-use packet consumed; never replay')
    p.require(p.digest(p.SSL)==p.BASE['tools']['GitOpenSSL'],'verified OpenSSL changed')
    os.environ['PATH']=str(p.SSL.parent)+os.pathsep+os.environ.get('PATH','')
    p.require(Path(shutil.which('openssl') or '').resolve()==p.SSL.resolve(),'OpenSSL resolution mismatch')
    subprocess.run([str(p.SSL),'version'],check=True,capture_output=True,timeout=10)
    p.require(p.digest(p.HERE/'manager.before.dll')==p.OLD_SHA and p.digest(p.HERE/'manager.dll')==p.NEW_SHA,'manager/recovery artifact changed')
    for name,checksum in json.loads((p.HERE/'seal.json').read_text()).items():
        p.require(p.digest(p.HERE/name)==checksum,'sealed packet changed: '+name)
    p.tools.local_checks()
    p.make_private_directory(p.HERE/'execution')
    deployment = Deployment(BridgeSDK(save),save)
    try:
        await deployment.run()
    finally:
        await deployment.finish()
        with (p.HERE/'SPENT').open('x',encoding='ascii') as stream:
            stream.write('One-use deployment consumed; never replay.\n')
        save('deployment-closeout',applied=deployment.applied,cleanup_pending=deployment.cleanup_pending,close_errors=deployment.close_errors)
        p.require(not deployment.cleanup_pending and not deployment.close_errors,'closeout incomplete; retain evidence')
    sdk = BridgeSDK(save)
    try:
        await sdk.connect()
        deployment.sdk = sdk
        await deployment.baseline()
        await recovery.stop(sdk,save,deployment.recovery_receipt)
        await deployment.baseline()
    finally:
        await sdk.disconnect()
    with (p.HERE/'deployment-result.json').open('x',encoding='utf-8') as stream:
        json.dump({'installed':True,'sha256':p.NEW_SHA,'boot':p.BOOT,'backup':p.BACKUP,'recovery_removed':True,'cleanup_pending':[],'UI_launches':0,'reboots':0},stream,indent=2)
    print(json.dumps({'deployment':'verified','recovery_removed':True,'cleanup_pending':[]}),flush=True)

if __name__=='__main__': asyncio.run(main())
