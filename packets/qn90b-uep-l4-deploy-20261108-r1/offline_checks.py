import ast
import asyncio
import base64
import json
import subprocess
import packet as p
import sdk
from deploy import Deployment, INITIAL

checks = 0
def require(value, message):
    global checks
    p.require(value,message)
    checks += 1

for file in p.HERE.glob('*.py'):
    ast.parse(file.read_text(encoding='utf-8'),filename=str(file))
    checks += 1
for name in ('stage.sh','snapshot.sh','repair.sh','rollback.sh','status.sh','fdet.sh','gate-readonly.sh','gate-active.sh','gate-remove.sh'):
    file = p.HERE/name
    require(b'\r' not in file.read_bytes() and '@BOOT@' not in file.read_text(),'script not normalized/expanded')
    subprocess.run(['C:/Program Files/Git/bin/bash.exe','-n',str(file)],check=True,capture_output=True)
    checks += 1
repair = (p.HERE/'repair.sh').read_text()
fdet = (p.HERE/'fdet.sh').read_text()
require(repair.count('\nmanager_absent\n') == 2,'manager absence must be checked before mutation and replacement')
require(repair.index('cp -a -- "$target" "$backup"') < repair.index('cat '+p.STAGE+'/manager.dll > "$temp"') < repair.index('mv -T -- "$temp" "$target"'),'backup/verified temporary replacement order')
for token in ('FDET_INSTALL_COMPLETE','FDET_METADATA'):
    require(token in fdet, 'fdet install must receipt: '+token)
gate_markers = {'gate-readonly.sh':'GATE_CONFIG_READONLY_COMPLETE','gate-active.sh':'GATE_CONFIG_ACTIVE_COMPLETE','gate-remove.sh':'GATE_CONFIG_REMOVED_COMPLETE'}
for gate, marker in gate_markers.items():
    text = (p.HERE/gate).read_text()
    require(marker in text,'gate script must receipt: '+gate)
    require('GATE_METADATA' in text,'gate script must register metadata: '+gate)
require('gate-readonly.sh' in (p.HERE/'BridgeRepairAgent.cs').read_text() and 'fdet.sh' in (p.HERE/'BridgeRepairAgent.cs').read_text(),'root helper lacks the L4 ops')
require('fdet-install' in (p.HERE/'deploy.py').read_text(),'deploy wiring lacks the L4 fdet step')
require('FDET_EXPECT' in (p.HERE/'packet.py').read_text(),'expectations must merge the fdet hashes after install')
for path in (p.STAGE+'/../manager.dll','/tmp/manager.dll',p.STAGE+'/unlisted.dll'):
    try:
        sdk.prepare_upload(p.HERE/'status.sh',path,'9:9')
    except p.Stop:
        checks += 1
    else:
        raise p.Stop('unsafe upload target accepted')
for command in ('x\0y','x'*(sdk.MAX_SCRIPT+1)):
    try:
        sdk.script_payload(command,'0'*16)
    except ValueError:
        checks += 1
    else:
        raise p.Stop('invalid/oversized command accepted')

async def test_baseline(override=None, applied=False):
    deployment = Deployment(None,lambda *args,**kwargs:None)
    deployment.applied = applied
    replies = {
        'current-boot':'uid=901\nboot='+p.BOOT+'\nip='+INITIAL['ip']+'\nmode='+INITIAL['mode'],
        'protected-hashes':base64.b64decode(INITIAL['hashes']).decode().strip(),
        'manager-hash':(p.NEW_SHA if applied else p.OLD_SHA)+'  '+p.TARGET,
        'bridge-active':'active','proof-hash':INITIAL['proof_hash'],
        'pairing-hash':INITIAL['pairing_hash'],'service-unit':INITIAL['unit'],
        'startup':INITIAL['startup'],'port-config':'absent',
    }
    if override: replies.update(override)
    async def read(label,command): return replies[label]
    deployment.read = read
    await deployment.baseline()

async def verify_guards():
    global checks
    await test_baseline()
    await test_baseline(applied=True)
    checks += 2
    for override in ({'manager-hash':'changed'},{'proof-hash':'changed'},{'startup':'svcapp|true|true'},{'bridge-active':'inactive'},{'port-config':'configured'},{'protected-hashes':'changed'}):
        try:
            await test_baseline(override)
        except p.Stop:
            checks += 1
        else:
            raise p.Stop('baseline drift accepted')


import tempfile
from pathlib import Path
from shlex import quote
guard='manager_absent() {'+repair.split('manager_absent() {',1)[1].split('\n}',1)[0]+'\n}'
with tempfile.TemporaryDirectory(prefix='manager-guard-',dir=p.HERE) as directory:
    proc=Path(directory)
    (proc/'424242').mkdir()
    cmdline=proc/'424242/cmdline'
    local_guard=guard.replace('/proc/',proc.as_posix()+'/')
    def run_guard(data,pgrep_code=0):
        cmdline.write_bytes(data)
        mock='pgrep() { printf \'424242\\n\'; return '+str(pgrep_code)+'; }\n'
        command='target='+quote(p.TARGET)+'\n'+mock+local_guard+'\nmanager_absent\n'
        return subprocess.run(['C:/Program Files/Git/bin/bash.exe','-c',command],capture_output=True).returncode
    require(run_guard(b'/bin/sh\0-c\0'+repair.encode()+b'\0')==0,'guard must ignore its own embedded deployment command')
    require(run_guard(b'/usr/bin/dotnet\0'+p.TARGET.encode()+b'\0')==74,'guard must reject the actual manager argument')
    require(run_guard(b'/bin/sh\0-c\0echo before\n'+p.TARGET.encode()+b'\nafter\0')==0,'newlines inside one shell argument are not manager arguments')
    require(run_guard(b'/usr/bin/dotnet\0'+p.TARGET.encode()+b'.backup\0')==0,'guard must compare the whole argument')
    require(run_guard(b'',1)==0,'no candidates means manager absent')
    require(run_guard(b'',2)==75,'process inspection failure must stop deployment')
    cmdline.unlink()
    mock='pgrep() { printf \'424242\\n\'; }\n'
    command='target='+quote(p.TARGET)+'\n'+mock+local_guard+'\nmanager_absent\n'
    require(subprocess.run(['C:/Program Files/Git/bin/bash.exe','-c',command],capture_output=True).returncode==75,'unreadable candidate must stop deployment')

asyncio.run(verify_guards())
p.tools.local_checks()
require(p.digest(p.HERE/'manager.dll')==p.NEW_SHA and p.digest(p.HERE/'manager.before.dll')==p.OLD_SHA,'manager/recovery hashes changed')
for name, expected in (('artifacts/FdetProbe.dll',p.FDET_PROBE_SHA),('artifacts/FdetProbe.runtimeconfig.json',p.FDET_RUNTIMECONFIG_SHA),('artifacts/uep-probe.elf',p.NATIVE_SHA)):
    require(p.digest(p.HERE/name)==expected,'validated payload drifted: '+name)
require(not (p.HERE/'execution').exists() and not (p.HERE/'SPENT').exists(),'packet already consumed')
seal_names = ['packet.py','bootstrap_sdk.py','sdk.py','trial.py','inspect_tv.py','prepare.py','deploy.py','recovery.py','offline_checks.py','precheck_offline.py','stage.sh','snapshot.sh','repair.sh','rollback.sh','status.sh','fdet.sh','gate-readonly.sh','gate-active.sh','gate-remove.sh','BridgeRepairAgent.cs','BridgeRepairAgent.csproj','inspection.json','operation.json','manager.dll','manager.before.dll','artifacts/manager.dll','artifacts/manager.runtimeconfig.json','artifacts/FdetProbe.dll','artifacts/FdetProbe.runtimeconfig.json','artifacts/uep-probe.elf','PLAN.md','offline-status.json','precheck.json']
with (p.HERE/'seal.json').open('x',encoding='utf-8') as stream:
    json.dump({name:p.digest(p.HERE/name) for name in seal_names},stream,indent=2)
result = {'offline_checks':'passed','checks':checks,'sealed_files':len(seal_names),'manager_bytes':(p.HERE/'manager.dll').stat().st_size,'helper_bytes':(p.HERE/'build/SamsungTvRootAgent.dll').stat().st_size,'fdet_bytes':(p.HERE/'artifacts/FdetProbe.dll').stat().st_size,'TV_operations':0}
with (p.HERE/'offline-results.json').open('x',encoding='utf-8') as stream:
    json.dump(result,stream,indent=2)
print(json.dumps(result))
