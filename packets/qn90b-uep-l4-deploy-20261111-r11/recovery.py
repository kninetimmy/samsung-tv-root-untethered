import asyncio
import re
from shlex import quote
import packet as p

NAME = 'tvroot-quiet-recovery-20261102-r1'
PATH = p.ROOT + '/' + NAME
PORT = 26105
RUNTIME = p.RELAY.removesuffix('.dll') + '.runtimeconfig.json'
ARGS = '/usr/bin/dotnet ' + PATH + '/recovery.dll 26105 /opt/usr/share/selfroot/bridge.conf /dev/null '


async def validate(sdk, save, fields):
    p.require(re.fullmatch(r'\d+:\d+:901:700', fields['directory']) and re.fullmatch(r'[1-9]\d*', fields['pid']) and re.fullmatch(r'\d+', fields['birth']), 'invalid recovery receipt')
    command = ('set -eu\n' +
        'test "$(readlink -f ' + PATH + ')" = ' + quote(p.CANON + '/' + NAME) + '\n' +
        'test "$(stat -c %d:%i:%u:%a ' + PATH + ')" = ' + quote(fields['directory']) + '\n' +
        'test "$(stat -c %u /proc/' + fields['pid'] + ')" = 901\n' +
        'test "$(awk \'{print $22}\' /proc/' + fields['pid'] + '/stat)" = ' + quote(fields['birth']) + '\n' +
        'test "$(tr \'\\0\' \' \' < /proc/' + fields['pid'] + '/cmdline)" = ' + quote(ARGS) + '\n' +
        'test "$(sha256sum ' + PATH + '/recovery.dll)" = ' + quote(p.RELAY_SHA + '  ' + PATH + '/recovery.dll') + '\n' +
        'echo RECOVERY_VALIDATED')
    code, output = await sdk.capture(command)
    p.require(code == 0 and output == 'RECOVERY_VALIDATED', 'existing recovery relay changed')
    save('recovery-relay-ownership-verified', path=PATH, pid=int(fields['pid']))


async def start(sdk, save):
    command = r'''set -euo pipefail
umask 077
test "$(id -u)" = 901
test "$(readlink -f @ROOT@)" = @CANON@
test "$(sha256sum @TARGET@)" = '@OLD@  @TARGET@'
test "$(sha256sum @RUNTIME@)" = '@RUNTIME_SHA@  @RUNTIME@'
test "$(awk '$2 ~ /:65F9$/ && $4 == "0A" {n++} END {print n+0}' /proc/net/tcp)" = 0
cd -P @ROOT@
mkdir -m 700 -- @NAME@
cd -P @PATH@
test "$PWD" = @CANON@/@NAME@
printf 'directory=%s\n' "$(stat -c '%d:%i:%u:%a' .)"
test ! -e recovery.dll && test ! -L recovery.dll
test ! -e recovery.runtimeconfig.json && test ! -L recovery.runtimeconfig.json
cp -- @TARGET@ recovery.dll
cp -- @RUNTIME@ recovery.runtimeconfig.json
chmod 600 recovery.dll recovery.runtimeconfig.json
test "$(sha256sum recovery.dll)" = '@OLD@  recovery.dll'
test "$(sha256sum recovery.runtimeconfig.json)" = '@RUNTIME_SHA@  recovery.runtimeconfig.json'
/usr/bin/setsid /usr/bin/dotnet @PATH@/recovery.dll 26105 /opt/usr/share/selfroot/bridge.conf /dev/null </dev/null >/dev/null 2>&1 3>&- &
pid=$!
for attempt in 1 2 3 4 5; do
    if test "$(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null)" = @ARGS@; then break; fi
    sleep 1
done
test "$(tr '\0' ' ' < /proc/$pid/cmdline)" = @ARGS@
test "$(stat -c %u /proc/$pid)" = 901
birth=$(awk '{print $22}' /proc/$pid/stat)
(set -C; printf '%s %s\n' "$pid" "$birth" > pid)
printf 'pid=%s\nbirth=%s\n' "$pid" "$birth"
'''
    values = {'ROOT':p.ROOT,'CANON':p.CANON,'TARGET':p.RELAY,'OLD':p.RELAY_SHA,'RUNTIME':RUNTIME,'RUNTIME_SHA':p.EXPECTED[RUNTIME],'NAME':NAME,'PATH':PATH,'ARGS':quote(ARGS)}
    for key,value in values.items(): command=command.replace('@'+key+'@',value)
    p.require('@' not in command,'recovery template not expanded')
    code,output=await sdk.capture(command)
    p.require(code == 0,'temporary recovery relay did not start: '+output[-1000:])
    fields=dict(line.split('=',1) for line in output.splitlines())
    p.require(re.fullmatch(r'\d+:\d+:901:700',fields.get('directory','')) and re.fullmatch(r'[1-9]\d*',fields.get('pid','')) and re.fullmatch(r'\d+',fields.get('birth','')),'invalid recovery ownership receipt')
    save('recovery-relay-started',path=PATH,port=PORT,**fields)
    return fields


async def stop(sdk, save, fields):
    command = r'''set -euo pipefail
test "$(id -u)" = 901
test "$(readlink -f @PATH@)" = @CANON@/@NAME@
test ! -L @PATH@
cd -P @PATH@
test "$(stat -c '%d:%i:%u:%a' .)" = '@DIRECTORY@'
for file in recovery.dll recovery.runtimeconfig.json pid; do
    test -f "$file" && test ! -L "$file"
    test "$(stat -c '%u:%h' "$file")" = 901:1
done
test "$(find . -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = 'pid
recovery.dll
recovery.runtimeconfig.json'
test "$(sha256sum recovery.dll)" = '@OLD@  recovery.dll'
test "$(sha256sum recovery.runtimeconfig.json)" = '@RUNTIME_SHA@  recovery.runtimeconfig.json'
test "$(cat pid)" = '@PID@ @BIRTH@'
test "$(awk '{print $22}' /proc/@PID@/stat)" = '@BIRTH@'
test "$(stat -c %u /proc/@PID@)" = 901
test "$(tr '\0' ' ' < /proc/@PID@/cmdline)" = @ARGS@
kill -TERM @PID@
for attempt in 1 2 3 4 5; do
    if test ! -e /proc/@PID@; then break; fi
    sleep 1
done
test ! -e /proc/@PID@
unlink pid
unlink recovery.runtimeconfig.json
unlink recovery.dll
cd -P @ROOT@
rmdir -- @NAME@
test ! -e @PATH@ && test ! -L @PATH@
printf 'RECOVERY_RELAY_REMOVED\n'
'''
    values = {'ROOT':p.ROOT,'CANON':p.CANON,'OLD':p.RELAY_SHA,'RUNTIME_SHA':p.EXPECTED[RUNTIME],'NAME':NAME,'PATH':PATH,'ARGS':quote(ARGS),'DIRECTORY':fields['directory'],'PID':fields['pid'],'BIRTH':fields['birth']}
    for key,value in values.items(): command=command.replace('@'+key+'@',value)
    p.require('@' not in command,'cleanup template not expanded')
    code,output=await sdk.capture(command)
    p.require(code == 0 and output == 'RECOVERY_RELAY_REMOVED','temporary relay cleanup failed: '+output[-1000:])
    save('recovery-relay-removed',path=PATH,pid=int(fields['pid']))
