import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r24-pycache-')

import asyncio
import re
from shlex import quote
import packet as p

NAME = 'tvroot-quiet-recovery-20261102-r1'
PATH = p.ROOT + '/' + NAME
PORT = 26105
RUNTIME = p.RELAY.removesuffix('.dll') + '.runtimeconfig.json'
ARGS = '/usr/bin/dotnet ' + PATH + '/recovery.dll 26105 /opt/usr/share/selfroot/bridge.conf /dev/null '


def reconciliation_command(boot, proof, *, remove=False):
    """Only packet pins enter this command. Never consumes a host attempt.

    A present path must be the exact three-file dead relay before any unlink.
    Removal is provisional; the caller MUST check absence in a new SDK session.
    """
    p.require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', boot or '')
              and re.fullmatch(r'[0-9a-f]{64}', proof or ''), 'relay anchor malformed')
    command = r'''set -euo pipefail
export LC_ALL=C
refuse() { printf 'RELAY_REFUSAL: %s\n' "$1" >&2; exit 74; }
test "$(id -u)" = 901 || refuse 'SDK uid is not 901'
test "$(cat /proc/sys/kernel/random/boot_id)" = '@BOOT@' || refuse 'stage boot changed'
test "$(sha256sum @PROOF@)" = '@PROOF_SHA@  @PROOF@' || refuse 'stage proof changed'
test "$(readlink -f @ROOT@)" = @CANON@ || refuse 'SDK root redirected'
test "$(sha256sum @TARGET@)" = '@OLD@  @TARGET@' || refuse 'source relay hash changed'
test "$(sha256sum @RUNTIME@)" = '@RUNTIME_SHA@  @RUNTIME@' || refuse 'source runtimeconfig hash changed'
for table in /proc/net/tcp /proc/net/tcp6; do
    if test "$table" = /proc/net/tcp || test -e "$table"; then
        test -r "$table" || refuse 'listener table unreadable'
        listeners=$(awk '$2 ~ /:65F9$/ && $4 == "0A" {n++} END {print n+0}' "$table") || refuse 'listener read failed'
        test "$listeners" = 0 || refuse 'port 26105 has a listener'
    fi
done
'''
    if remove:
        command += r'''if test -e @PATH@ || test -L @PATH@; then
    test ! -L @PATH@ || refuse 'relay directory is a symlink'
    test -d @PATH@ || refuse 'relay path is not a directory'
    test "$(readlink -f @PATH@)" = @CANON@/@NAME@ || refuse 'relay path redirected'
    cd -P @PATH@
    test "$PWD" = @CANON@/@NAME@ || refuse 'relay cwd redirected'
    test "$(stat -c '%F:%u:%a' .)" = 'directory:901:700' || refuse 'relay directory owner or mode changed'
    directory=$(stat -c '%d:%i:%u:%a' .)
    test "$(find . -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" = 'pid
recovery.dll
recovery.runtimeconfig.json' || refuse 'relay inventory is not the exact known shape'
    for file in recovery.dll recovery.runtimeconfig.json pid; do
        test ! -L "$file" || refuse 'relay child is a symlink'
        test -f "$file" || refuse 'relay child is not regular'
        # GNU stat calls an empty regular inode "regular empty file". The
        # standalone -f guard above proves type; hashes/pid shape reject empties.
        test "$(stat -c '%u:%a:%h' "$file")" = '901:600:1' || refuse 'relay child metadata changed'
    done
    test "$(sha256sum recovery.dll)" = '@OLD@  recovery.dll' || refuse 'stale relay dll hash changed'
    test "$(sha256sum recovery.runtimeconfig.json)" = '@RUNTIME_SHA@  recovery.runtimeconfig.json' || refuse 'stale runtimeconfig hash changed'
    test "$(stat -c %s pid)" -le 64 || refuse 'pid file oversized'
    record=$(cat pid)
    [[ "$record" =~ ^([1-9][0-9]*)\ ([0-9]+)$ ]] || refuse 'pid file malformed'
    pid=${BASH_REMATCH[1]}
    birth=${BASH_REMATCH[2]}
    expected=$(printf '%s %s\n' "$pid" "$birth" | sha256sum)
    actual=$(sha256sum pid)
    test "${actual%% *}" = "${expected%% *}" || refuse 'pid file is not byte-exact'
    # Stricter than pid+birth nonexistence: even PID reuse is an owner refusal.
    test ! -e /proc/$pid || refuse 'recorded pid still exists (live or reused)'
    test ! -L /proc/$pid || refuse 'recorded pid is redirected'
    test "$(stat -c '%d:%i:%u:%a' .)" = "$directory" || refuse 'relay identity changed before unlink'
    test ! -L @PATH@ || refuse 'relay path linked before unlink'
    test "$(stat -c '%d:%i:%u:%a' @PATH@)" = "$directory" || refuse 'relay path identity changed before unlink'
    unlink pid
    unlink recovery.runtimeconfig.json
    unlink recovery.dll
    cd -P @ROOT@
    test ! -L @NAME@ || refuse 'relay path linked before rmdir'
    test "$(stat -c '%d:%i:%u:%a' @NAME@)" = "$directory" || refuse 'relay path identity changed before rmdir'
    rmdir -- @NAME@
    test ! -e @PATH@ || refuse 'relay remains after removal'
    test ! -L @PATH@ || refuse 'relay link remains after removal'
    printf 'RELAY_REMOVED_PROVISIONAL\n'
else
    printf 'RELAY_ABSENT\n'
fi
'''
    else:
        command += r'''test ! -e @PATH@ || refuse 'relay present in fresh SDK session'
test ! -L @PATH@ || refuse 'relay symlink in fresh SDK session'
printf 'RELAY_ABSENT\n'
'''
    values = {'ROOT': p.ROOT, 'CANON': p.CANON, 'NAME': NAME, 'PATH': PATH,
              'TARGET': p.RELAY, 'OLD': p.RELAY_SHA, 'RUNTIME': RUNTIME,
              'RUNTIME_SHA': p.EXPECTED[RUNTIME], 'BOOT': boot,
              'PROOF': p.EV + '/selfroot-proof.txt', 'PROOF_SHA': proof}
    for key, value in values.items():
        command = command.replace('@' + key + '@', value)
    p.require('@' not in command, 'relay reconciliation template not expanded')
    return command


async def verify_absent(factory, save, boot, proof):
    """Construct/connect a NEW ordinary SDK session, never reuse the remover."""
    sdk = factory()
    try:
        await sdk.connect()
        code, output = await sdk.capture(reconciliation_command(boot, proof))
        p.require(code == 0 and output == 'RELAY_ABSENT',
                  'relay fresh-session absence verification refused: ' + output[-1000:])
        save('recovery-relay-fresh-absence-verified', path=PATH, boot=boot)
    finally:
        await sdk.disconnect()


async def reconcile(factory, save, boot, proof):
    """Run inside prerequisites for BOTH remaining stages, before take().

    No launch, no kill, no root op. Only exact dead relay files may be unlinked.
    A persistent alternate view refuses BEFORE an attempt; no removal retry.
    """
    sdk = factory()
    try:
        await sdk.connect()
        code, output = await sdk.capture(reconciliation_command(boot, proof, remove=True))
        p.require(code == 0 and output in ('RELAY_ABSENT', 'RELAY_REMOVED_PROVISIONAL'),
                  'relay reconciliation refused before attempt: ' + output[-1000:])
        save('recovery-relay-reconciliation-provisional', outcome=output, boot=boot)
    finally:
        await sdk.disconnect()
    await verify_absent(factory, save, boot, proof)


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
test ! -e recovery.dll
test ! -L recovery.dll
test ! -e recovery.runtimeconfig.json
test ! -L recovery.runtimeconfig.json
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
    test -f "$file"
    test ! -L "$file"
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
test ! -L @PATH@
test "$(stat -c '%d:%i:%u:%a' @PATH@)" = '@DIRECTORY@'
unlink pid
unlink recovery.runtimeconfig.json
unlink recovery.dll
cd -P @ROOT@
test ! -L @NAME@
test "$(stat -c '%d:%i:%u:%a' @NAME@)" = '@DIRECTORY@'
rmdir -- @NAME@
test ! -e @PATH@
test ! -L @PATH@
printf 'RECOVERY_RELAY_REMOVED\n'
'''
    values = {'ROOT':p.ROOT,'CANON':p.CANON,'OLD':p.RELAY_SHA,'RUNTIME_SHA':p.EXPECTED[RUNTIME],'NAME':NAME,'PATH':PATH,'ARGS':quote(ARGS),'DIRECTORY':fields['directory'],'PID':fields['pid'],'BIRTH':fields['birth']}
    for key,value in values.items(): command=command.replace('@'+key+'@',value)
    p.require('@' not in command,'cleanup template not expanded')
    code,output=await sdk.capture(command)
    p.require(code == 0 and output == 'RECOVERY_RELAY_REMOVED','temporary relay cleanup failed: '+output[-1000:])
    save('recovery-relay-removal-provisional',path=PATH,pid=int(fields['pid']))
