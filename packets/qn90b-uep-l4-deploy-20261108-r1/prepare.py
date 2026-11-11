"""Offline build of the L4 deploy scripts. Requires the read-only inspection; touches no TV."""
import base64
import json
import re
import subprocess
from shlex import quote
import packet as p

initial = json.loads((p.HERE / 'inspection.json').read_text())
p.require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p.REPO).decode().strip() == p.COMMIT, 'source head changed')
p.require(subprocess.check_output(['git', 'status', '--porcelain', '--', 'boot-agent', '.github/workflows/build.yml'], cwd=p.REPO) == b'', 'source edits pending')
p.require(p.digest(p.NEW) == p.NEW_SHA, 'manager artifact changed')
p.require(p.digest(p.BEFORE) == p.OLD_SHA, 'rollback artifact (v5.17) changed')
p.require(p.digest(p.FDET_PROBE) == p.FDET_PROBE_SHA and p.digest(p.FDET_RUNTIMECONFIG) == p.FDET_RUNTIMECONFIG_SHA, 'FdetProbe payload changed from the live-validated bytes')
p.require(p.digest(p.NATIVE) == p.NATIVE_SHA, 'probe hash changed')
p.require(initial['boot'] == p.BOOT and re.fullmatch(r'regular file:(?:[0-9]+:){6}[0-9]+', initial['target_meta']), 'invalid inspected target metadata')
for field in ('selfroot_meta', 'selfroot_label', 'bridge_meta', 'bridge_label'):
    p.require(field in initial, 'inspection lacks the selfroot reference metadata: ' + field)
p.require(initial.get('uep_config', 'absent') == 'absent', 'gate config must be absent before deployment')
p.require(initial.get('fdet_home', 'absent') == 'absent', 'fdet probe home must not pre-exist')

with (p.HERE / 'manager.dll').open('xb') as stream:
    stream.write(p.NEW.read_bytes())

checks = '\n'.join('test "$(sha256sum /proc/1/root' + path + ')" = ' + quote(sha + '  /proc/1/root' + path) for path, sha in p.EXPECTED.items())

def baked(name, template, values):
    for key, value in values.items():
        template = template.replace('@' + key + '@', str(value))
    p.require('@' not in template, 'unexpanded script marker in ' + name)
    with (p.HERE / name).open('x', encoding='ascii', newline='\n') as stream:
        stream.write(template)

common_values = {
    'BOOT': initial['boot'], 'APP': p.APP, 'STAGE': p.STAGE, 'CANON': p.CANON, 'PKG': p.PKG,
    'EV': p.EV, 'PROOF': initial['proof_hash'].split('  ')[0],
    'TARGET': p.TARGET, 'BACKUP': p.BACKUP, 'TEMP': p.TEMP, 'ROLLBACK': p.ROLLBACK_TEMP,
    'META': initial['target_meta'], 'ATTR': ':'.join(initial['target_meta'].split(':')[3:7]),
    'OLD': p.OLD_SHA, 'NEW': p.NEW_SHA, 'CHECKS': checks,
    'SELROOT': '/opt/usr/share/selfroot', 'SELROOT_META': initial['selfroot_meta'],
    'SELROOT_LABEL': initial['selfroot_label'], 'BRIDGE_META': initial['bridge_meta'], 'BRIDGE_LABEL': initial['bridge_label'],
    'FDET_HOME': p.FDET_HOME, 'UEP_CONFIG': p.UEP_CONFIG,
    'FDET_DLL': p.FDET_PROBE_SHA, 'FDET_RC': p.FDET_RUNTIMECONFIG_SHA,
}

apply_common = r'''set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
test "$(cat /proc/sys/kernel/random/boot_id)" = '@BOOT@'
test "$(buxton2ctl get system db/sdk/develop/ip)" = '[system] db/sdk/develop/ip = String: 127.0.0.1'
test "$(buxton2ctl get system db/sdk/develop/mode)" = '[system] db/sdk/develop/mode = Int32: 1'
test "$(readlink -f @APP@)" = '@APP@'
target=@TARGET@
backup=@BACKUP@
temp=@TEMP@
rollback=@ROLLBACK@
stage=@STAGE@
regular() { test ! -L "$1" && test -f "$1" && test "$(stat -c %h "$1")" = 1; }
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
metadata() { stat -c '%u:%g:%a:%h' "$1"; }
label() { test "$(chsmack "$1")" = "$1 access=\"@BACKGROUND_LABEL@\""; }
manager_absent() {
    local ids pid argument
    if ids=$(pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll'); then
        for pid in $ids; do
            [[ $pid =~ ^[1-9][0-9]*$ ]] || return 75
            if test ! -e "/proc/$pid"; then continue; fi
            test -r "/proc/$pid/cmdline" || return 75
            while IFS= read -r -d '' argument; do
                if test "$argument" = "$target"; then return 74; fi
            done <"/proc/$pid/cmdline"
        done
    else
        test "$?" = 1 || return 75
    fi
    return 0
}
regular "$target"
test "$target" -ef /proc/1/root@TARGET@
test "$(metadata "$target")" = '@ATTR@'
label "$target"
manager_absent
'''

apply_body = r'''
test "$(readlink -f "$stage")" = '@CANON@/@PKG@'
test ! -L "$stage"
test "$(stat -c '%u:%a' "$stage")" = '901:700'
test "$(stat -c '%F:%d:%i:%u:%g:%a:%h:%s' "$target")" = '@META@'
test "$(hash "$target")" = '@OLD@'
test ! -e "$backup" && test ! -L "$backup"
test ! -e "$temp" && test ! -L "$temp"
test ! -e "$rollback" && test ! -L "$rollback"
regular "$stage/manager.dll"
test "$(hash "$stage/manager.dll")" = '@NEW@'
@CHECKS@
test "$(sha256sum @EV@/selfroot-proof.txt)" = '@PROOF@  @EV@/selfroot-proof.txt'
test "$(systemctl is-active tvroot-bridge.service)" = active
cp -a -- "$target" "$backup"
regular "$backup"
test "$(hash "$backup")" = '@OLD@'
test "$(metadata "$backup")" = '@ATTR@'
label "$backup"
cp -a -- "$target" "$temp"
regular "$temp"
cat @STAGE@/manager.dll > "$temp"
test "$(hash "$temp")" = '@NEW@'
test "$(metadata "$temp")" = '@ATTR@'
label "$temp"
manager_absent
test "$(hash "$target")" = '@OLD@'
mv -T -- "$temp" "$target"
regular "$target"
test "$(hash "$target")" = '@NEW@'
test "$(metadata "$target")" = '@ATTR@'
label "$target"
@CHECKS@
test "$(sha256sum @EV@/selfroot-proof.txt)" = '@PROOF@  @EV@/selfroot-proof.txt'
test "$(systemctl is-active tvroot-bridge.service)" = active
printf 'MANAGER_UPDATE_COMPLETE\n'
sha256sum "$target" "$backup"
stat -c 'TARGET_METADATA %u:%g:%a:%h' "$target"
'''

fdet_body = r'''
dir=@FDET_HOME@
stage_dir=@STAGE@
test ! -L "$dir"
test ! -e "$dir"
test "$(readlink -f "$stage_dir")" = '@CANON@/@PKG@'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
test "$(hash "$stage_dir/FdetProbe.dll")" = '@FDET_DLL@'
test "$(hash "$stage_dir/FdetProbe.runtimeconfig.json")" = '@FDET_RC@'
@CHECKS@
mkdir -m 755 -- "$dir"
chsmack -a '@SELROOT_LABEL@' "$dir"
cat "$stage_dir/FdetProbe.dll" > "$dir/FdetProbe.dll"
test "$(hash "$dir/FdetProbe.dll")" = '@FDET_DLL@'
cat "$stage_dir/FdetProbe.runtimeconfig.json" > "$dir/FdetProbe.runtimeconfig.json"
test "$(hash "$dir/FdetProbe.runtimeconfig.json")" = '@FDET_RC@'
chown 0:0 "$dir/FdetProbe.dll" "$dir/FdetProbe.runtimeconfig.json"
chmod 0755 "$dir/FdetProbe.dll"
chmod 0644 "$dir/FdetProbe.runtimeconfig.json"
chsmack -a '@SELROOT_LABEL@' "$dir/FdetProbe.dll" "$dir/FdetProbe.runtimeconfig.json"
@CHECKS@
printf 'FDET_INSTALL_COMPLETE\n'
sha256sum "$dir/FdetProbe.dll" "$dir/FdetProbe.runtimeconfig.json"
stat -c 'FDET_METADATA %u:%g:%a:%h' "$dir/FdetProbe.dll"
'''

# The three gate scripts; each is one bounded root op, verified end to end.
import hashlib  # noqa: E402
h_readonly = hashlib.sha256(b'read-only\n').hexdigest()
h_active = hashlib.sha256(b'active\n').hexdigest()
gate_specs = {
    'gate-readonly.sh': ('read-only', 'GATE_CONFIG_READONLY_COMPLETE'),
    'gate-active.sh': ('active', 'GATE_CONFIG_ACTIVE_COMPLETE'),
    'gate-remove.sh': (None, 'GATE_CONFIG_REMOVED_COMPLETE'),
}
gate_template = r'''set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
test "$(cat /proc/sys/kernel/random/boot_id)" = '@BOOT@'
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
cfg=@UEP_CONFIG@
temp=@UEP_CONFIG@.prepared
stage_dir=@STAGE@
rm -f -- "$temp"
test "$(readlink -f "$stage_dir")" = '@CANON@/@PKG@'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
if test -e "$cfg" && test ! -L "$cfg"; then
    test "$(stat -c '%u:%g:%a' "$cfg")" = '0:0:644'
fi
if test '@CONTENT@' = 'absent'; then
    test ! -L "$cfg" && test -e "$cfg"
    current=$(hash "$cfg")
    test "$current" = '@HASH_READONLY@' || test "$current" = '@HASH_ACTIVE@'
    rm -f -- "$cfg"
else
    test ! -e "$cfg" && test ! -L "$cfg"
    printf '%s\n' '@CONTENT@' > "$temp"
    test "$(hash "$temp")" = '@HASH_CONTENT@'
    test "$(stat -c '%s' "$temp")" = '@CONTENT_BYTES@'
    mv -T -- "$temp" "$cfg"
    chown 0:0 "$cfg"
    chmod 0644 "$cfg"
    chsmack -a '@SELROOT_LABEL@' "$cfg"
fi
printf '@@GATE_MARK@@\n'
if test -e "$cfg" && test ! -L "$cfg"; then
    test "$(hash "$cfg")" = '@HASH_END@'
    sha256sum "$cfg"
    stat -c 'GATE_METADATA %u:%g:%a:%h' "$cfg"
else
    printf 'GATE_ABSENT\n'
fi
'''
for name, (content, marker_text) in gate_specs.items():
    template = gate_template.replace('@@GATE_MARK@@', marker_text)
    if content is None:
        # CONTENT_BYTES is never executed on the remove path (line 185 sits in
        # the create branch); a real value keeps the baked script free of
        # unexpanded markers so the static expansion check passes.
        values = dict(common_values, CONTENT='absent',
                      HASH_READONLY=h_readonly, HASH_ACTIVE=h_active,
                      HASH_CONTENT=h_readonly, HASH_END=h_readonly,
                      CONTENT_BYTES=len('read-only') + 1)
    else:
        values = dict(common_values, CONTENT=content,
                      HASH_READONLY=h_readonly, HASH_ACTIVE=h_active,
                      HASH_CONTENT=hashlib.sha256((content + '\n').encode('ascii')).hexdigest(),
                      HASH_END=hashlib.sha256((content + '\n').encode('ascii')).hexdigest(),
                      CONTENT_BYTES=len(content) + 1)
    baked(name, template, values)

apply_values = dict(common_values)
apply_values['BACKGROUND_LABEL'] = 'User::Pkg::com.samsung.tv.ghservice::RO'
repair = apply_common + apply_body
baked('repair.sh', repair, apply_values)

rollback = apply_common + r'''
regular "$backup"
test "$(hash "$backup")" = '@OLD@'
test "$(metadata "$backup")" = '@ATTR@'
label "$backup"
current=$(hash "$target")
test "$current" = '@OLD@' || test "$current" = '@NEW@'
test ! -e "$rollback" && test ! -L "$rollback"
if test "$current" = '@NEW@'; then
    cp -a -- "$backup" "$rollback"
    regular "$rollback"
    test "$(hash "$rollback")" = '@OLD@'
    test "$(metadata "$rollback")" = '@ATTR@'
    label "$rollback"
    manager_absent
    test "$(hash "$target")" = '@NEW@'
    mv -T -- "$rollback" "$target"
fi
test "$(hash "$target")" = '@OLD@'
test "$(metadata "$target")" = '@ATTR@'
label "$target"
printf 'MANAGER_ROLLBACK_COMPLETE\n'
sha256sum "$target" "$backup"
'''
baked('rollback.sh', rollback, apply_values)

fdet = apply_common + fdet_body
baked('fdet.sh', fdet, apply_values)

with (p.HERE / 'status.sh').open('x', encoding='ascii', newline='\n') as stream:
    stream.write('set -eu\nsha256sum ' + p.TARGET + '\nif test -e ' + p.BACKUP + '; then sha256sum ' + p.BACKUP + '; fi\nsystemctl is-active tvroot-bridge.service\n')

with (p.HERE / 'operation.json').open('x', encoding='utf-8') as stream:
    json.dump({
        'old_sha': p.OLD_SHA, 'new_sha': p.NEW_SHA,
        'fdet_reference': {'sha256': p.FDET_PROBE_SHA, 'runtimeconfig_sha256': p.FDET_RUNTIMECONFIG_SHA, 'home': p.FDET_HOME},
        'gate_ops': ['gate-readonly', 'gate-active', 'gate-remove'],
        'boot': initial['boot'], 'target': p.TARGET, 'backup': p.BACKUP,
        'stage': p.STAGE, 'source_commit': p.COMMIT,
    }, stream, indent=2)
print(json.dumps({'prepared': True, 'manager_sha': p.NEW_SHA, 'protected_files': len(p.EXPECTED) + len(p.FDET_EXPECT), 'TV_operations': 0}))
