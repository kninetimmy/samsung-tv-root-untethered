"""Offline build of the r13 gate scripts (install, activate, remove).

The live gate ops executed by this packet are the three authenticated agent
commands `gate-install:<boot id>`, `gate-config-active:<boot id>` and
`gate-remove:<boot id>`: the ROOT AGENT asserts the expected boot inside the
root shell (prefix injected from the op parameter; the baked scripts carry no
boot pin of their own, exactly as in the reviewed r6-r8 lineage).

- gate-install.sh installs the v5.19 manager (with a persistent v5.18 backup),
  the root-context module and host, then creates the read-only config and runs
  the host once as root. Every refusal is checked BEFORE the first write:
  config/state/module/backup absent, manager bytes exactly the v5.18 baseline,
  staged bytes exactly the packet artifacts.
- gate-config-active.sh replaces ONLY the verified read-only bytes with
  `active\\n`; any other content, metadata, label or a pre-existing budget
  state is a refusal (exit 74), never a write.
- gate-remove.sh removes ONLY the verified active bytes after requiring the
  current boot's single-line budget receipt; it asserts absence afterwards.
- No script can create `active` from absent, remove a read-only config, or
  write a config twice: every transition is a single reviewed edge.
- The budget-temp checks are pre-write refusals, not a guarantee about the
  host's own write; that residual is recorded in packet.BUDGET_WRITER_RESIDUAL.

bake() functions are pure string builders (no packet reads); packet-time checks
live in main() so rehearsals can import this module host-side.
"""
import base64
import json
import re
import subprocess

import packet as p

PRELUDE = r'''set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
# the boot expectation arrives via the authenticated agent op command
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
cfg=@UEP_CONFIG@
state=@UEP_STATE@
stage_dir=@STAGE@
test "$(readlink -f "$stage_dir")" = '@CANON@/@PKG@'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
good_config() {
    test -e "$cfg" && test ! -L "$cfg" || return 1
    test "$(stat -c '%F' "$cfg")" = 'regular file' || return 1
    test "$(stat -c '%u:%g:%a' "$cfg")" = '0:0:644' || return 1
    test "$(stat -c %h "$cfg")" = 1 || return 1
    test "$(chsmack "$cfg")" = "$cfg access=\"@LABEL@\"" || return 1
}
'''

INSTALL_BODY = r'''
app=@APP@
target=@TARGET@
target_rc=@TARGET_RC@
mod=@MODULE_DIR@
backup=@BACKUP_DIR@
mod_host=@MODULE_HOST@
# --- refusals BEFORE any write ---
test ! -e "$cfg"
test ! -L "$cfg"
test ! -e "$state"
test ! -L "$state"
# r12 residual (packet.BUDGET_WRITER_RESIDUAL): the host writes "$state.tmp"
# with a plain overwrite before renaming, so a pre-existing or linked temp path
# would redirect a root write. This refuses a temp path already planted before
# the stage starts; it runs BEFORE the host and cannot cover the check-to-write
# window inside SaveBudget. Exclusive-create hardening is task 40 / v5.20.
test ! -e "$state.tmp"
test ! -L "$state.tmp"
test ! -e "$mod"
test ! -L "$mod"
test ! -e "$backup"
test ! -L "$backup"
test -d "$app"
test ! -L "$app"
# r10 M2: temp-name collisions are refused BEFORE the backup and the first
# write. r9 discovered "$cfg.r9-tmp" only after replacing the manager and
# installing the module, so a predictable refusal left a partial deployment.
test ! -e "$target.r9-tmp"
test ! -L "$target.r9-tmp"
test ! -e "$target_rc.r9-tmp"
test ! -L "$target_rc.r9-tmp"
test ! -e "$cfg.r9-tmp"
test ! -L "$cfg.r9-tmp"
test "$(hash "$target")" = '@H_PREV_MANAGER@'
test "$(hash "$target_rc")" = '@H_PREV_RC@'
for name in manager.dll manager.runtimeconfig.json UepGateHost.dll UepGateHost.runtimeconfig.json boot.sh module.json; do
    test -f "$stage_dir/$name"
    test ! -L "$stage_dir/$name"
done
test "$(hash "$stage_dir/manager.dll")" = '@H_MANAGER@'
test "$(hash "$stage_dir/manager.runtimeconfig.json")" = '@H_MANAGER_RC@'
test "$(hash "$stage_dir/UepGateHost.dll")" = '@H_HOST@'
test "$(hash "$stage_dir/UepGateHost.runtimeconfig.json")" = '@H_HOST_RC@'
test "$(hash "$stage_dir/boot.sh")" = '@H_BOOT@'
test "$(hash "$stage_dir/module.json")" = '@H_MODULE_JSON@'
# --- persistent v5.18 backup ---
mkdir -- "$backup"
cp -p -- "$target" "$backup/com.samsung.tv.ghservice.dll"
cp -p -- "$target_rc" "$backup/com.samsung.tv.ghservice.runtimeconfig.json"
test "$(hash "$backup/com.samsung.tv.ghservice.dll")" = '@H_PREV_MANAGER@'
test "$(hash "$backup/com.samsung.tv.ghservice.runtimeconfig.json")" = '@H_PREV_RC@'
printf 'GATE_BACKUP_COMPLETE\n'
install_file() {
    local src=$1 dst=$2 owner=$3 mode=$4 label=$5 want=$6 tmp
    test -f "$src"
    test ! -L "$src"
    test "$(hash "$src")" = "$want"
    tmp="$dst.r9-tmp"
    test ! -e "$tmp"
    test ! -L "$tmp"
    cp -- "$src" "$tmp"
    chown "$owner" "$tmp"
    chmod "$mode" "$tmp"
    chsmack -a "$label" "$tmp"
    test "$(stat -c '%u:%g:%a:%h' -- "$tmp")" = "$owner:$mode:1"
    test "$(chsmack "$tmp")" = "$tmp access=\"$label\""
    mv -- "$tmp" "$dst"
    test "$(hash "$dst")" = "$want"
    test "$(stat -c '%u:%g:%a:%h' -- "$dst")" = "$owner:$mode:1"
    test "$(chsmack "$dst")" = "$dst access=\"$label\""
}
# --- v5.19 manager (package owner/mode/label preserved) ---
install_file "$stage_dir/manager.dll" "$target" '@TARGET_OWNER@' '@TARGET_MODE@' '@TARGET_LABEL_VALUE@' '@H_MANAGER@'
install_file "$stage_dir/manager.runtimeconfig.json" "$target_rc" '@TARGET_RC_OWNER@' '@TARGET_RC_MODE@' '@TARGET_RC_LABEL_VALUE@' '@H_MANAGER_RC@'
printf 'GATE_MANAGER_INSTALLED\n'
# --- root-context module ---
mkdir -- "$mod"
# r10 B5: `mkdir` under `umask 077` creates a root-owned 0700 directory that
# uid 901 cannot traverse, so the SDK-side verification and the manager could
# not read the module. The directory metadata is part of the installed shape.
chown '@MODULE_DIR_OWNER@' "$mod"
chmod '@MODULE_DIR_MODE@' "$mod"
chsmack -a '_' "$mod"
test "$(stat -c '%F:%u:%g:%a' -- "$mod")" = '@MODULE_DIR_META@'
test "$(chsmack "$mod")" = "$mod access=\"_\""
install_file "$stage_dir/boot.sh" "$mod/boot.sh" '0:0' '755' '_' '@H_BOOT@'
install_file "$stage_dir/module.json" "$mod/module.json" '0:0' '644' '_' '@H_MODULE_JSON@'
install_file "$stage_dir/UepGateHost.dll" "$mod/UepGateHost.dll" '0:0' '644' '_' '@H_HOST@'
install_file "$stage_dir/UepGateHost.runtimeconfig.json" "$mod/UepGateHost.runtimeconfig.json" '0:0' '644' '_' '@H_HOST_RC@'
printf 'GATE_MODULE_INSTALLED\n'
# --- read-only config (single reviewed create edge) ---
tmp="$cfg.r9-tmp"
test ! -e "$tmp"
test ! -L "$tmp"
printf '%s\n' '@READONLY@' > "$tmp"
chmod 644 "$tmp"
chown 0:0 "$tmp"
chsmack -a '_' "$tmp"
mv -- "$tmp" "$cfg"
test "$(hash "$cfg")" = '@H_READONLY@'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = '@UEP_META@'
good_config
printf 'GATE_READONLY_CREATED\n'
# --- root-context execution proof: one read, zero stores ---
out=$(@DOTNET@ "$mod_host" manual)
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -qx '@RECEIPT_READONLY_MANUAL@'
printf '%s\n' "$out" | grep -qx '@LOG_READONLY_MANUAL@'
test ! -e "$state"
test ! -L "$state"
printf 'GATE_MANUAL_READ_OK\n'
printf 'GATE_INSTALL_COMPLETE\n'
'''

ACTIVE_BODY = r'''
# --- refusals BEFORE any write ---
test -e "$cfg"
test ! -L "$cfg"
test "$(hash "$cfg")" = '@H_READONLY@'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = '@UEP_META@'
good_config
test ! -e "$state"
test ! -L "$state"
# r12 residual (packet.BUDGET_WRITER_RESIDUAL): the guarded clear is the first
# store, so a planted temp path is refused before activation too. This is a
# pre-write check only; the host's own File.WriteAllText is not covered.
test ! -e "$state.tmp"
test ! -L "$state.tmp"
tmp="$cfg.r9-tmp"
test ! -e "$tmp"
test ! -L "$tmp"
printf '%s\n' '@ACTIVE@' > "$tmp"
chmod 644 "$tmp"
chown 0:0 "$tmp"
chsmack -a '_' "$tmp"
mv -- "$tmp" "$cfg"
test "$(hash "$cfg")" = '@H_ACTIVE@'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = '@UEP_META@'
good_config
printf 'GATE_CONFIG_ACTIVE_VERIFIED\n'
printf 'GATE_ACTIVE_COMPLETE\n'
'''

REMOVE_BODY = r'''
# r13 B1 (was r12 B1): the writer (UepGate.SaveBudget) creates the state file
# from a File.WriteAllText temp under the root context's umask (0000), so the
# landed file is 0666 -- not the 0644 r11 demanded. Requiring 0644 would STOP a
# legitimate disable with the active config installed. Check the shape the
# writer actually promises instead: regular, single-linked, root-owned.
# r13 minor: compare the file to the EXACT current-boot one-line bytes by
# SHA-256. The r12 wc/cat test was not byte-exact: Bash command substitution
# discards NUL bytes, so an embedded NUL or an appended LF+NUL could pass and
# reach the unlink. A digest of the expected bytes rejects both.
current_boot=$(cat /proc/sys/kernel/random/boot_id)
test -e "$state"
test ! -L "$state"
test "$(stat -c '%F:%u:%g:%h' -- "$state")" = 'regular file:0:0:1'
receipt_sha=$(printf 'boot=%s clear=1 restore=0\n' "$current_boot" | sha256sum)
test "$(hash "$state")" = "${receipt_sha%% *}"
test "$(hash "$cfg")" = '@H_ACTIVE@'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = '@UEP_META@'
good_config
rm -- "$cfg"
printf 'GATE_CONFIG_REMOVED_COMPLETE\n'
test ! -e "$cfg"
test ! -L "$cfg"
printf 'GATE_ABSENT\n'
'''


def subst(name, template, values):
    for key, value in values.items():
        template = template.replace('@' + key + '@', str(value))
    p.require('@' not in template, 'unexpanded script marker in ' + name)
    p.require(template.isascii(), 'non-ascii byte in ' + name)
    return template


def render(out_dir, name, body, values):
    base = {
        'UEP_CONFIG': p.UEP_CONFIG,
        'UEP_STATE': p.UEP_STATE,
        'STAGE': p.STAGE, 'CANON': p.CANON, 'PKG': p.PKG,
        'APP': p.APP, 'TARGET': p.TARGET, 'TARGET_RC': p.TARGET_RC,
        'TARGET_OWNER': p.TARGET_OWNER, 'TARGET_MODE': p.TARGET_MODE,
        'TARGET_LABEL_VALUE': p.TARGET_LABEL_VALUE,
        'TARGET_RC_OWNER': p.TARGET_RC_OWNER, 'TARGET_RC_MODE': p.TARGET_RC_MODE,
        'TARGET_RC_LABEL_VALUE': p.TARGET_RC_LABEL_VALUE,
        'MODULE_DIR': p.MODULE_DIR, 'MODULE_HOST': p.MODULE_HOST,
        'MODULE_DIR_OWNER': p.MODULE_DIR_OWNER,
        'MODULE_DIR_MODE': p.MODULE_DIR_MODE,
        'MODULE_DIR_META': p.MODULE_DIR_META,
        'BACKUP_DIR': p.BACKUP_DIR,
        'DOTNET': '/usr/bin/dotnet',
        'LABEL': p.UEP_LABEL_VALUE,
        'H_PREV_MANAGER': p.PREV_MANAGER_SHA,
        'H_PREV_RC': p.PREV_MANAGER_RC_SHA,
        'H_MANAGER': p.NEW_MANAGER_SHA,
        'H_MANAGER_RC': p.NEW_MANAGER_RC_SHA,
        'H_HOST': p.HOST_SHA,
        'H_HOST_RC': p.HOST_RC_SHA,
        'H_BOOT': p.MODULE_BOOT_SHA,
        'H_MODULE_JSON': p.MODULE_JSON_SHA,
        'H_READONLY': p.UEP_READONLY_SHA,
        'H_ACTIVE': p.UEP_ACTIVE_SHA,
        'UEP_META': p.UEP_META,
        'READONLY': p.UEP_READONLY_CONTENT,
        'ACTIVE': p.UEP_ACTIVE_CONTENT,
        'RECEIPT_READONLY_MANUAL': p.RECEIPT_READONLY_MANUAL,
        'LOG_READONLY_MANUAL': p.LOG_READONLY.format('manual', p.FINGERPRINT),
    }
    base.update(values)
    script = subst(name, PRELUDE + body, base)
    path = out_dir / name
    p.require(not path.exists(), 'script already baked: ' + str(path))
    path.write_text(script, encoding='ascii', newline='\n')
    return script


def bake_install(out_dir):
    return {'gate-install.sh': render(out_dir, 'gate-install.sh', INSTALL_BODY, {})}


def bake_active(out_dir):
    return {'gate-config-active.sh': render(out_dir, 'gate-config-active.sh', ACTIVE_BODY, {})}


def bake_remove(out_dir):
    return {'gate-remove.sh': render(out_dir, 'gate-remove.sh', REMOVE_BODY, {})}


def bake_rehearsal(out_dir, layout):
    """Bake all three scripts against a rehearsal layout (host-only).

    Paths and the dotnet binary are substituted from the layout; content pins
    and every other production constant stay exact, so the rehearsal exercises
    the same bytes the live bake will carry.
    """
    overrides = {
        'UEP_CONFIG': layout['cfg'], 'UEP_STATE': layout['state'],
        'STAGE': layout['stage'], 'CANON': layout['canon'], 'PKG': layout['pkg'],
        'APP': layout['app'], 'TARGET': layout['target'], 'TARGET_RC': layout['target_rc'],
        'MODULE_DIR': layout['module_dir'], 'MODULE_HOST': layout['module_host'],
        'BACKUP_DIR': layout['backup'], 'DOTNET': layout['dotnet'],
    }
    return {
        'gate-install.sh': render(out_dir, 'gate-install.sh', INSTALL_BODY, overrides),
        'gate-config-active.sh': render(out_dir, 'gate-config-active.sh', ACTIVE_BODY, overrides),
        'gate-remove.sh': render(out_dir, 'gate-remove.sh', REMOVE_BODY, overrides),
    }


def main():
    initial = p.inspection()
    p.require(subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=p.REPO).decode().strip() == p.COMMIT,
              'source head changed')
    p.require(subprocess.check_output(['git', 'status', '--porcelain', '--', 'boot-agent', 'modules', '.github/workflows/build.yml'],
                                      cwd=p.REPO) == b'', 'source edits pending')
    p.require(initial['hash'].split('  ')[0] == p.PREV_MANAGER_SHA,
              'the inspected installed manager is not the pinned v5.18 baseline; STOP')
    p.require(initial['boot'] == p.BOOT and
              bool(re.fullmatch(r'regular file:(?:[0-9]+:){6}[0-9]+', initial['target_meta'])),
              'invalid inspected target metadata')
    p.require(initial.get('fdet_home') == 'present', 'the installed fdet payload is not present; STOP')
    p.require(initial.get('gate_config', 'present') == 'absent',
              'the gate config is not absent at preparation time; STOP')
    p.require(initial.get('gate_state', 'present') == 'absent',
              'the budget state file exists at preparation time; STOP')
    p.require(initial.get('module_dir', 'present') == 'absent',
              'the uep-gate module directory exists at preparation time; STOP')
    p.require(initial.get('backup_dir', 'present') == 'absent',
              'the r9 manager backup exists at preparation time; STOP')
    for packet_marker in ('STOP', 'SPENT'):
        p.require(not (p.HERE / packet_marker).exists(),
                  'the packet is stopped or spent; it never re-arms: ' + packet_marker)
    label = p.UEP_LABEL_VALUE
    p.require(re.fullmatch(r'[A-Za-z0-9:_-]{1,64}', label),
              'unexpected gate config smack label: ' + repr(label))
    baked = {}
    baked.update(bake_install(p.HERE))
    baked.update(bake_active(p.HERE))
    baked.update(bake_remove(p.HERE))
    print(json.dumps({'prepared': True, 'gate_scripts': sorted(baked),
                      'boot': p.BOOT, 'TV_operations': 0}))


if __name__ == '__main__':
    with p.preflight('prepare', 'preparation'):
        raise p.Stop('r16 never rebakes in place from historical inspection; offline bake helpers only')
