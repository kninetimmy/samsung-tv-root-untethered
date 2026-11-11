"""Shared rehearsal shim + layout for the r2 driver checks (host-only).

The shim models the POSIX identity layer (uid/gid/mode/links/smack) that
Windows cannot provide; everything else runs TRUE: content hashes via real
sha256sum, real mv/rm/readlink, real symlinks, real shell semantics.
Layout mirrors the TV tree under a temp dir with the same relative shape.
"""
import hashlib
import subprocess
import tempfile
from pathlib import Path

import packet as p
import prepare

REHEARSAL_BOOT = 'a1111111-2222-3333-4444-555555555555'
RO = 'read-only\n'
AC = 'active\n'
RO_HASH = prepare.h_readonly
AC_HASH = prepare.h_active
BASH = r'C:\Program Files\Git\bin\bash.exe'

SHIM = r'''
export LC_ALL=C
declare -A _META     # path -> uid:gid:mode
declare -A _SMACK    # path -> smack label
sha256sum() {
    # Git for Windows marks binary-mode input with '*'; the TV uses GNU's text separator.
    command sha256sum "$@" | sed 's/^\([0-9a-f]\{64\}\) \*/\1  /'
}
delete_record() { unset "_META[$1]" 2>/dev/null; unset "_SMACK[$1]" 2>/dev/null; }
move_record() {
    if test -n "${_META[$1]:-}"; then _META[$2]=${_META[$1]}; fi
    unset "_META[$1]" 2>/dev/null
    if test -n "${_SMACK[$1]:-}"; then _SMACK[$2]=${_SMACK[$1]}; fi
    unset "_SMACK[$1]" 2>/dev/null
}
chsmack() {
    if test "$1" = '-a'; then _SMACK[$3]=$2; return 0; fi
    printf '%s access="%s"\n' "$1" "${_SMACK[$1]:-}"
    return 0
}
id() { if test "$1" = '-u'; then echo 0; else command id "$@"; fi; }
cat() {
    case "$1" in
        /proc/sys/kernel/random/boot_id) echo __REHEARSAL_BOOT__;;
        *) command cat "$@";;
    esac
}
chown() {
    local owners=$1
    local target=$2
    local meta=${_META[$target]:-0:0:600}
    _META[$target]=$owners:${meta##*:}
    return 0
}
chmod() {
    command chmod "$@" >/dev/null 2>&1 || return
    local mode=$((10#$1))
    local target=$2
    local meta=${_META[$target]:-0:0:644}
    _META[$target]=${meta%%:*}:0:$mode
    return 0
}
stat() {
    local fmt=? POSITIONAL=()
    while test $# -gt 0; do
        case "$1" in
            -c) fmt=$2; shift 2;;
            *) POSITIONAL+=("$1"); shift;;
        esac
    done
    local target=${POSITIONAL[0]:-MISSING_TARGET}
    local prefix=
    case "$fmt" in
        'GATE_METADATA '*) prefix='GATE_METADATA '; fmt=${fmt#GATE_METADATA };;
        *) ;;
    esac
    case "$fmt" in
        '%F') command stat -c '%F' "$target"; return;;
        '%s') command stat -c '%s' "$target"; return;;
        '%d:%i') echo 45845:100001; return;;
        *) ;;
    esac
    local meta=${_META[$target]:-MISSING}
    if test "$meta" = MISSING; then echo "stat: no metadata model for $target" >&2; return 1; fi
    local uid=${meta%%:*}
    local rest=${meta#*:}
    local gid=${rest%%:*}
    local mode=$((10#${rest#*:}))
    local links=$(command stat -c %h "$target")
    case "$fmt" in
        '%F:%u:%a:%h') echo "regular file:$uid:$mode:$links"; return;;
        '%u:%a') echo $prefix$uid:$mode; return;;
        '%u:%g:%a') echo $prefix$uid:$gid:$mode; return;;
        '%u:%g:%a:%h') echo $prefix$uid:$gid:$mode:$links; return;;
        '%h') echo ${prefix}$links; return;;
        *) echo 'stat shim: unmodelled format' >&2; return 2;;
    esac
}
mv() {
    local a POSITIONAL=()
    for a in "$@"; do case "$a" in -*) ;; *) POSITIONAL+=("$a");; esac; done
    command mv "$@" || return
    move_record "${POSITIONAL[0]}" "${POSITIONAL[1]}"
    return 0
}
rm() {
    command rm "$@" >/dev/null 2>&1 || return
    local a
    for a in "$@"; do case "$a" in -*) ;; *) delete_record "$a";; esac; done
    return 0
}
'''


def shim_text(boot=REHEARSAL_BOOT):
    return SHIM.replace('__REHEARSAL_BOOT__', boot)


def stage_prelude(lay):
    return ('declare -A _META\ndeclare -A _SMACK\n_META['
            + lay['stage'] + ']=901:901:700\n')


def to_posix(win_path):
    return str(win_path).replace('\\', '/').replace('C:', '/c')


def new_layout():
    tmp = Path(tempfile.mkdtemp(prefix='r2-gate-rehearsal-'))
    sdk_root = tmp / 'home' / 'owner' / 'share' / 'tmp' / 'sdk_tools'
    stage_dir = sdk_root / 'archive-root-rehearsall0'
    stage_dir.mkdir(parents=True)
    (tmp / 'opt' / 'usr' / 'share' / 'selfroot').mkdir(parents=True)
    return {'tmp': tmp,
            'cfg': to_posix(tmp / 'opt/usr/share/selfroot/uep-off.conf'),
            'cfgwin': tmp / 'opt/usr/share/selfroot/uep-off.conf',
            'tempwin': tmp / 'opt/usr/share/selfroot/uep-off.conf.prepared',
            'stage': to_posix(stage_dir),
            'canon': to_posix(sdk_root)}


def bake_for(lay, boot_pin_boot=REHEARSAL_BOOT):
    boot_pin = "test \"$(cat /proc/sys/kernel/random/boot_id)\" = '" + boot_pin_boot + "'"
    no_pin = '# the boot expectation arrives via the authenticated agent op command'
    return {
        'gate-readonly.sh': prepare.bake(
            boot_pin, lay['cfg'], lay['stage'], lay['canon'],
            'archive-root-rehearsall0', '_', lay['tmp'],
            'gate-readonly.sh', prepare.CREATE_BODY, 'GATE_CONFIG_READONLY_COMPLETE',
            'read-only', prepare.h_readonly),
        'gate-active.sh': prepare.bake(
            boot_pin, lay['cfg'], lay['stage'], lay['canon'],
            'archive-root-rehearsall0', '_', lay['tmp'],
            'gate-active.sh', prepare.REPLACE_BODY, 'GATE_CONFIG_ACTIVE_COMPLETE',
            'active', prepare.h_active, h_source=prepare.h_readonly),
        'gate-remove.sh': prepare.bake(
            no_pin, lay['cfg'], lay['stage'], lay['canon'],
            'archive-root-rehearsall0', '_', lay['tmp'],
            'gate-remove.sh', prepare.REMOVE_BODY, 'GATE_CONFIG_REMOVED_COMPLETE',
            None, prepare.h_active, h_source=prepare.h_readonly),
    }


def write_cfg(lay, text):
    lay['cfgwin'].write_text(text, encoding='ascii', newline='\n')


def read_cfg(lay):
    return lay['cfgwin'].read_text(encoding='ascii')


def r1_gate_active_script(lay):
    """r1's baked gate-active.sh with its boot pin and absolute paths remapped
    to the rehearsal tree (declared substitution; its baked logic is what is
    under test as the r1 differential)."""
    r1_dir = p.HERE.parents[0] / 'qn90b-uep-l4-deploy-20261108-r1'
    r1_script = (r1_dir / 'gate-active.sh').read_text(encoding='ascii')
    return (r1_script
            .replace('27959362-134c-4ba8-95f4-5c00dfb16eaf', REHEARSAL_BOOT)
            .replace('/opt/usr/share/selfroot/uep-off.conf', lay['cfg'])
            .replace('/opt/usr/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83',
                     lay['stage'])
            .replace('/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83',
                     to_posix(lay['tmp']) + '/home/owner/share/tmp/sdk_tools/archive-root-rehearsall0'))


def bash(script, timeout=60):
    return subprocess.run([BASH, '-c', script], capture_output=True, timeout=timeout, text=True)
