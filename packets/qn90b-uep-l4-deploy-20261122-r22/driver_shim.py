"""Shared rehearsal shim + layout for the r9 script checks (host-only).

The shim models the POSIX identity layer (uid/gid/mode/links/smack) that
Windows cannot provide; everything else runs TRUE: content hashes via real
sha256sum, real cp/mv/rm/readlink, real symlinks, real shell semantics.
Layout mirrors the TV tree under a temp dir with the same relative shape.
Absolute paths and the dotnet binary are substituted at bake time only.
"""
import sys
import tempfile
if 'packet' not in sys.modules:
    sys.dont_write_bytecode = True
    sys.pycache_prefix = tempfile.mkdtemp(prefix='qn90b-r22-pycache-')

from pathlib import Path

import packet  # Adopt the bootstrap prefix before another local module can bootstrap.
import prepare

REHEARSAL_BOOT = 'a1111111-2222-3333-4444-555555555555'
BASH = r'C:\Program Files\Git\bin\bash.exe'

SHIM = r'''
export LC_ALL=C
declare -A _META     # path -> uid:gid:mode
declare -A _SMACK    # path -> smack label
declare -A _DIR      # path -> 1 when the shim itself created it as a directory
mkdir() {
    command mkdir "$@" >/dev/null 2>&1 || return
    local a
    for a in "$@"; do case "$a" in -*) ;; *) _DIR[$a]=1;; esac; done
    return 0
}
sha256sum() {
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
id() { if test "${1:-}" = '-u'; then echo "${REHEARSAL_UID:-0}"; else command id "$@"; fi; }
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
            --) shift;;
            *) POSITIONAL+=("$1"); shift;;
        esac
    done
    local target=${POSITIONAL[0]:-MISSING_TARGET}
    if test "$target" = '.'; then target=$PWD; fi
    case "$target" in /*) ;; *) target=$PWD/$target;; esac
    case "$fmt" in
        '%F') command stat -c '%F' "$target"; return;;
        '%s') command stat -c '%s' "$target"; return;;
        '%d:%i') echo 45845:100001; return;;
        '%Y') command stat -c '%Y' "$target"; return;;
        *) ;;
    esac
    local meta=${_META[$target]:-MISSING}
    if test "$meta" = MISSING; then echo "stat shim: no metadata model for $target" >&2; return 1; fi
    local uid=${meta%%:*}
    local rest=${meta#*:}
    local gid=${rest%%:*}
    local mode=$((10#${rest#*:}))
    local links=$(command stat -c %h "$target")
    local ftype='regular file'
    if test -n "${_DIR[$target]:-}"; then ftype=directory; fi
    case "$fmt" in
        '%d:%i:%u:%a') echo "45845:100001:$uid:$mode"; return;;
        '%F:%u:%g:%a') echo "$ftype:$uid:$gid:$mode"; return;;
        '%F:%u:%a:%h') echo "$ftype:$uid:$mode:$links"; return;;
        '%F:%u:%g:%h') echo "$ftype:$uid:$gid:$links"; return;;
        '%F:%u:%g:%a:%h') echo "$ftype:$uid:$gid:$mode:$links"; return;;
        '%u') echo $uid; return;;
        '%u:%a') echo $uid:$mode; return;;
        '%u:%g:%a') echo $uid:$gid:$mode; return;;
        '%u:%g:%a:%h') echo $uid:$gid:$mode:$links; return;;
        '%h') echo ${links}; return;;
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


def to_posix(win_path):
    return str(win_path).replace('\\', '/').replace('C:', '/c')


def seed(path, meta='0:0:644'):
    return '_META[' + to_posix(path) + ']=' + meta + '\n'


def new_layout():
    """One fresh rehearsal tree; no TV operation, no production path."""
    tmp = Path(tempfile.mkdtemp(prefix='l4-r9-gate-rehearsal-', dir=REHEARSAL_TEMP))
    sdk_root = tmp / 'home' / 'owner' / 'share' / 'tmp' / 'sdk_tools'
    stage_dir = sdk_root / 'archive-root-rehearsall0'
    stage_dir.mkdir(parents=True)
    (sdk_root / 'selfroot-evidence').mkdir()
    selfroot = tmp / 'opt' / 'usr' / 'share' / 'selfroot'
    selfroot.mkdir(parents=True)
    (selfroot / 'modules').mkdir()
    app = tmp / 'opt' / 'usr' / 'apps' / 'com.samsung.tv.ghservice'
    (app / 'bin').mkdir(parents=True)
    module = selfroot / 'modules' / 'uep-gate'
    bin_dir = tmp / 'bin'
    bin_dir.mkdir()
    return {
        'tmp': tmp,
        'cfg': to_posix(selfroot / 'uep-off.conf'),
        'state': to_posix(selfroot / 'uep-state.conf'),
        'stage': to_posix(stage_dir),
        'canon': to_posix(sdk_root),
        'pkg': 'archive-root-rehearsall0',
        'app': to_posix(app),
        'target': to_posix(app / 'bin' / 'com.samsung.tv.ghservice.dll'),
        'target_rc': to_posix(app / 'bin' / 'com.samsung.tv.ghservice.runtimeconfig.json'),
        'module_dir': to_posix(module),
        'module_host': to_posix(module / 'UepGateHost.dll'),
        'backup': to_posix(sdk_root / 'selfroot-evidence' / 'r9-manager-backup'),
        'dotnet': to_posix(bin_dir / 'dotnet'),
        'stage_win': stage_dir,
        'app_win': app,
        'module_win': module,
        'bin_win': bin_dir,
    }


REHEARSAL_TEMP = Path(tempfile.gettempdir()).resolve()


def bake_for(lay):
    return prepare.bake_rehearsal(lay['tmp'], lay)


def bash(script, timeout=60):
    import subprocess
    return subprocess.run([BASH, '-c', script], capture_output=True, timeout=timeout, text=True)
