set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
# the boot expectation arrives via the authenticated agent op command
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
cfg=/opt/usr/share/selfroot/uep-off.conf
state=/opt/usr/share/selfroot/uep-state.conf
stage_dir=/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83
test "$(readlink -f "$stage_dir")" = '/opt/usr/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
good_config() {
    test -e "$cfg" && test ! -L "$cfg" || return 1
    test "$(stat -c '%F' "$cfg")" = 'regular file' || return 1
    test "$(stat -c '%u:%g:%a' "$cfg")" = '0:0:644' || return 1
    test "$(stat -c %h "$cfg")" = 1 || return 1
    test "$(chsmack "$cfg")" = "$cfg access=\"_\"" || return 1
}

app=/opt/usr/apps/com.samsung.tv.ghservice
target=/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
target_rc=/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json
mod=/opt/usr/share/selfroot/modules/uep-gate
backup=/home/owner/share/tmp/sdk_tools/selfroot-evidence/r9-manager-backup
mod_host=/opt/usr/share/selfroot/modules/uep-gate/UepGateHost.dll
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
test "$(hash "$target")" = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'
test "$(hash "$target_rc")" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
for name in manager.dll manager.runtimeconfig.json UepGateHost.dll UepGateHost.runtimeconfig.json boot.sh module.json; do
    test -f "$stage_dir/$name"
    test ! -L "$stage_dir/$name"
done
test "$(hash "$stage_dir/manager.dll")" = '449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c'
test "$(hash "$stage_dir/manager.runtimeconfig.json")" = 'ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38'
test "$(hash "$stage_dir/UepGateHost.dll")" = '3b1e3a80dcb4b6aab8ad4c97bea6bf24ae536fe3a90b633e9e6a3755cf217d1f'
test "$(hash "$stage_dir/UepGateHost.runtimeconfig.json")" = 'ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38'
test "$(hash "$stage_dir/boot.sh")" = '1afd5b7c8c4158714726e627f70ef72adcb394e0e3db3eb563609fd41d2456b0'
test "$(hash "$stage_dir/module.json")" = '63b13c8439e4bcf94cd186406641a2a81368896cf43c8355b67352e6294177f5'
# --- persistent v5.18 backup ---
mkdir -- "$backup"
cp -p -- "$target" "$backup/com.samsung.tv.ghservice.dll"
cp -p -- "$target_rc" "$backup/com.samsung.tv.ghservice.runtimeconfig.json"
test "$(hash "$backup/com.samsung.tv.ghservice.dll")" = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'
test "$(hash "$backup/com.samsung.tv.ghservice.runtimeconfig.json")" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
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
install_file "$stage_dir/manager.dll" "$target" '201:0' '755' 'User::Pkg::com.samsung.tv.ghservice::RO' '449cf034c0b5ad26852740fdb5046f5301d7116610008abb0c15e185a196f86c'
install_file "$stage_dir/manager.runtimeconfig.json" "$target_rc" '201:0' '755' 'User::Pkg::com.samsung.tv.ghservice::RO' 'ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38'
printf 'GATE_MANAGER_INSTALLED\n'
# --- root-context module ---
mkdir -- "$mod"
# r10 B5: `mkdir` under `umask 077` creates a root-owned 0700 directory that
# uid 901 cannot traverse, so the SDK-side verification and the manager could
# not read the module. The directory metadata is part of the installed shape.
chown '0:0' "$mod"
chmod '755' "$mod"
chsmack -a '_' "$mod"
test "$(stat -c '%F:%u:%g:%a' -- "$mod")" = 'directory:0:0:755'
test "$(chsmack "$mod")" = "$mod access=\"_\""
install_file "$stage_dir/boot.sh" "$mod/boot.sh" '0:0' '755' '_' '1afd5b7c8c4158714726e627f70ef72adcb394e0e3db3eb563609fd41d2456b0'
install_file "$stage_dir/module.json" "$mod/module.json" '0:0' '644' '_' '63b13c8439e4bcf94cd186406641a2a81368896cf43c8355b67352e6294177f5'
install_file "$stage_dir/UepGateHost.dll" "$mod/UepGateHost.dll" '0:0' '644' '_' '3b1e3a80dcb4b6aab8ad4c97bea6bf24ae536fe3a90b633e9e6a3755cf217d1f'
install_file "$stage_dir/UepGateHost.runtimeconfig.json" "$mod/UepGateHost.runtimeconfig.json" '0:0' '644' '_' 'ed69fdc80437b2d0fd2b177d018a6e800517200e4fb6dd54705f5a62a908ec38'
printf 'GATE_MODULE_INSTALLED\n'
# --- read-only config (single reviewed create edge) ---
tmp="$cfg.r9-tmp"
test ! -e "$tmp"
test ! -L "$tmp"
printf '%s\n' 'read-only' > "$tmp"
chmod 644 "$tmp"
chown 0:0 "$tmp"
chsmack -a '_' "$tmp"
mv -- "$tmp" "$cfg"
test "$(hash "$cfg")" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = 'regular file:0:0:644:1'
good_config
printf 'GATE_READONLY_CREATED\n'
# --- root-context execution proof: one read, zero stores ---
out=$(/usr/bin/dotnet "$mod_host" manual)
printf '%s\n' "$out"
printf '%s\n' "$out" | grep -qx 'uep gate (manual) uid=0: read-only: enforcing'
printf '%s\n' "$out" | grep -qx 'uep gate: read-only manual: enforcing c07bd300 00000001 00000000 000004e2 (zero stores)'
test ! -e "$state"
test ! -L "$state"
printf 'GATE_MANUAL_READ_OK\n'
printf 'GATE_INSTALL_COMPLETE\n'
