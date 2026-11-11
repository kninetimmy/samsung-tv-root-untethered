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

# r11 M3: removal requires the ACTIVE BOOT's budget receipt at the root
# boundary, not only in the driver preflight. r10's script checked the config
# bytes and unlinked, so the receipt could disappear between preflight and the
# write without stopping the removal.
test -e "$state"
test ! -L "$state"
test "$(stat -c '%F:%u:%g:%a:%h' -- "$state")" = 'regular file:0:0:644:1'
grep -Eqx 'boot=[0-9a-f-]{36} clear=1 restore=0' "$state"
test "$(hash "$cfg")" = '45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = 'regular file:0:0:644:1'
good_config
rm -- "$cfg"
printf 'GATE_CONFIG_REMOVED_COMPLETE\n'
test ! -e "$cfg"
test ! -L "$cfg"
printf 'GATE_ABSENT\n'
