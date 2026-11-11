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

# r12 B1: the writer (UepGate.SaveBudget) creates the state file from a
# File.WriteAllText temp under the root context's umask (0000), so the landed
# file is 0666 -- not the 0644 r11 demanded. Requiring 0644 would STOP a
# legitimate disable with the active config installed. Check the shape the
# writer actually promises instead: regular, single-linked, root-owned.
# r12 M1: bind the receipt to THIS boot and require exactly ONE complete line,
# so a stale receipt from another boot or a second appended line cannot pass.
current_boot=$(cat /proc/sys/kernel/random/boot_id)
test -e "$state"
test ! -L "$state"
test "$(stat -c '%F:%u:%g:%h' -- "$state")" = 'regular file:0:0:1'
test "$(wc -l < "$state")" -eq 1
test "$(cat -- "$state")" = "boot=$current_boot clear=1 restore=0"
test "$(hash "$cfg")" = '45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = 'regular file:0:0:644:1'
good_config
rm -- "$cfg"
printf 'GATE_CONFIG_REMOVED_COMPLETE\n'
test ! -e "$cfg"
test ! -L "$cfg"
printf 'GATE_ABSENT\n'
