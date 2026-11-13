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
test "$(hash "$cfg")" = '45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = 'regular file:0:0:644:1'
good_config
rm -- "$cfg"
printf 'GATE_CONFIG_REMOVED_COMPLETE\n'
test ! -e "$cfg"
test ! -L "$cfg"
printf 'GATE_ABSENT\n'
