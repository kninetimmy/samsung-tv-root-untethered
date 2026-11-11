set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
test "$(cat /proc/sys/kernel/random/boot_id)" = '4b2c70c7-2d64-46df-b84e-02541ed33659'
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
cfg=/opt/usr/share/selfroot/uep-off.conf
temp=/opt/usr/share/selfroot/uep-off.conf.prepared
stage_dir=/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83
test "$(readlink -f "$stage_dir")" = '/opt/usr/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
test ! -e "$temp"
test ! -L "$temp"
probe() {
    test -e "$cfg" && test ! -L "$cfg" || return 1
    test "$(stat -c '%F' "$cfg")" = 'regular file' || return 1
    test "$(stat -c '%u:%g:%a' "$cfg")" = '0:0:644' || return 1
    test "$(stat -c %h "$cfg")" = 1 || return 1
    test "$(chsmack "$cfg")" = "$cfg access=\"_\"" || return 1
}
if test -e "$cfg" || test -L "$cfg"; then
    probe || exit 74
    current=$(hash "$cfg")
    test "$current" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de' || test "$current" = '45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659'
else
    current=absent
fi
test "$current" = 'absent'
test ! -L "$cfg"
test ! -e "$cfg"
printf '%s\n' 'read-only' > "$temp"
chown 0:0 "$temp"
chmod 0644 "$temp"
chsmack -a '_' "$temp"
test "$(stat -c '%u:%g:%a:%h' "$temp")" = '0:0:644:1'
test "$(stat -c '%s' "$temp")" = '10'
test "$(hash "$temp")" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de'
test "$(chsmack "$temp")" = "$temp access=\"_\""
mv -T -- "$temp" "$cfg"
printf 'GATE_CONFIG_READONLY_COMPLETE\n'
if test -e "$cfg" && test ! -L "$cfg"; then
    test "$(hash "$cfg")" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de'
    sha256sum "$cfg"
    stat -c 'GATE_METADATA %u:%g:%a:%h' "$cfg"
else
    printf 'GATE_ABSENT\n'
fi
