set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
test "$(cat /proc/sys/kernel/random/boot_id)" = '27959362-134c-4ba8-95f4-5c00dfb16eaf'
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
cfg=/opt/usr/share/selfroot/uep-off.conf
temp=/opt/usr/share/selfroot/uep-off.conf.prepared
stage_dir=/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83
rm -f -- "$temp"
test "$(readlink -f "$stage_dir")" = '/opt/usr/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
if test -e "$cfg" && test ! -L "$cfg"; then
    test "$(stat -c '%u:%g:%a' "$cfg")" = '0:0:644'
fi
if test 'absent' = 'absent'; then
    test ! -L "$cfg" && test -e "$cfg"
    current=$(hash "$cfg")
    test "$current" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de' || test "$current" = '45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659'
    rm -f -- "$cfg"
else
    test ! -e "$cfg" && test ! -L "$cfg"
    printf '%s\n' 'absent' > "$temp"
    test "$(hash "$temp")" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de'
    test "$(stat -c '%s' "$temp")" = '10'
    mv -T -- "$temp" "$cfg"
    chown 0:0 "$cfg"
    chmod 0644 "$cfg"
    chsmack -a '_' "$cfg"
fi
printf 'GATE_CONFIG_REMOVED_COMPLETE\n'
if test -e "$cfg" && test ! -L "$cfg"; then
    test "$(hash "$cfg")" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de'
    sha256sum "$cfg"
    stat -c 'GATE_METADATA %u:%g:%a:%h' "$cfg"
else
    printf 'GATE_ABSENT\n'
fi
