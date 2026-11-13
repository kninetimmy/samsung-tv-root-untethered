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

# --- refusals BEFORE any write ---
test -e "$cfg"
test ! -L "$cfg"
test "$(hash "$cfg")" = 'ef5898422bbd4916c0bbb5885c9185dafc38154bed8a40029300766674eb77de'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = 'regular file:0:0:644:1'
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
printf '%s\n' 'active' > "$tmp"
chmod 644 "$tmp"
chown 0:0 "$tmp"
chsmack -a '_' "$tmp"
mv -- "$tmp" "$cfg"
test "$(hash "$cfg")" = '45df5ad5e0ecfa54d3226343e0e6857337494ba6e32f189d1174070665d8c659'
test "$(stat -c '%F:%u:%g:%a:%h' -- "$cfg")" = 'regular file:0:0:644:1'
good_config
printf 'GATE_CONFIG_ACTIVE_VERIFIED\n'
printf 'GATE_ACTIVE_COMPLETE\n'
