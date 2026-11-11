set -euo pipefail
export LC_ALL=C
umask 077
test "$(id -u)" = 0
test "$(cat /proc/sys/kernel/random/boot_id)" = '27959362-134c-4ba8-95f4-5c00dfb16eaf'
test "$(buxton2ctl get system db/sdk/develop/ip)" = '[system] db/sdk/develop/ip = String: 127.0.0.1'
test "$(buxton2ctl get system db/sdk/develop/mode)" = '[system] db/sdk/develop/mode = Int32: 1'
test "$(readlink -f /opt/usr/apps/com.samsung.tv.ghservice)" = '/opt/usr/apps/com.samsung.tv.ghservice'
target=/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
backup=/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll.before-l4-20261108-r1
temp=/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll.prepared-l4-20261108-r1
rollback=/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll.rollback-l4-20261108-r1
stage=/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83
regular() { test ! -L "$1" && test -f "$1" && test "$(stat -c %h "$1")" = 1; }
hash() { local result; result=$(sha256sum "$1"); printf '%s' "${result%% *}"; }
metadata() { stat -c '%u:%g:%a:%h' "$1"; }
label() { test "$(chsmack "$1")" = "$1 access=\"User::Pkg::com.samsung.tv.ghservice::RO\""; }
manager_absent() {
    local ids pid argument
    if ids=$(pgrep -f '/com[.]samsung[.]tv[.]ghservice[.]dll'); then
        for pid in $ids; do
            [[ $pid =~ ^[1-9][0-9]*$ ]] || return 75
            if test ! -e "/proc/$pid"; then continue; fi
            test -r "/proc/$pid/cmdline" || return 75
            while IFS= read -r -d '' argument; do
                if test "$argument" = "$target"; then return 74; fi
            done <"/proc/$pid/cmdline"
        done
    else
        test "$?" = 1 || return 75
    fi
    return 0
}
regular "$target"
test "$target" -ef /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
test "$(metadata "$target")" = '201:0:755:1'
label "$target"
manager_absent

regular "$backup"
test "$(hash "$backup")" = 'eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1'
test "$(metadata "$backup")" = '201:0:755:1'
label "$backup"
current=$(hash "$target")
test "$current" = 'eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1' || test "$current" = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'
test ! -e "$rollback" && test ! -L "$rollback"
if test "$current" = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'; then
    cp -a -- "$backup" "$rollback"
    regular "$rollback"
    test "$(hash "$rollback")" = 'eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1'
    test "$(metadata "$rollback")" = '201:0:755:1'
    label "$rollback"
    manager_absent
    test "$(hash "$target")" = 'e2b14b4935328f06282966c44624d9f8237048f677a159404253300edcc8184a'
    mv -T -- "$rollback" "$target"
fi
test "$(hash "$target")" = 'eaeab5b3c3d1f5991952b83033be92328c07e2e3adade6fc55cfbeaad5095fc1'
test "$(metadata "$target")" = '201:0:755:1'
label "$target"
printf 'MANAGER_ROLLBACK_COMPLETE\n'
sha256sum "$target" "$backup"
