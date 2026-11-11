#!/bin/bash
# Only this sealed packet's directory, two hard links, and known children are eligible.
set -eu
export LC_ALL=C
umask 077
base=/home/owner/share/tmp/sdk_tools
canon=/opt/usr/home/owner/share/tmp/sdk_tools
pkg=archive-root-a553e5ee83632f83
stage=$base/$pkg
archive=$pkg.tar.gz
files=(manager.dll FdetProbe.dll FdetProbe.runtimeconfig.json stage.sh SamsungTvArchiveRoot.dll SamsungTvRootAgent.dll SamsungTvArchiveRoot.runtimeconfig.json SamsungTvRootAgent.runtimeconfig.json public.pem passwd root-agent.token "$archive" "$archive.signature" launcher.log)
action=$1; identity=$2; manifest=$3; agent=${4:-0}; helper=${5:-0}
[[ $identity =~ ^[0-9]+:[0-9]+$ && $manifest =~ ^[0-9a-f]{64}$ && $agent =~ ^[0-9]+$ && $helper =~ ^[0-9]+$ ]]
test "$(id -u)" = 901
test "$(readlink -f "$base")" = "$canon"
test "$(readlink -f "$base/on-demand")" = "$canon/on-demand" && test ! -L "$base/on-demand" || exit 1
test "$(readlink -f "$stage")" = "$canon/$pkg" && test ! -L "$stage" || exit 1
cd -P "$stage"
test "$(stat -c '%d:%i:%u:%a' .)" = "$identity:901:700"
regular() { test ! -L "$1" && test -f "$1" && test "$(stat -c %u "$1")" = 901; }
absent() { test ! -e "$1" && test ! -L "$1"; }
regular files.sha256
test "$(stat -c %h files.sha256)" = 1
actual=$(sha256sum files.sha256)
test "${actual%% *}" = "$manifest"
shopt -s nullglob dotglob
for f in *; do
    case "$f" in
        files.sha256|started) ;;
        *) known=0; for name in "${files[@]}"; do if test "$f" = "$name"; then known=1; fi; done; test "$known" = 1 ;;
    esac
done
started=0
if ! absent started; then
    test -d started && test ! -L started && test "$(stat -c '%u:%a' started)" = 901:700 || exit 1
    members=(started/*)
    test "${#members[@]}" = 1 && test "${members[0]}" = started/pid || exit 1
    regular started/pid && test "$(stat -c %h started/pid)" = 1 || exit 1
    read -r launcher log_id <started/pid
    [[ $launcher =~ ^[1-9][0-9]*$ && $log_id =~ ^[0-9]+:[0-9]+$ ]] && test "$launcher" -gt 1 || exit 1
    test "$(stat -c '%d:%i' launcher.log)" = "$log_id"
    started=1
fi

for f in "${files[@]}"; do
    if absent "$f"; then test "$action" = clean && test "$started" = 0 || exit 1; continue; fi
    regular "$f"
    if test "$f" = "$archive" || test "$f" = "$archive.signature"; then
        link=$base/on-demand/$f
        if absent "$link"; then test "$(stat -c %h "$f")" = 1
        else
            regular "$link" && test "$f" -ef "$link" && test "$(stat -c %h "$f")" = 2 || exit 1
        fi
    else
        test "$(stat -c %h "$f")" = 1
    fi
    if test "$started:$f" = '1:launcher.log'; then
        test "$(stat -c %s "$f")" -le 65536
    else
        actual=$(sha256sum "$f")
        grep -Fxq -- "${actual%% *}  $f" files.sha256
    fi
done
for f in "$archive" "$archive.signature"; do
    if ! absent "$base/on-demand/$f"; then regular "$f" && test "$f" -ef "$base/on-demand/$f" || exit 1; fi
done
case "$action" in
    publish)
        test "$started" = 0
        for f in "$archive" "$archive.signature"; do absent "$base/on-demand/$f"; done
        for f in "$archive" "$archive.signature"; do ln -T -- "$f" "$base/on-demand/$f"; done
        ;;
    launch)
        test "$started" = 0
        for f in "$archive" "$archive.signature"; do test "$f" -ef "$base/on-demand/$f"; done
        mkdir -m 700 -- started
        (set -C; printf '%s %s\n' "$$" "$(stat -c '%d:%i' launcher.log)" >started/pid)
        exec /usr/bin/dotnet "$stage/SamsungTvArchiveRoot.dll" "$pkg"
        ;;
    clean)
        if test "$started" = 1; then
            test "$agent" -gt 1 && absent "/proc/$agent" && absent "/proc/$launcher" || exit 1
        else test "$agent" = 0; fi

        for f in "$archive.signature" "$archive"; do
            if ! absent "$base/on-demand/$f"; then unlink "$base/on-demand/$f"; fi
        done
        if test "$started" = 1; then unlink started/pid; rmdir started; fi
        for f in "${files[@]}" files.sha256; do if ! absent "$f"; then unlink "$f"; fi; done
        cd -P "$base"; rmdir -- "$pkg"
        ;;
    *) exit 2 ;;
esac
