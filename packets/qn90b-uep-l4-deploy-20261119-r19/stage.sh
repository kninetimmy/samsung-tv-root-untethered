#!/bin/bash
# Only this sealed packet's directory, two hard links, and manifest-listed
# children are eligible.
#
# The manifest IS the file contract (r10 B1): every staged file must be listed
# exactly once with its pinned digest, and every listed file must be staged.
# r9 kept a hardcoded list here that still demanded FdetProbe files no gate
# session uploads and rejected the v5.19 module assets, so every gate op failed
# its own publish check.
set -eu
export LC_ALL=C
umask 077
base=/home/owner/share/tmp/sdk_tools
canon=/opt/usr/home/owner/share/tmp/sdk_tools
pkg=archive-root-a553e5ee83632f83
stage=$base/$pkg
archive=$pkg.tar.gz
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

# --- manifest shape: exactly "sha256  name", plain names, no duplicates ---
if grep -Evq '^[0-9a-f]{64}  [A-Za-z0-9._-]+$' files.sha256; then exit 1; fi
test "$(wc -l < files.sha256)" -gt 0
if test -n "$(awk '{print $2}' files.sha256 | LC_ALL=C sort | uniq -d)"; then exit 1; fi
if awk '{print $2}' files.sha256 | grep -Fxq -- files.sha256; then exit 1; fi

# --- no unlisted file may exist in the owned stage ---
shopt -s nullglob dotglob
for f in *; do
    case "$f" in
        files.sha256|started) continue ;;
    esac
    if ! awk '{print $2}' files.sha256 | grep -Fxq -- "$f"; then exit 1; fi
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

# --- every listed file is present, owned, single-linked and hash-exact ---
while read -r hash name || test -n "$hash"; do
    if absent "$name"; then test "$action" = clean && test "$started" = 0 || exit 1; continue; fi
    regular "$name"
    if test "$name" = "$archive" || test "$name" = "$archive.signature"; then
        link=$base/on-demand/$name
        if absent "$link"; then test "$(stat -c %h "$name")" = 1
        else
            regular "$link" && test "$name" -ef "$link" && test "$(stat -c %h "$name")" = 2 || exit 1
        fi
    else
        test "$(stat -c %h "$name")" = 1
    fi
    if test "$started:$name" = '1:launcher.log'; then
        test "$(stat -c %s "$name")" -le 65536
    else
        test "$(sha256sum "$name")" = "$hash  $name"
    fi
done < files.sha256

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
        while read -r hash name || test -n "$hash"; do
            if ! absent "$name"; then unlink "$name"; fi
        done < files.sha256
        if ! absent files.sha256; then unlink files.sha256; fi
        cd -P "$base"; rmdir -- "$pkg"
        ;;
    *) exit 2 ;;
esac
