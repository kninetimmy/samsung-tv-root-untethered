#!/bin/sh
# tvroot module: uep-gate
# v5.19: the L4 UEP gate runs HERE, in the root boot context, because the
# manager app (uid 901, User::Pkg::ghservice::RO) cannot see /usr/bin/dotnet
# and so failed closed on every boot with a gate config present.
#
# The host reads /opt/usr/share/selfroot/uep-off.conf itself and keeps the
# v5.18 fail-closed contract unchanged:
#   absent     -> one receipt line, no device state touched;
#   read-only  -> one fingerprint read, zero stores;
#   active     -> the guarded, neighbourhood-pinned compare-before-write clear;
#   anything else/unreadable -> fail closed, no store.
# This script adds no store path and never decides anything: it only starts the
# pinned host and records its exit status for the evidence log.
MODULE_DIR=${MODULE_DIR:-/opt/usr/share/selfroot/modules/uep-gate}
HOST="$MODULE_DIR/UepGateHost.dll"
if [ ! -f "$HOST" ]; then
    echo "uep gate: host missing ($HOST)"
    exit 0
fi
/usr/bin/dotnet "$HOST" boot
status=$?
echo "uep gate module exit=$status"
exit 0
