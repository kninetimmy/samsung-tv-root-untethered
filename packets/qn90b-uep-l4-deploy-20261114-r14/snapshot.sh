# Embedded in the diagnostic assembly. The authenticated agent supplies its own PID/TID.
set -eu
export LC_ALL=C
t=/proc/$agent/task/$tid
value() { key=$1; shift; result=$("$@") || return 1; printf '%s=%s\n' "$key" "$result"; }
value agent printf %s "$agent"
value tid printf %s "$tid"
value start awk '{print $22}' "/proc/$agent/stat"
value uid awk '/^Uid:/{print $2,$3,$4,$5}' "$t/status"
value gid awk '/^Gid:/{print $2,$3,$4,$5}' "$t/status"
for field in CapEff CapPrm CapBnd CapInh CapAmb Seccomp NoNewPrivs NSpid; do
    value "$field" awk -v f="$field:" '$1==f {$1=""; sub(/^ +/,""); print}' "$t/status"
done
value label cat "$t/attr/current"
value boot cat /proc/sys/kernel/random/boot_id
value init_comm cat /proc/1/comm
value init_ppid awk '/^PPid:/{print $2}' /proc/1/status
test /proc/1/exe -ef /proc/1/root/usr/lib/systemd/systemd
for ns in pid user mnt; do
    value "caller_$ns" readlink "$t/ns/$ns"
    value "init_$ns" readlink "/proc/1/ns/$ns"
done
for map in uid_map gid_map; do
    value "caller_$map" cat "$t/$map"
    value "init_$map" cat "/proc/1/$map"
done
value ip buxton2ctl get system db/sdk/develop/ip
value mode buxton2ctl get system db/sdk/develop/mode
value host_passwd sha256sum /proc/1/root/etc/passwd
value host_key sha256sum /proc/1/root/usr/share/sdbd/public.pem
value original sha256sum /proc/1/root/usr/lib/systemd/systemd-shutdown-original
metadata() {
    if info=$(stat -c '%A:%a:%u:%g:%n' "$2" 2>&1); then
        printf '%s=%s\n' "$1" "$info"
    else
        case "$info" in *'No such file or directory') printf '%s=absent\n' "$1";; *) return 1;; esac
    fi
}
metadata sysrq_trigger /proc/1/root/proc/sysrq-trigger
metadata sysrq_config /proc/1/root/proc/sys/kernel/sysrq
metadata shutdown_helper /proc/1/root/usr/lib/systemd/systemd-shutdown
metadata shutdown_original /proc/1/root/usr/lib/systemd/systemd-shutdown-original
value systemctl_filecaps getcap /proc/1/root/usr/bin/systemctl
value dotnet_filecaps getcap /proc/1/root/usr/bin/dotnet
value original_filecaps getcap /proc/1/root/usr/lib/systemd/systemd-shutdown-original
