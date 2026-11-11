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

dir=/opt/usr/share/selfroot/fdetprobe
stage_dir=/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83
test ! -L "$dir"
test ! -e "$dir"
test "$(readlink -f "$stage_dir")" = '/opt/usr/home/owner/share/tmp/sdk_tools/archive-root-a553e5ee83632f83'
test "$(stat -c '%u:%a' "$stage_dir")" = '901:700'
test "$(hash "$stage_dir/FdetProbe.dll")" = '2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb'
test "$(hash "$stage_dir/FdetProbe.runtimeconfig.json")" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json)" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz)" = 'efbe4616dd02b1b886f8cca70f7c426d7d69bf8bad09e4e6c08272a7b5152c98  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz.signature)" = '4f68c6c46001f2ce709c84beb31000f2b0bf6f10f7174cddcd2466762fd443f6  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz.signature'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/passwd)" = '3f84e1849b4aa0e9572c539204a7862e1268f245f06e654009a26006c961f004  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/passwd'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/public.pem)" = '2e21c4844744e618c36f1c7dbb6a115321b937804f99ceccac6a180df16325ee  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/public.pem'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.dll)" = 'e68cb38fb7c2c55e8e7f54d312cc028c80e8c781f348fd30fa5262c848729946  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.dll'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.runtimeconfig.json)" = '68cf6feb5470704dcc78260c6eac1ac026fb5345faf919458b3196e32e949c66  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.runtimeconfig.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/tizen-manifest.xml)" = 'd28b8c565cea1f486211fb1478c4c2b447bb5a991c81d0e93d093f91b9755bdb  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/tizen-manifest.xml'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/boot.sh)" = '112cdf61412f61b43806e569b48b9a731d634489cb1625b05e8e8f21551199a4  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/boot.sh'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/module.json)" = 'a417a8950c7fecfff8f57d947e8231f6beab8b35314040ca8b01fa3d1c240f9b  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/module.json'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.dll)" = 'ef42c7590ecb5e67b794295939e2be9658520b1b3b1222095063f93a5049f541  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.dll'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.runtimeconfig.json)" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.runtimeconfig.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/author-signature.xml)" = '8ca25676147ef0e64922b55af1d004149df74e4e7b8adebfe356cbe6526eb0cb  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/author-signature.xml'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.dll)" = '8f20859c7ab7577746f68c0e6b1e6c8a0ee315e4b8ad7e79d80c90a6bc191657  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.dll'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.pdb)" = '9e4da7cd18ff96f58453b058cbeb58ab83e2c056f95633f314c49764d72afba6  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.pdb'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/com.samsung.tv.ghservice.deps.json)" = 'c1d923618bb9a283d30830d899e2529582b7bfa1211c217615f91d89a8e5b838  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/com.samsung.tv.ghservice.deps.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/images/tizen-icon.png)" = 'c7a26d7e1bd79075942d68b1a162bb78b5c48c23a298b0965eb0a53c7f717b1b  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/images/tizen-icon.png'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.deps.json)" = 'b90af4c92e9d3cf94da06210a7309fa78e8796368886788c206993d5abfd5035  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.deps.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.dll)" = '8f20859c7ab7577746f68c0e6b1e6c8a0ee315e4b8ad7e79d80c90a6bc191657  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.dll'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.pdb)" = '9e4da7cd18ff96f58453b058cbeb58ab83e2c056f95633f314c49764d72afba6  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.pdb'
test "$(sha256sum /proc/1/root/etc/passwd)" = '279566bb88a6eec47760734d2d64a96e0d938cab6e677934488df73416038387  /proc/1/root/etc/passwd'
test "$(sha256sum /proc/1/root/usr/share/sdbd/public.pem)" = 'c83cab64331f092ba99f666b8bb20a49dd1fff04030336c2ea34f6b55ca09d09  /proc/1/root/usr/share/sdbd/public.pem'
test "$(sha256sum /proc/1/root/bin/bash)" = 'b4bec8b5061b4686372113b69fb957d82609ab27bcf84f1a42d0ab0ec632d148  /proc/1/root/bin/bash'
mkdir -m 755 -- "$dir"
chsmack -a '_' "$dir"
cat "$stage_dir/FdetProbe.dll" > "$dir/FdetProbe.dll"
test "$(hash "$dir/FdetProbe.dll")" = '2cfec6d19ab3ddcc7eb5ec4fe0cb511bf45864994cf990daf2e1ea722b88a8bb'
cat "$stage_dir/FdetProbe.runtimeconfig.json" > "$dir/FdetProbe.runtimeconfig.json"
test "$(hash "$dir/FdetProbe.runtimeconfig.json")" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b'
chown 0:0 "$dir/FdetProbe.dll" "$dir/FdetProbe.runtimeconfig.json"
chmod 0755 "$dir/FdetProbe.dll"
chmod 0644 "$dir/FdetProbe.runtimeconfig.json"
chsmack -a '_' "$dir/FdetProbe.dll" "$dir/FdetProbe.runtimeconfig.json"
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json)" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.runtimeconfig.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz)" = 'efbe4616dd02b1b886f8cca70f7c426d7d69bf8bad09e4e6c08272a7b5152c98  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz.signature)" = '4f68c6c46001f2ce709c84beb31000f2b0bf6f10f7174cddcd2466762fd443f6  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/archive-root-00b0000000000001.tar.gz.signature'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/passwd)" = '3f84e1849b4aa0e9572c539204a7862e1268f245f06e654009a26006c961f004  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/passwd'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/public.pem)" = '2e21c4844744e618c36f1c7dbb6a115321b937804f99ceccac6a180df16325ee  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/public.pem'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.dll)" = 'e68cb38fb7c2c55e8e7f54d312cc028c80e8c781f348fd30fa5262c848729946  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.dll'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.runtimeconfig.json)" = '68cf6feb5470704dcc78260c6eac1ac026fb5345faf919458b3196e32e949c66  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/res/selfroot/SamsungTvArchiveRoot.runtimeconfig.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/tizen-manifest.xml)" = 'd28b8c565cea1f486211fb1478c4c2b447bb5a991c81d0e93d093f91b9755bdb  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/tizen-manifest.xml'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/boot.sh)" = '112cdf61412f61b43806e569b48b9a731d634489cb1625b05e8e8f21551199a4  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/boot.sh'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/module.json)" = 'a417a8950c7fecfff8f57d947e8231f6beab8b35314040ca8b01fa3d1c240f9b  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/module.json'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.dll)" = 'ef42c7590ecb5e67b794295939e2be9658520b1b3b1222095063f93a5049f541  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.dll'
test "$(sha256sum /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.runtimeconfig.json)" = '2c6dd6135c044b210aa1168389205f5c4c2b6d721328f15a69d4dbde3510030b  /proc/1/root/opt/usr/share/selfroot/modules/bridge-service/TvRootBridgeRelay.runtimeconfig.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/author-signature.xml)" = '8ca25676147ef0e64922b55af1d004149df74e4e7b8adebfe356cbe6526eb0cb  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/author-signature.xml'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.dll)" = '8f20859c7ab7577746f68c0e6b1e6c8a0ee315e4b8ad7e79d80c90a6bc191657  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.dll'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.pdb)" = '9e4da7cd18ff96f58453b058cbeb58ab83e2c056f95633f314c49764d72afba6  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/bin/GHServiceLibAPIPlugIn.pdb'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/com.samsung.tv.ghservice.deps.json)" = 'c1d923618bb9a283d30830d899e2529582b7bfa1211c217615f91d89a8e5b838  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/com.samsung.tv.ghservice.deps.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/images/tizen-icon.png)" = 'c7a26d7e1bd79075942d68b1a162bb78b5c48c23a298b0965eb0a53c7f717b1b  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/images/tizen-icon.png'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.deps.json)" = 'b90af4c92e9d3cf94da06210a7309fa78e8796368886788c206993d5abfd5035  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.deps.json'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.dll)" = '8f20859c7ab7577746f68c0e6b1e6c8a0ee315e4b8ad7e79d80c90a6bc191657  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.dll'
test "$(sha256sum /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.pdb)" = '9e4da7cd18ff96f58453b058cbeb58ab83e2c056f95633f314c49764d72afba6  /proc/1/root/opt/usr/apps/com.samsung.tv.ghservice/shared/lib/netcoreapp2.0/GHServiceLibAPIPlugIn.pdb'
test "$(sha256sum /proc/1/root/etc/passwd)" = '279566bb88a6eec47760734d2d64a96e0d938cab6e677934488df73416038387  /proc/1/root/etc/passwd'
test "$(sha256sum /proc/1/root/usr/share/sdbd/public.pem)" = 'c83cab64331f092ba99f666b8bb20a49dd1fff04030336c2ea34f6b55ca09d09  /proc/1/root/usr/share/sdbd/public.pem'
test "$(sha256sum /proc/1/root/bin/bash)" = 'b4bec8b5061b4686372113b69fb957d82609ab27bcf84f1a42d0ab0ec632d148  /proc/1/root/bin/bash'
printf 'FDET_INSTALL_COMPLETE\n'
sha256sum "$dir/FdetProbe.dll" "$dir/FdetProbe.runtimeconfig.json"
stat -c 'FDET_METADATA %u:%g:%a:%h' "$dir/FdetProbe.dll"
