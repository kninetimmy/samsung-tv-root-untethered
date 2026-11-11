set -eu
sha256sum /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll
if test -e /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll.before-l4-20261108-r1; then sha256sum /opt/usr/apps/com.samsung.tv.ghservice/bin/com.samsung.tv.ghservice.dll.before-l4-20261108-r1; fi
systemctl is-active tvroot-bridge.service
