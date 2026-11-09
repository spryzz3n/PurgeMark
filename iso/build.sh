#!/bin/sh
# Builds the PurgeMark live ISO. Run as root on a Debian 13 (trixie) host:
#
#   sudo apt install live-build cmake ninja-build g++ git libssl-dev nlohmann-json3-dev libgtk-4-dev pkg-config
#   sudo iso/build.sh
#
# The binaries are compiled on the host (same Debian release as the image, so
# the shared libraries match) and copied into the image.
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
BUILD="$ROOT/build-iso"

if [ "$(id -u)" -ne 0 ]; then
    echo "iso/build.sh must run as root (live-build needs it)" >&2
    exit 1
fi
if ! grep -q 'VERSION_CODENAME=trixie' /etc/os-release; then
    echo "warning: not a Debian trixie host; binaries may not match the image's libraries" >&2
fi

cmake -S "$ROOT" -B "$BUILD" -G Ninja -DCMAKE_BUILD_TYPE=Release -DZT_BUILD_TESTS=OFF
cmake --build "$BUILD"

BIN="$HERE/config/includes.chroot/usr/local/bin"
install -m 0755 "$BUILD/pmark" "$BUILD/purgemark" "$BUILD/purgemark-gui" "$BIN/"
chmod 0755 "$BIN/purgemark-kiosk" "$HERE/config/hooks/normal/"*.hook.chroot "$HERE/auto/"*

# live-build's boot menus wait forever (isolinux "timeout 0", no GRUB timeout).
# A kiosk should boot unattended, so override both with a 5 second timeout.
DEFAULTS=/usr/share/live/build/bootloaders
rm -rf "$HERE/config/bootloaders"
mkdir -p "$HERE/config/bootloaders"
cp -a "$DEFAULTS/isolinux" "$DEFAULTS/grub-pc" "$HERE/config/bootloaders/"
sed -i 's/^timeout 0$/timeout 50/' "$HERE/config/bootloaders/isolinux/isolinux.cfg"
sed -i '1i set timeout=5' "$HERE/config/bootloaders/grub-pc/config.cfg"
grep -q '^timeout 50$' "$HERE/config/bootloaders/isolinux/isolinux.cfg" || { echo "isolinux timeout patch failed" >&2; exit 1; }

cd "$HERE"
lb clean
lb config
lb build

ISO=$(ls -t "$HERE"/*.iso 2>/dev/null | head -n1)
[ -n "$ISO" ] || { echo "no ISO produced; see iso/build.log" >&2; exit 1; }
sha256sum "$ISO" | tee "$ISO.sha256"
echo "built: $ISO"
