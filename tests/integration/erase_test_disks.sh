#!/usr/bin/env bash
# Integration test on real (or emulated) block devices. DESTROYS the test disks.
#
#   sudo tests/integration/erase_test_disks.sh NVME_SERIAL SATA_SERIAL SATA_SERIAL2
#
# Disks are located by serial number so the script can't hit the wrong drive.
# Used on a QEMU VM with:
#   -device nvme,serial=ZTNVME0001   and two SATA disks with serials ZTSATA0001/2
set -u
ZT=${ZT:-$(dirname "$0")/../../build/zt}
[ $# -eq 3 ] || { echo "usage: $0 NVME_SERIAL SATA_SERIAL SATA_SERIAL2" >&2; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "needs root" >&2; exit 2; }

by_serial() { lsblk -dno NAME,SERIAL | awk -v s="$1" '$2==s {print "/dev/"$1}'; }
NVME=$(by_serial "$1"); SATA0=$(by_serial "$2"); SATA1=$(by_serial "$3")
[ -n "$NVME" ] && [ -n "$SATA0" ] && [ -n "$SATA1" ] || { echo "test disks not found" >&2; exit 1; }
echo "test disks: nvme=$NVME sata0=$SATA0 sata1=$SATA1"

W=$(mktemp -d)
trap 'umount "$W/mnt" 2>/dev/null; rm -rf "$W"' EXIT
mkdir -p "$W/certs" "$W/mnt"
"$ZT" keygen "$W/op" >/dev/null
FAIL=0
expect() { if [ "$1" = "$2" ]; then echo "  ok: $3"; else echo "  FAIL: $3 (got $1, want $2)"; FAIL=1; fi; }

# Random data plus findable secrets spread across the disk.
seed() {
    local dev=$1 size_mb
    size_mb=$(( $(blockdev --getsize64 "$dev") / 1048576 ))
    dd if=/dev/urandom of="$dev" bs=1M count=64 oflag=direct status=none
    for frac in 0 10 30 50 70 90; do
        printf 'SECRET-CUSTOMER-RECORD-%s\n' "$frac" |
            dd of="$dev" bs=1M seek=$(( size_mb * frac / 100 )) conv=notrunc oflag=direct status=none
    done
    sync
}
# Streams the whole disk; zeros become newlines so grep never buffers a giant "line".
secrets() { dd if="$1" bs=4M iflag=direct status=none | tr '\0' '\n' | grep -a -c SECRET-CUSTOMER-RECORD; }

echo "== NVMe: Sanitize refused when the controller lacks it"
"$ZT" erase "$NVME" --method nvme-sanitize-crypto --experimental --confirm "$1" >/dev/null 2>&1
expect $? 1 "unsupported method refused"

echo "== NVMe: auto method"
seed "$NVME"; expect "$(secrets "$NVME")" 6 "secrets planted"
"$ZT" erase "$NVME" --confirm "$1" --key "$W/op.key" --out "$W/certs" >/dev/null 2>&1
expect $? 0 "erase + verification succeeded"
expect "$(secrets "$NVME")" 0 "no secrets left"

echo "== SATA: auto method"
seed "$SATA0"; expect "$(secrets "$SATA0")" 6 "secrets planted"
"$ZT" erase "$SATA0" --confirm "$2" --key "$W/op.key" --out "$W/certs" >/dev/null 2>&1
expect $? 0 "erase + verification succeeded"
expect "$(secrets "$SATA0")" 0 "no secrets left"

echo "== SATA: mounted disk refused"
mkfs.ext4 -q -F "$SATA1" && mount "$SATA1" "$W/mnt"
"$ZT" erase "$SATA1" --confirm "$3" >/dev/null 2>&1
expect $? 1 "mounted disk refused"
umount "$W/mnt"

echo "== Wrong confirmation writes nothing"
seed "$SATA1"
"$ZT" erase "$SATA1" --confirm WRONG >/dev/null 2>&1
expect $? 1 "mismatched confirmation refused"
expect "$(secrets "$SATA1")" 6 "data untouched"

echo "== Certificates"
for c in "$W"/certs/*.json; do
    "$ZT" verify-cert "$c" --trusted-key "$W/op.pub" >/dev/null
    expect $? 0 "$(basename "$c") verifies"
done

[ $FAIL -eq 0 ] && echo "integration: all checks passed" || echo "integration: FAILED"
exit $FAIL
