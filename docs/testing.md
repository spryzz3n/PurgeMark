# Testing

## Unit tests

`ctest` runs four suites, none of which need root or real disks:

- **device**: builds a fake sysfs tree (NVMe, SATA, USB, a disk held by LVM, a loop device, an empty card reader, an NVMe multipath path node) and checks discovery and the safety checks against it.
- **identify**: parses synthetic NVMe and ATA identify data, checks method ranking, and checks the exact bytes of every ATA PASS-THROUGH command and the parsing of both sense-data formats.
- **crypto**: canonical JSON (including the RFC 8785 key-order example), Ed25519 signing and tamper detection, key files, and the offset-addressable keystream.
- **erase**: overwrite, both verification modes and cancellation, run against image files.

`node verifier/test.js` checks that a certificate signed by the C++ tool verifies in the JavaScript verifier.

## On real block devices

`tests/integration/erase_test_disks.sh` is destructive and finds its disks by serial number, so it can't hit the wrong one. It plants secret strings across each disk and erases with the default method. It then checks the whole disk for leftovers, streaming it, since a fully zeroed disk has no newlines and naive `grep` runs out of memory. It also checks that a mounted disk and a wrong confirmation are both refused, and that the certificates verify.

I ran it on a Debian 13 VM on Proxmox with an emulated NVMe drive and two SATA disks. QEMU emulates NVMe Format but not Sanitize, and its SATA disks support neither SANITIZE nor the security feature set. So in practice that run covered overwrite on SATA and Format SES=1 on NVMe. On the NVMe disk an independent full read afterwards found zero non-zero bytes.

```
args: -drive file=/dev/pve/vm-NNN-disk-nvme,if=none,id=nvme0,format=raw \
      -device nvme,drive=nvme0,serial=PMNVME0001
```

## The ISO

The ISO was booted in a separate VM with no network, under both OVMF (UEFI) and SeaBIOS, with an NVMe disk, a SATA disk and a small USB stick labelled `PM-CERTS`. Screenshots came from the QEMU monitor (`screendump`), and keystrokes were sent with `qm sendkey`.

That first boot found several real problems, all fixed:

- the boot menus waited forever
- there was no D-Bus, so logind didn't run, nothing spawned on tty2 and the power button was ignored
- the console font couldn't draw the radio-button symbols, so the selected erase method was unreadable
- live-config's own autologin for a non-existent user broke the tty2 shell

After the fixes it boots unattended in both modes. It erases a disk, writes the certificate to the USB stick, and powers off cleanly from `p p` or the power button. The certificate still verified after the stick was read back on another machine.

## Not tested yet

NVMe Sanitize and ATA SANITIZE haven't run against real hardware. That needs a spare SSD passed through to a VM (or a spare machine), which I haven't set up yet.
