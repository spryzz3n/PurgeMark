# ZeroTrace

Verifiable storage sanitization for IT asset reuse: a bootable Linux ISO that erases drives, reads them back to prove it, and issues a signed certificate anyone can check.

> **Status:** early development. Working and tested in VMs: overwrite and NVMe Format erase, verification, signed certificates, the terminal UI, and the live ISO (UEFI and legacy BIOS). NVMe Sanitize is implemented but experimental until it runs on real hardware; ATA SANITIZE/Security Erase are detected but not executed yet. Don't point this at drives you care about.

## Why

People hoard old laptops and drives because they don't trust that wiping works. Free tools mostly overwrite, which can't reach the spare flash inside SSDs. Commercial tools are closed and licensed per drive. ZeroTrace aims to be open, standards-based, and honest about what its certificates prove.

## How it works

```
discover → safety checks → probe capabilities → erase → verify → sign certificate
```

- **Safety checks** refuse drives that are read-only, mounted (including the live USB itself), used as swap, or held by LVM/RAID/LUKS. The erase path also opens the disk with `O_EXCL`, which the kernel refuses while anything holds it, and asks the operator to type the drive's serial.
- **Probing** talks to the drive directly: NVMe Identify Controller via the admin ioctl, and ATA IDENTIFY DEVICE through SCSI/ATA Translation (`SG_IO`, ATA PASS-THROUGH(16)). It reports which sanitize methods the drive supports and ranks them, conservatively labelling vendor-dependent ones as *Clear*.
- **Overwrite** writes the whole drive once, with zeros or with an AES-256-CTR keystream. Random data defeats controllers that compress zeros, and because the keystream is addressable by offset, verification can recompute the expected bytes anywhere.
- **Verification** reads back ~1000 reproducible random samples (always including the first and last regions) with `O_DIRECT`, so the page cache can't fake a pass. For firmware methods it will compare before/after fingerprints instead.
- **Certificates** are JSON signed with Ed25519 over the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical form, so pretty-printing or reordering keys doesn't break them.

| Media | Preferred method | Fallback |
|---|---|---|
| NVMe | Sanitize (crypto/block erase), Format with SES=2 | overwrite |
| SATA | ATA SANITIZE (crypto scramble/block erase) | ATA Security Erase, overwrite |
| SAS/SCSI | SCSI SANITIZE | overwrite |
| USB / other | — | overwrite |

## What a certificate proves

A valid signature proves the certificate hasn't changed since it was issued. Who issued it depends on the key:

- **operator key** (`zt keygen`, then `--key`): verifiers pin the operator's public key with `--trusted-key` and know who signed.
- **self-attested** (no key given): a one-off key. It proves integrity, not identity. The certificate says so.

No signing key ships inside the ISO. Anyone could extract it and forge certificates.

## Usage

```sh
zt list                                  # disks and why each one is blocked
sudo zt probe                            # supported sanitize methods per drive
zt keygen ~/operator                     # operator.key (keep offline) + operator.pub
sudo zt erase sdb --key ~/operator.key --operator "Name" --out certs/
zt verify-cert certs/zerotrace-*.json --trusted-key ~/operator.pub

sudo zerotrace                           # full-screen terminal UI (what the ISO runs)
```

Testing without a spare disk: `zt erase --image disk.img` and `zerotrace --include-loop` work on image files and loop devices.

**Web verifier:** open [`verifier/index.html`](verifier/index.html) (works offline from disk) and drop a certificate on it. Verification runs locally with Web Crypto.

## Live ISO

Debian 13 live image that boots unattended (UEFI or legacy BIOS) straight into the terminal UI on tty1, with a root shell on tty2 for diagnostics. It never activates swap, mounts nothing automatically, and masks udisks/LVM/mdadm so target drives stay untouched. On the text console the UI uses ASCII symbols; `p` twice powers off.

Certificates go to a second USB stick labelled `ZT-CERTS`. If that stick holds an `operator.key`, it's used for signing. Without the stick, certificates live in RAM and the UI warns that they'll be lost at power-off.

```sh
# on a Debian 13 host
sudo apt install live-build cmake ninja-build g++ git libssl-dev nlohmann-json3-dev
sudo iso/build.sh
```

## Build and test

Linux only. C++20, CMake ≥ 3.25, OpenSSL 3, nlohmann-json. FTXUI comes from the system or is fetched (v5.0.0).

```sh
cmake -S . -B build -G Ninja && cmake --build build
ctest --test-dir build        # sysfs fixtures, synthetic IDENTIFY data, crypto, erase on image files
node verifier/test.js         # certificates signed by the C++ tool must verify in JavaScript
```

## Layout

```
core/      libztcore: discovery, safety, NVMe/ATA identify, method ranking,
           block I/O, overwrite, verification, canonical JSON, certificates
cli/       zt command-line tool
tui/       zerotrace terminal UI (FTXUI)
verifier/  static web verifier + cross-implementation test
iso/       Debian live-build configuration and kiosk service
tests/     unit tests
docs/      design notes and project history
```

## History

ZeroTrace started as Team CYBROS's Smart India Hackathon 2025 entry (problem SIH25070). This repository is a ground-up rewrite. [docs/history.md](docs/history.md) covers what the prototype got wrong and what changed.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
