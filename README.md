# ZeroTrace

Verifiable storage sanitization for IT asset reuse: a bootable Linux ISO that purges drives using their own firmware sanitize commands, checks the result, and issues a signed certificate that anyone can verify.

> **Status:** early development. Everything so far is read-only: device discovery, safety checks, and capability probing. Nothing erases yet.

```
zt list               # disks, with why each one is blocked (mounted, swap, LVM/RAID, read-only)
sudo zt probe         # NVMe Identify / ATA IDENTIFY → supported sanitize methods, ranked
```

## Why

People hoard old laptops and drives because they don't trust that wiping works. Free tools mostly overwrite, which is the wrong technique for SSDs. Commercial tools are closed and licensed per drive. ZeroTrace aims to be open, standards-based (NIST SP 800-88, IEEE 2883), and honest about what its certificates prove.

## Planned pipeline

```
discover → probe capabilities → plan method → sanitize → verify → report → sign
```

| Media | Preferred method | Fallback |
|---|---|---|
| NVMe | Sanitize (crypto erase / block erase), Format with SES=2 | Format SES=1, overwrite |
| SATA | ATA SANITIZE (crypto scramble / block erase) | ATA Security Erase (enhanced), overwrite |
| SAS/SCSI | SCSI SANITIZE | overwrite |
| USB / other | — | overwrite (Clear only) |

## Build

Linux only, C++20, CMake ≥ 3.20.

```sh
cmake -S . -B build && cmake --build build
ctest --test-dir build
./build/zt list
```

## Layout

```
core/     libztcore: discovery, safety checks, NVMe/ATA identify, method ranking
cli/      zt command-line tool
tests/    unit tests: fake sysfs tree, synthetic IDENTIFY buffers
```

## History

ZeroTrace started as Team CYBROS's Smart India Hackathon 2025 entry (problem SIH25070). This repository is a ground-up rewrite. See [docs/history.md](docs/history.md) for what the prototype got wrong and what changed.
