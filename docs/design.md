# Design notes

These are the decisions that weren't obvious to me when I started, and why each one went the way it did.

## Use the drive's own erase where possible

On an SSD, overwriting from the host can't reach everything. The drive keeps spare flash for wear levelling and bad blocks, and a write to LBA 0 lands wherever the controller decides. Modern SSDs already encrypt everything they store with an internal key, so the fast and thorough way to erase one is to have the drive throw that key away (a crypto erase) or erase its flash blocks itself. That's what NVMe Sanitize, NVMe Format with SES=2, and ATA SANITIZE are for.

So the order of preference is:

| Drive | First choice | Fallback |
|---|---|---|
| NVMe | Sanitize (crypto or block erase), Format SES=2 | Format SES=1, overwrite |
| SATA | SANITIZE (crypto scramble or block erase) | overwrite |
| USB stick, SD card, virtual disk | none | overwrite |

Overwrite stays as the fallback because it works on anything, and on a hard disk without remapped sectors it's perfectly good.

## NIST levels are claimed conservatively

NIST SP 800-88 has three levels: Clear (protects against ordinary recovery tools), Purge (protects against lab-grade recovery), and Destroy (physical destruction). Whether a command reaches Purge sometimes depends on how the vendor implemented it. ATA Security Erase on SSDs and NVMe Format SES=1 are the usual examples. In those cases ZeroTrace claims Clear. The mapping lives in one function, `nominal_level()` in `core/src/methods.cpp`, so the UI can't contradict the certificate.

## Verification has two modes

After an overwrite the expected bytes are known, so the check is direct: read about 1000 random 64 KiB samples and compare them with what was written. The random pattern is an AES-256-CTR keystream, so the expected bytes can be regenerated at any offset without storing anything. Reads use `O_DIRECT`, so the page cache can't hand back what we just wrote.

After a firmware erase the drive decides what's left (zeros, ones, or ciphertext under a key that no longer exists), so there's nothing to compare against. Comparing against the old contents doesn't work well either, because a brand-new drive is mostly zeros before and after. So before sending the command, ZeroTrace writes random canaries into every region it's going to sample, and afterwards none of them may survive. This also catches a drive that reports success without doing anything.

The sample positions come from a seed that's recorded in the certificate, and the first and last regions are always included, because that's where partition tables live.

## Safety checks before anything is written

A disk is refused if it's:

- read-only
- mounted, including the live USB the ISO booted from
- used as active swap
- held by device-mapper, md RAID, LVM or LUKS

The operator also has to type the drive's serial number. The live system boots with `noswap`, doesn't auto-mount anything, and has udisks, LVM and mdadm masked, so the disks it's about to erase stay untouched.

## Failures stay contained

The firmware commands that haven't been tested on real hardware are labelled experimental. `auto` and the UI's default only ever pick tested methods. If a sanitize fails, ZeroTrace sends the command that lets the drive leave its "sanitize failed" state (AUSE on NVMe, FAILURE MODE plus CLEAR on ATA), so a failure doesn't leave the drive refusing all access. Status polling gives up after five consecutive errors or 24 hours. Every erase runs inside a catch-all that turns an unexpected exception into a failed certificate instead of a crashed kiosk.

## Talking to drives directly

There's no dependency on nvme-cli, hdparm or sg3_utils. NVMe commands go through `NVME_IOCTL_ADMIN_CMD`. ATA commands go through `SG_IO` as ATA PASS-THROUGH(16), with both descriptor-format and fixed-format sense data parsed for the returned registers. The byte-level encoding and parsing are pure functions with unit tests (`tests/test_identify.cpp`), separate from the ioctl calls.
