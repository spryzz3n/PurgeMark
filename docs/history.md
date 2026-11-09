# History

PurgeMark started as an entry for Smart India Hackathon 2025, problem SIH25070: secure data wiping to make people trust IT asset recycling. People keep old laptops and phones in drawers because they don't believe a wipe really removes their data, so the idea was a tool that erases properly and hands you proof.

The original version was a handful of bash scripts, a Python/pywebview menu and an Android skeleton, put together without much coding experience. It didn't get through, and looking back, it didn't work. This repository is a rewrite of the same idea.

## What the first version got wrong

**The erase didn't erase.** It LUKS-formatted the disk, wrapped the key with SoftHSM, then deleted the key from SoftHSM. But `luksFormat` only writes a header, and everything already on the disk stayed readable. Encrypting a disk only protects data written afterwards. The rewrite uses the drive's own sanitize commands, which destroy the internal key every modern SSD already uses, or overwrites the whole disk and checks it.

**The certificate proved nothing.** It was a PDF with a SHA-256 hash attached. Anyone could edit the data and recompute the hash. The signing script that did exist used a private key sitting next to the scripts. Now certificates are signed with Ed25519 over canonical JSON, and no signing key ships with the tool.

**"Reuse" mode zeroed the first 10 to 100 MB** and called the disk wiped.

**It could wipe the wrong disk.** The target was hardcoded to `/dev/sda`, and HSM PINs were in the source. Now disks in use are refused, and the operator has to type the serial number of the disk being erased.

**Nothing was verified.** NIST SP 800-88 expects you to check the result. Now every erase is followed by a read-back.

**The Android app couldn't work as designed.** It signed a record with a key in the phone's keystore, then factory-reset the phone, which destroys that keystore. It also tried to read the IMEI and serial number, which apps haven't been allowed to do since Android 10. The redesign checks a hardware-attested record at a separate station before the reset. It isn't in this repository yet.
