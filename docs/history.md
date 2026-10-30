# From the SIH 2025 prototype to this rewrite

The 2025 prototype was a set of Bash scripts plus a pywebview menu (for PCs) and a Kotlin skeleton (for Android). This page records what it got wrong, because those lessons shaped the current design.

| Prototype | Problem | Rewrite |
|---|---|---|
| "Crypto erase" by running `luksFormat` on the target, wrapping the key with SoftHSM, then deleting the HSM key | `luksFormat` only writes a header, so existing data stays readable in plaintext. Crypto erase only covers data written *after* encryption. | Use the drive's own sanitize commands (NVMe, ATA, SCSI), which destroy the media encryption key every modern SSD already uses internally. |
| Certificate = PDF + attached SHA-256 hash | Anyone can edit the JSON and recompute the hash. | Canonical JSON (RFC 8785) signed with Ed25519. Org keys live on a PKCS#11 token; without one, the certificate is labelled self-attested. |
| Signing key shipped beside the scripts | Shared private key = anyone can forge. | No signing key ships in the ISO. |
| "Reuse" option zeroed the first 10–100 MB | Not sanitization. | Reformat only after a verified sanitize. |
| Hardcoded `/dev/sda`, PINs in source | Easy to wipe the wrong disk. | Device discovery with refusal rules (mounted, held, boot media) and typed confirmation of the serial. |
| No verification | NIST 800-88 requires it. | Post-sanitize sampled read-back. |
| Android: device-signed proof saved before the factory reset | The keystore key dies in the reset, and a pre-wipe signature proves intent, not erasure. | Planned: the ISO acts as a USB witness for the phone. |
