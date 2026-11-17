# Certificates

Every erase, successful or not, produces a JSON file like this (trimmed):

```json
{
  "schema": "purgemark.certificate/v1",
  "certificate_id": "98998668-8234-4b63-9d6b-8438acaa8fe5",
  "issued_at": "2026-10-30T08:29:54Z",
  "result": "sanitized",
  "device": {
    "model": "Samsung SSD 980 PRO 500GB",
    "serial": "S5GXNX0R123456",
    "bus": "nvme",
    "media": "ssd",
    "capacity_bytes": 500107862016
  },
  "sanitization": {
    "method": "nvme-format-ses1",
    "nist_level": "Clear",
    "started_at": "2026-10-30T08:29:52Z",
    "finished_at": "2026-10-30T08:29:54Z",
    "completed": true
  },
  "verification": {
    "mode": "canary",
    "passed": true,
    "samples": 997,
    "mismatches": 0,
    "scope": "sampled",
    "coverage": "0.013%",
    "sample_seed": "15962972881059263092"
  },
  "signer": {
    "algorithm": "Ed25519",
    "public_key": "UNqmYMB1RlPR/xwUc9a4UIkVGsWDVkYiSxeovWRnYBs=",
    "key_id": "c75971e3bee491c1",
    "attestation": "operator-key"
  },
  "signature": "zqv8xiKOH4wOo3s80U+hOiN5..."
}
```

`result` is `sanitized` only when the erase completed and the verification passed. Anything else is recorded as `failed`, with the reason in `sanitization.error` or `verification.error`.

`verification.coverage` says how much of the disk was actually read back, rounded down so a sample never shows as `100%`. By default that's about 1000 random 64 KiB regions plus the first and last, which on a 500 GB drive is around 0.013%. Sampling catches an erase that failed or stopped part way, but not a small leftover patch between the samples. For an overwrite, `pmark erase --full-verify` reads back every byte instead (it takes about as long as the overwrite), and the certificate then says `"scope": "full"` with `"coverage": "100%"` and no `sample_seed`. Firmware erases leave vendor-defined content, so there's nothing to compare a full read against; they stay sampled, checked with canaries. Certificates made before 0.4 don't have `scope` or `coverage`.

## What gets signed

The signature is Ed25519 over the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical form of the whole object, minus the `signature` field. Canonical form means no whitespace, object keys sorted by UTF-16 code units, and a fixed escaping rule for strings. Pretty-printing or reordering the file doesn't change the canonical bytes, so it doesn't break the signature.

To keep the C++ and JavaScript implementations in exact agreement, certificates only use integers within ±2^53, never floats. The 64-bit sample seed is stored as a string for the same reason. Both verifiers also refuse a file with a number written with a decimal point or exponent (JavaScript would read `1.0` as `1`, C++ as a float) or with a key repeated inside one object (parsers disagree on which copy wins), so a certificate can't read one way in one verifier and another way in the other. The JavaScript verifier is tested against a certificate signed by the C++ tool that includes non-ASCII text and a character outside the Basic Multilingual Plane.

## What a valid signature proves

It proves the file hasn't changed since it was signed. Who signed it depends on the key:

- **operator-key**: a long-lived key made with `pmark keygen`. Give the public half to whoever needs to check your certificates. They pass it as `--trusted-key` (or paste it into the browser verifier) and get a clear yes or no on whether you signed it.
- **self-attested**: no key was given, so PurgeMark made a one-off key for this certificate. That proves integrity, but anyone could have produced it. The certificate says so, and the verifiers say so too.

The ISO deliberately ships without a signing key. Any key baked into a public image could be extracted, and then anyone could forge certificates with it.

## What it doesn't prove

A signature ties the contents to a key. It says nothing about whether those contents were true when they were written, so most fields are best read as the operator's claim.

The times (`issued_at`, `started_at`, `finished_at`) come from the clock of the machine that ran the erase. The live ISO has no network and doesn't sync time, so that's whatever the motherboard clock says, which can be wrong by years on an old machine with a flat battery or set to anything on purpose. Nothing outside the operator's machine confirms when a certificate was made, so it can be backdated.

The drive's model, serial and firmware are what the drive reported, passed through any USB bridge on the way. PurgeMark reads them directly rather than trusting the operator to type them, but a drive or bridge that reports someone else's serial will end up in the certificate.

`certificate_id` is a random UUID. It isn't registered anywhere, so nothing stops someone from erasing the same drive twice and keeping only the certificate they like, or quietly deleting the record of a failed run. Whoever holds an operator key can also sign a certificate by hand without running PurgeMark at all. Trusting an operator-key certificate means trusting that operator to look after their key and to be honest with it.

None of this is unusual for a tool that runs offline on the operator's own hardware, but it does decide what the certificate is good for. It's a tamper-evident record made by someone you already trust, not independent proof.

Two things would close most of the gap, and neither is built yet:

1. An [RFC 3161](https://www.rfc-editor.org/rfc/rfc3161) timestamp. After signing, send the signature's hash to a timestamping authority and store its signed reply in the certificate. That proves the certificate existed by a certain time, so it can't be backdated later. It needs network access at the end of the erase, or a step afterwards on another machine.
2. A transparency log: an append-only public log that every certificate is submitted to, in the style of Certificate Transparency or Sigstore's Rekor. Anyone could then list every certificate issued for a drive serial or by an operator key, so a failed run can't be hidden and a drive can't be quietly erased again for a nicer certificate.

## Checking one

```sh
pmark verify-cert purgemark-....json --trusted-key operator.pub
```

The exit status is 0 only if the signature is valid, the signer matches the trusted key (when one is given), and the certificate reports success.

Or use the browser verifier at [purgemark.skysec.org/verify](https://purgemark.skysec.org/verify/), which does the same with Web Crypto without uploading the file. It's also in the repo as `verifier/index.html` and works opened straight from disk with no network access.
