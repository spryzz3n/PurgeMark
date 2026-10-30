# Certificates

Every erase, successful or not, produces a JSON file like this (trimmed):

```json
{
  "schema": "zerotrace.certificate/v1",
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

## What gets signed

The signature is Ed25519 over the [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) canonical form of the whole object, minus the `signature` field. Canonical form means no whitespace, object keys sorted by UTF-16 code units, and a fixed escaping rule for strings. Pretty-printing or reordering the file doesn't change the canonical bytes, so it doesn't break the signature.

To keep the C++ and JavaScript implementations in exact agreement, certificates only use integers within ±2^53, never floats. The 64-bit sample seed is stored as a string for the same reason. The JavaScript verifier is tested against a certificate signed by the C++ tool that includes non-ASCII text and a character outside the Basic Multilingual Plane.

## What a valid signature proves

It proves the file hasn't changed since it was signed. Who signed it depends on the key:

- **operator-key**: a long-lived key made with `zt keygen`. Give the public half to whoever needs to check your certificates. They pass it as `--trusted-key` (or paste it into the browser verifier) and get a clear yes or no on whether you signed it.
- **self-attested**: no key was given, so ZeroTrace made a one-off key for this certificate. That proves integrity, but anyone could have produced it. The certificate says so, and the verifiers say so too.

The ISO deliberately ships without a signing key. Any key baked into a public image could be extracted, and then anyone could forge certificates with it.

## Checking one

```sh
zt verify-cert zerotrace-....json --trusted-key operator.pub
```

The exit status is 0 only if the signature is valid, the signer matches the trusted key (when one is given), and the certificate reports success.

Or use the browser verifier at [zerotrace.skysec.org/verify](https://zerotrace.skysec.org/verify/), which does the same with Web Crypto without uploading the file. It's also in the repo as `verifier/index.html` and works opened straight from disk with no network access.
