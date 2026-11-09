// PurgeMark certificate verification for browsers and Node (>= 20).
// Mirrors core/src/certificate.cpp: the Ed25519 signature covers the RFC 8785
// canonical JSON of the certificate without its "signature" member.
//
// A classic script (not an ES module) so index.html also works when opened
// straight from disk; it exposes globalThis.PMVerify.

(function (global) {
  "use strict";

  const SCHEMA = "purgemark.certificate/v1";
  // DER prefix of an Ed25519 SubjectPublicKeyInfo; the raw 32-byte key follows.
  const SPKI_ED25519_PREFIX = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];

  // RFC 8785. JSON.stringify already escapes strings exactly as JCS requires,
  // and the default sort compares UTF-16 code units, which JCS mandates for keys.
  function canonicalize(value) {
    if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
    if (typeof value === "number") {
      if (!Number.isInteger(value) || Math.abs(value) > Number.MAX_SAFE_INTEGER) {
        throw new Error("non-integer or unsafe number");
      }
      return JSON.stringify(value);
    }
    if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
    if (typeof value === "object") {
      const keys = Object.keys(value).sort();
      return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
    }
    throw new Error("unsupported JSON value");
  }

  function base64ToBytes(b64) {
    if (typeof b64 !== "string" || b64.length % 4 !== 0) throw new Error("invalid base64");
    const bin = atob(b64);
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  }

  const hex = (bytes) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  const equalBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  async function keyId(publicRaw) {
    return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", publicRaw))).slice(0, 16);
  }

  // Accepts a PEM "PUBLIC KEY" (as written by `pmark keygen`) and returns the raw 32 bytes.
  function parsePublicKeyPem(pem) {
    const body = pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, "");
    const der = base64ToBytes(body);
    if (der.length !== 44 || !SPKI_ED25519_PREFIX.every((b, i) => der[i] === b)) {
      throw new Error("not an Ed25519 public key");
    }
    return der.slice(12);
  }

  // Resolves to { valid, trusted, keyId, attestation, error }.
  // `trustedRaw` is optional; without it the signer's identity is not checked.
  async function verifyCertificate(cert, trustedRaw) {
    const out = { valid: false, trusted: false, keyId: "", attestation: "", error: "" };
    try {
      if (typeof cert !== "object" || cert === null || Array.isArray(cert)) throw new Error("not a JSON object");
      if (cert.schema !== SCHEMA) throw new Error("unknown schema");
      if (typeof cert.signature !== "string") throw new Error("missing signature");
      const signer = cert.signer;
      if (typeof signer !== "object" || signer === null) throw new Error("missing signer");
      if (signer.algorithm !== "Ed25519") throw new Error("unsupported signature algorithm");

      const pub = base64ToBytes(signer.public_key);
      if (pub.length !== 32) throw new Error("malformed signer public key");
      out.keyId = await keyId(pub);
      out.attestation = String(signer.attestation ?? "");
      if (signer.key_id !== out.keyId) throw new Error("signer key_id does not match its public key");

      const { signature, ...body } = cert;
      const message = new TextEncoder().encode(canonicalize(body));
      const key = await crypto.subtle.importKey("raw", pub, { name: "Ed25519" }, false, ["verify"]);
      out.valid = await crypto.subtle.verify({ name: "Ed25519" }, key, base64ToBytes(signature), message);
      if (!out.valid) throw new Error("signature does not match certificate contents");
      out.trusted = trustedRaw != null && equalBytes(trustedRaw, pub);
    } catch (e) {
      out.valid = false;
      out.error = e.message;
    }
    return out;
  }

  global.PMVerify = { SCHEMA, canonicalize, keyId, parsePublicKeyPem, verifyCertificate };
})(globalThis);
