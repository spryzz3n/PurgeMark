// Cross-implementation test: certificates signed by the C++ tool must verify
// in JavaScript, which only works if both canonicalize to identical bytes.
// Run: node verifier/test.js

"use strict";
const fs = require("fs");
const path = require("path");
require("./zt-verify.js");
const { canonicalize, parsePublicKeyPem, verifyCertificate } = globalThis.ZTVerify;

const fx = (name) => fs.readFileSync(path.join(__dirname, "fixtures", name), "utf8");
let failures = 0;
const check = (cond, what) => {
  if (!cond) {
    console.error("FAIL:", what);
    failures++;
  }
};

(async () => {
  const cert = JSON.parse(fx("valid-certificate.json"));
  const operator = parsePublicKeyPem(fx("operator.pub"));
  const other = parsePublicKeyPem(fx("other.pub"));

  let r = await verifyCertificate(cert, operator);
  check(r.valid && r.trusted && r.attestation === "operator-key", "C++-signed certificate verifies and is trusted");
  check(/[^\x00-\x7f]/.test(cert.operator.name), "fixture exercises non-ASCII text");

  r = await verifyCertificate(cert);
  check(r.valid && !r.trusted, "valid without a trusted key, but not trusted");

  r = await verifyCertificate(cert, other);
  check(r.valid && !r.trusted, "different trusted key: valid but untrusted");

  const tampered = structuredClone(cert);
  tampered.device.capacity_bytes += 512;
  r = await verifyCertificate(tampered, operator);
  check(!r.valid && /does not match/.test(r.error), "tampered field is rejected");

  const swapped = structuredClone(cert);
  swapped.signer.key_id = "0000000000000000";
  check(!(await verifyCertificate(swapped)).valid, "mismatched key_id is rejected");

  check(!(await verifyCertificate([])).valid, "non-object is rejected");
  check(!(await verifyCertificate({ ...cert, schema: "x" })).valid, "unknown schema is rejected");

  // RFC 8785 §3.2.3 key ordering (UTF-16 code units).
  const sorted = canonicalize(JSON.parse('{"\\ufb33":1,"\\ud83d\\ude00":2,"\\u20ac":3,"\\u00f6":4,"\\u0080":5,"1":6,"\\r":7}'));
  check(sorted === '{"\\r":7,"1":6,"\u0080":5,"\u00f6":4,"\u20ac":3,"\ud83d\ude00":2,"\ufb33":1}', "UTF-16 key order");
  let threw = false;
  try {
    canonicalize({ x: 1.5 });
  } catch {
    threw = true;
  }
  check(threw, "floats are rejected");

  try {
    parsePublicKeyPem("-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----");
    check(false, "bad PEM is rejected");
  } catch {}

  console.log(failures === 0 ? "verifier: all tests passed" : `verifier: ${failures} failure(s)`);
  process.exit(failures === 0 ? 0 : 1);
})();
