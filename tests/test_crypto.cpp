// Canonical JSON, Ed25519 certificates, keys on disk, and the keystream.

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "check.hpp"
#include "zt/canonical_json.hpp"
#include "zt/certificate.hpp"
#include "zt/crypto.hpp"

namespace fs = std::filesystem;
using nlohmann::json;

static std::string canon(const json& j) {
    const auto r = zt::canonicalize(j);
    return r ? r.value() : "<error: " + r.error() + ">";
}

static void test_canonical() {
    // Key order and whitespace don't matter; output is stable.
    CHECK(canon(json::parse(R"({ "b": 1, "a": [true, null, "x"] })")) == R"({"a":[true,null,"x"],"b":1})");

    // RFC 8785 §3.2.3: sort by UTF-16 code units. U+1F600 (surrogate pair D83D DE00)
    // sorts before U+FB33, the opposite of code point order.
    const json keys = json::parse(R"({"\ufb33":1,"\ud83d\ude00":2,"\u20ac":3,"\u00f6":4,"\u0080":5,"1":6,"\r":7})");
    CHECK(canon(keys) == "{\"\\r\":7,\"1\":6,\"\u0080\":5,\"\u00f6\":4,\"\u20ac\":3,\"\U0001F600\":2,\"\uFB33\":1}");

    // Escaping: short forms, lowercase \u00xx for other controls, '/' and DEL verbatim.
    CHECK(canon(json(std::string("q\"b\\n\n\x01/\x7f"))) == "\"q\\\"b\\\\n\\n\\u0001/\x7f\"");

    CHECK(canon(json(9007199254740991LL)) == "9007199254740991");
    CHECK(!zt::canonicalize(json(9007199254740992ULL)));  // 2^53 is out of range
    CHECK(!zt::canonicalize(json(-9007199254740992LL)));
    CHECK(!zt::canonicalize(json(1.5)));
    CHECK(!zt::canonicalize(json(std::string("\xC3\x28"))));      // invalid UTF-8
    CHECK(!zt::canonicalize(json(std::string("\xED\xA0\x80"))));  // encoded surrogate
    CHECK(!zt::canonicalize(json(std::string("\xC0\xAF"))));      // overlong '/'
}

static void test_base64() {
    for (const std::string s : {"", "f", "fo", "foo", "foob", "fooba", "foobar"}) {
        const auto enc = zt::base64_encode(zt::bytes_of(s));
        const auto dec = zt::base64_decode(enc);
        CHECK(dec && std::string(dec->begin(), dec->end()) == s);
    }
    CHECK(zt::base64_encode(zt::bytes_of("foobar")) == "Zm9vYmFy");
    CHECK(!zt::base64_decode("abc"));
}

static json sample_body() {
    zt::CertificateInput in;
    in.device.model = "Samsung SSD 860 EVO 500GB";
    in.device.serial = "S3Z9NB0K123456X";
    in.device.size_bytes = 500107862016ULL;
    in.sanitization.completed = true;
    in.sanitization.started_at = "2026-10-30T10:00:00Z";
    in.sanitization.finished_at = "2026-10-30T10:42:00Z";
    in.verification.mode = "pattern";
    in.verification.samples = 1000;
    in.verification.seed = 0xFFFFFFFFFFFFFFFFULL;  // must survive as a string
    in.operator_name = "Ravi Kumar";
    return zt::make_certificate_body(in);
}

static void test_certificate() {
    const auto key = zt::SigningKey::generate();
    const auto body = sample_body();
    CHECK(body["result"] == "sanitized");
    CHECK(body["verification"]["sample_seed"] == "18446744073709551615");

    const auto signed_cert = zt::sign_certificate(body, key, zt::Attestation::SelfAttested);
    CHECK(static_cast<bool>(signed_cert));
    if (!signed_cert) return;
    const json& cert = signed_cert.value();

    auto c = zt::verify_certificate(cert, std::nullopt);
    CHECK(c.signature_valid && !c.trusted && c.attestation == "self-attested");
    CHECK(c.key_id == zt::key_id(key.public_raw()));

    // Survives a pretty-printed round trip: the signature covers the canonical form.
    c = zt::verify_certificate(json::parse(cert.dump(4)), key.public_raw());
    CHECK(c.signature_valid && c.trusted);

    auto tampered = cert;
    tampered["device"]["serial"] = "SOMETHING-ELSE";
    CHECK(!zt::verify_certificate(tampered, std::nullopt).signature_valid);

    tampered = cert;
    tampered["result"] = "sanitized ";
    CHECK(!zt::verify_certificate(tampered, std::nullopt).signature_valid);

    // Swapping in an attacker's key re-signs nothing: key_id and signature both break.
    const auto other = zt::SigningKey::generate();
    tampered = cert;
    tampered["signer"]["public_key"] = zt::base64_encode(other.public_raw());
    CHECK(!zt::verify_certificate(tampered, std::nullopt).signature_valid);

    // A cert properly signed by another key is valid but not trusted.
    const auto foreign = zt::sign_certificate(body, other, zt::Attestation::OperatorKey);
    c = zt::verify_certificate(foreign.value(), key.public_raw());
    CHECK(c.signature_valid && !c.trusted);

    // Wrong types in untrusted input fail cleanly instead of throwing.
    tampered = cert;
    tampered["signer"]["algorithm"] = 42;
    CHECK(!zt::verify_certificate(tampered, std::nullopt).signature_valid);
    CHECK(!zt::verify_certificate(json::array(), std::nullopt).signature_valid);
}

static void test_key_files() {
    const fs::path dir = fs::temp_directory_path() / "zt-test-keys";
    fs::remove_all(dir);
    fs::create_directories(dir);
    const std::string prefix = (dir / "op").string();

    const auto key = zt::SigningKey::generate();
    CHECK(static_cast<bool>(key.save_pem(prefix + ".key", prefix + ".pub")));
    CHECK(!key.save_pem(prefix + ".key", prefix + ".pub"));  // never overwrites
    CHECK((fs::status(prefix + ".key").permissions() & fs::perms::others_read) == fs::perms::none);

    const auto loaded = zt::SigningKey::load_private_pem(prefix + ".key");
    CHECK(loaded && loaded->public_raw() == key.public_raw());
    const auto pub = zt::load_public_pem(prefix + ".pub");
    CHECK(pub && pub.value() == key.public_raw());
    CHECK(!zt::load_public_pem(prefix + ".key"));
    fs::remove_all(dir);
}

static void test_keystream() {
    const auto ks = zt::Keystream::random();
    std::vector<std::uint8_t> whole(1000);
    ks.fill(0, whole);
    // Any fragment, at any unaligned offset, matches the corresponding slice.
    for (const std::uint64_t off : {0ULL, 1ULL, 15ULL, 16ULL, 17ULL, 333ULL, 999ULL}) {
        std::vector<std::uint8_t> part(std::min<std::size_t>(77, 1000 - off));
        ks.fill(off, part);
        CHECK(std::equal(part.begin(), part.end(), whole.begin() + static_cast<long>(off)));
    }
    CHECK(std::any_of(whole.begin(), whole.end(), [](std::uint8_t b) { return b != 0; }));
    std::vector<std::uint8_t> other(1000);
    zt::Keystream::random().fill(0, other);
    CHECK(other != whole);
}

int main() {
    test_canonical();
    test_base64();
    test_certificate();
    test_key_files();
    test_keystream();
    CHECK(zt::uuid_v4().size() == 36 && zt::uuid_v4()[14] == '4');
    return finish("crypto");
}
