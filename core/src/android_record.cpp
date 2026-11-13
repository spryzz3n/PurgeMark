#include "pm/android_record.hpp"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <memory>

#include "pm/canonical_json.hpp"
#include "pm/crypto.hpp"

namespace pm {

namespace {

using json = nlohmann::json;

struct X509Free {
    void operator()(X509* x) const { X509_free(x); }
};
using X509Ptr = std::unique_ptr<X509, X509Free>;

struct Attestation {
    std::vector<std::uint8_t> challenge;
    std::string level;
};

X509Ptr parse_der(const std::vector<std::uint8_t>& der) {
    const unsigned char* p = der.data();
    return X509Ptr(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
}

// Reads one DER element, leaving p just past its header.
bool next_tag(const unsigned char*& p, long& remaining, int expected, long& len) {
    int tag = 0, cls = 0;
    const unsigned char* q = p;
    const int flags = ASN1_get_object(&q, &len, &tag, &cls, remaining);
    if ((flags & 0x80) || tag != expected || cls != V_ASN1_UNIVERSAL) return false;
    remaining -= static_cast<long>(q - p);
    p = q;
    return true;
}

bool skip(const unsigned char*& p, long& remaining, int expected) {
    long len = 0;
    if (!next_tag(p, remaining, expected, len)) return false;
    p += len;
    remaining -= len;
    return true;
}

// KeyDescription ::= SEQUENCE { attestationVersion INTEGER, attestationSecurityLevel
// ENUMERATED, keyMintVersion INTEGER, keyMintSecurityLevel ENUMERATED,
// attestationChallenge OCTET STRING, ... }
std::optional<Attestation> read_attestation(X509* leaf) {
    using ObjPtr = std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)>;
    const ObjPtr oid(OBJ_txt2obj("1.3.6.1.4.1.11129.2.1.17", 1), ASN1_OBJECT_free);
    if (!oid) return std::nullopt;
    const int idx = X509_get_ext_by_OBJ(leaf, oid.get(), -1);
    if (idx < 0) return std::nullopt;
    const ASN1_OCTET_STRING* data = X509_EXTENSION_get_data(X509_get_ext(leaf, idx));
    const unsigned char* p = ASN1_STRING_get0_data(data);
    long remaining = ASN1_STRING_length(data);

    long len = 0;
    if (!next_tag(p, remaining, V_ASN1_SEQUENCE, len)) return std::nullopt;
    remaining = len;
    if (!skip(p, remaining, V_ASN1_INTEGER)) return std::nullopt;

    if (!next_tag(p, remaining, V_ASN1_ENUMERATED, len) || len != 1) return std::nullopt;
    const int level = *p;
    p += len;
    remaining -= len;

    if (!skip(p, remaining, V_ASN1_INTEGER)) return std::nullopt;
    if (!skip(p, remaining, V_ASN1_ENUMERATED)) return std::nullopt;
    if (!next_tag(p, remaining, V_ASN1_OCTET_STRING, len) || len > remaining) return std::nullopt;

    Attestation a;
    a.challenge.assign(p, p + len);
    a.level = level == 2 ? "strongbox" : level == 1 ? "tee" : "software";
    return a;
}

bool verify_ecdsa(EVP_PKEY* key, const std::string& message, const std::vector<std::uint8_t>& signature) {
    std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    if (!ctx || EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) return false;
    return EVP_DigestVerify(ctx.get(), signature.data(), signature.size(),
                            reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
}

std::string public_key_sha256(X509* cert) {
    unsigned char* der = nullptr;
    const int len = i2d_PUBKEY(X509_get0_pubkey(cert), &der);
    if (len <= 0) return {};
    const auto digest = sha256({der, static_cast<std::size_t>(len)});
    OPENSSL_free(der);
    return hex(digest);
}

bool root_in_pem(X509* root, const std::string& pem) {
    std::unique_ptr<BIO, decltype(&BIO_free)> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())), BIO_free);
    if (!bio) return false;
    while (X509Ptr trusted{PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)}) {
        if (EVP_PKEY_eq(X509_get0_pubkey(trusted.get()), X509_get0_pubkey(root)) == 1) return true;
    }
    return false;
}

}  // namespace

std::string base64url_encode(const std::vector<std::uint8_t>& data) {
    std::string s = base64_encode(data);
    std::replace(s.begin(), s.end(), '+', '-');
    std::replace(s.begin(), s.end(), '/', '_');
    s.erase(std::find(s.begin(), s.end(), '='), s.end());
    return s;
}

Result<std::vector<std::uint8_t>> base64url_decode(std::string_view text) {
    std::string s(text);
    if (s.find_first_of("+/=") != std::string::npos) return Result<std::vector<std::uint8_t>>::fail("not base64url");
    std::replace(s.begin(), s.end(), '-', '+');
    std::replace(s.begin(), s.end(), '_', '/');
    s.append((4 - s.size() % 4) % 4, '=');
    return base64_decode(s);
}

std::string challenge_payload(const std::vector<std::uint8_t>& challenge) {
    return std::string(kChallengePrefix) + base64url_encode(challenge);
}

Result<std::vector<std::uint8_t>> parse_challenge_payload(std::string_view payload) {
    using R = Result<std::vector<std::uint8_t>>;
    if (payload.substr(0, kChallengePrefix.size()) != kChallengePrefix) return R::fail("not a PurgeMark challenge");
    auto bytes = base64url_decode(payload.substr(kChallengePrefix.size()));
    if (!bytes) return bytes;
    if (bytes->size() != kChallengeSize) return R::fail("challenge has the wrong length");
    return bytes;
}

AndroidRecordCheck check_android_record(const json& record,
                                        const std::optional<std::vector<std::uint8_t>>& expected_challenge,
                                        const std::optional<std::string>& roots_pem) {
    AndroidRecordCheck out;
    auto stop = [&](std::string why) {
        out.error = std::move(why);
        return out;
    };

    try {
        if (!record.is_object() || record.value("schema", "") != kAndroidRecordSchema) return stop("unknown schema");

        std::vector<X509Ptr> chain;
        for (const auto& item : record.at("key").at("attestation_chain")) {
            const auto der = base64_decode(item.get<std::string>());
            if (!der) return stop("attestation chain is not base64");
            auto cert = parse_der(der.value());
            if (!cert) return stop("attestation chain holds an invalid certificate");
            chain.push_back(std::move(cert));
        }
        if (chain.size() < 2) return stop("attestation chain is too short");

        out.chain_ok = true;
        for (std::size_t i = 0; i < chain.size(); ++i) {
            X509* issuer = chain[std::min(i + 1, chain.size() - 1)].get();  // the root signs itself
            if (X509_verify(chain[i].get(), X509_get0_pubkey(issuer)) != 1) out.chain_ok = false;
        }
        X509* root = chain.back().get();
        out.root_sha256 = public_key_sha256(root);
        if (roots_pem) out.root_trusted = root_in_pem(root, *roots_pem);

        json body = record;
        const auto signature = base64_decode(body.at("signature").get<std::string>());
        body.erase("signature");
        const auto canonical = canonicalize(body);
        if (!signature || !canonical) return stop("cannot rebuild the signed bytes");
        out.signature_ok = verify_ecdsa(X509_get0_pubkey(chain.front().get()), canonical.value(), signature.value());

        const auto challenge = base64url_decode(record.at("challenge").at("value").get<std::string>());
        if (!challenge) return stop("record challenge is not base64url");
        const auto attestation = read_attestation(chain.front().get());
        if (!attestation) return stop("leaf certificate has no readable attestation");
        out.security_level = attestation->level;
        out.challenge_in_attestation = attestation->challenge == challenge.value();
        if (expected_challenge) out.challenge_expected = attestation->challenge == *expected_challenge;
        out.level_consistent = record.at("key").at("security_level").get<std::string>() == attestation->level;
    } catch (const json::exception& e) {
        return stop(std::string("malformed record: ") + e.what());
    }
    return out;
}

}  // namespace pm
