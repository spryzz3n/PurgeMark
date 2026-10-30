#include "zt/certificate.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <filesystem>

#include "zt/canonical_json.hpp"

namespace zt {

using nlohmann::json;

namespace {

const char* method_id(Method m) {
    switch (m) {
        case Method::NvmeSanitizeCrypto: return "nvme-sanitize-crypto";
        case Method::NvmeSanitizeBlock: return "nvme-sanitize-block";
        case Method::NvmeFormatCrypto: return "nvme-format-ses2";
        case Method::NvmeSanitizeOverwrite: return "nvme-sanitize-overwrite";
        case Method::NvmeFormatUserData: return "nvme-format-ses1";
        case Method::AtaSanitizeCrypto: return "ata-sanitize-crypto";
        case Method::AtaSanitizeBlock: return "ata-sanitize-block";
        case Method::AtaSanitizeOverwrite: return "ata-sanitize-overwrite";
        case Method::AtaSecurityEraseEnhanced: return "ata-security-erase-enhanced";
        case Method::AtaSecurityErase: return "ata-security-erase";
        case Method::Overwrite: return "overwrite";
    }
    return "unknown";
}

const char* attestation_name(Attestation a) {
    return a == Attestation::OperatorKey ? "operator-key" : "self-attested";
}

}  // namespace

std::string key_id(std::span<const std::uint8_t> public_raw) { return hex(sha256(public_raw)).substr(0, 16); }

json make_certificate_body(const CertificateInput& in) {
    const auto& d = in.device;
    const auto& s = in.sanitization;
    const auto& v = in.verification;

    json sanitization = {
        {"method", method_id(s.method)},
        {"method_name", to_string(s.method)},
        {"nist_level", to_string(s.level)},
        {"standard", "NIST SP 800-88"},
        {"started_at", s.started_at},
        {"finished_at", s.finished_at},
        {"completed", s.completed},
    };
    if (!s.pattern.empty()) sanitization["pattern"] = s.pattern;
    if (s.bytes_written) sanitization["bytes_written"] = s.bytes_written;
    if (!s.error.empty()) sanitization["error"] = s.error;

    json verification = {
        {"mode", v.mode},
        {"passed", v.passed()},
        {"samples", v.samples},
        {"sample_bytes", v.sample_bytes},
        {"bytes_checked", v.bytes_checked},
        {"mismatches", v.mismatches},
        // The seed is a 64-bit value; as a decimal string it survives JSON
        // parsers that only handle 53-bit integers.
        {"sample_seed", std::to_string(v.seed)},
    };
    if (v.skipped) verification["skipped_uniform_samples"] = v.skipped;
    if (v.inconclusive) verification["inconclusive"] = true;
    if (v.first_mismatch) verification["first_mismatch_offset"] = *v.first_mismatch;
    if (!v.error.empty()) verification["error"] = v.error;

    const bool success = s.completed && v.passed();
    json body = {
        {"schema", kCertificateSchema},
        {"certificate_id", uuid_v4()},
        {"issued_at", utc_now_iso8601()},
        {"result", success ? "sanitized" : "failed"},
        {"tool", {{"name", "zerotrace"}, {"version", kToolVersion}}},
        {"device",
         {{"model", d.model},
          {"serial", d.serial},
          {"firmware", d.firmware},
          {"bus", to_string(d.bus)},
          {"media", d.rotational ? "hdd" : "ssd"},
          {"capacity_bytes", d.size_bytes}}},
        {"sanitization", sanitization},
        {"verification", verification},
    };
    if (!in.operator_name.empty() || !in.organization.empty()) {
        body["operator"] = {{"name", in.operator_name}, {"organization", in.organization}};
    }
    return body;
}

Result<json> sign_certificate(json body, const SigningKey& key, Attestation attestation) {
    body.erase("signature");
    const auto pub = key.public_raw();
    body["signer"] = {
        {"algorithm", "Ed25519"},
        {"public_key", base64_encode(pub)},
        {"key_id", key_id(pub)},
        {"attestation", attestation_name(attestation)},
    };
    const auto canonical = canonicalize(body);
    if (!canonical) return Result<json>::fail("cannot canonicalize certificate: " + canonical.error());
    body["signature"] = base64_encode(key.sign(bytes_of(canonical.value())));
    return Result<json>::ok(std::move(body));
}

namespace {

CertificateCheck verify_unchecked(const json& cert, const std::optional<std::vector<std::uint8_t>>& trusted) {
    CertificateCheck c;
    auto fail = [&](std::string why) {
        c.error = std::move(why);
        return c;
    };

    if (!cert.is_object()) return fail("certificate is not a JSON object");
    if (cert.value("schema", "") != kCertificateSchema) return fail("unknown schema");
    if (!cert.contains("signature") || !cert["signature"].is_string()) return fail("missing signature");
    if (!cert.contains("signer") || !cert["signer"].is_object()) return fail("missing signer");

    const auto& signer = cert["signer"];
    if (signer.value("algorithm", "") != "Ed25519") return fail("unsupported signature algorithm");
    const auto pub = base64_decode(signer.value("public_key", ""));
    if (!pub || pub->size() != 32) return fail("malformed signer public key");
    c.key_id = key_id(pub.value());
    c.attestation = signer.value("attestation", "");
    if (signer.value("key_id", "") != c.key_id) return fail("signer key_id does not match its public key");

    const auto sig = base64_decode(cert["signature"].get<std::string>());
    if (!sig) return fail("malformed signature");

    json body = cert;
    body.erase("signature");
    const auto canonical = canonicalize(body);
    if (!canonical) return fail("cannot canonicalize: " + canonical.error());

    c.signature_valid = ed25519_verify(pub.value(), bytes_of(canonical.value()), sig.value());
    if (!c.signature_valid) return fail("signature does not match certificate contents");
    c.trusted = trusted && *trusted == pub.value();
    return c;
}

}  // namespace

Result<std::string> save_certificate(const json& cert, const std::string& dir) {
    using R = Result<std::string>;
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) return R::fail("cannot create " + dir + ": " + ec.message());

    const auto id = cert.find("certificate_id");
    if (id == cert.end() || !id->is_string()) return R::fail("certificate has no id");
    const std::string path = (std::filesystem::path(dir) / ("zerotrace-" + id->get<std::string>() + ".json")).string();
    const std::string text = cert.dump(2) + "\n";

    // The certificate may be the only record of the erase: make sure it hits the disk.
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    if (fd < 0) return R::fail("create " + path + ": " + std::strerror(errno));
    const bool ok = ::write(fd, text.data(), text.size()) == static_cast<ssize_t>(text.size()) && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) return R::fail("write " + path + " failed");
    return R::ok(path);
}

CertificateCheck verify_certificate(const json& cert, const std::optional<std::vector<std::uint8_t>>& trusted) {
    // Certificates are untrusted input; wrong field types must fail, not throw.
    try {
        return verify_unchecked(cert, trusted);
    } catch (const json::exception& e) {
        CertificateCheck c;
        c.error = std::string("malformed certificate: ") + e.what();
        return c;
    }
}

}  // namespace zt
