#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "pm/crypto.hpp"
#include "pm/device.hpp"
#include "pm/methods.hpp"
#include "pm/verify.hpp"

namespace pm {

inline constexpr const char* kCertificateSchema = "purgemark.certificate/v1";
inline constexpr const char* kToolVersion = "0.3.0";

struct SanitizationRecord {
    Method method = Method::Overwrite;
    Level level = Level::Clear;
    std::string pattern;  // overwrite only
    std::string started_at;
    std::string finished_at;
    std::uint64_t bytes_written = 0;
    bool completed = false;
    std::string error;
};

struct CertificateInput {
    Device device;
    SanitizationRecord sanitization;
    VerifyReport verification;
    std::string operator_name;
    std::string organization;
};

// How much the signer's identity is worth:
//  - "self-attested": a one-off key generated for this run. Proves the record
//    wasn't altered after issuance, not who issued it.
//  - "operator-key": a long-lived key the verifier can pin with --trusted-key.
enum class Attestation { SelfAttested, OperatorKey };

// Builds the unsigned certificate body.
nlohmann::json make_certificate_body(const CertificateInput& in);

// Adds a "signer" block, signs the RFC 8785 canonical form of everything
// except "signature", and stores the Base64 signature under "signature".
Result<nlohmann::json> sign_certificate(nlohmann::json body, const SigningKey& key, Attestation attestation);

struct CertificateCheck {
    bool signature_valid = false;
    bool trusted = false;  // signer key equals the caller-supplied trusted key
    std::string key_id;
    std::string attestation;
    std::string error;
};

CertificateCheck verify_certificate(const nlohmann::json& cert,
                                    const std::optional<std::vector<std::uint8_t>>& trusted_public_key);

// Writes "<dir>/purgemark-<certificate_id>.json" (created exclusively, fsynced)
// and returns its path. Creates `dir` if needed.
Result<std::string> save_certificate(const nlohmann::json& cert, const std::string& dir);

// First 16 hex chars of SHA-256 over the raw public key.
std::string key_id(std::span<const std::uint8_t> public_raw);

}  // namespace pm
