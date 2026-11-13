#pragma once

// Checks the pre-wipe record the Android app produces.
//
// The record is signed with a key made inside the phone's keystore and carries
// that key's attestation chain. Nothing here trusts what the record says about
// itself: the signature, the challenge and the security level all come from the
// certificates.

#include <nlohmann/json.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "pm/result.hpp"

namespace pm {

inline constexpr const char* kAndroidRecordSchema = "purgemark.android-record/v1";
inline constexpr std::string_view kChallengePrefix = "purgemark-challenge:v1:";
inline constexpr std::size_t kChallengeSize = 32;

// Base64url without padding, as the app and the QR code use it.
std::string base64url_encode(const std::vector<std::uint8_t>& data);
Result<std::vector<std::uint8_t>> base64url_decode(std::string_view text);

std::string challenge_payload(const std::vector<std::uint8_t>& challenge);
Result<std::vector<std::uint8_t>> parse_challenge_payload(std::string_view payload);

struct AndroidRecordCheck {
    bool signature_ok = false;
    bool chain_ok = false;
    bool challenge_in_attestation = false;  // the record's challenge is the one the hardware attested
    std::optional<bool> challenge_expected;  // set when the station's challenge was given
    std::optional<bool> root_trusted;        // set when trusted roots were given
    bool level_consistent = false;           // the record claims what the attestation says
    std::string security_level;              // from the attestation: software, tee or strongbox
    std::string root_sha256;                 // of the root's public key
    std::string error;

    // Hardware-backed, signed, challenged and anchored in a trusted root.
    bool passed() const {
        return signature_ok && chain_ok && challenge_in_attestation && level_consistent &&
               challenge_expected.value_or(false) && root_trusted.value_or(false) &&
               security_level != "software" && !security_level.empty();
    }
};

// roots_pem is the text of a PEM file with one or more trusted root certificates.
AndroidRecordCheck check_android_record(const nlohmann::json& record,
                                        const std::optional<std::vector<std::uint8_t>>& expected_challenge,
                                        const std::optional<std::string>& roots_pem);

}  // namespace pm
