#pragma once

#include <string>
#include <string_view>

#include <nlohmann/json.hpp>

#include "pm/result.hpp"

namespace pm {

// RFC 8785 (JSON Canonicalization Scheme) serialization: no whitespace,
// object keys sorted by UTF-16 code units, minimal string escaping.
// Supports the subset certificates use: floats and integers beyond ±2^53
// are rejected rather than risk a number format that differs between
// implementations. Strings must be valid UTF-8.
Result<std::string> canonicalize(const nlohmann::json& value);

// Parses JSON that will be signed or verified. On top of normal parsing it
// rejects numbers with a fraction or exponent and objects with a repeated
// key. Parsers disagree on which of two equal keys wins, so a certificate
// with one could show different contents in different verifiers.
// verifier/pm-verify.js applies the same rules.
Result<nlohmann::json> parse_strict(std::string_view text);

}  // namespace pm
