#pragma once

#include <string>

#include <nlohmann/json.hpp>

#include "pm/result.hpp"

namespace pm {

// RFC 8785 (JSON Canonicalization Scheme) serialization: no whitespace,
// object keys sorted by UTF-16 code units, minimal string escaping.
// Supports the subset certificates use: floats and integers beyond ±2^53
// are rejected rather than risk a number format that differs between
// implementations. Strings must be valid UTF-8.
Result<std::string> canonicalize(const nlohmann::json& value);

}  // namespace pm
