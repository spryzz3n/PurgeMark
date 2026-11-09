#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

#include "pm/blockio.hpp"
#include "pm/verify.hpp"

namespace pm {

enum class Pattern { Zero, Random };
std::string to_string(Pattern p);

struct OverwriteOptions {
    Pattern pattern = Pattern::Random;
    std::size_t chunk_bytes = 8 << 20;
    // Called after each chunk with bytes written so far; return false to cancel.
    std::function<bool(std::uint64_t done, std::uint64_t total)> progress;
};

struct OverwriteOutcome {
    std::uint64_t bytes_written = 0;
    double seconds = 0;
    ExpectedContent expected;  // regenerates what was written, for verify_pattern()
};

// Single-pass overwrite of the whole target (NIST SP 800-88 Clear), then a
// cache flush so the data is on the media before verification.
Result<OverwriteOutcome> overwrite(const Target& target, const OverwriteOptions& options);

}  // namespace pm
