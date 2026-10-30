#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include "zt/blockio.hpp"
#include "zt/crypto.hpp"

namespace zt {

// Which regions of the target get read back. Always includes the first and
// last sample (partition tables and backup GPT live there), plus `count`
// pseudo-random ones from `seed`, so a report can be reproduced.
struct SamplePlan {
    std::vector<std::uint64_t> offsets;  // sorted, unique, aligned
    std::uint32_t sample_bytes = 0;
    std::uint64_t seed = 0;
};

SamplePlan plan_samples(std::uint64_t target_size, std::uint32_t alignment, std::uint32_t sample_bytes,
                        std::uint32_t count, std::uint64_t seed);

struct VerifyReport {
    std::string mode;  // "pattern" or "changed"
    std::uint32_t samples = 0;
    std::uint64_t bytes_checked = 0;
    std::uint32_t mismatches = 0;
    std::optional<std::uint64_t> first_mismatch;
    std::uint32_t skipped = 0;  // "changed": samples that were uniform before the erase
    bool inconclusive = false;  // "changed": every sample was skipped
    std::string error;          // I/O failure during verification
    std::uint64_t seed = 0;
    std::uint32_t sample_bytes = 0;

    bool passed() const { return error.empty() && mismatches == 0 && !inconclusive && samples > 0; }
};

// Produces the bytes the target should contain at an offset.
using ExpectedContent = std::function<void(std::uint64_t offset, std::span<std::uint8_t> out)>;

// After an overwrite: every sampled byte must equal the written pattern.
VerifyReport verify_pattern(const Target& target, const SamplePlan& plan, const ExpectedContent& expected);

// For firmware methods, whose post-erase content is vendor-defined (zeros, ones,
// or ciphertext under a discarded key). Before the erase, random canaries are
// written into every sample region; afterwards none of them may remain. Unlike
// comparing against prior content, this is conclusive even on a blank drive and
// catches firmware that reports success without erasing.
Result<ExpectedContent> plant_canaries(const Target& target, const SamplePlan& plan);
VerifyReport verify_canaries_gone(const Target& target, const SamplePlan& plan, const ExpectedContent& canary);

// Compares against content fingerprinted before the erase: each sample
// must differ from its pre-erase fingerprint. Samples that were uniform before
// (e.g. never-written zeros) prove nothing and are skipped.
struct Fingerprint {
    Sha256 digest{};
    bool uniform = false;
};
Result<std::vector<Fingerprint>> fingerprint(const Target& target, const SamplePlan& plan);
VerifyReport verify_changed(const Target& target, const SamplePlan& plan, const std::vector<Fingerprint>& before);

}  // namespace zt
