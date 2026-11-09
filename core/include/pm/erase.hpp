#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "pm/certificate.hpp"
#include "pm/device.hpp"
#include "pm/overwrite.hpp"

namespace pm {

struct EraseJob {
    std::string target_path;  // block device, or an image file for testing (overwrite only)
    Device device;            // identity recorded in the certificate
    Method method = Method::Overwrite;
    Pattern pattern = Pattern::Random;  // overwrite only
    bool allow_experimental = false;    // run methods not yet validated on real hardware
    std::uint32_t verify_samples = 1000;
    std::uint32_t sample_bytes = 64 << 10;
    // Progress callback; returning false cancels an overwrite. Firmware commands
    // can't be interrupted once issued, so for them the return value is ignored.
    std::function<bool(std::uint64_t done, std::uint64_t total)> progress;
};

// Runs the erase and its verification. Never throws away a failure: the
// returned record always describes what happened, so the caller can still
// issue a certificate marked "failed".
CertificateInput run_erase(const EraseJob& job);

}  // namespace pm
