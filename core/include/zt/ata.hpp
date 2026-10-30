#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "zt/result.hpp"

namespace zt {

// Fields of ATA IDENTIFY DEVICE (ACS-4) that matter for sanitization.
struct AtaIdentify {
    std::string model;
    std::string serial;
    std::string firmware;
    bool non_rotating = false;  // word 217 == 1

    // Security feature set (word 128)
    bool security_supported = false;
    bool security_enabled = false;  // a user password is set
    bool security_locked = false;
    bool security_frozen = false;  // BIOS froze it at boot; needs a suspend/resume cycle
    bool security_count_expired = false;
    bool enhanced_erase_supported = false;
    unsigned normal_erase_minutes = 0;  // 0 = not reported
    unsigned enhanced_erase_minutes = 0;

    // SANITIZE feature set (word 59)
    bool sanitize_supported = false;
    bool sanitize_crypto = false;
    bool sanitize_block = false;
    bool sanitize_overwrite = false;
};

using AtaIdentifyData = std::array<std::uint8_t, 512>;

Result<AtaIdentify> parse_ata_identify(std::span<const std::uint8_t, 512> raw);

// Issues IDENTIFY DEVICE through SCSI/ATA Translation (ATA PASS-THROUGH(16)) on
// /dev/sdX. Needs root. Fails on SAS drives and on USB bridges without SAT.
Result<AtaIdentifyData> ata_identify_raw(const std::string& dev_path);

}  // namespace zt
