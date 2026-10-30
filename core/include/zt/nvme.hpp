#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "zt/result.hpp"

namespace zt {

// Fields of the NVMe Identify Controller data structure (CNS 01h) that matter
// for sanitization. Offsets per NVM Express Base Specification 2.0.
struct NvmeIdentify {
    std::string model;     // MN, bytes 63:24
    std::string serial;    // SN, bytes 23:04
    std::string firmware;  // FR, bytes 71:64
    std::uint32_t namespace_count = 0;  // NN, bytes 519:516

    bool format_supported = false;  // OACS bit 1

    // FNA, byte 524
    bool format_all_namespaces = false;        // bit 0: format affects every namespace
    bool secure_erase_all_namespaces = false;  // bit 1: secure erase affects every namespace
    bool format_crypto_erase = false;          // bit 2: SES=2 (crypto erase) supported

    // SANICAP, bytes 331:328
    bool sanitize_crypto = false;     // bit 0
    bool sanitize_block = false;      // bit 1
    bool sanitize_overwrite = false;  // bit 2

    bool sanitize_supported() const { return sanitize_crypto || sanitize_block || sanitize_overwrite; }
};

using NvmeIdentifyData = std::array<std::uint8_t, 4096>;

Result<NvmeIdentify> parse_nvme_identify_ctrl(std::span<const std::uint8_t, 4096> raw);

// Sends Identify Controller through NVME_IOCTL_ADMIN_CMD. Needs root.
Result<NvmeIdentifyData> nvme_identify_ctrl_raw(const std::string& dev_path);

}  // namespace zt
