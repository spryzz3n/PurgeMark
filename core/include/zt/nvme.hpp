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
    std::uint32_t max_namespaces = 0;     // NN, bytes 519:516: highest valid NSID, not how many exist
    std::uint32_t active_namespaces = 0;  // from the active NSID list (CNS 02h); 0 = unknown

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

// The parts of Identify Namespace (CNS 00h) a Format must preserve.
struct NvmeNamespaceFormat {
    std::uint32_t nsid = 0;
    std::uint8_t lba_format = 0;  // FLBAS index (bits 3:0 plus 6:5)
    bool metadata_extended = false;  // FLBAS bit 4 -> MSET
    std::uint8_t protection_type = 0;  // DPS bits 2:0 -> PI
    bool protection_first = false;     // DPS bit 3 -> PIL
};

// Sanitize Status log page (LID 81h).
struct NvmeSanitizeStatus {
    enum State : std::uint8_t { Never = 0, Succeeded = 1, InProgress = 2, Failed = 3, SucceededNoDealloc = 4 };
    std::uint16_t progress = 0;  // SPROG: fraction complete, n / 65536
    std::uint8_t state = Never;  // SSTAT bits 2:0
    bool done() const { return state != InProgress; }
    bool succeeded() const { return state == Succeeded || state == SucceededNoDealloc; }
};

using NvmeIdentifyData = std::array<std::uint8_t, 4096>;

// --- pure parsing / encoding (unit-tested) ---
Result<NvmeIdentify> parse_nvme_identify_ctrl(std::span<const std::uint8_t, 4096> raw);
NvmeNamespaceFormat parse_nvme_identify_ns(std::span<const std::uint8_t, 4096> raw, std::uint32_t nsid);
std::uint32_t count_active_namespaces(std::span<const std::uint8_t, 4096> nsid_list);
// CDW10 for Format NVM with Secure Erase Setting 0, 1 (user data) or 2 (crypto).
std::uint32_t nvme_format_cdw10(const NvmeNamespaceFormat& ns, unsigned ses);
NvmeSanitizeStatus parse_nvme_sanitize_log(std::span<const std::uint8_t> log);

// --- device I/O (needs root) ---
Result<NvmeIdentifyData> nvme_identify_ctrl_raw(const std::string& dev_path);
Result<NvmeIdentifyData> nvme_identify_ns_raw(const std::string& dev_path, std::uint32_t nsid);
Result<NvmeIdentifyData> nvme_active_ns_list_raw(const std::string& dev_path);
Result<std::uint32_t> nvme_namespace_id(const std::string& dev_path);  // NSID of a namespace block device

// Destructive. `fd` must be an open (O_EXCL) handle on the namespace block device.
Result<bool> nvme_format(int fd, std::uint32_t nsid, std::uint32_t cdw10);
enum class SanitizeAction : std::uint8_t { ExitFailureMode = 1, BlockErase = 2, Overwrite = 3, CryptoErase = 4 };
Result<bool> nvme_sanitize_start(int fd, SanitizeAction action);
Result<NvmeSanitizeStatus> nvme_sanitize_status(int fd);

}  // namespace zt
