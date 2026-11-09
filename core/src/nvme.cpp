#include "pm/nvme.hpp"

#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "fd.hpp"

namespace pm {

namespace {

constexpr std::uint8_t kOpGetLogPage = 0x02;
constexpr std::uint8_t kOpIdentify = 0x06;
constexpr std::uint8_t kOpFormatNvm = 0x80;
constexpr std::uint8_t kOpSanitize = 0x84;
constexpr std::uint8_t kLogSanitizeStatus = 0x81;
constexpr std::uint32_t kAllNamespaces = 0xFFFFFFFF;

std::uint32_t le32(std::span<const std::uint8_t> raw, std::size_t off) {
    return static_cast<std::uint32_t>(raw[off]) | static_cast<std::uint32_t>(raw[off + 1]) << 8 |
           static_cast<std::uint32_t>(raw[off + 2]) << 16 | static_cast<std::uint32_t>(raw[off + 3]) << 24;
}

// NVMe strings are plain ASCII, space padded.
std::string nvme_string(std::span<const std::uint8_t, 4096> raw, std::size_t off, std::size_t len) {
    std::string s(reinterpret_cast<const char*>(raw.data() + off), len);
    s.erase(std::find_if(s.rbegin(), s.rend(), [](char c) { return c != ' ' && c != '\0'; }).base(), s.end());
    return s;
}

std::string status_message(const char* what, int rc) {
    char msg[96];
    // Status Code Type in bits 10:8, Status Code in bits 7:0 of the returned status.
    std::snprintf(msg, sizeof msg, "%s failed (NVMe status 0x%04X: SCT %u, SC 0x%02X)", what,
                  static_cast<unsigned>(rc), (static_cast<unsigned>(rc) >> 8) & 0x7U, static_cast<unsigned>(rc) & 0xFFU);
    return msg;
}

// Sends an admin command; a positive ioctl return is the NVMe completion status.
Result<bool> admin(int fd, nvme_admin_cmd& cmd, const char* what) {
    const int rc = ::ioctl(fd, NVME_IOCTL_ADMIN_CMD, &cmd);
    if (rc < 0) {
        if (errno == EPERM || errno == EACCES) return Result<bool>::fail("NVMe admin commands need root");
        return Result<bool>::fail(std::string(what) + ": " + std::strerror(errno));
    }
    if (rc > 0) return Result<bool>::fail(status_message(what, rc));
    return Result<bool>::ok(true);
}

Result<NvmeIdentifyData> identify(const std::string& dev_path, std::uint32_t nsid, std::uint32_t cns) {
    using R = Result<NvmeIdentifyData>;
    Fd fd(::open(dev_path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) return R::fail("open " + dev_path + ": " + std::strerror(errno));
    NvmeIdentifyData buf{};
    nvme_admin_cmd cmd{};
    cmd.opcode = kOpIdentify;
    cmd.nsid = nsid;
    cmd.addr = reinterpret_cast<std::uintptr_t>(buf.data());
    cmd.data_len = static_cast<std::uint32_t>(buf.size());
    cmd.cdw10 = cns;
    cmd.timeout_ms = 10'000;
    if (auto r = admin(fd.get(), cmd, "Identify"); !r) return R::fail(r.error());
    return R::ok(buf);
}

}  // namespace

Result<NvmeIdentify> parse_nvme_identify_ctrl(std::span<const std::uint8_t, 4096> raw) {
    NvmeIdentify id;
    id.serial = nvme_string(raw, 4, 20);
    id.model = nvme_string(raw, 24, 40);
    id.firmware = nvme_string(raw, 64, 8);
    if (id.serial.empty() && id.model.empty()) return Result<NvmeIdentify>::fail("empty Identify Controller data");

    const std::uint32_t oacs = raw[256] | (raw[257] << 8);
    id.format_supported = (oacs >> 1) & 1U;

    const std::uint32_t sanicap = le32(raw, 328);
    id.sanitize_crypto = sanicap & 1U;
    id.sanitize_block = (sanicap >> 1) & 1U;
    id.sanitize_overwrite = (sanicap >> 2) & 1U;

    id.max_namespaces = le32(raw, 516);

    const std::uint8_t fna = raw[524];
    id.format_all_namespaces = fna & 1U;
    id.secure_erase_all_namespaces = (fna >> 1) & 1U;
    id.format_crypto_erase = (fna >> 2) & 1U;
    return Result<NvmeIdentify>::ok(id);
}

NvmeNamespaceFormat parse_nvme_identify_ns(std::span<const std::uint8_t, 4096> raw, std::uint32_t nsid) {
    NvmeNamespaceFormat ns;
    ns.nsid = nsid;
    const std::uint8_t flbas = raw[26];
    ns.lba_format = static_cast<std::uint8_t>((flbas & 0x0FU) | ((flbas >> 1) & 0x30U));
    ns.metadata_extended = (flbas >> 4) & 1U;
    const std::uint8_t dps = raw[29];
    ns.protection_type = dps & 0x07U;
    ns.protection_first = (dps >> 3) & 1U;
    return ns;
}

std::uint32_t count_active_namespaces(std::span<const std::uint8_t, 4096> nsid_list) {
    // A list of up to 1024 ascending NSIDs, terminated by the first zero entry.
    std::uint32_t n = 0;
    while (n < 1024 && le32(nsid_list, n * 4) != 0) ++n;
    return n;
}

std::uint32_t nvme_format_cdw10(const NvmeNamespaceFormat& ns, unsigned ses) {
    // LBAF bits 3:0 (+ upper bits 13:12), MSET bit 4, PI bits 7:5, PIL bit 8, SES bits 11:9.
    std::uint32_t v = ns.lba_format & 0x0FU;
    v |= static_cast<std::uint32_t>(ns.metadata_extended) << 4;
    v |= (ns.protection_type & 0x07U) << 5;
    v |= static_cast<std::uint32_t>(ns.protection_first) << 8;
    v |= (ses & 0x07U) << 9;
    v |= static_cast<std::uint32_t>((ns.lba_format >> 4) & 0x03U) << 12;
    return v;
}

NvmeSanitizeStatus parse_nvme_sanitize_log(std::span<const std::uint8_t> log) {
    NvmeSanitizeStatus s;
    if (log.size() < 4) return s;
    s.progress = static_cast<std::uint16_t>(log[0] | (log[1] << 8));
    s.state = log[2] & 0x07U;
    return s;
}

Result<NvmeIdentifyData> nvme_identify_ctrl_raw(const std::string& dev_path) { return identify(dev_path, 0, 0x01); }

Result<NvmeIdentifyData> nvme_identify_ns_raw(const std::string& dev_path, std::uint32_t nsid) {
    return identify(dev_path, nsid, 0x00);
}

Result<NvmeIdentifyData> nvme_active_ns_list_raw(const std::string& dev_path) { return identify(dev_path, 0, 0x02); }

Result<std::uint32_t> nvme_namespace_id(const std::string& dev_path) {
    using R = Result<std::uint32_t>;
    Fd fd(::open(dev_path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) return R::fail("open " + dev_path + ": " + std::strerror(errno));
    const int nsid = ::ioctl(fd.get(), NVME_IOCTL_ID);
    if (nsid <= 0) return R::fail(dev_path + " is not an NVMe namespace");
    return R::ok(static_cast<std::uint32_t>(nsid));
}

Result<bool> nvme_format(int fd, std::uint32_t nsid, std::uint32_t cdw10) {
    nvme_admin_cmd cmd{};
    cmd.opcode = kOpFormatNvm;
    cmd.nsid = nsid;
    cmd.cdw10 = cdw10;
    cmd.timeout_ms = 4 * 60 * 60 * 1000;  // crypto erase is instant; user-data erase can take hours
    return admin(fd, cmd, "Format NVM");
}

Result<bool> nvme_sanitize_start(int fd, SanitizeAction action) {
    nvme_admin_cmd cmd{};
    cmd.opcode = kOpSanitize;
    cmd.nsid = 0;
    // SANACT bits 2:0; AUSE bit 3 lets the drive leave a failed sanitize without
    // another one; OWPASS bits 7:4 = 1 pass for overwrite. CDW11 = overwrite pattern 0.
    cmd.cdw10 = static_cast<std::uint32_t>(action) | (1U << 3) | (action == SanitizeAction::Overwrite ? 1U << 4 : 0U);
    cmd.cdw11 = 0;
    cmd.timeout_ms = 60'000;  // the command returns once accepted; progress is polled via the log
    return admin(fd, cmd, "Sanitize");
}

Result<NvmeSanitizeStatus> nvme_sanitize_status(int fd) {
    std::array<std::uint8_t, 512> log{};
    nvme_admin_cmd cmd{};
    cmd.opcode = kOpGetLogPage;
    cmd.nsid = kAllNamespaces;
    cmd.addr = reinterpret_cast<std::uintptr_t>(log.data());
    cmd.data_len = static_cast<std::uint32_t>(log.size());
    const std::uint32_t dwords = static_cast<std::uint32_t>(log.size() / 4 - 1);  // 0-based
    cmd.cdw10 = kLogSanitizeStatus | ((dwords & 0xFFFFU) << 16);
    cmd.cdw11 = dwords >> 16;
    cmd.timeout_ms = 10'000;
    if (auto r = admin(fd, cmd, "Get Log Page (Sanitize Status)"); !r) return Result<NvmeSanitizeStatus>::fail(r.error());
    return Result<NvmeSanitizeStatus>::ok(parse_nvme_sanitize_log(log));
}

}  // namespace pm
