#include "zt/nvme.hpp"

#include <fcntl.h>
#include <linux/nvme_ioctl.h>
#include <sys/ioctl.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>

#include "fd.hpp"

namespace zt {

namespace {

std::uint32_t le32(std::span<const std::uint8_t, 4096> raw, std::size_t off) {
    return static_cast<std::uint32_t>(raw[off]) | static_cast<std::uint32_t>(raw[off + 1]) << 8 |
           static_cast<std::uint32_t>(raw[off + 2]) << 16 | static_cast<std::uint32_t>(raw[off + 3]) << 24;
}

// NVMe strings are plain ASCII, space padded.
std::string nvme_string(std::span<const std::uint8_t, 4096> raw, std::size_t off, std::size_t len) {
    std::string s(reinterpret_cast<const char*>(raw.data() + off), len);
    s.erase(std::find_if(s.rbegin(), s.rend(), [](char c) { return c != ' ' && c != '\0'; }).base(), s.end());
    return s;
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

    id.namespace_count = le32(raw, 516);

    const std::uint8_t fna = raw[524];
    id.format_all_namespaces = fna & 1U;
    id.secure_erase_all_namespaces = (fna >> 1) & 1U;
    id.format_crypto_erase = (fna >> 2) & 1U;
    return Result<NvmeIdentify>::ok(id);
}

Result<NvmeIdentifyData> nvme_identify_ctrl_raw(const std::string& dev_path) {
    using R = Result<NvmeIdentifyData>;
    Fd fd(::open(dev_path.c_str(), O_RDONLY | O_CLOEXEC));
    if (!fd) return R::fail("open " + dev_path + ": " + std::strerror(errno));

    NvmeIdentifyData buf{};
    nvme_admin_cmd cmd{};
    cmd.opcode = 0x06;  // Identify
    cmd.addr = reinterpret_cast<std::uintptr_t>(buf.data());
    cmd.data_len = static_cast<std::uint32_t>(buf.size());
    cmd.cdw10 = 1;  // CNS 01h: Identify Controller
    cmd.timeout_ms = 10'000;

    const int rc = ::ioctl(fd.get(), NVME_IOCTL_ADMIN_CMD, &cmd);
    if (rc < 0) {
        if (errno == EPERM || errno == EACCES) return R::fail("NVMe admin commands need root");
        return R::fail(std::string("NVME_IOCTL_ADMIN_CMD: ") + std::strerror(errno));
    }
    if (rc > 0) {  // positive return is the NVMe completion status
        char msg[64];
        std::snprintf(msg, sizeof msg, "Identify failed (NVMe status 0x%04X)", static_cast<unsigned>(rc));
        return R::fail(msg);
    }
    return R::ok(buf);
}

}  // namespace zt
