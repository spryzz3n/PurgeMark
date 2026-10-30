#include "zt/ata.hpp"

#include <fcntl.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <numeric>

#include "fd.hpp"

namespace zt {

namespace {

std::uint16_t word(std::span<const std::uint8_t, 512> raw, std::size_t i) {
    return static_cast<std::uint16_t>(raw[2 * i] | (raw[2 * i + 1] << 8));
}

bool bit(std::uint16_t w, unsigned n) { return (w >> n) & 1U; }

// ATA strings store two characters per word, first character in the high byte.
std::string ata_string(std::span<const std::uint8_t, 512> raw, std::size_t first, std::size_t last) {
    std::string s;
    for (std::size_t w = first; w <= last; ++w) {
        s.push_back(static_cast<char>(raw[2 * w + 1]));
        s.push_back(static_cast<char>(raw[2 * w]));
    }
    s.erase(std::find_if(s.rbegin(), s.rend(), [](char c) { return c != ' ' && c != '\0'; }).base(), s.end());
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](char c) { return c != ' '; }));
    return s;
}

// Words 89/90: bit 15 selects the extended format (bits 14:0) over the short one
// (bits 7:0). Either way the unit is 2 minutes; 0 means "not reported".
unsigned erase_minutes(std::uint16_t w) {
    const unsigned v = bit(w, 15) ? (w & 0x7FFFU) : (w & 0x00FFU);
    return v * 2;
}

}  // namespace

Result<AtaIdentify> parse_ata_identify(std::span<const std::uint8_t, 512> raw) {
    if (bit(word(raw, 0), 15)) return Result<AtaIdentify>::fail("not an ATA device (ATAPI or invalid data)");

    // Word 255: when the signature byte is 0xA5, all 512 bytes must sum to 0 mod 256.
    if ((word(raw, 255) & 0xFF) == 0xA5) {
        const unsigned sum = std::accumulate(raw.begin(), raw.end(), 0U);
        if ((sum & 0xFF) != 0) return Result<AtaIdentify>::fail("IDENTIFY checksum mismatch");
    }

    AtaIdentify id;
    id.serial = ata_string(raw, 10, 19);
    id.firmware = ata_string(raw, 23, 26);
    id.model = ata_string(raw, 27, 46);
    id.non_rotating = word(raw, 217) == 1;

    const std::uint16_t sec = word(raw, 128);
    id.security_supported = bit(sec, 0);
    id.security_enabled = bit(sec, 1);
    id.security_locked = bit(sec, 2);
    id.security_frozen = bit(sec, 3);
    id.security_count_expired = bit(sec, 4);
    id.enhanced_erase_supported = bit(sec, 5);
    id.normal_erase_minutes = erase_minutes(word(raw, 89));
    id.enhanced_erase_minutes = erase_minutes(word(raw, 90));

    const std::uint16_t san = word(raw, 59);
    id.sanitize_supported = bit(san, 12);
    id.sanitize_crypto = id.sanitize_supported && bit(san, 13);
    id.sanitize_overwrite = id.sanitize_supported && bit(san, 14);
    id.sanitize_block = id.sanitize_supported && bit(san, 15);
    return Result<AtaIdentify>::ok(id);
}

Result<AtaIdentifyData> ata_identify_raw(const std::string& dev_path) {
    using R = Result<AtaIdentifyData>;
    Fd fd(::open(dev_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (!fd) return R::fail("open " + dev_path + ": " + std::strerror(errno));

    AtaIdentifyData buf{};
    std::uint8_t sense[32]{};
    // SAT ATA PASS-THROUGH(16): PIO data-in, transfer length in the sector count
    // field, counted in 512-byte blocks, direction from device.
    std::uint8_t cdb[16]{};
    cdb[0] = 0x85;
    cdb[1] = 4 << 1;  // protocol 4 = PIO data-in
    cdb[2] = 0x0E;    // T_DIR=1, BYT_BLOK=1, T_LENGTH=2 (sector count)
    cdb[6] = 1;       // one sector
    cdb[14] = 0xEC;   // IDENTIFY DEVICE

    sg_io_hdr_t h{};
    h.interface_id = 'S';
    h.dxfer_direction = SG_DXFER_FROM_DEV;
    h.cmd_len = sizeof cdb;
    h.mx_sb_len = sizeof sense;
    h.dxfer_len = static_cast<unsigned>(buf.size());
    h.dxferp = buf.data();
    h.cmdp = cdb;
    h.sbp = sense;
    h.timeout = 10'000;  // ms

    if (::ioctl(fd.get(), SG_IO, &h) < 0) {
        if (errno == EPERM || errno == EACCES) return R::fail("ATA pass-through needs root");
        return R::fail(std::string("SG_IO: ") + std::strerror(errno));
    }
    if (h.host_status != 0 || (h.driver_status & 0x07) != 0) {
        return R::fail("ATA pass-through not supported by this path (host/driver error)");
    }
    if (h.status == 0x02) {  // CHECK CONDITION: some SATLs report success this way too
        const bool descriptor = (sense[0] & 0x7F) >= 0x72;
        const unsigned key = (descriptor ? sense[1] : sense[2]) & 0x0FU;
        const unsigned asc = descriptor ? sense[2] : sense[12];
        const unsigned ascq = descriptor ? sense[3] : sense[13];
        if (key != 0 && key != 1) {
            char msg[160];
            std::snprintf(msg, sizeof msg,
                          "ATA pass-through rejected (sense key %X, ASC/ASCQ %02X/%02X): "
                          "virtual disk, SAS drive, or USB bridge without SAT",
                          key, asc, ascq);
            return R::fail(msg);
        }
    } else if (h.status != 0) {
        return R::fail("ATA pass-through failed (SCSI status " + std::to_string(h.status) + ")");
    }
    if (h.resid >= static_cast<int>(buf.size())) return R::fail("IDENTIFY returned no data");
    return R::ok(buf);
}

}  // namespace zt
