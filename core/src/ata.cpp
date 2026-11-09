#include "pm/ata.hpp"

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

namespace pm {

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

std::array<std::uint8_t, 16> ata_pt16_cdb(const AtaTaskfile& tf, AtaProtocol protocol, bool check_condition) {
    std::array<std::uint8_t, 16> cdb{};
    const auto byte = [](std::uint64_t v, unsigned shift) { return static_cast<std::uint8_t>((v >> shift) & 0xFF); };
    cdb[0] = 0x85;  // ATA PASS-THROUGH(16)
    cdb[1] = static_cast<std::uint8_t>((static_cast<unsigned>(protocol) << 1) | (tf.extended ? 1U : 0U));
    // CK_COND (bit 5) asks for the output registers in the sense data. For data-in:
    // T_DIR=1, BYT_BLOK=1, T_LENGTH=2 (length in the COUNT field, in 512-byte blocks).
    cdb[2] = static_cast<std::uint8_t>((check_condition ? 0x20U : 0U) | (protocol == AtaProtocol::PioDataIn ? 0x0EU : 0U));
    cdb[3] = byte(tf.features, 8);
    cdb[4] = byte(tf.features, 0);
    cdb[5] = byte(tf.count, 8);
    cdb[6] = byte(tf.count, 0);
    cdb[7] = byte(tf.lba, 24);
    cdb[8] = byte(tf.lba, 0);
    cdb[9] = byte(tf.lba, 32);
    cdb[10] = byte(tf.lba, 8);
    cdb[11] = byte(tf.lba, 40);
    cdb[12] = byte(tf.lba, 16);
    cdb[13] = tf.device;
    cdb[14] = tf.command;
    return cdb;
}

std::optional<AtaRegisters> parse_ata_sense(std::span<const std::uint8_t> sense) {
    if (sense.size() < 8) return std::nullopt;
    const unsigned code = sense[0] & 0x7FU;
    if (code == 0x72 || code == 0x73) {
        // Descriptor format: find the ATA Status Return descriptor (09h).
        const std::size_t end = std::min<std::size_t>(sense.size(), 8U + sense[7]);
        for (std::size_t pos = 8; pos + 2 <= end;) {
            const std::size_t len = 2U + sense[pos + 1];
            if (sense[pos] == 0x09 && len >= 14 && pos + 14 <= end) {
                const auto d = sense.subspan(pos, 14);
                AtaRegisters r;
                r.error = d[3];
                r.count = static_cast<std::uint16_t>((d[4] << 8) | d[5]);
                r.lba = static_cast<std::uint64_t>(d[7]) | static_cast<std::uint64_t>(d[9]) << 8 |
                        static_cast<std::uint64_t>(d[11]) << 16 | static_cast<std::uint64_t>(d[6]) << 24 |
                        static_cast<std::uint64_t>(d[8]) << 32 | static_cast<std::uint64_t>(d[10]) << 40;
                r.device = d[12];
                r.status = d[13];
                return r;
            }
            pos += len;
        }
        return std::nullopt;
    }
    if ((code == 0x70 || code == 0x71) && sense.size() >= 12) {
        // Fixed format (SAT-4): INFORMATION = error, status, device, count(7:0);
        // COMMAND-SPECIFIC INFORMATION = flags, lba(7:0), lba(15:8), lba(23:16).
        AtaRegisters r;
        r.error = sense[3];
        r.status = sense[4];
        r.device = sense[5];
        r.count = sense[6];
        r.count_upper_nonzero = (sense[8] >> 6) & 1U;
        r.lba = static_cast<std::uint64_t>(sense[9]) | static_cast<std::uint64_t>(sense[10]) << 8 |
                static_cast<std::uint64_t>(sense[11]) << 16;
        r.upper_bytes_known = false;
        return r;
    }
    return std::nullopt;
}

Result<AtaRegisters> ata_passthrough(int fd, const AtaTaskfile& tf, AtaProtocol protocol,
                                     std::span<std::uint8_t> data_in, unsigned timeout_ms) {
    using R = Result<AtaRegisters>;
    const bool want_registers = protocol == AtaProtocol::NonData;
    auto cdb = ata_pt16_cdb(tf, protocol, want_registers);
    std::array<std::uint8_t, 64> sense{};

    sg_io_hdr_t h{};
    h.interface_id = 'S';
    h.dxfer_direction = data_in.empty() ? SG_DXFER_NONE : SG_DXFER_FROM_DEV;
    h.cmd_len = static_cast<unsigned char>(cdb.size());
    h.mx_sb_len = static_cast<unsigned char>(sense.size());
    h.dxfer_len = static_cast<unsigned>(data_in.size());
    h.dxferp = data_in.empty() ? nullptr : data_in.data();
    h.cmdp = cdb.data();
    h.sbp = sense.data();
    h.timeout = timeout_ms;

    if (::ioctl(fd, SG_IO, &h) < 0) {
        if (errno == EPERM || errno == EACCES) return R::fail("ATA pass-through needs root");
        return R::fail(std::string("SG_IO: ") + std::strerror(errno));
    }
    if (h.host_status != 0 || (h.driver_status & 0x07) != 0) {
        return R::fail("ATA pass-through not supported by this path (host/driver error)");
    }
    if (h.status == 0) return R::ok(AtaRegisters{});
    if (h.status != 0x02) return R::fail("ATA pass-through failed (SCSI status " + std::to_string(h.status) + ")");

    // CHECK CONDITION. With the ATA registers attached it's an ATA-level result
    // (success with CK_COND, or an ATA error): hand the registers back.
    if (auto regs = parse_ata_sense(std::span(sense).first(h.sb_len_wr))) return R::ok(*regs);
    const bool descriptor = (sense[0] & 0x7F) >= 0x72;
    const unsigned key = (descriptor ? sense[1] : sense[2]) & 0x0FU;
    const unsigned asc = descriptor ? sense[2] : sense[12];
    const unsigned ascq = descriptor ? sense[3] : sense[13];
    if (key == 0 || key == 1) return R::ok(AtaRegisters{});  // some SATLs report success this way
    char msg[160];
    std::snprintf(msg, sizeof msg,
                  "ATA pass-through rejected (sense key %X, ASC/ASCQ %02X/%02X): "
                  "virtual disk, SAS drive, or USB bridge without SAT",
                  key, asc, ascq);
    return R::fail(msg);
}

Result<AtaIdentifyData> ata_identify_raw(const std::string& dev_path) {
    using R = Result<AtaIdentifyData>;
    Fd fd(::open(dev_path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC));
    if (!fd) return R::fail("open " + dev_path + ": " + std::strerror(errno));

    AtaIdentifyData buf{};
    AtaTaskfile tf;
    tf.command = 0xEC;  // IDENTIFY DEVICE
    tf.count = 1;       // one 512-byte block
    tf.device = 0;
    const auto r = ata_passthrough(fd.get(), tf, AtaProtocol::PioDataIn, buf, 10'000);
    if (!r) return R::fail(r.error());
    if (r->has_error()) return R::fail("IDENTIFY DEVICE aborted by the drive");
    if (std::all_of(buf.begin(), buf.end(), [](std::uint8_t b) { return b == 0; })) {
        return R::fail("IDENTIFY returned no data");
    }
    return R::ok(buf);
}

// --- SANITIZE ------------------------------------------------------------------

namespace {
constexpr std::uint8_t kSanitizeDevice = 0xB4;
constexpr std::uint16_t kFailureMode = 1U << 4;  // COUNT bit 4
}  // namespace

AtaTaskfile ata_sanitize_taskfile(AtaSanitizeAction action) {
    AtaTaskfile tf;
    tf.command = kSanitizeDevice;
    tf.extended = true;
    tf.count = kFailureMode;
    switch (action) {
        case AtaSanitizeAction::CryptoScramble:
            tf.features = 0x0011;  // CRYPTO SCRAMBLE EXT
            tf.lba = 0x43727970;   // "Cryp" signature
            break;
        case AtaSanitizeAction::BlockErase:
            tf.features = 0x0012;  // BLOCK ERASE EXT
            tf.lba = 0x426B4572;   // "BkEr" signature
            break;
        case AtaSanitizeAction::Overwrite:
            tf.features = 0x0014;                         // OVERWRITE EXT
            tf.lba = std::uint64_t{0x4F57} << 32;         // "OW" signature, pattern 0
            tf.count = static_cast<std::uint16_t>(tf.count | 1U);  // one pass
            break;
    }
    return tf;
}

AtaTaskfile ata_sanitize_status_taskfile(bool clear_failure) {
    AtaTaskfile tf;
    tf.command = kSanitizeDevice;
    tf.extended = true;
    tf.features = 0x0000;  // SANITIZE STATUS EXT
    tf.count = clear_failure ? 1U : 0U;  // CLEAR SANITIZE OPERATION FAILED
    return tf;
}

AtaSanitizeStatus parse_ata_sanitize_status(const AtaRegisters& regs) {
    AtaSanitizeStatus s;
    // The progress indicator is FFFFh whenever no sanitize is running.
    s.progress = static_cast<std::uint16_t>(regs.lba & 0xFFFF);
    if (regs.has_error()) {
        // ABORT on SANITIZE STATUS EXT: the last sanitize failed.
        s.failed = true;
        return s;
    }
    if (regs.upper_bytes_known) {
        s.completed_ok = (regs.count >> 15) & 1U;
        s.in_progress = (regs.count >> 14) & 1U;
        s.frozen = (regs.count >> 13) & 1U;
    } else {
        // Fixed-format sense lost COUNT(15:8); fall back to the progress indicator.
        // A wrong guess here can't produce a false pass: the canary check after
        // the sanitize is what decides whether the erase succeeded.
        s.in_progress = s.progress != 0xFFFF;
        s.completed_ok = !s.in_progress && regs.count_upper_nonzero;
    }
    return s;
}

Result<bool> ata_sanitize_start(int fd, AtaSanitizeAction action) {
    // The command returns once accepted; the drive then sanitizes in the background.
    const auto r = ata_passthrough(fd, ata_sanitize_taskfile(action), AtaProtocol::NonData, {}, 60'000);
    if (!r) return Result<bool>::fail(r.error());
    if (r->has_error()) {
        char msg[96];
        std::snprintf(msg, sizeof msg, "drive rejected SANITIZE (error register 0x%02X)", r->error);
        return Result<bool>::fail(msg);
    }
    return Result<bool>::ok(true);
}

Result<AtaSanitizeStatus> ata_sanitize_status(int fd, bool clear_failure) {
    const auto r =
        ata_passthrough(fd, ata_sanitize_status_taskfile(clear_failure), AtaProtocol::NonData, {}, 10'000);
    if (!r) return Result<AtaSanitizeStatus>::fail(r.error());
    return Result<AtaSanitizeStatus>::ok(parse_ata_sanitize_status(r.value()));
}

}  // namespace pm
