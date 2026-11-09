#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

#include "pm/result.hpp"

namespace pm {

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

// --- ATA pass-through (SAT, ATA PASS-THROUGH(16)) ------------------------------

struct AtaTaskfile {
    std::uint16_t features = 0;
    std::uint16_t count = 0;
    std::uint64_t lba = 0;  // 48 bits
    std::uint8_t device = 0x40;  // LBA mode
    std::uint8_t command = 0;
    bool extended = false;  // 48-bit command (EXTEND bit)
};

// Output registers, from the ATA Status Return sense descriptor.
struct AtaRegisters {
    std::uint8_t status = 0;
    std::uint8_t error = 0;
    std::uint8_t device = 0;
    std::uint16_t count = 0;
    std::uint64_t lba = 0;
    // Fixed-format sense only carries the low bytes; these say what's missing.
    bool upper_bytes_known = true;
    bool count_upper_nonzero = false;
    bool has_error() const { return status & 0x01; }
};

enum class AtaProtocol : std::uint8_t { NonData = 3, PioDataIn = 4 };

std::array<std::uint8_t, 16> ata_pt16_cdb(const AtaTaskfile& tf, AtaProtocol protocol, bool check_condition);
std::optional<AtaRegisters> parse_ata_sense(std::span<const std::uint8_t> sense);

// Sends one command. Fails only on transport problems (no SAT, no permission);
// an ATA-level error comes back as registers with has_error() set.
Result<AtaRegisters> ata_passthrough(int fd, const AtaTaskfile& tf, AtaProtocol protocol,
                                     std::span<std::uint8_t> data_in, unsigned timeout_ms);

// --- SANITIZE feature set (ACS-4 7.30) ------------------------------------------

enum class AtaSanitizeAction { CryptoScramble, BlockErase, Overwrite };

struct AtaSanitizeStatus {
    bool completed_ok = false;  // last sanitize finished without error
    bool in_progress = false;
    bool frozen = false;        // SANITIZE FREEZE LOCK is in effect
    bool failed = false;        // last sanitize failed (or the status command was aborted)
    std::uint16_t progress = 0;  // n / 65536 while in progress
};

// FAILURE MODE is always set: if the sanitize fails, the drive may leave the
// failed state via SANITIZE STATUS EXT with CLEAR, instead of refusing all
// media access until a sanitize succeeds.
AtaTaskfile ata_sanitize_taskfile(AtaSanitizeAction action);
AtaTaskfile ata_sanitize_status_taskfile(bool clear_failure);
AtaSanitizeStatus parse_ata_sanitize_status(const AtaRegisters& regs);

Result<bool> ata_sanitize_start(int fd, AtaSanitizeAction action);
Result<AtaSanitizeStatus> ata_sanitize_status(int fd, bool clear_failure = false);

}  // namespace pm
