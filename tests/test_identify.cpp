// Parses synthetic IDENTIFY buffers and checks method ranking.

#include <algorithm>
#include <cstring>
#include <numeric>
#include <string>

#include "check.hpp"
#include "zt/ata.hpp"
#include "zt/methods.hpp"
#include "zt/nvme.hpp"

namespace {

// --- ATA helpers -----------------------------------------------------------

void set_word(zt::AtaIdentifyData& d, std::size_t w, std::uint16_t v) {
    d[2 * w] = static_cast<std::uint8_t>(v & 0xFF);
    d[2 * w + 1] = static_cast<std::uint8_t>(v >> 8);
}

// Inverse of the ATA string encoding: first char of each pair goes in the high byte.
void set_ata_string(zt::AtaIdentifyData& d, std::size_t first, std::size_t last, const std::string& s) {
    std::string padded = s;
    padded.resize((last - first + 1) * 2, ' ');
    for (std::size_t w = first, i = 0; w <= last; ++w, i += 2) {
        d[2 * w + 1] = static_cast<std::uint8_t>(padded[i]);
        d[2 * w] = static_cast<std::uint8_t>(padded[i + 1]);
    }
}

void seal_checksum(zt::AtaIdentifyData& d) {
    d[510] = 0xA5;
    d[511] = 0;
    const unsigned sum = std::accumulate(d.begin(), d.end() - 1, 0U);
    d[511] = static_cast<std::uint8_t>((256 - (sum & 0xFF)) & 0xFF);
}

zt::AtaIdentifyData sata_ssd() {
    zt::AtaIdentifyData d{};
    set_word(d, 0, 0x0040);
    set_ata_string(d, 10, 19, "S3Z9NB0K123456X");
    set_ata_string(d, 23, 26, "RVT02B6Q");
    set_ata_string(d, 27, 46, "Samsung SSD 860 EVO 500GB");
    set_word(d, 59, (1 << 12) | (1 << 13) | (1 << 15));  // sanitize: crypto + block
    set_word(d, 89, 1);                                    // 2 min
    set_word(d, 90, 4);                                    // 8 min
    set_word(d, 128, (1 << 0) | (1 << 5));                 // security supported, enhanced erase
    set_word(d, 217, 1);                                   // non-rotating
    seal_checksum(d);
    return d;
}

zt::AtaIdentifyData frozen_hdd() {
    zt::AtaIdentifyData d{};
    set_ata_string(d, 27, 46, "WDC WD10EZEX-08WN4A0");
    set_word(d, 89, 0x8000 | 60);                       // extended format: 120 min
    set_word(d, 128, (1 << 0) | (1 << 3) | (1 << 5));   // supported, FROZEN, enhanced
    set_word(d, 217, 7200);
    return d;  // no checksum signature: must still parse
}

// --- NVMe helpers ----------------------------------------------------------

zt::NvmeIdentifyData nvme_ctrl(std::uint32_t sanicap, std::uint8_t fna, std::uint32_t nn) {
    zt::NvmeIdentifyData d{};
    std::memset(d.data() + 4, ' ', 20 + 40 + 8);
    std::memcpy(d.data() + 4, "S5GXNX0R123456", 14);
    std::memcpy(d.data() + 24, "Samsung SSD 980 PRO 500GB", 25);
    std::memcpy(d.data() + 64, "5B2QGXA7", 8);
    d[256] = 0x02;  // OACS: Format NVM supported
    for (int i = 0; i < 4; ++i) d[328 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(sanicap >> (8 * i));
    for (int i = 0; i < 4; ++i) d[516 + static_cast<std::size_t>(i)] = static_cast<std::uint8_t>(nn >> (8 * i));
    d[524] = fna;
    return d;
}

const zt::Candidate* find(const std::vector<zt::Candidate>& v, zt::Method m) {
    for (const auto& c : v)
        if (c.method == m) return &c;
    return nullptr;
}

}  // namespace

int main() {
    // ATA: SATA SSD with sanitize
    {
        const auto raw = sata_ssd();
        const auto r = zt::parse_ata_identify(raw);
        CHECK(static_cast<bool>(r));
        if (r) {
            CHECK(r->model == "Samsung SSD 860 EVO 500GB");
            CHECK(r->serial == "S3Z9NB0K123456X");
            CHECK(r->firmware == "RVT02B6Q");
            CHECK(r->non_rotating);
            CHECK(r->sanitize_supported && r->sanitize_crypto && r->sanitize_block && !r->sanitize_overwrite);
            CHECK(r->security_supported && !r->security_frozen && r->enhanced_erase_supported);
            CHECK(r->normal_erase_minutes == 2 && r->enhanced_erase_minutes == 8);

            zt::Device dev;
            dev.rotational = false;
            const auto m = zt::rank_methods(dev, std::nullopt, r.value());
            CHECK(!m.empty() && m.front().method == zt::Method::AtaSanitizeCrypto);
            CHECK(m.front().level == zt::Level::Purge);
            const auto* enh = find(m, zt::Method::AtaSecurityEraseEnhanced);
            CHECK(enh && enh->available && enh->level == zt::Level::Clear);  // conservative on SSDs
            const auto* ow = find(m, zt::Method::AtaSanitizeOverwrite);
            CHECK(ow && !ow->available);
            CHECK(m.back().available == false);  // unavailable ones sort last
        }
    }

    // ATA: corrupted checksum is rejected
    {
        auto raw = sata_ssd();
        raw[100] ^= 0xFF;
        CHECK(!zt::parse_ata_identify(raw));
    }

    // ATA: frozen HDD, no sanitize
    {
        const auto raw = frozen_hdd();
        const auto r = zt::parse_ata_identify(raw);
        CHECK(static_cast<bool>(r));
        if (r) {
            CHECK(r->security_frozen && !r->non_rotating);
            CHECK(r->normal_erase_minutes == 120);
            zt::Device dev;
            dev.rotational = true;
            const auto m = zt::rank_methods(dev, std::nullopt, r.value());
            const auto* se = find(m, zt::Method::AtaSecurityErase);
            CHECK(se && !se->available && se->note.find("frozen") != std::string::npos);
            CHECK(se && se->level == zt::Level::Purge);  // HDD
            CHECK(m.front().method == zt::Method::Overwrite);  // only thing left
        }
    }

    // ATA: ATAPI signature rejected
    {
        zt::AtaIdentifyData raw{};
        raw[1] = 0x80;
        CHECK(!zt::parse_ata_identify(raw));
    }

    // NVMe: full sanitize support, single namespace
    {
        const auto raw = nvme_ctrl(0b111, 0b111, 1);
        const auto r = zt::parse_nvme_identify_ctrl(raw);
        CHECK(static_cast<bool>(r));
        if (r) {
            CHECK(r->model == "Samsung SSD 980 PRO 500GB");
            CHECK(r->serial == "S5GXNX0R123456");
            CHECK(r->firmware == "5B2QGXA7");
            CHECK(r->format_supported && r->format_crypto_erase);
            CHECK(r->sanitize_crypto && r->sanitize_block && r->sanitize_overwrite);
            CHECK(r->max_namespaces == 1);
            const auto m = zt::rank_methods({}, r.value(), std::nullopt);
            CHECK(m.front().method == zt::Method::NvmeSanitizeCrypto);
            CHECK(m.front().note.empty());  // one namespace: nothing extra to warn about
        }
    }

    // NVMe: no sanitize, format-with-crypto only. NN=256 like QEMU, but only 3 active:
    // the warning must use the active count, not NN.
    {
        const auto raw = nvme_ctrl(0, 0b101, 256);
        auto r = zt::parse_nvme_identify_ctrl(raw);
        CHECK(static_cast<bool>(r));
        if (r) {
            auto id = r.value();
            CHECK(!id.sanitize_supported() && id.max_namespaces == 256);
            zt::NvmeIdentifyData list{};
            // Little-endian NSIDs 1, 2, 5 in consecutive 4-byte slots, then a zero terminator.
            list[0] = 1;
            list[4] = 2;
            list[8] = 5;
            id.active_namespaces = zt::count_active_namespaces(list);
            CHECK(id.active_namespaces == 3);
            const auto m = zt::rank_methods({}, id, std::nullopt);
            CHECK(m.front().method == zt::Method::NvmeFormatCrypto);
            CHECK(m.front().note.find("all 3 namespaces") != std::string::npos);
            const auto* ses1 = find(m, zt::Method::NvmeFormatUserData);
            CHECK(ses1 && ses1->available && ses1->level == zt::Level::Clear);
        }
    }

    // NVMe: Identify Namespace -> Format CDW10 keeps the current LBA format and PI settings
    {
        zt::NvmeIdentifyData ns{};
        ns[26] = 0x12 | 0x20;  // FLBAS: index low bits 2, MSET=1, upper bits (6:5) = 01 -> index 0x12
        ns[29] = 0x09;         // DPS: PI type 1, PIL=1
        const auto f = zt::parse_nvme_identify_ns(ns, 7);
        CHECK(f.nsid == 7 && f.lba_format == 0x12 && f.metadata_extended);
        CHECK(f.protection_type == 1 && f.protection_first);
        const std::uint32_t cdw10 = zt::nvme_format_cdw10(f, 2);
        CHECK((cdw10 & 0x0F) == 0x2);          // LBAF low
        CHECK(((cdw10 >> 4) & 1) == 1);        // MSET
        CHECK(((cdw10 >> 5) & 7) == 1);        // PI
        CHECK(((cdw10 >> 8) & 1) == 1);        // PIL
        CHECK(((cdw10 >> 9) & 7) == 2);        // SES = crypto erase
        CHECK(((cdw10 >> 12) & 3) == 1);       // LBAF high
        CHECK(zt::nvme_format_cdw10(zt::NvmeNamespaceFormat{}, 1) == (1u << 9));
    }

    // NVMe: Sanitize Status log
    {
        std::array<std::uint8_t, 512> log{};
        log[0] = 0x00;
        log[1] = 0x80;  // SPROG = 32768 -> 50%
        log[2] = 0x02;  // in progress
        auto s = zt::parse_nvme_sanitize_log(log);
        CHECK(s.progress == 32768 && !s.done());
        log[2] = 0x01;
        s = zt::parse_nvme_sanitize_log(log);
        CHECK(s.done() && s.succeeded());
        log[2] = 0x03;
        CHECK(!zt::parse_nvme_sanitize_log(log).succeeded());
        log[2] = 0x04;
        CHECK(zt::parse_nvme_sanitize_log(log).succeeded());
    }

    // ATA PASS-THROUGH(16): IDENTIFY must encode exactly as the VM-tested original
    {
        zt::AtaTaskfile tf;
        tf.command = 0xEC;
        tf.count = 1;
        tf.device = 0;
        const auto cdb = zt::ata_pt16_cdb(tf, zt::AtaProtocol::PioDataIn, false);
        const std::array<std::uint8_t, 16> want{0x85, 0x08, 0x0E, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0xEC, 0};
        CHECK(cdb == want);
    }

    // SANITIZE CRYPTO SCRAMBLE EXT: 48-bit non-data, CK_COND, signature in the LBA,
    // FAILURE MODE set so a failed sanitize can be cleared.
    {
        const auto tf = zt::ata_sanitize_taskfile(zt::AtaSanitizeAction::CryptoScramble);
        CHECK(tf.command == 0xB4 && tf.features == 0x0011 && tf.extended);
        CHECK((tf.count & 0x10) != 0);
        const auto cdb = zt::ata_pt16_cdb(tf, zt::AtaProtocol::NonData, true);
        CHECK(cdb[0] == 0x85 && cdb[1] == ((3 << 1) | 1) && cdb[2] == 0x20);
        CHECK(cdb[4] == 0x11 && cdb[6] == 0x10 && cdb[14] == 0xB4);
        // LBA bytes in PT(16) order: 31:24, 7:0, 39:32, 15:8, 47:40, 23:16 -> "Cryp" = 0x43727970
        CHECK(cdb[7] == 0x43 && cdb[8] == 0x70 && cdb[10] == 0x79 && cdb[12] == 0x72);

        const auto ow = zt::ata_sanitize_taskfile(zt::AtaSanitizeAction::Overwrite);
        CHECK(ow.features == 0x0014 && ((ow.lba >> 32) & 0xFFFF) == 0x4F57 && (ow.count & 0x0F) == 1);
        CHECK(zt::ata_sanitize_taskfile(zt::AtaSanitizeAction::BlockErase).lba == 0x426B4572);
        CHECK(zt::ata_sanitize_status_taskfile(true).count == 1 && zt::ata_sanitize_status_taskfile(false).count == 0);
    }

    // ATA Status Return descriptor (descriptor-format sense) -> registers -> sanitize status
    {
        std::array<std::uint8_t, 22> sense{};
        sense[0] = 0x72;
        sense[1] = 0x01;  // RECOVERED ERROR: "ATA pass through information available"
        sense[7] = 14;    // additional length
        auto d = std::span(sense).subspan(8);
        d[0] = 0x09;
        d[1] = 0x0C;
        d[2] = 0x01;          // EXTEND
        d[4] = 0x40;          // COUNT(15:8): bit 14 = in progress
        d[7] = 0x00;          // LBA(7:0)
        d[9] = 0x80;          // LBA(15:8) -> progress 0x8000
        d[13] = 0x50;         // STATUS: DRDY | DSC, no ERR
        auto regs = zt::parse_ata_sense(sense);
        CHECK(regs && regs->count == 0x4000 && (regs->lba & 0xFFFF) == 0x8000 && !regs->has_error());
        auto st = zt::parse_ata_sanitize_status(*regs);
        CHECK(st.in_progress && !st.completed_ok && st.progress == 0x8000);

        d[4] = 0x80;  // bit 15: completed without error
        d[9] = 0xFF;
        d[7] = 0xFF;
        st = zt::parse_ata_sanitize_status(*zt::parse_ata_sense(sense));
        CHECK(st.completed_ok && !st.in_progress && !st.failed);

        d[13] = 0x51;  // ERR: last sanitize failed
        CHECK(zt::parse_ata_sanitize_status(*zt::parse_ata_sense(sense)).failed);
    }

    // Fixed-format sense: upper COUNT byte is lost, progress indicator is the fallback
    {
        std::array<std::uint8_t, 18> sense{};
        sense[0] = 0x70;
        sense[2] = 0x01;
        sense[4] = 0x50;  // STATUS
        sense[8] = 0x40;  // COUNT UPPER NONZERO
        sense[9] = 0x00;
        sense[10] = 0x20;  // progress 0x2000
        auto regs = zt::parse_ata_sense(sense);
        CHECK(regs && !regs->upper_bytes_known);
        CHECK(zt::parse_ata_sanitize_status(*regs).in_progress);
        sense[9] = 0xFF;
        sense[10] = 0xFF;  // no operation running
        CHECK(zt::parse_ata_sanitize_status(*zt::parse_ata_sense(sense)).completed_ok);
        sense[8] = 0x00;  // nothing in the upper byte: not a success
        CHECK(!zt::parse_ata_sanitize_status(*zt::parse_ata_sense(sense)).completed_ok);
    }

    // Garbage sense data never parses into registers
    {
        std::array<std::uint8_t, 8> junk{0x72, 0x05, 0x24, 0, 0, 0, 0, 40};  // length beyond buffer
        CHECK(!zt::parse_ata_sense(junk));
        CHECK(!zt::parse_ata_sense(std::span<const std::uint8_t>{}));
    }

    // Method IDs round-trip, and support levels are as documented
    for (int i = 0; i <= static_cast<int>(zt::Method::Overwrite); ++i) {
        const auto m = static_cast<zt::Method>(i);
        CHECK(zt::method_from_id(zt::method_id(m)) == m);
    }
    CHECK(!zt::method_from_id("rm-rf"));
    CHECK(zt::support(zt::Method::NvmeFormatCrypto) == zt::Support::Implemented);
    CHECK(zt::support(zt::Method::NvmeSanitizeCrypto) == zt::Support::Experimental);
    CHECK(zt::support(zt::Method::AtaSanitizeBlock) == zt::Support::Experimental);
    CHECK(zt::support(zt::Method::AtaSecurityErase) == zt::Support::NotImplemented);

    // NVMe: empty data rejected
    {
        zt::NvmeIdentifyData raw{};
        CHECK(!zt::parse_nvme_identify_ctrl(raw));
    }

    // No identify data at all (virtio): overwrite only, Clear
    {
        zt::Device dev;
        const auto m = zt::rank_methods(dev, std::nullopt, std::nullopt);
        CHECK(m.size() == 1 && m[0].method == zt::Method::Overwrite && m[0].level == zt::Level::Clear);
    }

    return finish("identify");
}
