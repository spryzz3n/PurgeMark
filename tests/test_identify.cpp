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
            CHECK(r->namespace_count == 1);
            const auto m = zt::rank_methods({}, r.value(), std::nullopt);
            CHECK(m.front().method == zt::Method::NvmeSanitizeCrypto);
        }
    }

    // NVMe: no sanitize, format-with-crypto only, multiple namespaces
    {
        const auto raw = nvme_ctrl(0, 0b101, 3);
        const auto r = zt::parse_nvme_identify_ctrl(raw);
        CHECK(static_cast<bool>(r));
        if (r) {
            CHECK(!r->sanitize_supported());
            const auto m = zt::rank_methods({}, r.value(), std::nullopt);
            CHECK(m.front().method == zt::Method::NvmeFormatCrypto);
            CHECK(m.front().note.find("3 namespaces") != std::string::npos);
            const auto* ses1 = find(m, zt::Method::NvmeFormatUserData);
            CHECK(ses1 && ses1->available && ses1->level == zt::Level::Clear);
        }
    }

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
