#include "zt/methods.hpp"

#include <algorithm>

namespace zt {

std::string to_string(Method m) {
    switch (m) {
        case Method::NvmeSanitizeCrypto: return "NVMe Sanitize (crypto erase)";
        case Method::NvmeSanitizeBlock: return "NVMe Sanitize (block erase)";
        case Method::NvmeFormatCrypto: return "NVMe Format (crypto erase, SES=2)";
        case Method::NvmeSanitizeOverwrite: return "NVMe Sanitize (overwrite)";
        case Method::NvmeFormatUserData: return "NVMe Format (user data erase, SES=1)";
        case Method::AtaSanitizeCrypto: return "ATA SANITIZE (crypto scramble)";
        case Method::AtaSanitizeBlock: return "ATA SANITIZE (block erase)";
        case Method::AtaSanitizeOverwrite: return "ATA SANITIZE (overwrite)";
        case Method::AtaSecurityEraseEnhanced: return "ATA Security Erase (enhanced)";
        case Method::AtaSecurityErase: return "ATA Security Erase (normal)";
        case Method::Overwrite: return "Software overwrite";
    }
    return "unknown";
}

std::string to_string(Level l) { return l == Level::Purge ? "Purge" : "Clear"; }

namespace {

void add_nvme(std::vector<Candidate>& out, const NvmeIdentify& id) {
    const std::string multi_ns =
        id.namespace_count > 1 ? "affects all " + std::to_string(id.namespace_count) + " namespaces" : "";

    out.push_back({Method::NvmeSanitizeCrypto, Level::Purge, id.sanitize_crypto,
                   id.sanitize_crypto ? "" : "not supported by controller"});
    out.push_back({Method::NvmeSanitizeBlock, Level::Purge, id.sanitize_block,
                   id.sanitize_block ? "" : "not supported by controller"});

    const bool fmt_crypto = id.format_supported && id.format_crypto_erase;
    out.push_back({Method::NvmeFormatCrypto, Level::Purge, fmt_crypto,
                   fmt_crypto ? multi_ns : "not supported by controller"});
    out.push_back({Method::NvmeSanitizeOverwrite, Level::Purge, id.sanitize_overwrite,
                   id.sanitize_overwrite ? "slow; adds flash wear" : "not supported by controller"});
    out.push_back({Method::NvmeFormatUserData, Level::Clear, id.format_supported,
                   id.format_supported ? "vendor-dependent; claimed as Clear only" : "Format NVM not supported"});
}

void add_ata(std::vector<Candidate>& out, const AtaIdentify& id, bool ssd) {
    const auto sanitize_note = [&](bool supported) -> std::string {
        if (!id.sanitize_supported) return "SANITIZE feature set not supported";
        return supported ? "" : "not supported by drive";
    };
    out.push_back({Method::AtaSanitizeCrypto, Level::Purge, id.sanitize_crypto, sanitize_note(id.sanitize_crypto)});
    out.push_back({Method::AtaSanitizeBlock, Level::Purge, id.sanitize_block, sanitize_note(id.sanitize_block)});
    out.push_back({Method::AtaSanitizeOverwrite, ssd ? Level::Clear : Level::Purge, id.sanitize_overwrite,
                   sanitize_note(id.sanitize_overwrite)});

    // Security Erase is blocked by a frozen/locked state; frozen is common and fixable.
    std::string blocked;
    if (!id.security_supported) blocked = "security feature set not supported";
    else if (id.security_frozen) blocked = "drive is security-frozen; suspend and resume to unfreeze";
    else if (id.security_locked) blocked = "drive is locked with an unknown password";
    else if (id.security_count_expired) blocked = "password attempt counter expired; power-cycle the drive";

    const auto with_time = [](unsigned minutes) {
        return minutes ? "drive estimates ~" + std::to_string(minutes) + " min" : std::string{};
    };
    const std::string ssd_caveat = ssd ? "vendor-dependent on SSDs; claimed as Clear only" : "";

    const bool enhanced = id.enhanced_erase_supported && blocked.empty();
    std::string enh_note = !id.security_supported      ? blocked
                           : !id.enhanced_erase_supported ? "enhanced mode not supported"
                           : !blocked.empty()           ? blocked
                           : !ssd_caveat.empty()        ? ssd_caveat
                                                        : with_time(id.enhanced_erase_minutes);
    out.push_back({Method::AtaSecurityEraseEnhanced, ssd ? Level::Clear : Level::Purge, enhanced, enh_note});

    const bool normal = blocked.empty();
    std::string normal_note = !blocked.empty()    ? blocked
                              : !ssd_caveat.empty() ? ssd_caveat
                                                    : with_time(id.normal_erase_minutes);
    out.push_back({Method::AtaSecurityErase, ssd ? Level::Clear : Level::Purge, normal, normal_note});
}

}  // namespace

std::vector<Candidate> rank_methods(const Device& dev, const std::optional<NvmeIdentify>& nvme,
                                    const std::optional<AtaIdentify>& ata) {
    std::vector<Candidate> out;
    const bool ssd = ata ? ata->non_rotating : !dev.rotational;
    if (nvme) add_nvme(out, *nvme);
    if (ata) add_ata(out, *ata, ssd);

    // Overwrite always applies but cannot reach remapped or over-provisioned
    // blocks, so it never reaches Purge.
    std::string ow_note = ssd ? "cannot reach over-provisioned flash" : "cannot reach reallocated sectors";
    out.push_back({Method::Overwrite, Level::Clear, !dev.read_only, dev.read_only ? "device is read-only" : ow_note});

    std::stable_partition(out.begin(), out.end(), [](const Candidate& c) { return c.available; });
    return out;
}

}  // namespace zt
