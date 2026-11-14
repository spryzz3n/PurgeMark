#include "pm/methods.hpp"

#include <algorithm>

namespace pm {

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

const char* method_id(Method m) {
    switch (m) {
        case Method::NvmeSanitizeCrypto: return "nvme-sanitize-crypto";
        case Method::NvmeSanitizeBlock: return "nvme-sanitize-block";
        case Method::NvmeFormatCrypto: return "nvme-format-ses2";
        case Method::NvmeSanitizeOverwrite: return "nvme-sanitize-overwrite";
        case Method::NvmeFormatUserData: return "nvme-format-ses1";
        case Method::AtaSanitizeCrypto: return "ata-sanitize-crypto";
        case Method::AtaSanitizeBlock: return "ata-sanitize-block";
        case Method::AtaSanitizeOverwrite: return "ata-sanitize-overwrite";
        case Method::AtaSecurityEraseEnhanced: return "ata-security-erase-enhanced";
        case Method::AtaSecurityErase: return "ata-security-erase";
        case Method::Overwrite: return "overwrite";
    }
    return "unknown";
}

std::optional<Method> method_from_id(const std::string& id) {
    for (int i = 0; i <= static_cast<int>(Method::Overwrite); ++i) {
        const auto m = static_cast<Method>(i);
        if (id == method_id(m)) return m;
    }
    return std::nullopt;
}

Support support(Method m) {
    switch (m) {
        case Method::Overwrite:
        case Method::NvmeFormatUserData:
        case Method::NvmeFormatCrypto:
            return Support::Implemented;
        case Method::NvmeSanitizeCrypto:
        case Method::NvmeSanitizeBlock:
        case Method::NvmeSanitizeOverwrite:
        case Method::AtaSanitizeCrypto:
        case Method::AtaSanitizeBlock:
        case Method::AtaSanitizeOverwrite:
            return Support::Experimental;
        default:
            return Support::NotImplemented;
    }
}

Level nominal_level(Method m, bool ssd) {
    switch (m) {
        case Method::NvmeSanitizeCrypto:
        case Method::NvmeSanitizeBlock:
        case Method::NvmeSanitizeOverwrite:
        case Method::NvmeFormatCrypto:
        case Method::AtaSanitizeCrypto:
        case Method::AtaSanitizeBlock:
            return Level::Purge;
        case Method::AtaSanitizeOverwrite:
        case Method::AtaSecurityEraseEnhanced:
        case Method::AtaSecurityErase:
            return ssd ? Level::Clear : Level::Purge;
        case Method::NvmeFormatUserData:
        case Method::Overwrite:
            return Level::Clear;
    }
    return Level::Clear;
}

bool is_controller_wide(Method m, const NvmeIdentify& id) {
    switch (m) {
        case Method::NvmeSanitizeCrypto:
        case Method::NvmeSanitizeBlock:
        case Method::NvmeSanitizeOverwrite:
            return true;
        case Method::NvmeFormatCrypto:
        case Method::NvmeFormatUserData:
            return id.format_all_namespaces || id.secure_erase_all_namespaces;
        default:
            return false;
    }
}

bool is_ata_sanitize(Method m) {
    return m == Method::AtaSanitizeCrypto || m == Method::AtaSanitizeBlock || m == Method::AtaSanitizeOverwrite;
}

bool ata_sanitize_supported(Method m, const AtaIdentify& id) {
    if (!id.sanitize_supported) return false;
    switch (m) {
        case Method::AtaSanitizeCrypto: return id.sanitize_crypto;
        case Method::AtaSanitizeBlock: return id.sanitize_block;
        case Method::AtaSanitizeOverwrite: return id.sanitize_overwrite;
        default: return false;
    }
}

const char* const kUsbSanitizeNote = "behind a USB bridge; needs --allow-usb-sanitize";

bool usb_sanitize_blocked(const Device& dev, Method m) {
    return dev.bus == Bus::Usb && is_ata_sanitize(m);
}

namespace {

void add_nvme(std::vector<Candidate>& out, const NvmeIdentify& id) {
    // Sanitize always covers the whole controller; Format does when FNA bit 0 is set.
    const std::string all_ns = id.active_namespaces > 1
                                   ? "erases all " + std::to_string(id.active_namespaces) + " namespaces"
                                   : "";
    const std::string fmt_scope = is_controller_wide(Method::NvmeFormatCrypto, id) ? all_ns : "";

    out.push_back({Method::NvmeSanitizeCrypto, {}, id.sanitize_crypto,
                   id.sanitize_crypto ? all_ns : "not supported by controller"});
    out.push_back({Method::NvmeSanitizeBlock, {}, id.sanitize_block,
                   id.sanitize_block ? all_ns : "not supported by controller"});

    const bool fmt_crypto = id.format_supported && id.format_crypto_erase;
    out.push_back({Method::NvmeFormatCrypto, {}, fmt_crypto, fmt_crypto ? fmt_scope : "not supported by controller"});
    out.push_back({Method::NvmeSanitizeOverwrite, {}, id.sanitize_overwrite,
                   id.sanitize_overwrite ? "slow; adds flash wear" : "not supported by controller"});
    out.push_back({Method::NvmeFormatUserData, {}, id.format_supported,
                   id.format_supported ? "vendor-dependent; claimed as Clear only" : "Format NVM not supported"});
}

void add_ata(std::vector<Candidate>& out, const AtaIdentify& id, bool ssd) {
    const auto sanitize_note = [&](bool supported) -> std::string {
        if (!id.sanitize_supported) return "SANITIZE feature set not supported";
        return supported ? "" : "not supported by drive";
    };
    out.push_back({Method::AtaSanitizeCrypto, {}, id.sanitize_crypto, sanitize_note(id.sanitize_crypto)});
    out.push_back({Method::AtaSanitizeBlock, {}, id.sanitize_block, sanitize_note(id.sanitize_block)});
    out.push_back({Method::AtaSanitizeOverwrite, {}, id.sanitize_overwrite, sanitize_note(id.sanitize_overwrite)});

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
    out.push_back({Method::AtaSecurityEraseEnhanced, {}, enhanced, enh_note});

    const bool normal = blocked.empty();
    std::string normal_note = !blocked.empty()    ? blocked
                              : !ssd_caveat.empty() ? ssd_caveat
                                                    : with_time(id.normal_erase_minutes);
    out.push_back({Method::AtaSecurityErase, {}, normal, normal_note});
}

}  // namespace

std::vector<Candidate> rank_methods(const Device& dev, const std::optional<NvmeIdentify>& nvme,
                                    const std::optional<AtaIdentify>& ata,
                                    const std::vector<std::string>& sibling_in_use) {
    std::vector<Candidate> out;
    const bool ssd = ata ? ata->non_rotating : !dev.rotational;
    if (nvme) {
        add_nvme(out, *nvme);
        for (auto& c : out) {
            if (sibling_in_use.empty() || !c.available || !is_controller_wide(c.method, *nvme)) continue;
            c.available = false;
            c.note = "would also erase " + sibling_in_use.front();
        }
    }
    if (ata) {
        add_ata(out, *ata, ssd);
        for (auto& c : out) {
            if (!c.available || !usb_sanitize_blocked(dev, c.method)) continue;
            c.available = false;
            c.note = kUsbSanitizeNote;
        }
    }

    // Overwrite always applies but cannot reach remapped or over-provisioned
    // blocks, so it never reaches Purge.
    std::string ow_note = ssd ? "cannot reach over-provisioned flash" : "cannot reach reallocated sectors";
    out.push_back({Method::Overwrite, {}, !dev.read_only, dev.read_only ? "device is read-only" : ow_note});

    for (auto& c : out) c.level = nominal_level(c.method, ssd);
    std::stable_partition(out.begin(), out.end(), [](const Candidate& c) { return c.available; });
    return out;
}

}  // namespace pm
