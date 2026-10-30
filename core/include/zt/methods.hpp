#pragma once

#include <optional>
#include <string>
#include <vector>

#include "zt/ata.hpp"
#include "zt/device.hpp"
#include "zt/nvme.hpp"

namespace zt {

enum class Method {
    NvmeSanitizeCrypto,
    NvmeSanitizeBlock,
    NvmeFormatCrypto,  // Format NVM, SES=2
    NvmeSanitizeOverwrite,
    NvmeFormatUserData,  // Format NVM, SES=1
    AtaSanitizeCrypto,
    AtaSanitizeBlock,
    AtaSanitizeOverwrite,
    AtaSecurityEraseEnhanced,
    AtaSecurityErase,
    Overwrite,  // software overwrite through the block layer
};

// NIST SP 800-88 sanitization levels. Destroy is physical and out of scope.
enum class Level { Clear, Purge };

std::string to_string(Method m);
std::string to_string(Level l);

struct Candidate {
    Method method;
    Level level;
    bool available;
    std::string note;  // why unavailable, or a caveat
};

// All methods that apply to this drive, best first; unavailable ones sort last.
// Levels are deliberately conservative: where the standard depends on the
// vendor's implementation (e.g. ATA Security Erase on SSDs), we claim Clear.
std::vector<Candidate> rank_methods(const Device& dev, const std::optional<NvmeIdentify>& nvme,
                                    const std::optional<AtaIdentify>& ata);

}  // namespace zt
