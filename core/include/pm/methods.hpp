#pragma once

#include <optional>
#include <string>
#include <vector>

#include "pm/ata.hpp"
#include "pm/device.hpp"
#include "pm/nvme.hpp"

namespace pm {

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
const char* method_id(Method m);  // stable identifier used in certificates and on the CLI
std::optional<Method> method_from_id(const std::string& id);

// How far PurgeMark can execute a method. Experimental ones are written to the
// spec but haven't run against real hardware yet and need an explicit opt-in.
enum class Support { Implemented, Experimental, NotImplemented };
Support support(Method m);

// The NIST level a method achieves. Deliberately conservative: where the
// standard depends on the vendor's implementation (ATA Security Erase or
// SANITIZE overwrite on SSDs, NVMe Format SES=1), we claim Clear.
Level nominal_level(Method m, bool ssd);

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

}  // namespace pm
