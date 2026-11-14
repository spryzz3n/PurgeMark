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
// sibling_in_use lists why other namespaces on the same controller must not be
// touched; methods that reach the whole controller become unavailable if it isn't empty.
std::vector<Candidate> rank_methods(const Device& dev, const std::optional<NvmeIdentify>& nvme,
                                    const std::optional<AtaIdentify>& ata,
                                    const std::vector<std::string>& sibling_in_use = {});

// Sanitize always acts on the whole controller; Format does when FNA says so.
bool is_controller_wide(Method m, const NvmeIdentify& id);

bool is_ata_sanitize(Method m);
bool ata_sanitize_supported(Method m, const AtaIdentify& id);

// ATA SANITIZE through a USB bridge stays off unless the operator overrides it.
// Many bridges drop the command, time out on it, or reset part way through,
// which can leave the drive stuck in a sanitize-failed state. rank_methods
// marks these unavailable and run_erase refuses them without the override.
bool usb_sanitize_blocked(const Device& dev, Method m);
extern const char* const kUsbSanitizeNote;

}  // namespace pm
