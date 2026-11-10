#pragma once

#include <string>
#include <vector>

#include "pm/device.hpp"

namespace pm {

// Reasons this disk must not be erased; empty means no blocker was found.
// This is the read-only pre-check. The erase path additionally opens the
// device with O_EXCL, which the kernel refuses for any disk it still holds.
std::vector<std::string> erase_blockers(const Device& d);

// Why the other namespaces on d's NVMe controller must not be erased. Controller-wide
// methods (Sanitize, some Formats) reach those too, so they have to be idle as well.
std::vector<std::string> sibling_blockers(const Device& d, const SystemRoots& roots = {});

}  // namespace pm
