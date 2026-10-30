#pragma once

#include <string>
#include <vector>

#include "zt/device.hpp"

namespace zt {

// Reasons this disk must not be erased; empty means no blocker was found.
// This is the read-only pre-check. The erase path additionally opens the
// device with O_EXCL, which the kernel refuses for any disk it still holds.
std::vector<std::string> erase_blockers(const Device& d);

}  // namespace zt
