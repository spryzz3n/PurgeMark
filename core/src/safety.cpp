#include "zt/safety.hpp"

namespace zt {

std::vector<std::string> erase_blockers(const Device& d) {
    std::vector<std::string> reasons;
    if (d.read_only) reasons.push_back("device is read-only");
    // A mounted disk includes the live medium itself (/run/live/medium) and the host's root.
    for (const auto& m : d.mountpoints) reasons.push_back("mounted at " + m);
    for (const auto& s : d.swaps) reasons.push_back("active swap on " + s);
    for (const auto& h : d.holders) reasons.push_back("in use by " + h + " (LVM, RAID, LUKS or multipath)");
    return reasons;
}

}  // namespace zt
