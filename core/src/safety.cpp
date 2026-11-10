#include "pm/safety.hpp"

namespace pm {

std::vector<std::string> erase_blockers(const Device& d) {
    std::vector<std::string> reasons;
    if (d.read_only) reasons.push_back("device is read-only");
    // A mounted disk includes the live medium itself (/run/live/medium) and the host's root.
    for (const auto& m : d.mountpoints) reasons.push_back("mounted at " + m);
    for (const auto& s : d.swaps) reasons.push_back("active swap on " + s);
    for (const auto& h : d.holders) reasons.push_back("in use by " + h + " (LVM, RAID, LUKS or multipath)");
    return reasons;
}

namespace {

// "nvme0n1" -> "nvme0n". Empty for anything else.
std::string controller_prefix(const std::string& name) {
    if (name.rfind("nvme", 0) != 0) return {};
    std::size_t i = 4;
    while (i < name.size() && name[i] >= '0' && name[i] <= '9') ++i;
    if (i == 4 || i >= name.size() || name[i] != 'n') return {};
    return name.substr(0, i + 1);
}

}  // namespace

std::vector<std::string> sibling_blockers(const Device& d, const SystemRoots& roots) {
    std::vector<std::string> reasons;
    const std::string prefix = controller_prefix(d.name);
    if (prefix.empty()) return reasons;
    for (const auto& other : list_devices(roots)) {
        if (other.name == d.name || other.name.rfind(prefix, 0) != 0) continue;
        for (const auto& why : erase_blockers(other)) reasons.push_back(other.name + " " + why);
    }
    return reasons;
}

}  // namespace pm
