#pragma once

#include <optional>
#include <string>
#include <vector>

#include "zt/ata.hpp"
#include "zt/device.hpp"
#include "zt/methods.hpp"
#include "zt/nvme.hpp"

namespace zt {

struct ProbeResult {
    Device device;
    std::optional<NvmeIdentify> nvme;
    std::optional<AtaIdentify> ata;
    std::string identify_error;  // why the drive couldn't be queried, if it couldn't
    std::vector<std::string> blockers;
    std::vector<Candidate> methods;  // best first
};

// Queries the drive's identify data (read-only commands) and ranks erase methods.
ProbeResult probe(const Device& dev);

}  // namespace zt
