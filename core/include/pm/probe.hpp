#pragma once

#include <optional>
#include <string>
#include <vector>

#include "pm/ata.hpp"
#include "pm/device.hpp"
#include "pm/methods.hpp"
#include "pm/nvme.hpp"

namespace pm {

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

}  // namespace pm
