#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "zt/result.hpp"

namespace ztcli {

struct Args {
    std::vector<std::string> positional;
    std::map<std::string, std::string> options;  // --name value
    std::set<std::string> flags;                 // --name

    bool has(const std::string& f) const { return flags.count(f) > 0; }
    std::string get(const std::string& name, const std::string& fallback = "") const {
        const auto it = options.find(name);
        return it == options.end() ? fallback : it->second;
    }
};

// Options listed in `with_value` consume the next argument; those in `flags` don't.
zt::Result<Args> parse_args(const std::vector<std::string_view>& argv, const std::set<std::string>& with_value,
                            const std::set<std::string>& flags);

std::string human_size(std::uint64_t bytes);
std::string or_dash(const std::string& s);

int cmd_list(const std::vector<std::string_view>& argv);
int cmd_probe(const std::vector<std::string_view>& argv);
int cmd_erase(const std::vector<std::string_view>& argv);
int cmd_keygen(const std::vector<std::string_view>& argv);
int cmd_verify_cert(const std::vector<std::string_view>& argv);

}  // namespace ztcli
