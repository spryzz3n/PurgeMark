#include "common.hpp"

#include <cstdio>

namespace ztcli {

zt::Result<Args> parse_args(const std::vector<std::string_view>& argv, const std::set<std::string>& with_value,
                            const std::set<std::string>& flags) {
    using R = zt::Result<Args>;
    Args a;
    for (std::size_t i = 0; i < argv.size(); ++i) {
        const std::string arg(argv[i]);
        if (arg.rfind("--", 0) != 0) {
            a.positional.push_back(arg);
            continue;
        }
        const std::string name = arg.substr(2);
        if (flags.count(name)) {
            a.flags.insert(name);
        } else if (with_value.count(name)) {
            if (i + 1 >= argv.size()) return R::fail("option " + arg + " needs a value");
            a.options[name] = std::string(argv[++i]);
        } else {
            return R::fail("unknown option " + arg);
        }
    }
    return R::ok(std::move(a));
}

std::string human_size(std::uint64_t bytes) {
    static constexpr const char* units[] = {"B", "K", "M", "G", "T", "P"};
    double v = static_cast<double>(bytes);
    int u = 0;
    while (v >= 1024.0 && u < 5) {
        v /= 1024.0;
        ++u;
    }
    char buf[32];
    std::snprintf(buf, sizeof buf, u == 0 ? "%.0f%s" : "%.1f%s", v, units[u]);
    return buf;
}

std::string or_dash(const std::string& s) { return s.empty() ? "-" : s; }

}  // namespace ztcli
