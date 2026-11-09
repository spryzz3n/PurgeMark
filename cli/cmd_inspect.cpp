// `pmark list` and `pmark probe`: read-only inspection.

#include <unistd.h>

#include <cstdio>
#include <iostream>

#include "common.hpp"
#include "pm/device.hpp"
#include "pm/probe.hpp"
#include "pm/safety.hpp"

namespace pmcli {

namespace {

const char* yes_no(bool b) { return b ? "yes" : "no"; }

void print_probe(const pm::ProbeResult& r) {
    const auto& d = r.device;
    std::printf("%s  %s  %s\n", d.path.c_str(), or_dash(d.model).c_str(), human_size(d.size_bytes).c_str());
    std::printf("  bus %s, serial %s, firmware %s\n", pm::to_string(d.bus).c_str(),
                or_dash(d.serial).c_str(), or_dash(d.firmware).c_str());

    if (r.blockers.empty()) {
        std::printf("  safety: no blockers found\n");
    } else {
        for (const auto& b : r.blockers) std::printf("  safety: BLOCKED, %s\n", b.c_str());
    }

    if (!r.identify_error.empty()) std::printf("  identify: %s\n", r.identify_error.c_str());
    if (r.nvme) {
        const auto& n = *r.nvme;
        std::printf("  nvme: active namespaces %u, format %s, sanitize crypto/block/overwrite %s/%s/%s\n",
                    n.active_namespaces, yes_no(n.format_supported), yes_no(n.sanitize_crypto),
                    yes_no(n.sanitize_block), yes_no(n.sanitize_overwrite));
    }
    if (r.ata) {
        const auto& a = *r.ata;
        std::printf("  ata: %s, security %s%s%s%s, sanitize crypto/block/overwrite %s/%s/%s\n",
                    a.non_rotating ? "non-rotating" : "rotating",
                    a.security_supported ? "supported" : "unsupported",
                    a.security_enabled ? ", PASSWORD SET" : "", a.security_frozen ? ", FROZEN" : "",
                    a.security_locked ? ", LOCKED" : "", yes_no(a.sanitize_crypto),
                    yes_no(a.sanitize_block), yes_no(a.sanitize_overwrite));
    }

    std::printf("  methods (best first):\n");
    int rank = 1;
    for (const auto& m : r.methods) {
        const std::string marker = m.available ? std::to_string(rank++) + "." : " -";
        std::printf("    %-3s %-38s %-5s %s%s\n", marker.c_str(), pm::to_string(m.method).c_str(),
                    pm::to_string(m.level).c_str(), m.available ? "" : "unavailable: ", m.note.c_str());
    }
}

}  // namespace

int cmd_list(const std::vector<std::string_view>&) {
    const auto devices = pm::list_devices();
    if (devices.empty()) {
        std::cout << "no block devices found\n";
        return 0;
    }
    std::printf("%-10s %-7s %8s %-4s %-28s %-22s %s\n", "NAME", "BUS", "SIZE", "TYPE", "MODEL",
                "SERIAL", "STATUS");
    for (const auto& d : devices) {
        const auto blockers = pm::erase_blockers(d);
        std::string status = blockers.empty() ? "free" : "BLOCKED: " + blockers.front();
        if (blockers.size() > 1) status += " (+" + std::to_string(blockers.size() - 1) + ")";
        std::printf("%-10s %-7s %8s %-4s %-28s %-22s %s\n", d.name.c_str(),
                    pm::to_string(d.bus).c_str(), human_size(d.size_bytes).c_str(),
                    d.rotational ? "hdd" : "ssd", or_dash(d.model).c_str(),
                    or_dash(d.serial).c_str(), status.c_str());
    }
    return 0;
}

int cmd_probe(const std::vector<std::string_view>& targets) {
    if (::geteuid() != 0) std::cerr << "pmark: warning: not root, identify commands will fail\n";

    const auto devices = pm::list_devices();
    int status = 0;
    bool first = true;
    auto show = [&](const pm::Device& d) {
        if (!first) std::cout << "\n";
        first = false;
        print_probe(pm::probe(d));
    };

    if (targets.empty()) {
        for (const auto& d : devices) show(d);
        return 0;
    }
    for (const auto t : targets) {
        bool found = false;
        for (const auto& d : devices) {
            if (t == d.path || t == d.name) {
                show(d);
                found = true;
            }
        }
        if (!found) {
            std::cerr << "pmark: no whole-disk device named '" << t << "'\n";
            status = 1;
        }
    }
    return status;
}

}  // namespace pmcli
