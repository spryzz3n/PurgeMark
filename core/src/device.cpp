#include "zt/device.hpp"

#include <algorithm>
#include <array>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string_view>

namespace fs = std::filesystem;

namespace zt {

std::string to_string(Bus bus) {
    switch (bus) {
        case Bus::Nvme: return "nvme";
        case Bus::Sata: return "sata";
        case Bus::Usb: return "usb";
        case Bus::Scsi: return "scsi";
        case Bus::Virtio: return "virtio";
        case Bus::Mmc: return "mmc";
        case Bus::Unknown: break;
    }
    return "unknown";
}

namespace {

std::string trim(std::string s) {
    const auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

// sysfs attributes are single short lines; a missing file just means "not exposed".
std::string read_attr(const fs::path& p) {
    std::ifstream in(p);
    if (!in) return {};
    std::string line;
    std::getline(in, line);
    return trim(line);
}

bool read_flag(const fs::path& p) { return read_attr(p) == "1"; }

bool starts_with(std::string_view s, std::string_view prefix) {
    return s.substr(0, prefix.size()) == prefix;
}

// Virtual or non-disk devices that are never erase targets.
bool is_ignored(std::string_view name) {
    static constexpr std::array prefixes{"loop", "ram", "zram", "dm-", "md", "sr", "fd", "nbd"};
    return std::any_of(prefixes.begin(), prefixes.end(),
                       [&](std::string_view p) { return starts_with(name, p); });
}

Bus detect_bus(const std::string& name, const fs::path& block_entry) {
    if (starts_with(name, "nvme")) return Bus::Nvme;
    if (starts_with(name, "vd")) return Bus::Virtio;
    if (starts_with(name, "mmcblk")) return Bus::Mmc;
    // /sys/block/<name> is a symlink into the device tree; its target reveals the transport.
    std::error_code ec;
    const std::string real = fs::canonical(block_entry, ec).string();
    if (ec) return Bus::Unknown;
    if (real.find("/usb") != std::string::npos) return Bus::Usb;
    if (real.find("/ata") != std::string::npos) return Bus::Sata;
    if (starts_with(name, "sd")) return Bus::Scsi;
    return Bus::Unknown;
}

std::vector<std::string> list_dir_names(const fs::path& dir) {
    std::vector<std::string> out;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(dir, ec)) out.push_back(e.path().filename().string());
    std::sort(out.begin(), out.end());
    return out;
}

// /proc/self/mounts escapes space, tab, newline and backslash as \ooo octal.
std::string unescape_mount_field(const std::string& s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '\\' && i + 3 < s.size()) {
            const std::string oct = s.substr(i + 1, 3);
            if (std::all_of(oct.begin(), oct.end(), [](char c) { return c >= '0' && c <= '7'; })) {
                out.push_back(static_cast<char>(std::stoi(oct, nullptr, 8)));
                i += 3;
                continue;
            }
        }
        out.push_back(s[i]);
    }
    return out;
}

// "/dev/disk/by-uuid/..." or "/dev/mapper/x" -> kernel name ("sda1", "dm-0").
// Falls back to the last path component when the node doesn't exist (e.g. in tests).
std::string kernel_name(const std::string& dev_path) {
    std::error_code ec;
    const fs::path real = fs::canonical(dev_path, ec);
    return (ec ? fs::path(dev_path) : real).filename().string();
}

using NameIndex = std::map<std::string, std::vector<std::string>>;

// Maps kernel name -> mountpoints, from entries whose source is a /dev node.
NameIndex read_mounts(const fs::path& mounts) {
    NameIndex out;
    std::ifstream in(mounts);
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream fields(line);
        std::string source, target;
        if (!(fields >> source >> target)) continue;
        if (!starts_with(source, "/dev/")) continue;
        out[kernel_name(unescape_mount_field(source))].push_back(unescape_mount_field(target));
    }
    return out;
}

// Maps kernel name -> swap area path. Swap files live on a mounted filesystem,
// so only partition/device swaps need handling here.
NameIndex read_swaps(const fs::path& swaps) {
    NameIndex out;
    std::ifstream in(swaps);
    std::string line;
    std::getline(in, line);  // header
    while (std::getline(in, line)) {
        std::istringstream fields(line);
        std::string filename, type;
        if (!(fields >> filename >> type) || type != "partition") continue;
        filename = unescape_mount_field(filename);
        out[kernel_name(filename)].push_back(filename);
    }
    return out;
}

// Builds the Device for /sys/block/<name>; nullopt for zero-size devices
// (empty card readers, unpopulated slots).
std::optional<Device> describe(const fs::path& block_dir, const std::string& name, const NameIndex& mounts,
                               const NameIndex& swaps) {
    const fs::path entry = block_dir / name;
    Device d;
    d.name = name;
    d.path = "/dev/" + name;
    // The size attribute is always in 512-byte units regardless of the logical block size.
    try {
        d.size_bytes = std::stoull(read_attr(entry / "size")) * 512ULL;
    } catch (const std::exception&) {
        d.size_bytes = 0;
    }
    if (d.size_bytes == 0) return std::nullopt;
    // Hidden disks have no /dev node, e.g. NVMe multipath paths (nvme0c0n1)
    // that the kernel exposes only through their shared nvme0n1 head.
    if (read_flag(entry / "hidden")) return std::nullopt;

    d.bus = detect_bus(name, entry);
    d.model = read_attr(entry / "device" / "model");
    d.serial = read_attr(entry / "device" / "serial");  // NVMe exposes this; SCSI/SATA don't
    d.firmware = read_attr(entry / "device" / "firmware_rev");
    if (d.firmware.empty()) d.firmware = read_attr(entry / "device" / "rev");
    d.rotational = read_flag(entry / "queue" / "rotational");
    d.removable = read_flag(entry / "removable");
    d.read_only = read_flag(entry / "ro");

    // Partitions are child directories carrying a "partition" attribute.
    for (const auto& child : list_dir_names(entry)) {
        if (fs::exists(entry / child / "partition")) d.partitions.push_back(child);
    }

    std::vector<std::string> names{name};
    names.insert(names.end(), d.partitions.begin(), d.partitions.end());
    for (const auto& n : names) {
        if (auto it = mounts.find(n); it != mounts.end()) {
            d.mountpoints.insert(d.mountpoints.end(), it->second.begin(), it->second.end());
        }
        if (auto it = swaps.find(n); it != swaps.end()) {
            d.swaps.insert(d.swaps.end(), it->second.begin(), it->second.end());
        }
        const fs::path holders_dir = n == name ? entry / "holders" : entry / n / "holders";
        for (const auto& h : list_dir_names(holders_dir)) d.holders.push_back(h);
    }
    return d;
}

}  // namespace

std::vector<Device> list_devices(const SystemRoots& roots) {
    const fs::path block_dir = roots.sys / "block";
    const auto mounts = read_mounts(roots.mounts);
    const auto swaps = read_swaps(roots.swaps);
    std::vector<Device> devices;
    for (const auto& name : list_dir_names(block_dir)) {
        if (is_ignored(name)) continue;
        if (auto d = describe(block_dir, name, mounts, swaps)) devices.push_back(std::move(*d));
    }
    return devices;
}

std::optional<Device> find_device(const std::string& name_or_path, const SystemRoots& roots) {
    const std::string name = fs::path(name_or_path).filename().string();
    const fs::path block_dir = roots.sys / "block";
    if (name.empty() || !fs::exists(block_dir / name)) return std::nullopt;
    return describe(block_dir, name, read_mounts(roots.mounts), read_swaps(roots.swaps));
}

}  // namespace zt
